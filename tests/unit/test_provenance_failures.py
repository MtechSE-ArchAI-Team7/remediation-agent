"""Malformed and exhausted control-plane discovery cannot establish release identity."""

from collections.abc import Mapping

import pytest

from remediation_agent.adapters.provenance import AgentCoreReleaseProvenance


class Client:
    def __init__(self, pages: list[dict[str, object]]) -> None:
        self.pages = iter(pages)
        self.calls: list[dict[str, object]] = []

    def list_agent_runtime_versions(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(kwargs)
        return next(self.pages)

    def get_agent_runtime(self, **kwargs: object) -> Mapping[str, object]:
        return {}


def adapter(client: Client, limit: int = 2) -> AgentCoreReleaseProvenance:
    return AgentCoreReleaseProvenance(
        runtime_id="remediation-1234567890",
        release_id="fixture",
        source_revision="a" * 40,
        image_digest="sha256:" + "b" * 64,
        region_name="ap-southeast-1",
        expected_account_id="734849394833",
        client=client,
        max_versions=limit,
    )


@pytest.mark.parametrize(
    "page",
    [
        {},
        {"agentRuntimes": [None]},
        {"agentRuntimes": [{"agentRuntimeVersion": "bad"}]},
        {"agentRuntimes": [], "nextToken": ""},
        {"agentRuntimes": [{"agentRuntimeVersion": "1"}] * 3},
        {"agentRuntimes": [{"agentRuntimeVersion": "1"}, {"agentRuntimeVersion": "2"}], "nextToken": "more"},
    ],
)
async def test_malformed_or_unbounded_discovery_is_unavailable(page: dict[str, object]) -> None:
    result = await adapter(Client([page])).resolve()
    assert result.status == "UNAVAILABLE" and result.error_code


async def test_pagination_and_candidate_shape_are_verified() -> None:
    client = Client(
        [
            {"agentRuntimes": [{"agentRuntimeVersion": "1"}], "nextToken": "cursor"},
            {"agentRuntimes": [{"agentRuntimeVersion": "2"}]},
        ]
    )
    value = adapter(client)
    assert await value._list_versions() == ["1", "2"]
    assert client.calls[1]["nextToken"] == "cursor"
    responses: list[dict[str, object]] = [
        {},
        {"environmentVariables": {}, "agentRuntimeArtifact": {}},
        {"environmentVariables": {}, "agentRuntimeArtifact": {"containerConfiguration": {}}},
    ]
    for response in responses:
        assert value._matching_candidate(response) is None
    empty = adapter(Client([]), 0)
    assert await empty._list_versions() == []
