"""Release provenance adapter tests."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from remediation_agent.adapters.provenance import AgentCoreReleaseProvenance, LocalReleaseProvenance
from remediation_agent.domain.enums import ReleaseProvenanceStatus

_RUNTIME_ID = "remediation_agent-2425SXH9D3"
_RELEASE_ID = "12345-1"
_SOURCE = "a" * 40
_DIGEST = "sha256:" + "b" * 64
_REGION = "ap-southeast-1"
_ACCOUNT = "734849394833"
_ARN = f"arn:aws:bedrock-agentcore:{_REGION}:{_ACCOUNT}:runtime/{_RUNTIME_ID}"
_NOW = datetime(2026, 10, 7, tzinfo=UTC)


class _ControlClient:
    def __init__(self, versions: list[Mapping[str, object]], details: dict[str, Mapping[str, object]]) -> None:
        self.versions = versions
        self.details = details

    def list_agent_runtime_versions(self, **kwargs: object) -> Mapping[str, object]:
        del kwargs
        return {"agentRuntimes": self.versions}

    def get_agent_runtime(self, **kwargs: object) -> Mapping[str, object]:
        version = kwargs["agentRuntimeVersion"]
        assert isinstance(version, str)
        return self.details[version]


def _detail(
    version: str,
    *,
    release_id: str = _RELEASE_ID,
    container_uri: str | None = None,
) -> Mapping[str, object]:
    return {
        "agentRuntimeArn": _ARN,
        "agentRuntimeId": _RUNTIME_ID,
        "agentRuntimeVersion": version,
        "environmentVariables": {
            "AIOS_RELEASE_ID": release_id,
            "AIOS_RELEASE_SOURCE_SHA": _SOURCE,
            "AIOS_RELEASE_IMAGE_DIGEST": _DIGEST,
        },
        "agentRuntimeArtifact": {
            "containerConfiguration": {
                "containerUri": container_uri or f"{_ACCOUNT}.dkr.ecr.{_REGION}.amazonaws.com/app@{_DIGEST}"
            }
        },
    }


def _adapter(client: _ControlClient, *, max_versions: int = 100) -> AgentCoreReleaseProvenance:
    return AgentCoreReleaseProvenance(
        runtime_id=_RUNTIME_ID,
        release_id=_RELEASE_ID,
        source_revision=_SOURCE,
        image_digest=_DIGEST,
        region_name=_REGION,
        expected_account_id=_ACCOUNT,
        max_versions=max_versions,
        client=client,
        clock=lambda: _NOW,
    )


async def test_agentcore_provenance_resolves_one_exact_release() -> None:
    client = _ControlClient(
        [{"agentRuntimeVersion": "52"}, {"agentRuntimeVersion": "51"}],
        {"52": _detail("52"), "51": _detail("51", release_id="older")},
    )

    result = await _adapter(client).resolve()

    assert result.status is ReleaseProvenanceStatus.VERIFIED
    assert result.runtime_version == "52"
    assert result.image_digest == _DIGEST


async def test_agentcore_provenance_rejects_missing_and_duplicate_matches() -> None:
    missing = await _adapter(
        _ControlClient([{"agentRuntimeVersion": "51"}], {"51": _detail("51", release_id="older")})
    ).resolve()
    duplicate = await _adapter(
        _ControlClient(
            [{"agentRuntimeVersion": "52"}, {"agentRuntimeVersion": "53"}],
            {"52": _detail("52"), "53": _detail("53")},
        )
    ).resolve()

    assert missing.status is ReleaseProvenanceStatus.UNAVAILABLE
    assert missing.error_code == "RELEASE_PROVENANCE_NOT_FOUND"
    assert duplicate.status is ReleaseProvenanceStatus.AMBIGUOUS
    assert duplicate.error_code == "RELEASE_PROVENANCE_AMBIGUOUS"


async def test_agentcore_provenance_rejects_image_from_another_account_or_region() -> None:
    wrong_image = f"000000000000.dkr.ecr.us-east-1.amazonaws.com/app@{_DIGEST}"
    result = await _adapter(
        _ControlClient(
            [{"agentRuntimeVersion": "52"}],
            {"52": _detail("52", container_uri=wrong_image)},
        )
    ).resolve()

    assert result.status is ReleaseProvenanceStatus.UNAVAILABLE
    assert result.error_code == "RELEASE_PROVENANCE_NOT_FOUND"


async def test_agentcore_provenance_normalizes_malformed_or_oversized_results() -> None:
    malformed = await _adapter(_ControlClient([{"bad": "entry"}], {})).resolve()
    oversized = await _adapter(
        _ControlClient(
            [{"agentRuntimeVersion": "52"}, {"agentRuntimeVersion": "53"}],
            {"52": _detail("52"), "53": _detail("53")},
        ),
        max_versions=1,
    ).resolve()

    assert malformed.status is ReleaseProvenanceStatus.UNAVAILABLE
    assert malformed.error_code == "RELEASE_PROVENANCE_VALUEERROR"
    assert oversized.status is ReleaseProvenanceStatus.UNAVAILABLE
    assert oversized.error_code == "RELEASE_PROVENANCE_VALUEERROR"


async def test_local_provenance_is_explicit() -> None:
    result = await LocalReleaseProvenance(clock=lambda: _NOW).resolve()

    assert result.status is ReleaseProvenanceStatus.LOCAL
    assert result.runtime_version is None
