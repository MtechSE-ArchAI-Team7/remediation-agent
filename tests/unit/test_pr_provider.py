"""Draft-PR provider write gating and idempotency tests."""

from __future__ import annotations

import httpx
import pytest

from remediation_agent.adapters.pr import DraftPullRequestProvider
from remediation_agent.domain.enums import RepositoryProvider
from remediation_agent.domain.models import DraftPrPayload, RepositoryRef
from remediation_agent.ports.models import DraftPrRequest


def _request() -> DraftPrRequest:
    return DraftPrRequest(
        repository=RepositoryRef(
            provider=RepositoryProvider.GITHUB,
            url="https://github.com/example/project",
            base_branch="main",
        ),
        repository_slug="example/project",
        payload=DraftPrPayload(
            title="Bounded remediation",
            body="Human review required.",
            head_branch="aios/remediation/case-run",
            base_branch="main",
        ),
        idempotency_key="run:digest",
    )


async def test_remote_writes_are_disabled_by_default() -> None:
    provider = DraftPullRequestProvider()
    prepared = await provider.prepare(_request())
    assert not prepared.metadata.created
    with pytest.raises(RuntimeError, match="disabled"):
        await provider.create_draft(_request())


async def test_existing_open_draft_is_returned_idempotently() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return httpx.Response(
            200,
            json=[{"number": 42, "html_url": "https://github.com/example/project/pull/42"}],
        )

    provider = DraftPullRequestProvider(
        token="test-token",  # noqa: S106 - local fake credential
        writes_enabled=True,
        transport=httpx.MockTransport(handler),
    )
    created = await provider.create_draft(_request())
    assert calls == ["GET"]
    assert created.metadata.provider_id == "42"
    assert created.metadata.created
