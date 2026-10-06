"""Exact remote references, lost responses, and unrelated drafts fail closed."""

from __future__ import annotations

import httpx
import pytest

from remediation_agent.adapters.pr import DraftPullRequestProvider
from remediation_agent.domain.enums import RepositoryProvider
from remediation_agent.domain.models import DraftPrPayload, RepositoryRef
from remediation_agent.ports.models import DraftPrRequest, PublicationError


def _request() -> DraftPrRequest:
    return DraftPrRequest(
        repository=RepositoryRef(
            provider=RepositoryProvider.GITHUB, url="https://github.com/example/project", base_branch="main"
        ),
        repository_slug="example/project",
        payload=DraftPrPayload(
            title="Bounded remediation",
            body="Human review required.",
            head_branch="aios/remediation/case-run",
            base_branch="main",
        ),
        idempotency_key="run:digest",
        expected_commit="b" * 40,
        expected_base_commit="a" * 40,
    )


def _draft() -> dict[str, object]:
    return {
        "number": 42,
        "html_url": "https://github.com/example/project/pull/42",
        "draft": True,
        "state": "open",
        "head": {"ref": "aios/remediation/case-run", "sha": "b" * 40, "repo": {"full_name": "example/project"}},
        "base": {"ref": "main", "sha": "a" * 40, "repo": {"full_name": "example/project"}},
    }


async def test_remote_writes_are_disabled_by_default() -> None:
    provider = DraftPullRequestProvider()
    assert not (await provider.prepare(_request())).metadata.created
    with pytest.raises(PublicationError, match="PUBLICATION_NOT_CONFIGURED"):
        await provider.create_draft(_request())


@pytest.mark.parametrize("invalid", [None, "commit", "base", "repo", "draft", "closed", "merged", "ambiguous"])
async def test_only_exact_open_draft_is_returned_idempotently(invalid: str | None) -> None:
    value = _draft()
    if invalid in {"commit", "base", "repo"}:
        value["base" if invalid == "base" else "head"] = {
            "ref": "main" if invalid == "base" else "aios/remediation/case-run",
            "sha": "c" * 40,
            "repo": {"full_name": "other/repo" if invalid == "repo" else "example/project"},
        }
    if invalid == "draft":
        value["draft"] = False
    if invalid == "closed":
        value["state"] = "closed"
    if invalid == "merged":
        value["merged_at"] = "2026-10-01T00:00:00Z"
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return httpx.Response(200, json=[value, value] if invalid == "ambiguous" else [value])

    provider = DraftPullRequestProvider(token="test-token", writes_enabled=True, transport=httpx.MockTransport(handler))  # noqa: S106
    if invalid:
        with pytest.raises(PublicationError):
            await provider.create_draft(_request())
    else:
        assert (await provider.create_draft(_request())).metadata.provider_id == "42"
    assert calls == ["GET"]


async def test_lost_post_response_reconciles_without_duplicate_creation() -> None:
    created = False
    posts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal created, posts
        if request.method == "GET":
            return httpx.Response(200, json=[_draft()] if created else [])
        posts += 1
        created = True
        raise httpx.ReadTimeout("response lost")

    provider = DraftPullRequestProvider(token="test-token", writes_enabled=True, transport=httpx.MockTransport(handler))  # noqa: S106
    with pytest.raises(PublicationError) as failure:
        await provider.create_draft(_request())
    assert failure.value.retryable
    assert (await provider.create_draft(_request())).metadata.provider_id == "42"
    assert (await provider.verify_draft(_request())).metadata.created
    assert posts == 1


@pytest.mark.parametrize(
    "status,headers,retryable",
    [(429, {}, True), (403, {"x-ratelimit-remaining": "0"}, True), (403, {}, False), (503, {}, True), (400, {}, False)],
)
async def test_publication_error_classification(status: int, headers: dict[str, str], retryable: bool) -> None:
    provider = DraftPullRequestProvider(
        token="test-token",  # noqa: S106 - fake transport
        writes_enabled=True,  # noqa: S106
        transport=httpx.MockTransport(lambda _: httpx.Response(status, headers=headers)),
    )
    with pytest.raises(PublicationError) as failure:
        await provider.create_draft(_request())
    assert failure.value.retryable is retryable
