"""MCP draft publication preserves exact-candidate evidence and bounded recovery."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path

import httpx
import pytest
from mcp.types import CallToolResult, TextContent

from remediation_agent.adapters.pr import DraftPullRequestProvider, _LimitedStream
from remediation_agent.adapters.pr_fixture import SimulatedGitHubPrMcp
from remediation_agent.domain.enums import RepositoryProvider
from remediation_agent.domain.models import DraftPrPayload, RepositoryRef
from remediation_agent.ports.models import DraftPrRequest, PublicationError

CONTRACT = Path(__file__).parents[2] / "config/contracts/github-pr-mcp-tools.json"


def _request() -> DraftPrRequest:
    return DraftPrRequest(
        repository=RepositoryRef(
            provider=RepositoryProvider.GITHUB, url="https://github.com/example/project.git", base_branch="main"
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
        "merged": False,
        "head": {"ref": "aios/remediation/case-run", "sha": "b" * 40, "repo": {"full_name": "example/project"}},
        "base": {"ref": "main", "sha": "a" * 40, "repo": {"full_name": "example/project"}},
    }


def _fixture() -> tuple[SimulatedGitHubPrMcp, DraftPullRequestProvider]:
    fixture = SimulatedGitHubPrMcp(CONTRACT, lambda _: _draft())
    return fixture, DraftPullRequestProvider(token="test-token", writes_enabled=True, transport=fixture.transport())  # noqa: S106


async def test_remote_writes_are_disabled_by_default() -> None:
    provider = DraftPullRequestProvider()
    assert not (await provider.prepare(_request())).metadata.created
    with pytest.raises(PublicationError, match="PUBLICATION_NOT_CONFIGURED"):
        await provider.create_draft(_request())


@pytest.mark.parametrize("missing", ["gate", "token", "slug", "commit", "base", "repository"])
async def test_bad_configuration_or_missing_evidence_opens_no_session(missing: str) -> None:
    fixture, provider = _fixture()
    request = _request()
    if missing == "gate":
        provider.writes_enabled = False
    elif missing == "token":
        provider.token = None
    elif missing == "slug":
        request = request.model_copy(update={"repository_slug": None})
    elif missing in {"commit", "base"}:
        request = request.model_copy(
            update={"expected_commit" if missing == "commit" else "expected_base_commit": None}
        )
    else:
        request = request.model_copy(update={"repository_slug": "other/project"})
    with pytest.raises(PublicationError):
        await provider.create_draft(request)
    assert not fixture.requests


async def test_readiness_is_mcp_access_only_and_closes_session() -> None:
    fixture, provider = _fixture()
    result = await provider.check_readiness(_request().repository, "example/project")
    assert [r.operation for r in result.records] == ["discovery", "list_pull_requests"]
    assert fixture.calls == [
        (
            "list_pull_requests",
            {
                "owner": "example",
                "repo": "project",
                "state": "all",
                "perPage": 1,
                "page": 1,
                "fields": ["number"],
            },
        )
    ]
    assert fixture.initialized == fixture.closed == 1
    assert all("x-mcp-readonly" not in r.headers for r in fixture.requests)
    assert all(
        set(r.headers["x-mcp-tools"].split(",")) == {"list_pull_requests", "pull_request_read", "create_pull_request"}
        for r in fixture.requests
    )


async def test_create_reconciles_and_reads_exact_draft_before_success() -> None:
    fixture, provider = _fixture()
    result = await provider.create_draft(_request())
    assert result.metadata.created and result.metadata.provider_id == "42"  # not database ID 9000001
    assert [name for name, _ in fixture.calls] == ["list_pull_requests", "create_pull_request", "pull_request_read"]
    assert fixture.calls[0][1]["head"] == "example:aios/remediation/case-run"
    assert fixture.calls[0][1]["state"] == "all" and fixture.calls[0][1]["perPage"] == 2
    assert fixture.calls[1][1]["draft"] is True and fixture.calls[1][1]["maintainer_can_modify"] is False
    assert "reviewers" not in fixture.calls[1][1]
    assert fixture.calls[-1][1]["method"] == "get"
    assert len(result.records) == 4 and all(r.result_code == "OK" for r in result.records)
    assert fixture.initialized == fixture.closed == 1
    assert "test-token" not in result.model_dump_json()


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        "commit",
        "base",
        "repo",
        "draft",
        "closed",
        "merged",
        "ambiguous",
        "missing_merged",
        "missing_head",
        "url",
        "number",
        "head_branch",
        "base_branch",
    ],
)
async def test_only_exact_open_draft_is_returned_idempotently(invalid: str | None) -> None:
    fixture, provider = _fixture()
    value = _draft()
    if invalid in {"commit", "base", "repo", "head_branch", "base_branch"}:
        which = "base" if invalid in {"base", "base_branch"} else "head"
        value[which] = {
            "ref": "other"
            if invalid.endswith("branch")
            else ("main" if which == "base" else "aios/remediation/case-run"),
            "sha": ("c" if invalid in {"commit", "base"} else ("a" if which == "base" else "b")) * 40,
            "repo": {"full_name": "other/repo" if invalid == "repo" else "example/project"},
        }
    if invalid == "draft":
        value["draft"] = False
    if invalid == "closed":
        value["state"] = "closed"
    if invalid == "merged":
        value["merged"] = True
    if invalid == "url":
        value["html_url"] = "https://evil.invalid/pull/42"
    if invalid == "missing_merged":
        del value["merged"]
    if invalid == "missing_head":
        del value["head"]
    fixture.published = [_draft(), _draft()] if invalid == "ambiguous" else [_draft()]
    if invalid == "number":
        value["number"] = 999
    fixture.result_override = lambda name, _: _result(value) if name == "pull_request_read" else None
    if invalid:
        with pytest.raises(PublicationError):
            await provider.create_draft(_request())
    else:
        assert (await provider.create_draft(_request())).metadata.provider_id == "42"
    assert "create_pull_request" not in [name for name, _ in fixture.calls]
    assert fixture.initialized == fixture.closed == 1


def _result(value: object, *, error: bool = False) -> dict[str, object]:
    return {"content": [{"type": "text", "text": json.dumps(value)}], "isError": error}


async def test_verification_does_not_create_missing_draft() -> None:
    fixture, provider = _fixture()
    with pytest.raises(PublicationError, match="DRAFT_NOT_FOUND"):
        await provider.verify_draft(_request())
    assert [n for n, _ in fixture.calls] == ["list_pull_requests"]


async def test_lost_create_response_reconciles_without_duplicate_creation() -> None:
    fixture, provider = _fixture()
    fixture.lose_create_response = True
    with pytest.raises(PublicationError) as failure:
        await provider.create_draft(_request())
    assert failure.value.retryable
    assert (await provider.create_draft(_request())).metadata.provider_id == "42"
    assert (await provider.verify_draft(_request())).metadata.created
    assert [name for name, _ in fixture.calls].count("create_pull_request") == 1
    assert fixture.initialized == fixture.closed == 3


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.invalid/pull/42",
        "https://github.com/other/repo/pull/42",
        "https://github.com/example/project/pull/42?x=1",
        "https://github.com/example/project/pull/0",
    ],
)
async def test_creation_url_cannot_redirect_verification(url: str) -> None:
    fixture, provider = _fixture()
    fixture.result_override = lambda name, _: (
        _result({"id": "90001", "url": url}) if name == "create_pull_request" else None
    )
    with pytest.raises(PublicationError, match="GITHUB_RESPONSE_INVALID"):
        await provider.create_draft(_request())
    assert "pull_request_read" not in [name for name, _ in fixture.calls]


@pytest.mark.parametrize("change", ["extra", "missing", "duplicate", "required", "type", "method"])
async def test_discovery_drift_fails_before_any_tool_call(change: str) -> None:
    fixture, provider = _fixture()
    if change == "extra":
        fixture.tools.append({"name": "merge_pull_request", "inputSchema": {"type": "object"}})
    elif change == "missing":
        fixture.tools.pop()
    elif change == "duplicate":
        fixture.tools[1] = copy.deepcopy(fixture.tools[0])
    else:
        tool = next(t for t in fixture.tools if t["name"] == "pull_request_read")
        schema = tool["inputSchema"]
        assert isinstance(schema, dict)
        if change == "required":
            schema["required"] = []
        else:
            props = schema["properties"]
            props["method"] = {"type": "boolean" if change == "type" else "string", "enum": ["get_diff"]}
    with pytest.raises(PublicationError, match="GITHUB_MCP_(TOOLSET|SCHEMA)_DRIFT"):
        await provider.create_draft(_request())
    assert not fixture.calls and fixture.closed == 1


@pytest.mark.parametrize(
    "status,headers,retryable",
    [
        (429, {}, True),
        (403, {"x-ratelimit-remaining": "0"}, True),
        (403, {}, False),
        (503, {}, True),
        (400, {}, False),
    ],
)
async def test_publication_http_error_classification(status: int, headers: dict[str, str], retryable: bool) -> None:
    provider = DraftPullRequestProvider(
        token="test-token",  # noqa: S106 - in-process fixture
        writes_enabled=True,
        transport=httpx.MockTransport(lambda _: httpx.Response(status, headers=headers)),
    )
    with pytest.raises(PublicationError) as failure:
        await provider.create_draft(_request())
    assert failure.value.retryable is retryable
    assert failure.value.records[0].result_code == f"GITHUB_HTTP_{status}"


async def test_tool_error_is_redacted_and_does_not_create() -> None:
    fixture, provider = _fixture()
    fixture.result_override = lambda *_: _result("HTTP 403 secret github_pat_hidden", error=True)
    with pytest.raises(PublicationError) as failure:
        await provider.create_draft(_request())
    assert failure.value.code == "GITHUB_HTTP_403" and not failure.value.retryable
    assert "secret" not in str(failure.value)
    assert "github_pat" not in json.dumps([r.model_dump(mode="json") for r in failure.value.records])
    assert [n for n, _ in fixture.calls] == ["list_pull_requests"]


@pytest.mark.parametrize(
    "status,message,retryable",
    [
        (404, "Not Found", False),
        (403, "Forbidden", False),
        (403, "API rate limit exceeded", True),
        (429, "Too Many Requests", True),
        (503, "Service Unavailable", True),
    ],
)
async def test_hosted_github_tool_error_format(status: int, message: str, retryable: bool) -> None:
    fixture, provider = _fixture()
    fixture.result_override = lambda *_: {
        "content": [
            {
                "type": "text",
                "text": "failed to list pull requests: GET https://api.github.com/repos/example/project/pulls: "
                f"{status} {message} []",
            }
        ],
        "isError": True,
    }
    with pytest.raises(PublicationError) as failure:
        await provider.create_draft(_request())
    assert failure.value.code == f"GITHUB_HTTP_{status}"
    assert failure.value.retryable is retryable
    assert [name for name, _ in fixture.calls] == ["list_pull_requests"]


@pytest.mark.parametrize("value", [None, {}, {"items": []}, "untrusted prose", [{"number": "42"}]])
async def test_malformed_list_never_authorizes_creation(value: object) -> None:
    fixture, provider = _fixture()
    fixture.result_override = lambda *_: _result(value)
    with pytest.raises(PublicationError):
        await provider.create_draft(_request())
    assert [n for n, _ in fixture.calls] == ["list_pull_requests"]


def test_structured_response_and_conflicts() -> None:
    value = _draft()
    result = CallToolResult(
        content=[TextContent(type="text", text=json.dumps(value))], structuredContent={"pull_request": value}
    )
    assert DraftPullRequestProvider._response(result) == value  # noqa: SLF001
    result.structuredContent = {"pull_request": {"number": 7}}
    with pytest.raises(PublicationError, match="CONFLICT"):
        DraftPullRequestProvider._response(result)  # noqa: SLF001


async def test_http_body_is_bounded_and_closed() -> None:
    closed = False

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):  # type: ignore[no-untyped-def]
            yield b"a" * (1024 * 1024)
            yield b"b"

        async def aclose(self) -> None:
            nonlocal closed
            closed = True

    stream = _LimitedStream(Stream())
    with pytest.raises(PublicationError, match="OVERSIZED"):
        async for _ in stream:
            pass
    await stream.aclose()
    assert closed


async def test_timeout_and_cancellation_close_session() -> None:
    fixture, provider = _fixture()
    started = asyncio.Event()

    async def respond(request: httpx.Request) -> httpx.Response:
        if b'"tools/call"' in request.content:
            started.set()
            await asyncio.Event().wait()
        return fixture.respond(request)

    provider.transport = httpx.MockTransport(respond)
    provider.timeout_seconds = 0.1
    with pytest.raises(PublicationError) as failure:
        await provider.create_draft(_request())
    assert failure.value.retryable and fixture.closed == 1
    provider.timeout_seconds = 10
    started.clear()
    task = asyncio.create_task(provider.create_draft(_request()))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert fixture.closed == 2
