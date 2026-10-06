"""Hosted GitHub MCP transport and bounded-tool contract coverage."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool, StructuredTool
from langgraph.prebuilt import ToolNode
from langgraph.runtime import Runtime
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import BlobResourceContents, CallToolResult, EmbeddedResource, TextContent, TextResourceContents
from pydantic import AnyUrl

from remediation_agent.adapters.mcp import GITHUB_MCP_ENDPOINT, GitHubRemoteMcpInspectionTools
from remediation_agent.domain.enums import InspectionToolStatus, RepositoryProvider
from remediation_agent.domain.models import (
    GetFileContentsArgs,
    GetRepositoryTreeArgs,
    InspectionToolResponse,
    RepositoryRef,
    SearchCodeArgs,
    WorkspaceRef,
)
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy

pytestmark = pytest.mark.mcp

_OWNER = "MtechSE-ArchAI-Team7"
_REPO = "example-service"
_SHA = "a" * 40


class _FakeClient:
    def __init__(self, responses: dict[str, CallToolResult]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def call_tool(self, name: str, arguments: dict[str, object]) -> CallToolResult:
        self.calls.append((name, arguments))
        return self.responses[name]


def _provider(token: str = "github_pat_" + "a" * 32) -> GitHubRemoteMcpInspectionTools:
    policy_file = Path(__file__).parents[2] / "config" / "policies" / "reference.json"
    return GitHubRemoteMcpInspectionTools(token, PolicyEngine(load_policy(policy_file)))


def _repository() -> RepositoryRef:
    return RepositoryRef(
        provider=RepositoryProvider.GITHUB,
        url=f"https://github.com/{_OWNER}/{_REPO}.git",
        base_branch="main",
        commit_sha=_SHA,
    )


def _workspace(path: Path, *, sha: str = _SHA) -> WorkspaceRef:
    return WorkspaceRef(workspace_id=path.name, path=str(path), base_commit=sha)


def _json_result(value: object, *, error: bool = False) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(value))],
        isError=error,
    )


def _file_result(value: str) -> CallToolResult:
    return CallToolResult(
        content=[
            TextContent(type="text", text=f"successfully downloaded text file (SHA: {_SHA})"),
            EmbeddedResource(
                type="resource",
                resource=TextResourceContents(
                    uri=AnyUrl(f"repo://{_OWNER}/{_REPO}/{_SHA}/contents/src/app.py"),
                    mimeType="text/plain",
                    text=value,
                ),
            ),
        ]
    )


async def _call(
    tools: Sequence[BaseTool],
    name: str,
    arguments: dict[str, object],
    call_number: int,
) -> InspectionToolResponse:
    message = AIMessage(
        content="",
        tool_calls=[{"name": name, "args": arguments, "id": f"mcp-test-{call_number}", "type": "tool_call"}],
    )
    output = await ToolNode(tools, handle_tool_errors=False).ainvoke(
        {"messages": [message]},
        runtime=Runtime(),
    )
    tool_message = output["messages"][-1]
    assert isinstance(tool_message, ToolMessage)
    assert isinstance(tool_message.artifact, dict)
    return InspectionToolResponse.model_validate(tool_message.artifact["structured_content"])


async def test_native_tools_are_scoped_normalized_redacted_and_bounded(tmp_path: Path) -> None:
    workspace_path = tmp_path / "workspace"
    (workspace_path / "src").mkdir(parents=True)
    (workspace_path / "src" / "app.py").write_text("value = int(raw)\n", encoding="utf-8")
    (workspace_path / ".env").write_text("TOKEN=must-not-be-read\n", encoding="utf-8")
    (workspace_path / "link.py").symlink_to(workspace_path / "src" / "app.py")
    tree = {
        "sha": "b" * 40,
        "truncated": False,
        "tree": [
            {
                "path": "src/app.py",
                "type": "blob",
                "mode": "100644",
                "sha": "c" * 40,
                "url": "https://api.github.com/blob",
            },
            {"path": ".env", "type": "blob", "mode": "100644", "sha": "d" * 40, "url": "https://api.github.com/blob"},
            {
                "path": "link.py",
                "type": "blob",
                "mode": "120000",
                "sha": "e" * 40,
                "url": "https://api.github.com/blob",
            },
        ],
        "tree_sha": _SHA,
        "owner": _OWNER,
        "repo": _REPO,
        "recursive": True,
        "count": 3,
    }
    search = {
        "total_count": 1,
        "incomplete_results": False,
        "items": [{"name": "app.py", "path": "src/app.py", "sha": "c" * 40, "repository": f"{_OWNER}/{_REPO}"}],
    }
    client = _FakeClient(
        {
            "get_repository_tree": _json_result(tree),
            "get_file_contents": _file_result("api_key=visible-test-value\n" + "x" * 70_000),
            "search_code": _json_result(search),
        }
    )
    provider = _provider()
    workspace = _workspace(workspace_path)
    tools = provider._bounded_tools(client, provider._target(_repository(), workspace), workspace)  # type: ignore[arg-type]  # noqa: SLF001

    tree_response = await _call(
        tools,
        "get_repository_tree",
        {"owner": _OWNER, "repo": _REPO, "tree_sha": _SHA, "recursive": True},
        1,
    )
    assert tree_response.status is InspectionToolStatus.SUCCEEDED
    assert tree_response.artifact is not None
    assert tree_response.artifact.content == "src/app.py"

    file_response = await _call(
        tools,
        "get_file_contents",
        {"owner": _OWNER, "repo": _REPO, "path": "src/app.py", "sha": _SHA},
        2,
    )
    assert file_response.status is InspectionToolStatus.SUCCEEDED
    assert file_response.artifact is not None
    assert "visible-test-value" not in file_response.artifact.content
    assert "[REDACTED]" in file_response.artifact.content
    assert file_response.artifact.truncated
    assert len(file_response.artifact.content.encode("utf-8")) <= 65_536

    search_response = await _call(
        tools,
        "search_code",
        {"query": f"int( repo:{_OWNER}/{_REPO}"},
        3,
    )
    assert search_response.status is InspectionToolStatus.SUCCEEDED
    assert search_response.artifact is not None
    assert search_response.artifact.content == "src/app.py"
    assert client.calls[-1][1]["fields"] == ["name", "path", "sha", "repository"]


@pytest.mark.parametrize(
    ("name", "arguments", "error_code"),
    [
        (
            "get_repository_tree",
            {"owner": "other", "repo": _REPO, "tree_sha": _SHA},
            "REPOSITORY_SCOPE_DENIED",
        ),
        (
            "get_repository_tree",
            {"owner": _OWNER, "repo": _REPO, "tree_sha": "b" * 40},
            "IMMUTABLE_REF_REQUIRED",
        ),
        (
            "get_file_contents",
            {"owner": _OWNER, "repo": _REPO, "path": "src/app.py", "sha": _SHA, "ref": "main"},
            "MUTABLE_REF_DENIED",
        ),
        (
            "get_file_contents",
            {"owner": _OWNER, "repo": _REPO, "path": ".env", "sha": _SHA},
            "PATH_DENIED",
        ),
        (
            "get_file_contents",
            {"owner": _OWNER, "repo": _REPO, "path": "link.py", "sha": _SHA},
            "SYMLINK_DENIED",
        ),
        ("search_code", {"query": "secret org:example"}, "SEARCH_SCOPE_DENIED"),
        ("search_code", {"query": "secret repo:other/repository"}, "SEARCH_SCOPE_DENIED"),
    ],
)
async def test_policy_denials_do_not_reach_github(
    tmp_path: Path,
    name: str,
    arguments: dict[str, object],
    error_code: str,
) -> None:
    workspace_path = tmp_path / "workspace"
    (workspace_path / "src").mkdir(parents=True)
    (workspace_path / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    (workspace_path / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (workspace_path / "link.py").symlink_to(workspace_path / "src" / "app.py")
    client = _FakeClient({})
    provider = _provider()
    workspace = _workspace(workspace_path)
    tools = provider._bounded_tools(client, provider._target(_repository(), workspace), workspace)  # type: ignore[arg-type]  # noqa: SLF001

    response = await _call(tools, name, arguments, 1)

    assert response.status is InspectionToolStatus.DENIED
    assert response.error_code == error_code
    assert client.calls == []


async def test_binary_resources_and_remote_errors_are_typed(tmp_path: Path) -> None:
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    (workspace_path / "binary.bin").write_bytes(b"\x00\xff")
    binary = CallToolResult(
        content=[
            EmbeddedResource(
                type="resource",
                resource=BlobResourceContents(
                    uri=AnyUrl(f"repo://{_OWNER}/{_REPO}/{_SHA}/contents/binary.bin"),
                    mimeType="application/octet-stream",
                    blob="AP8=",
                ),
            )
        ]
    )
    client = _FakeClient(
        {
            "get_file_contents": binary,
            "search_code": _json_result({"message": "token=github_pat_" + "z" * 32}, error=True),
        }
    )
    provider = _provider()
    workspace = _workspace(workspace_path)
    tools = provider._bounded_tools(client, provider._target(_repository(), workspace), workspace)  # type: ignore[arg-type]  # noqa: SLF001

    binary_response = await _call(
        tools,
        "get_file_contents",
        {"owner": _OWNER, "repo": _REPO, "path": "binary.bin", "sha": _SHA},
        1,
    )
    error_response = await _call(
        tools,
        "search_code",
        {"query": f"secret repo:{_OWNER}/{_REPO}"},
        2,
    )

    assert binary_response.error_code == "BINARY_FILE_DENIED"
    assert error_response.status is InspectionToolStatus.ERROR
    assert "github_pat_" not in error_response.detail
    assert "[REDACTED]" in error_response.detail


def _discovered_tools() -> list[BaseTool]:
    async def operation(**arguments: object) -> str:
        _ = arguments
        return "fixture"

    return [
        StructuredTool.from_function(
            coroutine=operation,
            name="get_repository_tree",
            description="fixture",
            args_schema=GetRepositoryTreeArgs,
        ),
        StructuredTool.from_function(
            coroutine=operation,
            name="get_file_contents",
            description="fixture",
            args_schema=GetFileContentsArgs,
        ),
        StructuredTool.from_function(
            coroutine=operation,
            name="search_code",
            description="fixture",
            args_schema=SearchCodeArgs,
        ),
    ]


async def test_session_uses_streamable_http_and_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class _HttpClient:
        async def __aenter__(self) -> _HttpClient:
            return self

        async def __aexit__(self, *arguments: object) -> None:
            observed["http_closed"] = True

    def http_client_factory(**arguments: object) -> _HttpClient:
        observed["http_arguments"] = arguments
        return _HttpClient()

    @asynccontextmanager
    async def transport(url: str, *, http_client: object) -> AsyncIterator[tuple[str, str, object]]:
        observed["url"] = url
        observed["http_client"] = http_client
        try:
            yield "read", "write", object()
        finally:
            observed["transport_closed"] = True

    class _Session:
        def __init__(self, read: object, write: object) -> None:
            observed["streams"] = (read, write)

        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *arguments: object) -> None:
            observed["session_closed"] = True

        async def initialize(self) -> None:
            observed["initialized"] = True

        async def call_tool(self, name: str, arguments: dict[str, object]) -> CallToolResult:
            _ = (name, arguments)
            raise AssertionError("fixture session should not execute a tool")

    async def discover(client: object, *, handle_tool_errors: bool) -> list[BaseTool]:
        observed["discovery"] = (client, handle_tool_errors)
        return _discovered_tools()

    monkeypatch.setattr("remediation_agent.adapters.mcp.httpx.AsyncClient", http_client_factory)
    monkeypatch.setattr("remediation_agent.adapters.mcp.streamable_http_client", transport)
    monkeypatch.setattr("remediation_agent.adapters.mcp.ClientSession", _Session)
    monkeypatch.setattr("remediation_agent.adapters.mcp.load_mcp_tools", discover)
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()

    class ThrottlingException(Exception):
        pass

    with pytest.raises(ThrottlingException, match="model quota"):
        async with _provider().session(_repository(), _workspace(workspace_path)) as tools:
            assert {tool.name for tool in tools} == {"get_repository_tree", "get_file_contents", "search_code"}
            raise ThrottlingException("model quota")

    assert observed["url"] == GITHUB_MCP_ENDPOINT
    assert observed["http_arguments"] == {
        "headers": _provider()._headers(),  # noqa: SLF001 - transport security contract
        "auth": None,
        "timeout": 30.0,
        "verify": True,
        "follow_redirects": False,
        "trust_env": False,
    }
    assert observed["initialized"] is True
    assert observed["session_closed"] is True
    assert observed["transport_closed"] is True
    assert observed["http_closed"] is True


async def test_in_process_streamable_http_fixture_discovers_and_executes_native_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = FastMCP(
        "github-shaped-fixture",
        streamable_http_path="/mcp/",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(allowed_hosts=["api.githubcopilot.com"]),
    )

    @fixture.tool()
    async def get_repository_tree(
        owner: str,
        repo: str,
        tree_sha: str | None = None,
        recursive: bool = False,
        path_filter: str | None = None,
    ) -> dict[str, object]:
        return {
            "sha": "b" * 40,
            "truncated": False,
            "tree": [
                {
                    "path": "src/app.py",
                    "type": "blob",
                    "size": 18,
                    "mode": "100644",
                    "sha": "c" * 40,
                    "url": "https://api.github.com/blob",
                }
            ],
            "tree_sha": tree_sha,
            "owner": owner,
            "repo": repo,
            "recursive": recursive,
            "count": 1,
        }

    @fixture.tool()
    async def get_file_contents(
        owner: str,
        repo: str,
        path: str | None = None,
        ref: str | None = None,
        sha: str | None = None,
        fields: list[str] | None = None,
    ) -> list[dict[str, object]]:
        _ = (owner, repo, path, ref, sha, fields)
        return []

    @fixture.tool()
    async def search_code(
        query: str,
        sort: str | None = None,
        order: str | None = None,
        fields: list[str] | None = None,
        page: int = 1,
        perPage: int = 30,
    ) -> dict[str, object]:
        _ = (query, sort, order, fields, page, perPage)
        return {"total_count": 0, "incomplete_results": False, "items": []}

    app = fixture.streamable_http_app()
    real_http_client = httpx.AsyncClient

    def http_client_factory(**arguments: object) -> httpx.AsyncClient:
        return real_http_client(
            transport=httpx.ASGITransport(app=app),
            headers=arguments["headers"],  # type: ignore[arg-type]
            timeout=arguments["timeout"],  # type: ignore[arg-type]
            follow_redirects=False,
        )

    monkeypatch.setattr("remediation_agent.adapters.mcp.httpx.AsyncClient", http_client_factory)
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()

    async with app.router.lifespan_context(app):
        async with _provider().session(_repository(), _workspace(workspace_path)) as tools:
            response = await _call(
                tools,
                "get_repository_tree",
                {"owner": _OWNER, "repo": _REPO, "tree_sha": _SHA, "recursive": False},
                1,
            )

    assert response.status is InspectionToolStatus.SUCCEEDED
    assert response.artifact is not None
    assert response.artifact.content == "src/app.py"


@pytest.mark.parametrize("status_code", [401, 403])
async def test_authentication_failures_are_normalized_without_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
) -> None:
    token = "github_pat_" + "sensitive" * 8
    request = httpx.Request("POST", GITHUB_MCP_ENDPOINT)
    response = httpx.Response(status_code, request=request)
    failure = httpx.HTTPStatusError(f"denied with {token}", request=request, response=response)

    @asynccontextmanager
    async def transport(url: str, *, http_client: object) -> AsyncIterator[tuple[str, str, object]]:
        _ = (url, http_client)
        raise failure
        yield "read", "write", object()  # pragma: no cover - makes this an async context manager

    monkeypatch.setattr("remediation_agent.adapters.mcp.streamable_http_client", transport)
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()

    with pytest.raises(RuntimeError, match=f"GitHub MCP session failed: HTTP_{status_code}") as caught:
        async with _provider(token).session(_repository(), _workspace(workspace_path)):
            pass

    assert token not in str(caught.value)


async def test_transport_timeout_is_normalized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    @asynccontextmanager
    async def transport(url: str, *, http_client: object) -> AsyncIterator[tuple[str, str, object]]:
        _ = (url, http_client)
        raise TimeoutError("hosted MCP did not respond")
        yield "read", "write", object()  # pragma: no cover - makes this an async context manager

    monkeypatch.setattr("remediation_agent.adapters.mcp.streamable_http_client", transport)
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()

    with pytest.raises(RuntimeError, match="GitHub MCP session failed: TIMEOUT"):
        async with _provider().session(_repository(), _workspace(workspace_path)):
            pass


@pytest.mark.live_mcp
async def test_live_hosted_github_mcp_contract(tmp_path: Path) -> None:
    token = os.environ.get("AIOS_GITHUB_TOKEN")
    repository_url = os.environ.get("AIOS_LIVE_GITHUB_MCP_REPOSITORY_URL")
    commit_sha = os.environ.get("AIOS_LIVE_GITHUB_MCP_COMMIT_SHA")
    if not token or not repository_url or not commit_sha:
        pytest.skip("live GitHub MCP contract variables are not configured")
    repository = RepositoryRef(
        provider=RepositoryProvider.GITHUB,
        url=repository_url,
        base_branch="main",
        commit_sha=commit_sha,
    )
    workspace = _workspace(tmp_path / "workspace", sha=commit_sha)
    Path(workspace.path).mkdir()
    provider = _provider(token)
    target = provider._target(repository, workspace)  # noqa: SLF001

    async with provider.session(repository, workspace) as tools:
        response = await _call(
            tools,
            "get_repository_tree",
            {"owner": target.owner, "repo": target.repo, "tree_sha": commit_sha, "recursive": False},
            1,
        )

    assert response.status is InspectionToolStatus.SUCCEEDED
