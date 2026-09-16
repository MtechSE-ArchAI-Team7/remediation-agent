"""Hosted GitHub MCP client registration and endpoint-locking tests."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from langchain_core.tools import StructuredTool

from remediation_agent.adapters.mcp import (
    GITHUB_MCP_ENDPOINT,
    INSPECTION_MCP_TOOL_NAMES,
    GitHubRemoteMcpInspectionTools,
    _mcp_failure_code,
)
from remediation_agent.domain.enums import RepositoryProvider
from remediation_agent.domain.models import (
    GetFileContentsArgs,
    GetRepositoryTreeArgs,
    RepositoryRef,
    SearchCodeArgs,
    WorkspaceRef,
)
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy


def _provider() -> GitHubRemoteMcpInspectionTools:
    policy_path = Path(__file__).parents[2] / "config" / "policies" / "reference.json"
    return GitHubRemoteMcpInspectionTools("github_pat_" + "a" * 32, PolicyEngine(load_policy(policy_path)))


def _fixture_tool(name: str, args_schema: type[object]) -> StructuredTool:
    def operation(**arguments: object) -> str:
        _ = arguments
        return "fixture"

    return StructuredTool.from_function(
        func=operation,
        name=name,
        description="Registration fixture.",
        args_schema=args_schema,  # type: ignore[arg-type]
    )


def test_hosted_endpoint_and_headers_are_fixed_and_read_only() -> None:
    provider = _provider()

    assert GITHUB_MCP_ENDPOINT == "https://api.githubcopilot.com/mcp/"
    assert provider._headers() == {  # noqa: SLF001 - security contract test
        "Authorization": "Bearer github_pat_" + "a" * 32,
        "X-MCP-Tools": "get_repository_tree,get_file_contents,search_code",
        "X-MCP-Readonly": "true",
        "X-MCP-Lockdown": "true",
    }


def test_registration_rejects_missing_extra_duplicate_and_changed_schemas() -> None:
    tree = _fixture_tool("get_repository_tree", GetRepositoryTreeArgs)
    read = _fixture_tool("get_file_contents", GetFileContentsArgs)
    search = _fixture_tool("search_code", SearchCodeArgs)

    GitHubRemoteMcpInspectionTools._validate_tools([tree, read, search])

    for invalid in (
        [tree, read],
        [tree, read, search, _fixture_tool("unexpected", SearchCodeArgs)],
        [tree, read, search, search],
    ):
        with pytest.raises(RuntimeError, match="unexpected tool set"):
            GitHubRemoteMcpInspectionTools._validate_tools(invalid)

    wrong_schema = _fixture_tool("search_code", GetFileContentsArgs)
    with pytest.raises(RuntimeError, match="unexpected argument schema"):
        GitHubRemoteMcpInspectionTools._validate_tools([tree, read, wrong_schema])


@pytest.mark.parametrize(
    "repository",
    [
        RepositoryRef(
            provider=RepositoryProvider.LOCAL,
            url="file:///tmp/repository",
            base_branch="main",
        ),
        RepositoryRef(
            provider=RepositoryProvider.GITHUB,
            url="https://github.com/example/repository",
            base_branch="main",
        ),
        RepositoryRef(
            provider=RepositoryProvider.GITHUB,
            url="https://github.com/example/repository.git/extra",
            base_branch="main",
        ),
        RepositoryRef(
            provider=RepositoryProvider.GITHUB,
            url="https://github.com//example/repository.git",
            base_branch="main",
        ),
    ],
)
def test_target_parser_rejects_non_github_and_noncanonical_urls(repository: RepositoryRef) -> None:
    workspace = WorkspaceRef(workspace_id="workspace", path="/workspace", base_commit="a" * 40)

    with pytest.raises(ValueError, match="GitHub MCP"):
        GitHubRemoteMcpInspectionTools._target(repository, workspace)


def test_tool_names_are_the_three_native_github_operations() -> None:
    assert INSPECTION_MCP_TOOL_NAMES == {"get_repository_tree", "get_file_contents", "search_code"}


def test_target_parser_requires_resolved_full_commit_sha() -> None:
    repository = RepositoryRef(
        provider=RepositoryProvider.GITHUB,
        url="https://github.com/example/repository.git",
        base_branch="main",
    )
    workspace = WorkspaceRef(workspace_id="workspace", path="/workspace", base_commit="main")

    with pytest.raises(ValueError, match="full immutable commit SHA"):
        GitHubRemoteMcpInspectionTools._target(repository, workspace)


def test_mcp_failure_code_unwraps_status_without_provider_text() -> None:
    request = httpx.Request("POST", GITHUB_MCP_ENDPOINT)
    response = httpx.Response(403, request=request)
    failure = httpx.HTTPStatusError("secret provider response", request=request, response=response)

    assert _mcp_failure_code(ExceptionGroup("wrapper", [failure])) == "HTTP_403"


def test_mcp_failure_code_classifies_nested_transport_failures() -> None:
    request = httpx.Request("POST", GITHUB_MCP_ENDPOINT)
    failure = httpx.ConnectError("secret connection detail", request=request)

    assert _mcp_failure_code(ExceptionGroup("wrapper", [failure])) == "CONNECT_ERROR"
    assert _mcp_failure_code(RuntimeError("secret provider response")) == "SESSION_ERROR"
