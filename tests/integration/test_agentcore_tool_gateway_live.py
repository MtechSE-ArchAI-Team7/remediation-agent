"""Opt-in live contract for the IAM-authenticated repository-inspection gateway."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool
from langgraph.prebuilt import ToolNode
from langgraph.runtime import Runtime

from remediation_agent.adapters.mcp import AgentCoreGatewayInspectionTools
from remediation_agent.config import Settings
from remediation_agent.domain.enums import InspectionToolStatus, RepositoryProvider
from remediation_agent.domain.models import InspectionToolResponse, RepositoryRef, WorkspaceRef
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy


async def _call(
    tools: Sequence[BaseTool],
    name: str,
    arguments: dict[str, object],
) -> InspectionToolResponse:
    message = AIMessage(
        content="",
        tool_calls=[{"name": name, "args": arguments, "id": f"live-{name}", "type": "tool_call"}],
    )
    output = await ToolNode(tools, handle_tool_errors=False).ainvoke(
        {"messages": [message]},
        runtime=Runtime(),
    )
    tool_message = output["messages"][-1]
    assert isinstance(tool_message, ToolMessage)
    assert isinstance(tool_message.artifact, dict)
    return InspectionToolResponse.model_validate(tool_message.artifact["structured_content"])


@pytest.mark.live_mcp
async def test_live_agentcore_tool_gateway_exposes_and_calls_only_three_read_tools(tmp_path: Path) -> None:
    if os.environ.get("AIOS_RUN_AGENTCORE_TOOL_GATEWAY_LIVE") != "1":
        pytest.skip("set AIOS_RUN_AGENTCORE_TOOL_GATEWAY_LIVE=1 to call the tool gateway")
    gateway_arn = os.environ.get("AIOS_INSPECTION_GATEWAY_ARN")
    repository_url = os.environ.get("AIOS_LIVE_GITHUB_MCP_REPOSITORY_URL")
    commit_sha = os.environ.get("AIOS_LIVE_GITHUB_MCP_COMMIT_SHA")
    if not gateway_arn or not repository_url or not commit_sha:
        pytest.skip("live AgentCore tool gateway variables are not configured")

    settings = Settings(
        policy_file=Path("config/policies/reference.json"),
        llm_provider="fake",
        aws_region="ap-southeast-1",
        inspection_mcp_mode="agentcore_gateway",
        inspection_gateway_arn=gateway_arn,
        _env_file=None,
    )  # type: ignore[call-arg]
    policy = PolicyEngine(load_policy(settings.policy_file))
    provider = AgentCoreGatewayInspectionTools(
        settings.inspection_gateway_endpoint(),
        "ap-southeast-1",
        policy,
    )
    repository = RepositoryRef(
        provider=RepositoryProvider.GITHUB,
        url=repository_url,
        base_branch="main",
        commit_sha=commit_sha,
    )
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    (workspace_path / "server.js").write_text("// live inspection fixture\n", encoding="utf-8")
    workspace = WorkspaceRef(workspace_id="live-gateway", path=str(workspace_path), base_commit=commit_sha)
    owner, repo = repository_url.removeprefix("https://github.com/").removesuffix(".git").split("/")

    async with provider.session(repository, workspace) as tools:
        assert {tool.name for tool in tools} == {"get_repository_tree", "get_file_contents", "search_code"}
        tree = await _call(
            tools,
            "get_repository_tree",
            {"owner": owner, "repo": repo, "tree_sha": commit_sha, "recursive": False},
        )
        file_result = await _call(
            tools,
            "get_file_contents",
            {"owner": owner, "repo": repo, "path": "server.js", "sha": commit_sha},
        )
        search = await _call(
            tools,
            "search_code",
            {"query": f"calculate-average repo:{owner}/{repo}", "page": 1, "perPage": 5},
        )

    assert tree.status is InspectionToolStatus.SUCCEEDED
    assert file_result.status is InspectionToolStatus.SUCCEEDED
    assert search.status is InspectionToolStatus.SUCCEEDED
