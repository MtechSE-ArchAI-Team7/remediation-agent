"""Real stdio MCP coverage for the fixed repository inspection server."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool
from langgraph.prebuilt import ToolNode
from langgraph.runtime import Runtime

from remediation_agent.adapters.mcp import INSPECTION_MCP_TOOL_NAMES, StdioMcpInspectionTools
from remediation_agent.domain.enums import InspectionToolStatus
from remediation_agent.domain.models import InspectionToolResponse, WorkspaceRef

pytestmark = pytest.mark.mcp


async def _call(
    tools: Sequence[BaseTool],
    name: str,
    arguments: dict[str, object],
    call_number: int,
) -> InspectionToolResponse:
    message = AIMessage(
        content="",
        tool_calls=[
            {
                "name": name,
                "args": arguments,
                "id": f"mcp-test-{call_number}",
                "type": "tool_call",
            }
        ],
    )
    output = await ToolNode(tools, handle_tool_errors=False).ainvoke(
        {"messages": [message]},
        runtime=Runtime(),
    )
    tool_message = output["messages"][-1]
    assert isinstance(tool_message, ToolMessage)
    assert isinstance(tool_message.artifact, dict)
    return InspectionToolResponse.model_validate(tool_message.artifact["structured_content"])


async def test_stdio_server_discovers_only_fixed_bounded_tools_and_executes_round_trip(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces"
    workspace_path = workspace_root / "workspace-1"
    source_path = workspace_path / "src" / "app.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_text("api_key=visible-test-value\nvalue = int(raw)\n", encoding="utf-8")
    (workspace_path / ".env").write_text("TOKEN=must-not-be-read\n", encoding="utf-8")
    (workspace_path / ".git").mkdir()
    (workspace_path / "binary.bin").write_bytes(b"\xff\xfe\x00")
    (workspace_path / "oversized.py").write_text("x" * 70_000, encoding="utf-8")
    (workspace_path / "link.py").symlink_to(source_path)
    policy_file = Path(__file__).parents[2] / "config" / "policies" / "reference.json"
    workspace = WorkspaceRef(
        workspace_id=workspace_path.name,
        path=str(workspace_path),
        base_commit="a" * 40,
    )
    provider = StdioMcpInspectionTools(workspace_root, policy_file)

    async with provider.session(workspace) as tools:
        by_name = {tool.name: tool for tool in tools}
        assert set(by_name) == INSPECTION_MCP_TOOL_NAMES
        assert set(by_name["list_repository_tree"].args) == {"relative_path"}
        assert set(by_name["read_repository_file"].args) == {"relative_path"}
        assert set(by_name["search_repository"].args) == {"query"}
        forbidden_arguments = {
            "workspace",
            "workspace_id",
            "workspace_root",
            "base_commit",
            "policy_file",
            "command",
            "url",
            "credentials",
            "max_bytes",
            "max_results",
        }
        assert all(not (set(tool.args) & forbidden_arguments) for tool in tools)

        tree = await _call(tools, "list_repository_tree", {"relative_path": "."}, 1)
        assert tree.status is InspectionToolStatus.SUCCEEDED
        assert tree.artifact is not None
        assert "src/app.py" in tree.artifact.content
        assert ".env" not in tree.artifact.content
        assert ".git" not in tree.artifact.content

        file_result = await _call(tools, "read_repository_file", {"relative_path": "src/app.py"}, 2)
        assert file_result.status is InspectionToolStatus.SUCCEEDED
        assert file_result.artifact is not None
        assert "value = int(raw)" in file_result.artifact.content
        assert "visible-test-value" not in file_result.artifact.content
        assert "[REDACTED]" in file_result.artifact.content

        search = await _call(tools, "search_repository", {"query": "int("}, 3)
        assert search.status is InspectionToolStatus.SUCCEEDED
        assert search.artifact is not None
        assert "src/app.py:2:value = int(raw)" in search.artifact.content

        denied = await _call(tools, "read_repository_file", {"relative_path": ".env"}, 4)
        assert denied.status is InspectionToolStatus.DENIED
        assert denied.error_code == "PATH_DENIED"

        symlink = await _call(tools, "read_repository_file", {"relative_path": "link.py"}, 5)
        assert symlink.status is InspectionToolStatus.ERROR
        assert "symlink" in symlink.detail

        binary = await _call(tools, "read_repository_file", {"relative_path": "binary.bin"}, 6)
        assert binary.status is InspectionToolStatus.ERROR
        assert "UTF-8" in binary.detail

        oversized = await _call(tools, "read_repository_file", {"relative_path": "oversized.py"}, 7)
        assert oversized.status is InspectionToolStatus.SUCCEEDED
        assert oversized.artifact is not None
        assert oversized.artifact.truncated
        assert len(oversized.artifact.content.encode("utf-8")) == 65_536


@pytest.mark.parametrize("relative_path", ["../outside.txt", "/etc/passwd", ".git/config"])
async def test_stdio_server_returns_bounded_denial_for_unsafe_paths(tmp_path: Path, relative_path: str) -> None:
    workspace_root = tmp_path / "workspaces"
    workspace_path = workspace_root / "workspace-2"
    workspace_path.mkdir(parents=True)
    policy_file = Path(__file__).parents[2] / "config" / "policies" / "reference.json"
    workspace = WorkspaceRef(
        workspace_id=workspace_path.name,
        path=str(workspace_path),
        base_commit="b" * 40,
    )

    async with StdioMcpInspectionTools(workspace_root, policy_file).session(workspace) as tools:
        response = await _call(tools, "read_repository_file", {"relative_path": relative_path}, 1)

    assert response.status is InspectionToolStatus.DENIED
    assert response.artifact is None


async def test_stdio_process_start_failure_is_normalized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_root = tmp_path / "workspaces"
    workspace_path = workspace_root / "workspace-3"
    workspace_path.mkdir(parents=True)
    policy_file = Path(__file__).parents[2] / "config" / "policies" / "reference.json"
    workspace = WorkspaceRef(
        workspace_id=workspace_path.name,
        path=str(workspace_path),
        base_commit="c" * 40,
    )
    monkeypatch.setattr("remediation_agent.adapters.mcp.sys.executable", str(tmp_path / "missing-python"))

    with pytest.raises(RuntimeError, match="repository MCP session failed"):
        async with StdioMcpInspectionTools(workspace_root, policy_file).session(workspace):
            pytest.fail("a missing MCP process must not produce a session")
