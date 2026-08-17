"""Run-scoped stdio MCP client for repository-inspection tools."""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path

from langchain_core.tools import BaseTool
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from remediation_agent.domain.models import WorkspaceRef
from remediation_agent.policy.loader import load_policy

INSPECTION_MCP_TOOL_NAMES = frozenset(
    {
        "list_repository_tree",
        "read_repository_file",
        "search_repository",
    }
)

_EXPECTED_ARGUMENTS = {
    "list_repository_tree": {"relative_path"},
    "read_repository_file": {"relative_path"},
    "search_repository": {"query"},
}


class StdioMcpInspectionTools:
    """Load the fixed MCP server through a fresh workspace-scoped session."""

    def __init__(self, workspace_root: Path, policy_file: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self.policy_file = policy_file.resolve()
        self.startup_timeout_seconds = load_policy(self.policy_file).limits.max_mcp_tool_timeout_seconds

    @asynccontextmanager
    async def session(self, workspace: WorkspaceRef) -> AsyncIterator[Sequence[BaseTool]]:
        if Path(workspace.path).resolve() != self.workspace_root / workspace.workspace_id:
            raise ValueError("workspace does not match the configured MCP workspace root")
        server = StdioServerParameters(
            command=sys.executable,
            args=["-m", "remediation_agent.mcp.server"],
            env={
                "AIOS_MCP_WORKSPACE_ROOT": str(self.workspace_root),
                "AIOS_MCP_WORKSPACE_ID": workspace.workspace_id,
                "AIOS_MCP_BASE_COMMIT": workspace.base_commit,
                "AIOS_MCP_POLICY_FILE": str(self.policy_file),
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONUNBUFFERED": "1",
            },
        )
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
            try:
                async with stdio_client(server, errlog=stderr) as (read, write):
                    async with ClientSession(read, write) as client:
                        async with asyncio.timeout(self.startup_timeout_seconds):
                            await client.initialize()
                            tools = await load_mcp_tools(client, handle_tool_errors=False)
                        self._validate_tools(tools)
                        yield tools
            except Exception as exc:  # noqa: BLE001 - normalize the external MCP transport boundary
                raise RuntimeError(f"repository MCP session failed: {type(exc).__name__}") from exc

    @staticmethod
    def _validate_tools(tools: Sequence[BaseTool]) -> None:
        by_name = {tool.name: tool for tool in tools}
        if len(tools) != len(INSPECTION_MCP_TOOL_NAMES) or set(by_name) != INSPECTION_MCP_TOOL_NAMES:
            raise RuntimeError("repository MCP server exposed an unexpected tool set")
        for name, expected in _EXPECTED_ARGUMENTS.items():
            properties = set(by_name[name].args)
            if properties != expected:
                raise RuntimeError(f"repository MCP tool has an unexpected argument schema: {name}")
