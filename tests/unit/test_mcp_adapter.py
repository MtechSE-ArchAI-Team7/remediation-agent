"""MCP client registration validation tests."""

from __future__ import annotations

from langchain_core.tools import StructuredTool

from remediation_agent.adapters.mcp import StdioMcpInspectionTools
from remediation_agent.domain.models import ListRepositoryTreeArgs, ReadRepositoryFileArgs, SearchRepositoryArgs


def _fixture_tool(
    name: str, args_schema: type[ListRepositoryTreeArgs | ReadRepositoryFileArgs | SearchRepositoryArgs]
) -> StructuredTool:
    def operation(**arguments: object) -> str:
        _ = arguments
        return "fixture"

    return StructuredTool.from_function(
        func=operation,
        name=name,
        description="Registration fixture.",
        args_schema=args_schema,
    )


def test_registration_rejects_missing_extra_duplicate_and_changed_schemas() -> None:
    tree = _fixture_tool("list_repository_tree", ListRepositoryTreeArgs)
    read = _fixture_tool("read_repository_file", ReadRepositoryFileArgs)
    search = _fixture_tool("search_repository", SearchRepositoryArgs)

    StdioMcpInspectionTools._validate_tools([tree, read, search])

    for invalid in (
        [tree, read],
        [tree, read, search, _fixture_tool("unexpected", SearchRepositoryArgs)],
        [tree, read, search, search],
    ):
        try:
            StdioMcpInspectionTools._validate_tools(invalid)
        except RuntimeError as exc:
            assert "unexpected tool set" in str(exc)
        else:  # pragma: no cover - makes a missing exception explicit
            raise AssertionError("invalid MCP registration was accepted")

    wrong_schema = _fixture_tool("search_repository", ReadRepositoryFileArgs)
    try:
        StdioMcpInspectionTools._validate_tools([tree, read, wrong_schema])
    except RuntimeError as exc:
        assert "unexpected argument schema" in str(exc)
    else:  # pragma: no cover - makes a missing exception explicit
        raise AssertionError("changed MCP argument schema was accepted")
