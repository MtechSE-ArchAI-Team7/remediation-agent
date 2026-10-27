"""Operational tool catalogue and generated-document contract tests."""

from pathlib import Path

import pytest

from remediation_agent.adapters.mcp import INSPECTION_MCP_TOOL_NAMES
from remediation_agent.domain.enums import OperationalToolExecutionMode
from remediation_agent.ports.protocols import (
    ArtifactStore,
    AuditSink,
    PullRequestProvider,
    RepositoryWorkspacePort,
    SandboxExecutor,
)
from remediation_agent.tools.catalog import OPERATIONAL_TOOL_CATALOG, operational_tool_counts
from remediation_agent.tools.inspection import FINISH_INSPECTION_TOOL_NAME
from scripts.export_tool_catalog import render_tool_catalog_markdown

_WORKFLOW_BOUNDARIES: dict[str, type[object]] = {
    "RepositoryWorkspacePort": RepositoryWorkspacePort,
    "SandboxExecutor": SandboxExecutor,
    "PullRequestProvider": PullRequestProvider,
    "AuditSink": AuditSink,
    "ArtifactStore": ArtifactStore,
}


def test_catalog_contains_seventeen_unique_real_operations() -> None:
    identifiers = [item.tool_id for item in OPERATIONAL_TOOL_CATALOG]
    model_tools = {
        item.operation
        for item in OPERATIONAL_TOOL_CATALOG
        if item.execution_mode is not OperationalToolExecutionMode.DETERMINISTIC_WORKFLOW
    }
    workflow_tools = [
        item
        for item in OPERATIONAL_TOOL_CATALOG
        if item.execution_mode is OperationalToolExecutionMode.DETERMINISTIC_WORKFLOW
    ]

    assert len(identifiers) == len(set(identifiers)) == 17
    assert operational_tool_counts() == (4, 13)
    assert model_tools == {*INSPECTION_MCP_TOOL_NAMES, FINISH_INSPECTION_TOOL_NAME}
    assert len(workflow_tools) == 13

    for item in workflow_tools:
        boundary = _WORKFLOW_BOUNDARIES[item.boundary]
        assert hasattr(boundary, item.operation), f"catalogued operation is not implemented: {item.tool_id}"

    assert {
        item.operation: item.arguments
        for item in OPERATIONAL_TOOL_CATALOG
        if item.execution_mode is not OperationalToolExecutionMode.DETERMINISTIC_WORKFLOW
    } == {
        "get_repository_tree": ("owner", "repo", "tree_sha", "recursive", "path_filter"),
        "get_file_contents": ("owner", "repo", "path", "ref", "sha", "fields"),
        "search_code": ("query", "sort", "order", "fields", "page", "perPage"),
        "finish_inspection": ("rationale",),
    }


def test_local_tool_catalog_document_matches_typed_catalogue() -> None:
    document = Path(__file__).parents[2] / "docs" / "TOOL_CATALOG.md"
    if not document.exists():
        pytest.skip("docs/ is a local, untracked directory; run `make tool-catalog` to generate it")
    assert document.read_text(encoding="utf-8") == render_tool_catalog_markdown()
