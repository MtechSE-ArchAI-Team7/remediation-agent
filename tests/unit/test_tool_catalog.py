"""Operational tool catalogue and generated-document contract tests."""

from pathlib import Path

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


def test_committed_tool_catalog_document_matches_typed_catalogue() -> None:
    document = Path(__file__).parents[2] / "docs" / "TOOL_CATALOG.md"
    assert document.read_text(encoding="utf-8") == render_tool_catalog_markdown()
