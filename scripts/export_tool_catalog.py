"""Export the operational tool catalogue as deterministic Markdown."""

from __future__ import annotations

from pathlib import Path

from remediation_agent.domain.enums import OperationalToolExecutionMode
from remediation_agent.tools.catalog import OPERATIONAL_TOOL_CATALOG, operational_tool_counts


def render_tool_catalog_markdown() -> str:
    """Render assessment-ready documentation from the typed catalogue."""

    model_count, workflow_count = operational_tool_counts()
    lines = [
        "# AIOS Operational Tool Catalogue",
        "",
        "> Generated from `src/remediation_agent/tools/catalog.py`; do not edit manually.",
        "",
        "The Resolution/Remediation Agent implements "
        f"**{len(OPERATIONAL_TOOL_CATALOG)} operational tools**: **{model_count} model-callable** "
        f"inspection/control tools and **{workflow_count} deterministic workflow-only** tools. "
        "All tools belong to the same agent and shared LangGraph state; they are not agents or subagents.",
        "",
        "## Authority boundary",
        "",
        "```mermaid",
        "flowchart LR",
        '    Model["Configured model"] -->|exact allowlist| Inspect["3 read-only MCP tools"]',
        '    Model --> Finish["finish_inspection control"]',
        '    Workflow["Deterministic LangGraph workflow"] --> Host["13 typed operational tools"]',
        '    Inspect --> GitHub["GitHub hosted MCP server"]',
        '    GitHub --> Repository["Authorized GitHub repository"]',
        "    Host --> Workspace",
        '    Host -->|double gated| Remote["Optional branch and draft PR"]',
        '    Host --> Evidence["Redacted local evidence"]',
        "```",
        "",
        "Repository content cannot expand the allowlist, choose commands, call mutation tools, or grant remote-write "
        "authority. The workflow resolves policy-controlled arguments and invokes workflow-only tools "
        "deterministically.",
        "",
        "## Implemented tools",
        "",
        "| Tool ID | Description | Operation / typed boundary | Arguments | Category | Execution | Effect | "
        "Availability | Controls |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for item in OPERATIONAL_TOOL_CATALOG:
        controls = "<br>".join(_escape(value) for value in item.controls)
        arguments = ", ".join(f"`{_escape(value)}`" for value in item.arguments) or "—"
        lines.append(
            f"| `{_escape(item.tool_id)}` | {_escape(item.description)} | `{_escape(item.operation)}` / "
            f"`{_escape(item.boundary)}` | {arguments} | `{item.category}` | `{item.execution_mode}` | "
            f"`{item.effect}` | `{item.availability}` | {controls} |"
        )
    lines.extend(
        [
            "",
            "## Model-callable subset",
            "",
            "Only these tools are bound to the model during repository inspection:",
            "",
        ]
    )
    for item in OPERATIONAL_TOOL_CATALOG:
        if item.execution_mode is not OperationalToolExecutionMode.DETERMINISTIC_WORKFLOW:
            signature = ", ".join(item.arguments)
            lines.append(f"- `{item.operation}({signature})` — {item.description}")
    lines.extend(
        [
            "",
            "The first three operations are discovered from GitHub's hosted run-scoped MCP session and are "
            "restricted to the authorized repository and immutable commit. "
            "`finish_inspection` is a local control with no repository authority. Every other catalogue entry is "
            "workflow-only and is never included in model-visible tool schemas.",
            "",
        ]
    )
    return "\n".join(lines)


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def main() -> None:
    output = Path(__file__).parents[1] / "docs" / "TOOL_CATALOG.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_tool_catalog_markdown(), encoding="utf-8")


if __name__ == "__main__":
    main()
