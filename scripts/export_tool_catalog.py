"""Export the operational tool catalogue as deterministic Markdown."""

from __future__ import annotations

import json
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
        "All tools belong to the same agent and shared LangGraph state; internal stages are workflow nodes.",
        "",
        "## Authority boundary",
        "",
        "```mermaid",
        "flowchart LR",
        '    Model["Configured model"] -->|exact allowlist| ModelTools["3 read-only MCP tools<br/>+ finish control"]',
        '    ModelTools --> Policy["Host policy boundary<br/>repository + commit + paths + limits"]',
        '    Policy --> GitHub["GitHub hosted MCP<br/>read-only inspection"]',
        '    Workflow["One LangGraph workflow"] --> Policy',
        '    Policy --> HostTools["13 deterministic workflow tools"]',
        '    HostTools --> Workspace["Disposable workspace"]',
        '    HostTools --> Sandbox["Docker / AgentCore Code Interpreter"]',
        '    HostTools --> Evidence["Redacted audit + artifacts"]',
        '    HostTools -->|application gate + policy gate| Remote["Optional Git push + MCP draft PR"]',
        '    Remote -. never .-> Merge["Merge or deploy"]',
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


def render_tool_catalog_json() -> str:
    """Render the typed catalogue as the JSON API representation."""

    model_count, workflow_count = operational_tool_counts()
    payload = {
        "catalog_version": "1.1",
        "total_tools": len(OPERATIONAL_TOOL_CATALOG),
        "model_callable_tools": model_count,
        "workflow_only_tools": workflow_count,
        "tools": [item.model_dump(mode="json") for item in OPERATIONAL_TOOL_CATALOG],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def main() -> None:
    root = Path(__file__).parents[1]
    markdown_output = root / "docs" / "TOOL_CATALOG.md"
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.write_text(render_tool_catalog_markdown(), encoding="utf-8")


if __name__ == "__main__":
    main()
