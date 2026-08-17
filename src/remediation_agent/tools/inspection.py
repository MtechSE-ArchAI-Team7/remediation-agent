"""Local control tool used to end the bounded inspection loop."""

from langchain_core.tools import tool

from remediation_agent.domain.models import FinishInspectionArgs

FINISH_INSPECTION_TOOL_NAME = "finish_inspection"


@tool(
    FINISH_INSPECTION_TOOL_NAME,
    args_schema=FinishInspectionArgs,
    description=(
        "Finish repository inspection after at least one successful repository tool call. "
        "Provide a concise rationale for why the collected evidence is sufficient."
    ),
)
def finish_inspection(rationale: str) -> str:
    """Return the rationale; the workflow decides whether finishing is valid."""

    return rationale
