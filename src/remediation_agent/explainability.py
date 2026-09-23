"""Build a bounded, redacted explanation from persisted workflow state."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from remediation_agent.adapters.evidence import SecretRedactor
from remediation_agent.domain.enums import FinalStatus
from remediation_agent.domain.models import (
    ApprovalRequest,
    ExplainabilityEvent,
    ExplainabilityEvidenceRef,
    ExplainabilityTraceV1,
)

if TYPE_CHECKING:
    from remediation_agent.workflow.state import RemediationState

_ActorType = Literal["DETERMINISTIC", "MODEL_ASSISTED", "TOOL", "HUMAN"]

_MODEL_EVENTS = frozenset({"REPOSITORY_INSPECTED", "PLAN_CREATED", "RISK_ASSESSED", "PATCH_GENERATED"})
_TOOL_EVENTS = frozenset(
    {"INSPECTION_TOOL_CALL", "VALIDATION_TASK_EXECUTED", "INCIDENT_MEMORY_RETRIEVED", "INCIDENT_MEMORY_WRITE"}
)
_HUMAN_EVENTS = frozenset({"APPROVAL_DECIDED"})


def build_explainability_trace(
    state: RemediationState,
    *,
    run_id: str,
    status: FinalStatus,
    approval_request: ApprovalRequest | None,
    redactor: SecretRedactor,
) -> ExplainabilityTraceV1:
    """Project internal state into a safe UI/A2A trace without raw model or repository content."""

    risk = state.get("risk_assessment")
    patch_policy = state.get("patch_policy")
    risk_controls = [item.code for item in risk.findings] if risk else []
    patch_controls = patch_policy.control_ids if patch_policy else []
    events: list[ExplainabilityEvent] = []
    for sequence, event in enumerate(state.get("audit_events", [])[:199], start=1):
        controls: list[str] = []
        if event.event_type == "RISK_ASSESSED":
            controls = risk_controls
        elif event.event_type == "PATCH_PREFLIGHT":
            controls = patch_controls
        events.append(
            ExplainabilityEvent(
                sequence=sequence,
                timestamp=event.timestamp,
                stage=_stage_for_event(event.event_type),
                actor_type=_actor_for_event(event.event_type),
                event_type=event.event_type,
                status=event.result_code,
                summary=redactor.redact(event.detail)[:4_000],
                policy_control_ids=controls[:20],
            )
        )
    if approval_request is not None and len(events) < 200:
        events.append(
            ExplainabilityEvent(
                sequence=len(events) + 1,
                timestamp=approval_request.requested_at,
                stage="approval",
                actor_type="HUMAN",
                event_type="APPROVAL_REQUESTED",
                status="PENDING",
                summary=redactor.redact(approval_request.summary)[:4_000],
            )
        )

    evidence = [
        ExplainabilityEvidenceRef(
            kind=item.kind,
            locator=redactor.redact(item.locator)[:2_048],
            digest=item.digest,
            truncated=item.truncated,
        )
        for item in state.get("inspection_artifacts", [])[:100]
    ]
    tool_calls = []
    for item in state.get("inspection_tool_calls", [])[:100]:
        arguments = {
            redactor.redact(str(key))[:200]: _redact_argument(value, redactor) for key, value in item.arguments.items()
        }
        tool_calls.append(item.model_copy(update={"arguments": arguments}))
    model_calls = [
        item.model_copy(
            update={
                "reasoning_summary": (
                    redactor.redact(item.reasoning_summary)[:4_000] if item.reasoning_summary else None
                )
            }
        )
        for item in state.get("model_calls", [])[:100]
    ]
    return ExplainabilityTraceV1(
        run_id=run_id,
        status=status,
        events=events,
        inspection_tool_calls=tool_calls,
        evidence=evidence,
        model_calls=model_calls,
        validation_executions=state.get("validation_execution_records", [])[:100],
        memory_retrieval=state.get("incident_memory_retrieval"),
        memory_write=state.get("incident_memory_write"),
    )


def _actor_for_event(event_type: str) -> _ActorType:
    if event_type in _TOOL_EVENTS:
        return "TOOL"
    if event_type in _HUMAN_EVENTS or event_type == "APPROVAL_REQUESTED":
        return "HUMAN"
    if event_type in _MODEL_EVENTS:
        return "MODEL_ASSISTED"
    return "DETERMINISTIC"


def _stage_for_event(event_type: str) -> str:
    if event_type.startswith("INTAKE"):
        return "intake"
    if event_type.startswith("SCOPE"):
        return "scope"
    if event_type.startswith("WORKSPACE_CREATE") or event_type == "WORKSPACE_CREATED":
        return "workspace"
    if event_type.startswith("INSPECTION") or event_type == "REPOSITORY_INSPECTED":
        return "inspection"
    if event_type.startswith("INCIDENT_MEMORY"):
        return "memory"
    if event_type.startswith("PLAN"):
        return "planning"
    if event_type.startswith("RISK"):
        return "risk"
    if event_type.startswith("APPROVAL"):
        return "approval"
    if event_type in {"PATCH_GENERATED", "PATCH_APPLIED"}:
        return "patch"
    if event_type == "PATCH_PREFLIGHT":
        return "policy"
    if event_type.startswith("VALIDATION") or event_type in {"WORKSPACE_RESTORED", "REVISION_PREPARED"}:
        return "validation"
    if event_type.startswith("ROLLBACK"):
        return "rollback"
    if event_type.startswith("DRAFT_PR"):
        return "draft_pr"
    if event_type.startswith("WORKSPACE_CLEANUP"):
        return "cleanup"
    if event_type.startswith("RUN_FINALIZED"):
        return "finalize"
    return "workflow"


def _redact_argument(value: object, redactor: SecretRedactor) -> object:
    if isinstance(value, str):
        return redactor.redact(value)[:4_000]
    if isinstance(value, bool | int | float) or value is None:
        return value
    return "[REDACTED_COMPLEX_ARGUMENT]"
