"""Bounded explainability projection tests."""

from __future__ import annotations

from typing import cast

from remediation_agent.adapters.evidence import AuditTrail, SecretRedactor
from remediation_agent.domain.enums import FinalStatus, InspectionToolStatus, ModelOperation
from remediation_agent.domain.models import InspectionArtifact, InspectionToolCallRecord, ModelCallRecord
from remediation_agent.explainability import build_explainability_trace
from remediation_agent.workflow.state import RemediationState
from tests.conftest import diagnosis_handoff


def test_trace_exposes_decisions_but_not_repository_content_or_secrets() -> None:
    audit = AuditTrail("1.0", "test-v1")
    event = audit.event(
        [],
        case_id="CASE-1",
        run_id="run-1",
        event_type="PLAN_CREATED",
        result_code="OK",
        detail="Use the bounded fix; token=hidden",
    )
    state = cast(
        RemediationState,
        {
            "run_id": "run-1",
            "handoff": diagnosis_handoff(),
            "final_status": FinalStatus.PENDING,
            "audit_events": [event],
            "inspection_artifacts": [
                InspectionArtifact(
                    kind="FILE",
                    locator="server.js",
                    content="API_KEY=must-not-leak",
                    digest="sha256:evidence",
                )
            ],
            "inspection_tool_calls": [
                InspectionToolCallRecord(
                    call_id="call-1",
                    tool_name="get_file_contents",
                    arguments={"path": "server.js", "token": "token=hidden"},
                    status=InspectionToolStatus.SUCCEEDED,
                    result_digest="sha256:result",
                )
            ],
            "model_calls": [
                ModelCallRecord(
                    operation=ModelOperation.PLANNING,
                    provider="openai",
                    model="gpt-5.6-terra",
                    prompt_version="test-v1",
                    duration_ms=12,
                    input_digest="sha256:input",
                    output_digest="sha256:output",
                    reasoning_summary="Check the evidence; password=hidden",
                )
            ],
        },
    )

    trace = build_explainability_trace(
        state,
        run_id="run-1",
        status=FinalStatus.PENDING,
        approval_request=None,
        redactor=SecretRedactor(),
    )
    serialized = trace.model_dump_json()

    assert trace.events[0].actor_type == "MODEL_ASSISTED"
    assert trace.events[0].stage == "planning"
    assert trace.evidence[0].locator == "server.js"
    assert trace.model_calls[0].reasoning_summary == "Check the evidence; [REDACTED]"
    assert "must-not-leak" not in serialized
    assert "token=hidden" not in serialized
    assert "password=hidden" not in serialized


def test_workspace_creation_failure_is_attributed_to_inspection_stage() -> None:
    audit = AuditTrail("1.0", "test-v1")
    event = audit.event(
        [],
        case_id="CASE-1",
        run_id="run-1",
        event_type="WORKSPACE_CREATE_FAILED",
        result_code="ERROR",
        detail="Clone failed.",
    )
    state = cast(
        RemediationState,
        {
            "run_id": "run-1",
            "handoff": diagnosis_handoff(),
            "final_status": FinalStatus.INTERNAL_ERROR,
            "audit_events": [event],
        },
    )

    trace = build_explainability_trace(
        state,
        run_id="run-1",
        status=FinalStatus.INTERNAL_ERROR,
        approval_request=None,
        redactor=SecretRedactor(),
    )

    assert trace.events[0].stage == "workspace"
