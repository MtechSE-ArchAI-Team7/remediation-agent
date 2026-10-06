"""Bounded-loop and interrupt/resume routing tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from remediation_agent.domain.enums import ApprovalStatus, FinalStatus, PolicyDecision, RiskLevel, ValidationOutcome
from remediation_agent.domain.models import ApprovalDecisionV1
from remediation_agent.service import ApprovalConflictError
from tests.conftest import build_test_service, diagnosis_handoff, patch_for, scripted_responses


async def test_repair_loop_stops_exactly_at_configured_maximum() -> None:
    initial = patch_for(new="value = safe_int_v1(raw)")
    revisions = [
        patch_for(new="value = safe_int_v2(raw)"),
        patch_for(new="value = safe_int_v3(raw)"),
    ]
    service, model, _, sandbox, pr, _, audit = build_test_service(
        scripted_responses(patch=initial, revisions=revisions),
        task_outcomes={"unit_tests": [ValidationOutcome.FAILED] * 3},
    )
    result = await service.start(diagnosis_handoff())

    assert result.status is FinalStatus.VALIDATION_FAILED
    assert result.result is not None
    assert len(result.result.validation_attempts) == 3
    assert len(sandbox.applied_patches) == 3
    assert sandbox.restores == 2
    assert pr.requests == []
    revision_requests = [request for request in model.requests if request.operation.value == "REVISION"]
    assert len(revision_requests) == 2
    assert "complete replacement patch" in revision_requests[0].system_instruction
    assert revision_requests[0].payload["previous_patch"] == {
        "unified_diff": initial,
        "rationale": "Bounded fix.",
        "proposed_validation_tasks": [],
    }
    audit_events = [json.loads(line) for line in audit.requests[-1].jsonl.splitlines()]
    failed_task_event = next(
        event
        for event in audit_events
        if event["event_type"] == "VALIDATION_TASK_EXECUTED" and event["result_code"] == "FAILED"
    )
    assert "failure=fake unit_tests: FAILED" in failed_task_event["detail"]


async def test_patch_apply_mismatch_restores_base_and_generates_bounded_revision() -> None:
    initial = patch_for(new="value = safe_int_v1(raw)")
    revision = patch_for(new="value = safe_int_v2(raw)")
    service, model, _, sandbox, pr, _, _ = build_test_service(
        scripted_responses(patch=initial, revisions=[revision]),
        apply_failures=["git apply failed: error: patch failed: src/app.py:1"],
    )

    result = await service.start(diagnosis_handoff())

    assert result.status is FinalStatus.DRAFT_PR_PREPARED
    assert result.result is not None
    assert len(sandbox.applied_patches) == 2
    assert sandbox.restores == 1
    assert len(pr.requests) == 1
    assert result.result.validation_attempts[0].outcome is ValidationOutcome.ERROR
    assert result.result.validation_attempts[0].results[0].task_name == "patch_apply"
    revision_requests = [request for request in model.requests if request.operation.value == "REVISION"]
    assert len(revision_requests) == 1
    assert "git apply failed" in str(revision_requests[0].payload["revision_context"])


async def test_patch_apply_mismatch_stops_at_configured_attempt_limit() -> None:
    initial = patch_for(new="value = safe_int_v1(raw)")
    revisions = [
        patch_for(new="value = safe_int_v2(raw)"),
        patch_for(new="value = safe_int_v3(raw)"),
    ]
    service, _, _, sandbox, pr, _, _ = build_test_service(
        scripted_responses(patch=initial, revisions=revisions),
        apply_failures=["git apply failed: patch does not apply"] * 3,
    )

    result = await service.start(diagnosis_handoff())

    assert result.status is FinalStatus.VALIDATION_FAILED
    assert result.result is not None
    assert len(result.result.validation_attempts) == 3
    assert all(attempt.outcome is ValidationOutcome.ERROR for attempt in result.result.validation_attempts)
    assert len(sandbox.applied_patches) == 3
    assert sandbox.restores == 2
    assert pr.requests == []
    assert any("Patch application failed" in risk for risk in result.result.residual_risks)


async def test_non_applicability_patch_error_remains_terminal() -> None:
    service, model, _, sandbox, pr, _, _ = build_test_service(
        scripted_responses(revisions=[patch_for(new="value = safe_int_v2(raw)")]),
        apply_failures=["applied workspace diff does not match the preflighted file scope"],
    )

    result = await service.start(diagnosis_handoff())

    assert result.status is FinalStatus.INTERNAL_ERROR
    assert len(sandbox.applied_patches) == 1
    assert sandbox.restores == 0
    assert pr.requests == []
    assert all(request.operation.value != "REVISION" for request in model.requests)


async def test_plan_approval_interrupt_can_resume_same_run() -> None:
    responses = scripted_responses(risk_level=RiskLevel.MEDIUM, risk_decision=PolicyDecision.ALLOW)
    service, _, _, sandbox, _, _, _ = build_test_service(responses)
    waiting = await service.start(diagnosis_handoff())

    assert waiting.status is FinalStatus.AWAITING_APPROVAL
    assert waiting.approval_request is not None
    request = waiting.approval_request
    decision = ApprovalDecisionV1(
        approval_id=request.approval_id,
        scope_digest=request.scope_digest,
        status=ApprovalStatus.APPROVED,
        reviewer_id="reviewer",
        decided_at=datetime.now(UTC),
    )
    completed = await service.approve(waiting.run_id, decision)

    assert completed.status is FinalStatus.DRAFT_PR_PREPARED
    assert completed.result is not None
    assert completed.result.approvals == [decision]
    assert sandbox.applied_patches


async def test_identical_approval_retry_resumes_failed_in_progress_checkpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = scripted_responses(risk_level=RiskLevel.MEDIUM, risk_decision=PolicyDecision.ALLOW)
    service, _, _, sandbox, _, _, _ = build_test_service(responses)
    waiting = await service.start(diagnosis_handoff())
    request = waiting.approval_request
    assert request is not None
    decision = ApprovalDecisionV1(
        approval_id=request.approval_id,
        scope_digest=request.scope_digest,
        status=ApprovalStatus.APPROVED,
        reviewer_id="Arabasta",
        decided_at=datetime.now(UTC),
        comment="Approved for the AgentCore demonstration.",
    )
    original_run_task = sandbox.run_task
    calls = 0

    class TransientCloudError(Exception):
        pass

    async def flaky_run_task(task: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TransientCloudError("temporary hosted sandbox denial")
        return await original_run_task(task)  # type: ignore[arg-type]

    monkeypatch.setattr(sandbox, "run_task", flaky_run_task)

    with pytest.raises(TransientCloudError):
        await service.approve(waiting.run_id, decision)

    completed = await service.approve(waiting.run_id, decision)

    assert completed.status is FinalStatus.DRAFT_PR_PREPARED
    assert completed.result is not None
    assert completed.result.approvals == [decision]
    assert calls == 2

    with pytest.raises(ApprovalConflictError, match="not waiting"):
        await service.approve(
            waiting.run_id,
            decision.model_copy(update={"reviewer_id": "different-reviewer"}),
        )


async def test_rejected_approval_makes_no_patch() -> None:
    responses = scripted_responses(risk_level=RiskLevel.HIGH, risk_decision=PolicyDecision.REQUIRE_APPROVAL)
    service, _, _, sandbox, _, _, _ = build_test_service(responses)
    waiting = await service.start(diagnosis_handoff())
    request = waiting.approval_request
    assert request is not None

    rejected = await service.approve(
        waiting.run_id,
        ApprovalDecisionV1(
            approval_id=request.approval_id,
            scope_digest=request.scope_digest,
            status=ApprovalStatus.REJECTED,
            reviewer_id="reviewer",
            decided_at=datetime.now(UTC),
            comment="Risk not accepted.",
        ),
    )
    assert rejected.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert sandbox.applied_patches == []


async def test_approval_is_bound_to_exact_scope() -> None:
    responses = scripted_responses(risk_level=RiskLevel.MEDIUM, risk_decision=PolicyDecision.ALLOW)
    service, _, _, _, _, _, _ = build_test_service(responses)
    waiting = await service.start(diagnosis_handoff())
    request = waiting.approval_request
    assert request is not None
    with pytest.raises(ApprovalConflictError, match="must match"):
        await service.approve(
            waiting.run_id,
            ApprovalDecisionV1(
                approval_id=request.approval_id,
                scope_digest="sha256:wrong",
                status=ApprovalStatus.APPROVED,
                reviewer_id="reviewer",
                decided_at=datetime.now(UTC),
            ),
        )


async def test_revised_sensitive_patch_invalidates_prior_diff_approval() -> None:
    first_patch = patch_for("pyproject.toml", old='name = "old"', new='name = "first"')
    revised_patch = patch_for("pyproject.toml", old='name = "old"', new='name = "second"')
    responses = scripted_responses(patch=first_patch, revisions=[revised_patch])
    service, _, _, sandbox, _, _, _ = build_test_service(
        responses,
        task_outcomes={"unit_tests": [ValidationOutcome.FAILED, ValidationOutcome.PASSED]},
    )
    first_wait = await service.start(diagnosis_handoff())
    first_request = first_wait.approval_request
    assert first_request is not None
    second_wait = await service.approve(
        first_wait.run_id,
        ApprovalDecisionV1(
            approval_id=first_request.approval_id,
            scope_digest=first_request.scope_digest,
            status=ApprovalStatus.APPROVED,
            reviewer_id="reviewer",
            decided_at=datetime.now(UTC),
        ),
    )
    second_request = second_wait.approval_request
    assert second_wait.status is FinalStatus.AWAITING_APPROVAL
    assert second_request is not None
    assert second_request.scope_digest != first_request.scope_digest
    assert len(sandbox.applied_patches) == 1


async def test_patch_path_outside_reviewed_plan_requires_approval() -> None:
    responses = scripted_responses(patch=patch_for("src/unplanned.py"))
    service, _, _, sandbox, _, _, _ = build_test_service(responses)
    waiting = await service.start(diagnosis_handoff())
    assert waiting.status is FinalStatus.AWAITING_APPROVAL
    assert waiting.approval_request is not None
    assert "beyond the reviewed plan" in waiting.approval_request.summary
    assert sandbox.applied_patches == []
