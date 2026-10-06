"""A syntax pass and a model assertion can never qualify a remediation for a PR."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from remediation_agent.domain.enums import ApprovalStatus, FinalStatus, ModelOperation, ValidationOutcome
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    BehavioralCaseResult,
    BehavioralReport,
    RemediationPlan,
    RiskAssessment,
    RiskFinding,
    VerificationBriefV1,
    VerificationCriterion,
)
from remediation_agent.ports.models import BehavioralTaskExecution, BehavioralTaskRequest
from remediation_agent.verification import acceptance_ids
from tests.conftest import build_test_service, diagnosis_handoff, scripted_responses


@pytest.mark.parametrize("mode", ["absent", "static", "unknown", "missing_ids", "duplicate"])
async def test_incomplete_contract_never_prepares_pr(mode: str) -> None:
    responses = scripted_responses()
    plan = responses[ModelOperation.PLANNING][0]
    assert isinstance(plan, RemediationPlan)
    criterion = plan.verification[0]
    changes: dict[str, object] = {}
    if mode == "absent":
        changes["verification"] = []
    if mode == "static":
        changes["verification"] = [criterion.model_copy(update={"task_name": "lint"})]
    if mode == "unknown":
        changes["proposed_validation_tasks"] = ["arbitrary_command"]
    if mode == "missing_ids":
        changes["verification"] = [criterion.model_copy(update={"test_ids": []})]
    if mode == "duplicate":
        changes["verification"] = [criterion, criterion]
    responses[ModelOperation.PLANNING] = [plan.model_copy(update=changes)]
    service, _, _, sandbox, pr, artifacts, _ = build_test_service(responses)
    result = await service.start(diagnosis_handoff())
    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not pr.requests and not sandbox.tasks_run and sandbox.destroyed
    brief = VerificationBriefV1.model_validate_json(artifacts.requests[-1].files["verification-brief.json"])
    assert not brief.locally_verified and brief.limitations


@pytest.mark.parametrize(
    "mode", ["base_passes", "setup", "skipped", "missing", "wrong_patch", "wrong_base", "unsupported", "cleanup"]
)
async def test_false_reproduction_fails_closed(mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    service, _, _, sandbox, pr, _, _ = build_test_service(scripted_responses())
    original = sandbox.run_behavior

    async def altered(request: BehavioralTaskRequest) -> BehavioralTaskExecution:
        if mode == "unsupported":
            raise ValueError("UNSUPPORTED_VALIDATION_ENVIRONMENT: absent native dependencies")
        execution = await original(request)
        evidence = execution.evidence
        if mode == "base_passes":
            evidence = evidence.model_copy(update={"base": evidence.candidate})
        if mode in {"setup", "skipped", "missing"}:
            report = BehavioralReport(
                cases=[
                    BehavioralCaseResult(
                        test_id="other" if mode == "missing" else "regression",
                        outcome="SETUP_ERROR" if mode == "setup" else "SKIPPED" if mode == "skipped" else "PASSED",
                    )
                ]
            )
            evidence = evidence.model_copy(update={"base": report})
        if mode == "wrong_base":
            evidence = evidence.model_copy(update={"base_commit": "b" * 40})
        if mode == "wrong_patch":
            evidence = evidence.model_copy(update={"patch_digest": "sha256:stale"})
        if mode == "cleanup":
            evidence = evidence.model_copy(update={"cleanup_succeeded": False})
        return execution.model_copy(update={"evidence": evidence})

    monkeypatch.setattr(sandbox, "run_behavior", altered)
    result = await service.start(diagnosis_handoff())
    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not pr.requests and sandbox.destroyed


async def test_behavioral_assertion_failure_revises_even_after_syntax_pass() -> None:
    from tests.conftest import patch_for

    service, _, _, sandbox, pr, artifacts, _ = build_test_service(
        scripted_responses(tasks=["lint", "unit_tests"], revisions=[patch_for(new="value = guarded(raw)")]),
        task_outcomes={"unit_tests": [ValidationOutcome.FAILED, ValidationOutcome.PASSED]},
    )
    result = await service.start(diagnosis_handoff())
    assert result.status is FinalStatus.DRAFT_PR_PREPARED
    assert sandbox.restores == 1 and len(pr.requests) == 1
    brief = VerificationBriefV1.model_validate_json(artifacts.requests[-1].files["verification-brief.json"])
    assert brief.locally_verified and len(brief.behavioral_evidence) == 2


async def test_risk_and_approved_deferred_checks_survive_into_pr() -> None:
    handoff = diagnosis_handoff().model_copy(
        update={
            "acceptance_criteria": [
                "Malformed values return a typed client error.",
                "Monitor the deployed error rate for 15 minutes.",
            ]
        }
    )
    ids = list(acceptance_ids(handoff))
    responses = scripted_responses()
    plan = responses[ModelOperation.PLANNING][0]
    assert isinstance(plan, RemediationPlan)
    plan = plan.model_copy(
        update={
            "verification": [
                plan.verification[0],
                VerificationCriterion(
                    criterion_id=ids[1],
                    scope="POST_DEPLOYMENT",
                    reason="Requires deployed telemetry unavailable to Agent 3.",
                ),
            ]
        }
    )
    responses[ModelOperation.PLANNING] = [plan]
    risk = responses[ModelOperation.RISK][0]
    assert isinstance(risk, RiskAssessment)
    responses[ModelOperation.RISK] = [
        risk.model_copy(
            update={
                "findings": [
                    RiskFinding(
                        code="DATA_ROLLBACK",
                        level=risk.level,
                        summary="Code rollback cannot restore consumed stock.",
                    )
                ]
            }
        )
    ]
    service, model, _, _, pr, artifacts, _ = build_test_service(responses)
    waiting = await service.start(handoff)
    assert waiting.status is FinalStatus.AWAITING_APPROVAL and waiting.approval_request
    completed = await service.approve(
        waiting.run_id,
        ApprovalDecisionV1(
            approval_id=waiting.approval_request.approval_id,
            scope_digest=waiting.approval_request.scope_digest,
            status=ApprovalStatus.APPROVED,
            reviewer_id="operator",
            decided_at=datetime.now(UTC),
        ),
    )
    assert completed.status is FinalStatus.DRAFT_PR_PREPARED
    body = pr.requests[0].payload.body
    assert "PENDING Agent 4" in body and "cannot restore consumed stock" in body and "None identified" not in body
    brief = VerificationBriefV1.model_validate_json(artifacts.requests[-1].files["verification-brief.json"])
    assert brief.pending_agent4_checks == [handoff.acceptance_criteria[1]]
    risk_request = next(item for item in model.requests if item.operation is ModelOperation.RISK)
    assert risk_request.payload["inspection_artifacts"] and risk_request.payload["base_commit"]
    result_payload = json.loads(artifacts.requests[-1].files["result.json"])
    assert "verification" not in result_payload and result_payload["schema_version"] == "1.0"


async def test_missing_behavior_cannot_enter_incident_memory() -> None:
    from remediation_agent.adapters.fakes import FakeIncidentMemory

    memory = FakeIncidentMemory()
    responses = scripted_responses()
    plan = responses[ModelOperation.PLANNING][0]
    assert isinstance(plan, RemediationPlan)
    responses[ModelOperation.PLANNING] = [plan.model_copy(update={"verification": []})]
    service, _, _, _, pr, _, _ = build_test_service(
        responses,
        incident_memory=memory,
        incident_memory_writes_enabled=True,
    )
    result = await service.start(diagnosis_handoff())
    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not memory.store_requests and not pr.requests


async def test_old_checkpoint_cannot_prepare_a_pr_without_revalidation(monkeypatch: pytest.MonkeyPatch) -> None:
    from remediation_agent.workflow.nodes import WorkflowNodes
    from remediation_agent.workflow.state import RemediationState

    original = WorkflowNodes.evaluate_validation

    async def legacy_evaluation(self: WorkflowNodes, state: RemediationState) -> dict[str, object]:
        update = await original(self, state)
        update["locally_verified"] = False
        update["behavioral_evidence"] = []
        return update

    monkeypatch.setattr(WorkflowNodes, "evaluate_validation", legacy_evaluation)
    service, _, _, sandbox, pr, _, _ = build_test_service(scripted_responses())
    result = await service.start(diagnosis_handoff())
    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not pr.requests and sandbox.destroyed


async def test_revision_cannot_change_assertions_to_turn_a_failure_green(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.conftest import patch_for

    service, _, _, sandbox, pr, _, _ = build_test_service(
        scripted_responses(revisions=[patch_for(new="value = guarded(raw)")]),
        task_outcomes={"unit_tests": [ValidationOutcome.FAILED, ValidationOutcome.PASSED]},
    )
    original = sandbox.run_behavior

    async def altered(request: BehavioralTaskRequest) -> BehavioralTaskExecution:
        result = await original(request)
        if request.attempt == 2:
            return result.model_copy(
                update={"evidence": result.evidence.model_copy(update={"assertions_digest": "sha256:changed"})}
            )
        return result

    monkeypatch.setattr(sandbox, "run_behavior", altered)
    result = await service.start(diagnosis_handoff())
    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not pr.requests and sandbox.destroyed


async def test_candidate_regression_without_base_reproduction_requires_human(monkeypatch: pytest.MonkeyPatch) -> None:
    service, _, _, sandbox, pr, _, _ = build_test_service(
        scripted_responses(),
        task_outcomes={"unit_tests": [ValidationOutcome.FAILED]},
    )
    original = sandbox.run_behavior

    async def altered(request: BehavioralTaskRequest) -> BehavioralTaskExecution:
        result = await original(request)
        base = BehavioralReport(cases=[BehavioralCaseResult(test_id="regression", outcome="PASSED")])
        return result.model_copy(update={"evidence": result.evidence.model_copy(update={"base": base})})

    monkeypatch.setattr(sandbox, "run_behavior", altered)
    result = await service.start(diagnosis_handoff())
    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not sandbox.restores and not pr.requests and sandbox.destroyed
