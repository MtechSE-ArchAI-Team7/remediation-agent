"""Failure routing and cleanup visibility tests."""

from __future__ import annotations

from remediation_agent.domain.enums import FinalStatus, ModelOperation, RemediationType
from tests.conftest import build_test_service, diagnosis_handoff, patch_for, scripted_responses


async def test_workspace_is_cleaned_when_model_fails_after_clone() -> None:
    service, _, repository, sandbox, _, _, _ = build_test_service({})
    result = await service.start(diagnosis_handoff())
    assert repository.created
    assert sandbox.destroyed
    assert result.status is FinalStatus.INTERNAL_ERROR
    assert result.result is not None
    assert result.result.errors[0].code == "INSPECTION_FAILED"


async def test_cleanup_failure_is_visible_in_final_result() -> None:
    service, _, _, sandbox, _, _, _ = build_test_service(
        scripted_responses(),
        cleanup_succeeds=False,
    )
    result = await service.start(diagnosis_handoff())
    assert sandbox.destroyed
    assert result.status is FinalStatus.CLEANUP_FAILED
    assert result.result is not None
    assert "Fake workspace cleanup failed." in result.result.residual_risks


async def test_deferred_workflow_never_creates_workspace_or_calls_model() -> None:
    service, model, repository, sandbox, _, _, _ = build_test_service({})
    result = await service.start(diagnosis_handoff(remediation_type=RemediationType.ACCOUNT_UNLOCK))
    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not repository.created
    assert not model.requests
    assert not sandbox.destroyed


async def test_disallowed_repository_fails_closed_before_inspection() -> None:
    responses = scripted_responses()
    service, model, repository, _, _, _, _ = build_test_service(responses)
    payload = diagnosis_handoff().model_dump(mode="json")
    payload["repository"]["url"] = "https://attacker.invalid/repository.git"
    result = await service.start(diagnosis_handoff().model_validate(payload))
    assert result.status is FinalStatus.INVALID_REQUEST
    assert not repository.created
    assert not model.requests
    assert ModelOperation.INSPECTION in responses


async def test_validation_task_workspace_tampering_is_detected_and_bounded() -> None:
    responses = scripted_responses(
        patch=patch_for(new="value = safe_v1(raw)"),
        revisions=[patch_for(new="value = safe_v2(raw)"), patch_for(new="value = safe_v3(raw)")],
    )
    service, _, _, sandbox, _, _, _ = build_test_service(
        responses,
        tampered_diff=patch_for(new="authentication = disabled"),
    )
    result = await service.start(diagnosis_handoff())
    assert result.status is FinalStatus.VALIDATION_FAILED
    assert result.result is not None
    assert len(result.result.validation_attempts) == 3
    assert all(
        any(task.task_name == "workspace_integrity" for task in attempt.results)
        for attempt in result.result.validation_attempts
    )
    assert sandbox.restores == 2
