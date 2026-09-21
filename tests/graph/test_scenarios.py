"""End-to-end graph tests"""

from __future__ import annotations

from remediation_agent.domain.enums import FinalStatus, RemediationType, ValidationOutcome
from tests.conftest import build_test_service, diagnosis_handoff, patch_for, scripted_responses


async def test_scenario_a_code_defect_prepares_evidence_backed_draft_pr() -> None:
    code_and_test_patch = (
        patch_for() + "--- a/tests/test_app.py\n+++ b/tests/test_app.py\n@@ -1 +1,2 @@\n def test_valid(): pass\n"
        "+def test_invalid(): pass\n"
    )
    service, model, _, sandbox, pr, artifacts, audit = build_test_service(
        scripted_responses(
            patch=code_and_test_patch,
            target_paths=["src/app.py", "tests/test_app.py"],
            tasks=["unit_tests", "lint", "type_check"],
        ),
        files={"src/app.py": "value = int(raw)\n", "tests/test_app.py": "def test_valid(): pass\n"},
    )
    result = await service.start(diagnosis_handoff())

    assert result.status is FinalStatus.DRAFT_PR_PREPARED
    assert result.result is not None
    assert result.result.changed_files == ["src/app.py", "tests/test_app.py"]
    assert result.result.validation_attempts[0].outcome is ValidationOutcome.PASSED
    assert result.result.rollback_instructions is not None
    assert result.result.draft_pr is not None
    assert result.result.draft_pr.payload.title == "[TICKET-111] Handle invalid integer conversion."
    assert "Human review" in result.result.draft_pr.payload.body
    assert sandbox.applied_patches and sandbox.destroyed
    assert sandbox.tasks_run == ["unit_tests", "lint", "type_check"]
    assert pr.requests and artifacts.requests and audit.requests
    assert [request.operation for request in model.requests][-1].value == "PATCH"


async def test_draft_pr_title_is_bounded_without_changing_case_based_branch_or_commit() -> None:
    summary = "S" * 300
    service, _, repository, _, pr, _, _ = build_test_service(
        scripted_responses(plan_summary=summary),
        github_writes_enabled=True,
        github_repository="MtechSE-ArchAI-Team7/example-service",
    )
    result = await service.start(diagnosis_handoff())

    assert result.result is not None
    assert result.result.draft_pr is not None
    assert result.result.draft_pr.payload.title.startswith("[TICKET-111] ")
    assert len(result.result.draft_pr.payload.title) == 240
    assert "case-123" in result.result.draft_pr.payload.head_branch
    assert repository.commits == ["fix: remediate CASE-123"]
    assert pr.requests[0].payload == result.result.draft_pr.payload


async def test_upstream_secret_like_text_is_redacted_before_checkpoint_and_model_use() -> None:
    handoff = diagnosis_handoff()
    evidence = handoff.supporting_evidence[0].model_copy(update={"excerpt": "token=upstream-secret"})
    handoff = handoff.model_copy(update={"supporting_evidence": [evidence]})
    service, model, _, _, _, _, _ = build_test_service(scripted_responses())
    result = await service.start(handoff)
    snapshot = await service.graph.aget_state({"configurable": {"thread_id": result.run_id}})
    assert "upstream-secret" not in str(snapshot.values)
    assert all("upstream-secret" not in str(request.payload) for request in model.requests)


async def test_scenario_b_configuration_defect_runs_config_validation() -> None:
    path = "config/service.json"
    responses = scripted_responses(
        target_path=path,
        patch=patch_for(path, old='{"timeout": -1}', new='{"timeout": 30}'),
        tasks=["config_validation"],
    )
    service, _, _, sandbox, _, _, _ = build_test_service(
        responses,
        files={path: '{"timeout": -1}\n'},
    )
    result = await service.start(diagnosis_handoff(remediation_type=RemediationType.CONFIGURATION))

    assert result.status is FinalStatus.DRAFT_PR_PREPARED
    assert sandbox.tasks_run == ["unit_tests", "config_validation"]
    assert result.result is not None
    assert result.result.rollback_instructions is not None
    assert any("-1" in step for step in result.result.rollback_instructions.before_commit)


async def test_scenario_c_security_weakening_is_rejected_without_side_effects() -> None:
    responses = scripted_responses(plan_summary="Disable authentication to avoid the failing request.")
    responses.pop(next(key for key in responses if key.value == "PATCH"))
    service, _, _, sandbox, pr, _, audit = build_test_service(responses)
    result = await service.start(diagnosis_handoff())

    assert result.status is FinalStatus.UNSAFE_REMEDIATION
    assert result.result is not None
    assert result.result.changed_files == []
    assert "SECURITY_WEAKENING" in result.result.policy_control_ids
    assert sandbox.applied_patches == []
    assert sandbox.tasks_run == []
    assert pr.requests == []
    assert audit.requests


async def test_explicit_run_id_makes_duplicate_start_idempotent() -> None:
    service, model, _, _, _, _, _ = build_test_service(scripted_responses())
    run_id = "2db1f13e-7351-4a1f-a4c6-630646366d52"

    first = await service.start(diagnosis_handoff(), run_id=run_id)
    request_count = len(model.requests)
    second = await service.start(diagnosis_handoff(), run_id=run_id)

    assert first == second
    assert first.run_id == run_id
    assert len(model.requests) == request_count
