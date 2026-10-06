"""Recovery cannot change the candidate or bypass qualifying durable evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from remediation_agent.adapters.fakes import FakeIncidentMemory
from remediation_agent.domain.enums import ApprovalStatus, FinalStatus, PolicyDecision, RiskLevel
from remediation_agent.domain.models import ApprovalDecisionV1
from remediation_agent.ports.models import ArtifactWriteRequest, CreatedDraftPr, DraftPrRequest, PublicationError
from remediation_agent.service import ApprovalConflictError
from tests.conftest import build_test_service, diagnosis_handoff, scripted_responses


async def test_exhausted_publication_can_retry_only_exact_verified_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    memory = FakeIncidentMemory()
    service, model, repository, sandbox, provider, artifacts, _ = build_test_service(
        scripted_responses(),
        github_writes_enabled=True,
        github_repository="MtechSE-ArchAI-Team7/example-service",
        incident_memory=memory,
        incident_memory_writes_enabled=True,
    )

    async def unavailable(_: DraftPrRequest) -> CreatedDraftPr:
        raise PublicationError("GITHUB_HTTP_503", retryable=True)

    original = provider.create_draft
    monkeypatch.setattr(provider, "create_draft", unavailable)
    failed = await service.start(diagnosis_handoff())
    assert failed.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert sandbox.destroyed and not memory.store_requests
    snapshot = await service.graph.aget_state(service._config(failed.run_id))
    digest = snapshot.values["diff_digest"]
    calls = len(model.requests)
    brief = artifacts.requests[-1].files["verification-brief.json"]
    with pytest.raises(ApprovalConflictError, match="REVALIDATION_REQUIRED"):
        await service.retry_publication(failed.run_id, "sha256:wrong")
    provider.create = True
    monkeypatch.setattr(provider, "create_draft", original)
    complete = await service.retry_publication(failed.run_id, digest)
    assert complete.status is FinalStatus.DRAFT_PR_CREATED
    assert len(model.requests) == calls
    assert len(memory.store_requests) == 1
    assert artifacts.requests[-1].files["verification-brief.json"] == brief
    journal = json.loads(artifacts.requests[-1].files["publication-journal.json"])
    assert journal["verified"] and journal["candidate_digest"] == digest
    assert [r["stage"] for r in journal["receipts"]] == ["BRANCH", "COMMIT", "PUSH", "DRAFT", "VERIFIED"]
    assert all(request.expected_commit == "b" * 40 for request in provider.requests if request.expected_commit)
    branches = len(repository.branches)
    assert (await service.retry_publication(failed.run_id, digest)).status is FinalStatus.DRAFT_PR_CREATED
    assert len(repository.branches) == branches


async def test_failed_candidate_artifact_write_prevents_all_publication(monkeypatch: pytest.MonkeyPatch) -> None:
    service, _, repository, sandbox, _, store, _ = build_test_service(
        scripted_responses(), github_writes_enabled=True, github_repository="MtechSE-ArchAI-Team7/example-service"
    )
    original = store.write_bundle

    async def fail_candidate(request: ArtifactWriteRequest):  # type: ignore[no-untyped-def]
        if "candidate-evidence.json" in request.files:
            raise OSError("artifact service unavailable")
        return await original(request)

    monkeypatch.setattr(store, "write_bundle", fail_candidate)
    result = await service.start(diagnosis_handoff())
    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not repository.branches and not repository.commits and not repository.pushes
    assert sandbox.destroyed


@pytest.mark.parametrize("changed", ["assets", "model", "contract"])
async def test_changed_execution_inputs_invalidate_approval_before_patch(
    monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    service, model, _, sandbox, pr, _, _ = build_test_service(
        scripted_responses(risk_level=RiskLevel.MEDIUM, risk_decision=PolicyDecision.REQUIRE_APPROVAL)
    )
    waiting = await service.start(diagnosis_handoff())
    approval = waiting.approval_request
    assert approval
    if changed == "assets":
        monkeypatch.setattr(sandbox, "verification_fingerprint", lambda: "sha256:changed-assets")
    elif changed == "model":
        monkeypatch.setattr(model, "configuration_digest", lambda: "sha256:changed-model")
    else:
        snapshot = await service.graph.aget_state(service._config(waiting.run_id))
        contract = snapshot.values["compiled_contract"].model_copy(
            update={"criteria": {"AC-new": "changed requirement"}}
        )
        await service.graph.aupdate_state(service._config(waiting.run_id), {"compiled_contract": contract})
    result = await service.approve(
        waiting.run_id,
        ApprovalDecisionV1(
            approval_id=approval.approval_id,
            scope_digest=approval.scope_digest,
            status=ApprovalStatus.APPROVED,
            reviewer_id="test",
            decided_at=datetime.now(UTC),
        ),
    )
    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not sandbox.applied_patches and not pr.requests and sandbox.destroyed


async def test_duplicate_run_cannot_replace_original_handoff() -> None:
    service, model, *_ = build_test_service(scripted_responses())
    original = diagnosis_handoff()
    first = await service.start(original)
    calls = len(model.requests)
    assert (await service.start(original, run_id=first.run_id)).status == first.status
    assert len(model.requests) == calls
    with pytest.raises(ApprovalConflictError, match="RUN_INPUT_MISMATCH"):
        await service.start(original.model_copy(update={"issue_summary": "A different defect"}), run_id=first.run_id)
