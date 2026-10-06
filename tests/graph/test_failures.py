"""Failure routing and cleanup visibility tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from remediation_agent.adapters.fakes import FakeIncidentMemory
from remediation_agent.domain.enums import (
    FinalStatus,
    ModelCallOutcome,
    ModelOperation,
    ReleaseProvenanceStatus,
    RemediationType,
    RepositoryProvider,
)
from remediation_agent.domain.models import ModelCallRecord, ReleaseProvenanceV1
from remediation_agent.ports.models import StructuredModelFailure
from tests.conftest import build_test_service, diagnosis_handoff, patch_for, scripted_responses


async def test_workspace_is_cleaned_when_model_fails_after_clone() -> None:
    service, _, repository, sandbox, _, _, _ = build_test_service({})
    result = await service.start(diagnosis_handoff())
    assert repository.created
    assert sandbox.destroyed
    assert result.status is FinalStatus.INTERNAL_ERROR
    assert result.result is not None
    assert result.result.errors[0].code == "INSPECTION_FAILED"


async def test_unverified_release_provenance_blocks_before_workspace_or_model() -> None:
    class MissingProvenance:
        async def resolve(self) -> ReleaseProvenanceV1:
            return ReleaseProvenanceV1(
                status=ReleaseProvenanceStatus.UNAVAILABLE,
                release_id="release-1",
                source_revision="a" * 40,
                image_digest="sha256:" + "b" * 64,
                runtime_id="runtime-1234567890",
                region="ap-southeast-1",
                verified_at=datetime(2026, 10, 7, tzinfo=UTC),
                verification_method="AGENTCORE_CONTROL_PLANE",
                error_code="RELEASE_PROVENANCE_NOT_FOUND",
            )

    memory = FakeIncidentMemory()
    service, model, repository, sandbox, pr_provider, artifacts, _ = build_test_service(
        scripted_responses(),
        release_provenance=MissingProvenance(),
        incident_memory=memory,
        incident_memory_writes_enabled=True,
    )

    result = await service.start(diagnosis_handoff())

    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not repository.created
    assert not sandbox.destroyed
    assert not model.requests
    assert not pr_provider.requests
    assert not memory.store_requests
    assert result.result is not None
    assert result.result.errors[0].code == "RELEASE_PROVENANCE_NOT_FOUND"
    assert "release-provenance.json" in artifacts.requests[0].files


async def test_provenance_adapter_failure_is_typed_and_blocks_before_workspace() -> None:
    class BrokenProvenance:
        async def resolve(self) -> ReleaseProvenanceV1:
            raise RuntimeError("provider body must not enter evidence")

    service, model, repository, _, _, artifacts, _ = build_test_service(
        scripted_responses(),
        release_provenance=BrokenProvenance(),
    )

    result = await service.start(diagnosis_handoff())

    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not repository.created
    assert not model.requests
    provenance = ReleaseProvenanceV1.model_validate_json(artifacts.requests[0].files["release-provenance.json"])
    assert provenance.status is ReleaseProvenanceStatus.UNAVAILABLE
    assert provenance.error_code == "RELEASE_PROVENANCE_FAILED"
    assert "provider body" not in artifacts.requests[0].files["release-provenance.json"]


async def test_structured_provider_failure_survives_final_artifacts(monkeypatch: pytest.MonkeyPatch) -> None:
    service, model, repository, sandbox, _, artifacts, _ = build_test_service(scripted_responses())
    original_generate = model.generate

    async def fail_planning(request: object, output_schema: object) -> object:
        if getattr(request, "operation", None) is ModelOperation.PLANNING:
            raise StructuredModelFailure(
                "structured model provider failed: INVALID_JSON_SCHEMA",
                record=ModelCallRecord(
                    operation=ModelOperation.PLANNING,
                    provider="openai",
                    model="gateway/model",
                    prompt_version="test-prompt-v1",
                    duration_ms=12,
                    input_digest="sha256:" + "1" * 64,
                    output_digest="sha256:" + "2" * 64,
                    outcome=ModelCallOutcome.FAILED,
                    error_code="INVALID_JSON_SCHEMA",
                    http_status=400,
                    error_parameter="text.format.schema",
                    retryable=False,
                ),
            )
        return await original_generate(request, output_schema)  # type: ignore[arg-type]

    monkeypatch.setattr(model, "generate", fail_planning)

    result = await service.start(diagnosis_handoff())

    assert repository.created
    assert sandbox.destroyed
    assert result.status is FinalStatus.INTERNAL_ERROR
    assert result.result is not None
    assert result.result.errors[-1].code == "PLAN_FAILED"
    assert result.result.errors[-1].retryable is False
    model_calls = artifacts.requests[-1].files["model-calls.json"]
    assert "INVALID_JSON_SCHEMA" in model_calls
    assert "text.format.schema" in model_calls


async def test_invocation_deadline_routes_through_normal_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    service, model, repository, sandbox, _, _, _ = build_test_service(
        scripted_responses(),
        invocation_timeout_seconds=1.0,
    )

    async def wait_past_deadline(*_: object) -> None:
        await asyncio.sleep(60)

    monkeypatch.setattr(model, "generate_tool_turn", wait_past_deadline)

    result = await service.start(diagnosis_handoff())

    assert repository.created
    assert sandbox.destroyed, result.model_dump()
    assert result.status is FinalStatus.INTERNAL_ERROR
    assert result.result is not None
    assert result.result.errors[-1].code == "INVOCATION_DEADLINE_EXCEEDED"


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


@pytest.mark.parametrize(
    "remediation_type",
    [
        RemediationType.ACCOUNT_UNLOCK,
        RemediationType.PASSWORD_RESET,
        RemediationType.ACCESS_PROVISIONING,
        RemediationType.PRIVILEGED_ACCESS,
        RemediationType.PRODUCTION_CHANGE,
    ],
)
async def test_human_only_agent2_scenarios_return_typed_terminal_status(
    remediation_type: RemediationType,
) -> None:
    service, model, repository, sandbox, _, _, _ = build_test_service({})

    result = await service.start(diagnosis_handoff(remediation_type=remediation_type))

    assert result.status is FinalStatus.HUMAN_ACTION_REQUIRED
    assert not repository.created
    assert not model.requests
    assert not sandbox.destroyed


@pytest.mark.parametrize("remediation_type", [RemediationType.SOFTWARE_REQUEST, RemediationType.OTHER])
async def test_unsupported_agent2_scenarios_return_typed_terminal_status(
    remediation_type: RemediationType,
) -> None:
    service, model, repository, sandbox, _, _, _ = build_test_service({})

    result = await service.start(diagnosis_handoff(remediation_type=remediation_type))

    assert result.status is FinalStatus.UNSUPPORTED_REMEDIATION_TYPE
    assert not repository.created
    assert not model.requests
    assert not sandbox.destroyed


async def test_disallowed_repository_fails_closed_before_inspection() -> None:
    responses = scripted_responses()
    service, model, repository, _, _, artifacts, _ = build_test_service(responses)
    payload = diagnosis_handoff().model_dump(mode="json")
    payload["repository"]["url"] = "https://attacker.invalid/repository.git"
    result = await service.start(diagnosis_handoff().model_validate(payload))
    assert result.status is FinalStatus.INVALID_REQUEST
    assert not repository.created
    assert not model.requests
    assert ModelOperation.INSPECTION in responses
    provenance = ReleaseProvenanceV1.model_validate_json(artifacts.requests[0].files["release-provenance.json"])
    assert provenance.status is ReleaseProvenanceStatus.LOCAL


@pytest.mark.parametrize(
    ("provider", "url"),
    [
        (RepositoryProvider.LOCAL, "file:///private/tmp/repository"),
        (RepositoryProvider.GITLAB, "https://gitlab.com/example/repository.git"),
        (RepositoryProvider.GENERIC_GIT, "https://git.example/repository.git"),
        (RepositoryProvider.GITHUB, "https://github.com/MtechSE-ArchAI-Team7/repository"),
    ],
)
async def test_non_github_repository_providers_are_rejected_before_workspace_creation(
    provider: RepositoryProvider,
    url: str,
) -> None:
    service, model, repository, _, _, _, _ = build_test_service(scripted_responses())
    payload = diagnosis_handoff().model_dump(mode="json")
    payload["repository"]["provider"] = provider
    payload["repository"]["url"] = url

    result = await service.start(diagnosis_handoff().model_validate(payload))

    assert result.status is FinalStatus.INVALID_REQUEST
    assert not repository.created
    assert not model.requests


async def test_github_write_target_must_match_handoff_repository() -> None:
    responses = scripted_responses()
    service, model, repository, _, _, _, _ = build_test_service(
        responses,
        github_writes_enabled=True,
        github_repository="MtechSE-ArchAI-Team7/buggy-ecommerce-demo",
    )
    payload = diagnosis_handoff().model_dump(mode="json")
    payload["repository"] = {
        "provider": "GITHUB",
        "url": "https://github.com/MtechSE-ArchAI-Team7/remediation-agent.git",
        "base_branch": "main",
        "commit_sha": "a" * 40,
    }

    result = await service.start(diagnosis_handoff().model_validate(payload))

    assert result.status is FinalStatus.INVALID_REQUEST
    assert not repository.created
    assert not model.requests
    assert result.result is not None
    assert result.result.errors[0].code == "REPOSITORY_NOT_ALLOWED"


async def test_partial_github_failure_retains_prepared_payload_and_cleanup_evidence() -> None:
    service, _, repository, sandbox, pr, _, _ = build_test_service(
        scripted_responses(),
        github_writes_enabled=True,
        github_repository="MtechSE-ArchAI-Team7/buggy-ecommerce-demo",
    )
    payload = diagnosis_handoff().model_dump(mode="json")
    payload["repository"] = {
        "provider": "GITHUB",
        "url": "https://github.com/MtechSE-ArchAI-Team7/buggy-ecommerce-demo.git",
        "base_branch": "main",
        "commit_sha": "a" * 40,
    }

    result = await service.start(diagnosis_handoff().model_validate(payload))

    assert result.status is FinalStatus.DRAFT_PR_PREPARED
    assert result.result is not None
    assert result.result.draft_pr is not None
    assert result.result.draft_pr.created is False
    assert result.result.errors[-1].code == "DRAFT_PR_CREATE_FAILED"
    assert repository.pushes
    assert len(pr.requests) == 2
    assert sandbox.destroyed


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
