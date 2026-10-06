"""Stable contract identities, strict reports and safe checkpoint round-trips."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from remediation_agent.adapters.checkpoint import checkpoint_serializer
from remediation_agent.domain.models import BehavioralCaseResult, BehavioralReport, VerificationBriefV1
from remediation_agent.policy.models import ValidationTaskConfig
from remediation_agent.verification import acceptance_ids
from tests.conftest import diagnosis_handoff


def test_criteria_have_stable_content_bound_ids() -> None:
    handoff = diagnosis_handoff()
    assert acceptance_ids(handoff) == acceptance_ids(handoff.model_copy())
    changed = handoff.model_copy(update={"acceptance_criteria": ["Different expected behavior."]})
    assert acceptance_ids(handoff).keys() != acceptance_ids(changed).keys()


@pytest.mark.parametrize(
    "cases", [[], [{"test_id": "x", "outcome": "PASSED"}] * 2, [{"test_id": "x", "outcome": "MODEL_SAYS_PASS"}]]
)
def test_empty_duplicate_or_invented_results_are_rejected(cases: list[dict[str, str]]) -> None:
    with pytest.raises(ValidationError):
        BehavioralReport.model_validate({"cases": cases})


def test_brief_and_reports_round_trip_through_safe_checkpointer() -> None:
    serializer = checkpoint_serializer()
    report = BehavioralReport(cases=[BehavioralCaseResult(test_id="test_one", outcome="ASSERTION_FAILED")])
    brief = VerificationBriefV1(run_id="test", criteria=acceptance_ids(diagnosis_handoff()))
    assert serializer.loads_typed(serializer.dumps_typed({"report": report, "brief": brief})) == {
        "report": report,
        "brief": brief,
    }


@pytest.mark.parametrize("path", ["../tests/test.py", "/outside/test.py", "src/app.py", "tests/../secret"])
def test_test_overlay_cannot_replace_application_code(path: str) -> None:
    with pytest.raises(ValidationError):
        ValidationTaskConfig(
            argv=["python"],
            kind="BEHAVIORAL",
            profile="pytest",
            test_paths=[path],
            timeout_seconds=20,
            output_limit_bytes=1000,
        )


@pytest.mark.parametrize("change", ["absent_contract", "wrong_route", "missing_caller"])
def test_purchase_requires_matching_contract_and_complete_inspection(change: str) -> None:
    from pathlib import Path

    from remediation_agent.domain.enums import ModelOperation
    from remediation_agent.domain.models import RemediationPlan
    from remediation_agent.policy.loader import load_policy
    from remediation_agent.verification import coverage_gaps
    from tests.conftest import scripted_responses

    policy = load_policy(Path(__file__).parents[2] / "config/policies/demo.json")
    task = policy.validation_tasks["purchase_regression"]
    contract = task.request_contract
    assert contract is not None
    plan = scripted_responses()[ModelOperation.PLANNING][0]
    assert isinstance(plan, RemediationPlan)
    plan = plan.model_copy(
        update={
            "verification": [
                plan.verification[0].model_copy(
                    update={"task_name": "purchase_regression", "test_ids": task.required_test_ids}
                )
            ],
            "request_contracts": [contract],
        }
    )
    paths = set(task.required_evidence_paths)
    assert not coverage_gaps(diagnosis_handoff(), plan, policy, paths)
    if change == "absent_contract":
        plan = plan.model_copy(update={"request_contracts": []})
    elif change == "wrong_route":
        plan = plan.model_copy(update={"request_contracts": [contract.model_copy(update={"path": "/checkout"})]})
    elif change == "missing_caller":
        paths.remove("public/app.js")
    assert coverage_gaps(diagnosis_handoff(), plan, policy, paths)


def test_approved_plan_limitations_do_not_replace_or_invalidate_complete_coverage() -> None:
    from remediation_agent.domain.enums import ModelOperation
    from remediation_agent.domain.models import RemediationPlan
    from remediation_agent.policy.loader import load_policy
    from remediation_agent.verification import coverage_gaps
    from tests.conftest import scripted_responses

    policy = load_policy(Path(__file__).parents[2] / "config/policies/demo.json")
    task = policy.validation_tasks["purchase_regression"]
    contract = task.request_contract
    assert contract is not None
    plan = scripted_responses()[ModelOperation.PLANNING][0]
    assert isinstance(plan, RemediationPlan)
    plan = plan.model_copy(
        update={
            "verification": [
                plan.verification[0].model_copy(
                    update={"task_name": "purchase_regression", "test_ids": task.required_test_ids}
                )
            ],
            "request_contracts": [contract],
            "unresolved_requirements": ["The order confirmation presentation is outside the supplied criterion."],
        }
    )

    assert not coverage_gaps(diagnosis_handoff(), plan, policy, set(task.required_evidence_paths))


async def test_verification_artifact_is_redacted_digest_bound_and_immutable(tmp_path: Path) -> None:
    import hashlib
    import json

    from remediation_agent.adapters.evidence import LocalArtifactStore, SecretRedactor
    from remediation_agent.ports.models import ArtifactWriteRequest

    brief = VerificationBriefV1(run_id="proof", criteria={"AC-01": "token=fixture-secret"})
    safe = json.dumps(SecretRedactor().redact_data(brief.model_dump(mode="json")))
    assert "fixture-secret" not in safe
    VerificationBriefV1.model_validate_json(safe)
    store = LocalArtifactStore(tmp_path)
    request = ArtifactWriteRequest(run_id="proof", files={"verification-brief.json": safe})
    manifest = await store.write_bundle(request)
    ref = manifest.artifacts[0]
    assert ref.digest == "sha256:" + hashlib.sha256((tmp_path / ref.path).read_bytes()).hexdigest()
    assert await store.write_bundle(request) == manifest
    with pytest.raises(ValueError, match="immutable"):
        await store.write_bundle(request.model_copy(update={"files": {"verification-brief.json": "{}"}}))
