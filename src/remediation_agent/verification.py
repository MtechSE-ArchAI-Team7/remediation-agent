"""Deterministic coverage checks; model mappings are proposals, never test verdicts."""

from __future__ import annotations

import hashlib

from remediation_agent.domain.models import (
    BehavioralEvidence,
    DiagnosisHandoffV1,
    RemediationPlan,
    VerificationObservation,
)
from remediation_agent.policy.models import PolicyConfig


def acceptance_ids(handoff: DiagnosisHandoffV1) -> dict[str, str]:
    return {
        f"AC-{index:02d}-{hashlib.sha256(text.encode()).hexdigest()[:8]}": text
        for index, text in enumerate(handoff.acceptance_criteria, start=1)
    }


def coverage_gaps(
    handoff: DiagnosisHandoffV1,
    plan: RemediationPlan,
    policy: PolicyConfig,
    inspected_paths: set[str],
) -> list[str]:
    gaps: list[str] = [f"Unresolved requirement: {item}" for item in plan.unresolved_requirements]
    expected = set(acceptance_ids(handoff))
    actual = [item.criterion_id for item in plan.verification]
    if set(actual) != expected or len(actual) != len(expected):
        gaps.append("Every acceptance criterion must have exactly one verification mapping using its supplied ID.")
    local = [item for item in plan.verification if item.scope == "LOCAL"]
    if not local:
        gaps.append("At least one local behavioral criterion is required to demonstrate the diagnosed defect.")
    for item in plan.verification:
        if item.scope == "POST_DEPLOYMENT":
            if not item.reason or item.task_name or item.test_ids:
                gaps.append(f"{item.criterion_id}: deployment deferral needs a reason and cannot claim local tests.")
            continue
        task = policy.validation_tasks.get(item.task_name or "")
        if task is None or task.kind != "BEHAVIORAL" or not item.test_ids:
            gaps.append(f"{item.criterion_id}: requires a known behavioral task and explicit test IDs.")
        elif task.required_test_ids and not set(item.test_ids).issubset(task.required_test_ids):
            gaps.append(f"{item.criterion_id}: test IDs are outside the operator-owned profile.")
        if task is not None:
            missing = set(task.required_evidence_paths) - inspected_paths
            if missing:
                gaps.append(
                    f"{item.criterion_id}: affected-path inspection is incomplete: {', '.join(sorted(missing))}"
                )
            if task.request_contract is not None:
                expected_contract = task.request_contract.model_dump(exclude={"evidence_paths"})
                if not any(
                    contract.model_dump(exclude={"evidence_paths"}) == expected_contract
                    for contract in plan.request_contracts
                ):
                    gaps.append(
                        f"{item.criterion_id}: request contract is absent or incompatible with the trusted profile."
                    )
    for contract in plan.request_contracts:
        if not set(contract.evidence_paths).issubset(inspected_paths):
            gaps.append(f"{contract.method} {contract.path}: request contract cites uninspected repository paths.")
    return gaps


def evidence_gaps(
    plan: RemediationPlan, evidence: list[BehavioralEvidence], patch_digest: str, base_commit: str
) -> list[str]:
    gaps: list[str] = []
    current = {
        item.task_name: item
        for item in evidence
        if item.patch_digest == patch_digest and item.base_commit == base_commit
    }
    reproduced = False
    base_reproduced = False
    for criterion in plan.verification:
        if criterion.scope != "LOCAL":
            continue
        pair = current.get(criterion.task_name or "")
        if pair is None or not pair.cleanup_succeeded:
            gaps.append(f"{criterion.criterion_id}: paired execution or cleanup evidence is missing.")
            continue
        base = {case.test_id: case.outcome for case in pair.base.cases}
        candidate = {case.test_id: case.outcome for case in pair.candidate.cases}
        if set(base) != set(candidate):
            gaps.append(f"{criterion.criterion_id}: base/candidate test identities differ.")
        for test_id in criterion.test_ids:
            base_reproduced = base_reproduced or base.get(test_id) == "ASSERTION_FAILED"
            if base.get(test_id) not in {"PASSED", "ASSERTION_FAILED"}:
                gaps.append(f"{criterion.criterion_id}: {test_id} did not execute an assertion on the base.")
            if candidate.get(test_id) not in {"PASSED", "ASSERTION_FAILED"}:
                gaps.append(f"{criterion.criterion_id}: {test_id} was missing, skipped, or failed during setup.")
            if base.get(test_id) == "ASSERTION_FAILED" and candidate.get(test_id) == "PASSED":
                reproduced = True
    # Failing candidate assertions must be repaired before asking whether the fix reproduced the defect.
    candidate_failed = any(
        case.outcome == "ASSERTION_FAILED" for pair in current.values() for case in pair.candidate.cases
    )
    if not base_reproduced:
        gaps.append("No mapped regression assertion reproduced the diagnosed defect on the immutable base.")
    elif not reproduced and not candidate_failed:
        gaps.append("No mapped regression assertion failed on the immutable base and passed on the candidate.")
    return list(dict.fromkeys(gaps))


def observations(evidence: list[BehavioralEvidence]) -> list[VerificationObservation]:
    results = []
    for pair in evidence:
        base = {case.test_id: case.outcome for case in pair.base.cases}
        for case in pair.candidate.cases:
            classification = {
                ("ASSERTION_FAILED", "PASSED"): "FIX_DEMONSTRATED",
                ("PASSED", "ASSERTION_FAILED"): "INTRODUCED_REGRESSION",
                ("ASSERTION_FAILED", "ASSERTION_FAILED"): "OBSERVED_BASELINE_FAILURE",
                ("PASSED", "PASSED"): "PASSED_BOTH",
            }.get((base.get(case.test_id) or "MISSING", case.outcome), "INCONCLUSIVE")
            results.append(
                VerificationObservation.model_validate(
                    {
                        "task_name": pair.task_name,
                        "test_id": case.test_id,
                        "classification": classification,
                    }
                )
            )
    return results
