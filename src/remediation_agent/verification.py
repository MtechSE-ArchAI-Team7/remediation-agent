"""Deterministic coverage checks; model mappings are proposals, never test verdicts."""

from __future__ import annotations

import fnmatch
import hashlib
import re

from remediation_agent.domain.models import (
    BehavioralEvidence,
    CompiledContractV1,
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
    gaps: list[str] = [
        f"Implementation requirement unresolved: {requirement}" for requirement in plan.blocking_requirements
    ]
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
            if item.test_ids and set(item.test_ids).issubset(task.regression_test_ids):
                gaps.append(f"{item.criterion_id}: unaffected-route regression checks cannot prove remediation.")
            if task.repository_patterns and not any(
                fnmatch.fnmatchcase(handoff.repository.url, pattern) for pattern in task.repository_patterns
            ):
                gaps.append(f"{item.criterion_id}: selected capability is not configured for this repository.")
            missing = set(task.required_evidence_paths) - inspected_paths
            if missing:
                gaps.append(
                    f"{item.criterion_id}: affected-path inspection is incomplete: {', '.join(sorted(missing))}"
                )
            if task.request_contract is not None:
                expected_contract = task.request_contract
                # Known profiles are canonical. Prose and JSON formatting are not executable semantics.
                same_route = [c for c in plan.request_contracts if c.path == expected_contract.path]
                for contract in same_route:
                    if (
                        contract.method != expected_contract.method
                        or contract.content_type != expected_contract.content_type
                        or _conflicting_field_types(contract.field_types, expected_contract.field_types)
                    ):
                        gaps.append(
                            f"{item.criterion_id}: request method, encoding, or field types conflict with the profile."
                        )
                if plan.request_contracts and not same_route:
                    gaps.append(f"{item.criterion_id}: request route conflicts with the selected profile.")
    for contract in plan.request_contracts:
        if not set(contract.evidence_paths).issubset(inspected_paths):
            gaps.append(f"{contract.method} {contract.path}: request contract cites uninspected repository paths.")
    return gaps


def _conflicting_field_types(proposed: dict[str, str], canonical: dict[str, str]) -> bool:
    """Compare explicit primitive shapes, never require identical descriptive prose.

    A selected immutable profile supplies every omitted or narrower assertion. Extra request
    fields do not change the profile; a declared incompatible primitive does block compilation.
    """

    def shape(value: str) -> str | None:
        text = value.casefold()
        for category, pattern in (
            ("array", r"\b(array|list)\b"),
            ("number", r"\b(integer|number|int|numeric)\b"),
            ("string", r"\bstring\b"),
            ("boolean", r"\b(bool|boolean)\b"),
            ("object", r"\b(object|mapping)\b"),
        ):
            if re.search(pattern, text):
                return category
        return None

    return any(
        shape(proposed[key]) is not None and shape(proposed[key]) != shape(value)
        for key, value in canonical.items()
        if key in proposed
    )


def evidence_gaps(
    plan: RemediationPlan,
    evidence: list[BehavioralEvidence],
    patch_digest: str,
    base_commit: str,
    policy: PolicyConfig,
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
            if test_id in policy.validation_tasks[criterion.task_name or ""].regression_test_ids:
                continue
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


def compile_contract(
    handoff: DiagnosisHandoffV1,
    plan: RemediationPlan,
    policy: PolicyConfig,
    base_commit: str,
) -> tuple[RemediationPlan, CompiledContractV1]:
    names = sorted({item.task_name for item in plan.verification if item.task_name})
    contracts = [
        policy.validation_tasks[name].request_contract
        for name in names
        if policy.validation_tasks[name].request_contract is not None
    ]
    canonical = plan.model_copy(update={"request_contracts": contracts or plan.request_contracts})
    contract = CompiledContractV1(
        base_commit=base_commit,
        policy_digest=_digest(policy.model_dump_json()),
        criteria=acceptance_ids(handoff),
        coverage=plan.verification,
        task_digests={name: _digest(policy.validation_tasks[name].model_dump_json()) for name in names},
        request_contracts=canonical.request_contracts,
        assertions={name: policy.validation_tasks[name].assertions for name in names},
        limitations=list(
            dict.fromkeys(
                [
                    *plan.unresolved_requirements,
                    *(limitation for name in names for limitation in policy.validation_tasks[name].limitations),
                ]
            )
        ),
    )
    return canonical, contract


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()
