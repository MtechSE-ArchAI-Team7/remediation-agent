"""Evaluation claims fail closed on inconsistent cases, counts and evidence."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from remediation_agent import evaluation as ev

ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize("tool", ["get_file_contents", "search_code", "finish_inspection"])
def test_inspection_fixture_requires_its_named_argument(tool: str) -> None:
    with pytest.raises(ValidationError):
        ev.EvaluationInspectionCall(tool_name=tool)


@pytest.mark.parametrize(
    "field,value",
    [
        ("required_validation_tasks", ["repeat", "repeat"]),
        ("required_policy_controls", ["repeat", "repeat"]),
        ("required_denied_tools", ["repeat", "repeat"]),
        ("expected_validation_attempts", 0),
    ],
)
def test_expectations_cannot_duplicate_or_omit_evidence(field: str, value: object) -> None:
    original = ev.load_evaluation_suite(ROOT / "config/evaluation/suite-v2.json").cases[0].expectation
    raw = original.model_dump()
    raw[field] = value
    with pytest.raises(ValidationError):
        ev.EvaluationExpectationV2.model_validate(raw)


def test_approval_expectations_cannot_claim_cleanup() -> None:
    with pytest.raises(ValidationError, match="resumable"):
        ev.EvaluationExpectationV2.model_validate(
            dict(
                route="APPROVAL",
                terminal_status="AWAITING_APPROVAL",
                require_cleanup=True,
                expected_validation_attempts=0,
            )
        )


@pytest.mark.parametrize("fault", ["tools", "hosted", "paths", "tasks"])
def test_suite_integrity_guards(fault: str) -> None:
    raw = ev.load_evaluation_suite(ROOT / "config/evaluation/suite-v2.json").model_dump(mode="json")
    if fault == "tools":
        raw["allowed_inspection_tools"][0] = "arbitrary_shell"
    elif fault == "hosted":
        for case in raw["cases"]:
            case["hosted"] = False
    elif fault == "paths":
        raw["cases"][0]["policy_path"] = "../outside.json"
    else:
        single = ev.load_evaluation_manifest(ROOT / "config/evaluation/division-by-zero.json").model_dump()
        single["required_validation_tasks"] *= 2
        with pytest.raises(ValidationError):
            ev.EvaluationManifest.model_validate(single)
        return
    with pytest.raises(ValidationError):
        ev.EvaluationSuiteManifestV2.model_validate(raw)


@pytest.mark.parametrize("applicable,score,citations", [(True, None, []), (True, 3, []), (False, None, ["evidence"])])
def test_judge_scores_require_matching_applicability_and_evidence(
    applicable: bool, score: int | None, citations: list[str]
) -> None:
    with pytest.raises(ValidationError):
        ev.JudgeDimensionV1(
            name=ev.JudgeDimensionName.EVIDENCE_GROUNDING,
            applicable=applicable,
            score=score,
            rationale="fixture",
            evidence_ids=citations,
        )


def test_judge_dimensions_and_result_state_are_complete() -> None:
    dimension = ev.JudgeDimensionV1(name=ev.JudgeDimensionName.PLAN_QUALITY, applicable=False, rationale="not assessed")
    with pytest.raises(ValidationError):
        ev.JudgeAssessmentV1(dimensions=[dimension] * 5)
    for status, score in [("COMPLETED", None), ("ERROR", 3)]:
        with pytest.raises(ValidationError):
            ev.JudgeResultV1.model_validate(
                dict(
                    trial_id="trial",
                    case_id="case",
                    status=status,
                    provider="fixture",
                    model="fixture",
                    prompt_version="fixture",
                    duration_ms=0,
                    input_tokens=0,
                    output_tokens=0,
                    overall_score=score,
                )
            )
    with pytest.raises(ValidationError):
        ev.RatioMetricV2(numerator=1, denominator=2, value=1.0)


@pytest.mark.parametrize("fault", ["cases", "order_count", "duplicate_arm", "counterbalance"])
def test_memory_benchmark_requires_a_paired_design(fault: str) -> None:
    raw = ev.load_memory_benchmark(ROOT / "config/evaluation/memory-benchmark-v1.json").model_dump(mode="json")
    if fault == "cases":
        raw["cases"].reverse()
    elif fault == "order_count":
        raw["counterbalanced_orders"].pop()
    elif fault == "duplicate_arm":
        raw["counterbalanced_orders"][0] = ["ON", "ON"]
    else:
        raw["counterbalanced_orders"].reverse()
        raw["counterbalanced_orders"][0] = ["ON", "OFF"]
    with pytest.raises(ValidationError):
        ev.MemoryBenchmarkManifestV1.model_validate(raw)


async def test_suite_result_counts_and_modes_cannot_be_rewritten(tmp_path: Path) -> None:
    from scripts.run_evaluation import run_deterministic

    target = tmp_path / "suite.json"
    await run_deterministic(ROOT / "config/evaluation/suite-v2.json", target)
    result = ev.load_evaluation_suite_result(target)
    for field, value in [("trial_count", 1), ("passed_trials", 0), ("mode", "hosted")]:
        with pytest.raises(ValidationError):
            ev.EvaluationSuiteResultV2.model_validate({**result.model_dump(), field: value})
