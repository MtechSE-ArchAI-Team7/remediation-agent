from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from remediation_agent.domain.enums import FinalStatus, MemoryRetrievalStatus
from remediation_agent.evaluation import (
    EvaluationJudgeInput,
    EvaluationManifest,
    EvaluationMetric,
    EvaluationSuiteManifestV2,
    EvaluationTrialV2,
    ExpectedRoute,
    JudgeAssessmentV1,
    JudgeDimensionName,
    JudgeDimensionV1,
    JudgeResultV1,
    MemoryArm,
    MemoryEvaluationTrialV1,
    _percentile,
    aggregate_evaluation_suite,
    aggregate_judge_results,
    aggregate_memory_evaluation,
    load_evaluation_manifest,
    load_evaluation_suite,
    load_memory_benchmark,
    render_assessment_report,
    render_suite_assessment_report,
)


def test_manifest_requires_the_exact_four_tool_allowlist() -> None:
    raw = {
        "evaluation_id": "eval",
        "scenario_id": "case",
        "title": "title",
        "handoff_path": "handoff.json",
        "policy_path": "policy.json",
        "expected_terminal_status": "DRAFT_PR_PREPARED",
        "required_validation_tasks": ["javascript_syntax"],
        "allowed_inspection_tools": ["get_file_contents"],
        "minimum_commit_pinned_reads": 1,
        "maximum_trials": 1,
    }

    with pytest.raises(ValidationError, match="exactly the four approved tools"):
        EvaluationManifest.model_validate(raw)


def test_tracked_manifest_is_strict_and_report_never_fabricates_hosted_evidence() -> None:
    root = Path(__file__).parents[2]
    manifest = load_evaluation_manifest(root / "config/evaluation/division-by-zero.json")

    report = render_assessment_report(manifest, None, None)

    assert manifest.required_validation_tasks == ["javascript_syntax", "average_regression"]
    assert "## Hosted demonstration\n\n**NOT RUN**" in report
    assert "AgentCore Code Interpreter" in report
    assert "raw session IDs" in report
    assert "repository contents" in report


def test_manifest_rejects_unknown_fields(tmp_path: Path) -> None:
    source = Path(__file__).parents[2] / "config/evaluation/division-by-zero.json"
    raw = json.loads(source.read_text(encoding="utf-8"))
    raw["ambient_write_override"] = True
    target = tmp_path / "manifest.json"
    target.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        load_evaluation_manifest(target)


def test_v2_suite_is_strict_unique_and_route_consistent() -> None:
    root = Path(__file__).parents[2]
    suite = load_evaluation_suite(root / "config/evaluation/suite-v2.json")
    raw = suite.model_dump(mode="json")
    raw["unknown"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        EvaluationSuiteManifestV2.model_validate(raw)

    duplicate = suite.model_dump(mode="json")
    duplicate["cases"][1]["case_id"] = duplicate["cases"][0]["case_id"]
    with pytest.raises(ValidationError, match="case IDs must be unique"):
        EvaluationSuiteManifestV2.model_validate(duplicate)

    inconsistent = suite.model_dump(mode="json")
    inconsistent["cases"][0]["expectation"]["terminal_status"] = "AWAITING_APPROVAL"
    with pytest.raises(ValidationError, match="inconsistent"):
        EvaluationSuiteManifestV2.model_validate(inconsistent)

    unsafe = suite.model_dump(mode="json")
    unsafe["cases"][0]["deterministic_fixture"]["inspection_calls"][1]["path"] = "../.env"
    with pytest.raises(ValidationError, match="unsafe inspection path"):
        EvaluationSuiteManifestV2.model_validate(unsafe)


def test_percentile_uses_nearest_rank() -> None:
    assert _percentile([10, 20, 30, 40], 0.95) == 40
    assert _percentile([], 0.95) == 0


def test_judge_excludes_na_and_cannot_override_hard_gate() -> None:
    dimensions = [
        JudgeDimensionV1(
            name=name,
            applicable=name is not JudgeDimensionName.PLAN_QUALITY,
            score=None if name is JudgeDimensionName.PLAN_QUALITY else 4,
            rationale="Bounded evidence.",
            evidence_ids=[] if name is JudgeDimensionName.PLAN_QUALITY else ["ev-01"],
        )
        for name in JudgeDimensionName
    ]
    assessment = JudgeAssessmentV1(dimensions=dimensions)
    result = JudgeResultV1(
        trial_id="hosted:EVAL-01:1",
        case_id="EVAL-01",
        status="COMPLETED",
        provider="judge",
        model="independent",
        prompt_version="judge-v1",
        assessment=assessment,
        overall_score=4,
        duration_ms=1,
        input_tokens=10,
        output_tokens=5,
    )
    judged = aggregate_judge_results(
        suite_id="suite", provider="judge", model="independent", prompt_version="judge-v1", results=[result]
    )

    assert judged.dimension_averages[JudgeDimensionName.PLAN_QUALITY] is None
    assert judged.overall_average == 4

    root = Path(__file__).parents[2]
    suite = load_evaluation_suite(root / "config/evaluation/suite-v2.json")
    failed_trial = EvaluationTrialV2(
        trial_id="hosted:EVAL-01:1",
        case_id="EVAL-01",
        mode="hosted",
        trial_number=1,
        generated_at=datetime.now(UTC),
        source_commit=suite.source_commit,
        expected_route=ExpectedRoute.AUTONOMOUS,
        actual_route=ExpectedRoute.FAIL_SAFE,
        final_status=FinalStatus.INTERNAL_ERROR,
        hard_gates=[EvaluationMetric(name="route", numerator=0, denominator=1, passed=False, detail="wrong")],
        passed=False,
        validation_attempt_count=0,
        inspection_call_count=1,
        unsupported_tool_calls=0,
        denied_tool_calls=0,
        commit_pinned_successes=0,
        patch_applied=False,
        cleanup_succeeded=True,
        remote_objects_created=0,
        model_call_count=1,
        model_latency_ms=10,
        model_input_tokens=20,
        model_output_tokens=5,
        judge_input=EvaluationJudgeInput(
            case_id="EVAL-01",
            trial_id="hosted:EVAL-01:1",
            diagnosis_summary="Bounded diagnosis.",
            acceptance_criteria=["Repair safely."],
            evidence_ids=["ev-01"],
            final_status=FinalStatus.INTERNAL_ERROR,
            changed_file_count=0,
        ),
    )
    hosted = aggregate_evaluation_suite(suite, "hosted", [failed_trial], [])
    report = render_suite_assessment_report(suite, None, hosted, judged)

    assert "Overall hard-gate result: **0/1**" in report
    assert "Overall applicable-dimension average: **4.00/5**" in report


def test_v2_report_marks_missing_hosted_and_judge_not_run() -> None:
    root = Path(__file__).parents[2]
    suite = load_evaluation_suite(root / "config/evaluation/suite-v2.json")
    report = render_suite_assessment_report(suite, None, None, None)

    assert report.count("**NOT RUN**") == 6
    assert "non-gating" in report.lower()
    assert "scripted model outputs and fake infrastructure" in report


def test_memory_benchmark_is_counterbalanced_and_aggregates_paired_denominators() -> None:
    root = Path(__file__).parents[2]
    suite = load_evaluation_suite(root / "config/evaluation/suite-v2.json")
    benchmark = load_memory_benchmark(root / "config/evaluation/memory-benchmark-v1.json")
    trials: list[MemoryEvaluationTrialV1] = []
    for memory_case in benchmark.cases:
        expected = next(item.expectation.route for item in suite.cases if item.case_id == memory_case.case_id)
        status = next(item.expectation.terminal_status for item in suite.cases if item.case_id == memory_case.case_id)
        for pair, order in enumerate(benchmark.counterbalanced_orders, start=1):
            assert set(order) == set(MemoryArm)
            for position, arm in enumerate(order, start=1):
                trial_id = f"deterministic:memory:{arm}:{memory_case.case_id}:{pair}"
                trial = EvaluationTrialV2(
                    trial_id=trial_id,
                    case_id=memory_case.case_id,
                    mode="deterministic",
                    trial_number=pair,
                    generated_at=datetime.now(UTC),
                    source_commit=suite.source_commit,
                    expected_route=expected,
                    actual_route=expected,
                    final_status=status,
                    hard_gates=[EvaluationMetric(name="route", numerator=1, denominator=1, passed=True, detail="ok")],
                    passed=True,
                    validation_attempt_count=0,
                    inspection_call_count=3 if arm is MemoryArm.ON else 4,
                    unsupported_tool_calls=0,
                    denied_tool_calls=0,
                    commit_pinned_successes=1,
                    patch_applied=expected is ExpectedRoute.AUTONOMOUS,
                    cleanup_succeeded=True,
                    remote_objects_created=0,
                    model_call_count=1,
                    model_latency_ms=10,
                    model_input_tokens=20,
                    model_output_tokens=5,
                    judge_input=EvaluationJudgeInput(
                        case_id=memory_case.case_id,
                        trial_id=trial_id,
                        diagnosis_summary="Bounded diagnosis.",
                        acceptance_criteria=["Remain safe."],
                        evidence_ids=["ev-01"],
                        final_status=status,
                        changed_file_count=0,
                    ),
                )
                hit = arm is MemoryArm.ON and memory_case.seed is not None
                trials.append(
                    MemoryEvaluationTrialV1(
                        arm=arm,
                        pair_number=pair,
                        execution_order=position,
                        memory_status=(
                            MemoryRetrievalStatus.RETRIEVED
                            if hit
                            else MemoryRetrievalStatus.NO_MATCH
                            if arm is MemoryArm.ON
                            else MemoryRetrievalStatus.DISABLED
                        ),
                        memory_retrieval_latency_ms=1 if arm is MemoryArm.ON else 0,
                        accepted_match_count=int(hit),
                        memory_write_status="NOT_ELIGIBLE",
                        trial=trial,
                    )
                )

    result = aggregate_memory_evaluation(benchmark, suite, "deterministic", trials, [])

    assert len(result.trials) == 18
    assert result.arms[MemoryArm.OFF].retrieval_hit_rate.denominator == 9
    assert result.arms[MemoryArm.ON].retrieval_hit_rate.numerator == 6
    assert result.deltas["average_inspection_calls"] == -1
