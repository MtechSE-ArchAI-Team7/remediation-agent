from __future__ import annotations

from pathlib import Path

from remediation_agent.evaluation import (
    ExpectedRoute,
    load_evaluation_suite,
    load_evaluation_suite_result,
)
from scripts.run_evaluation import _run_deterministic_case, run_deterministic


async def test_ten_case_evaluation_exercises_routes_and_controls(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    output = tmp_path / "suite-v2.json"

    passed = await run_deterministic(root / "config/evaluation/suite-v2.json", output)
    result = load_evaluation_suite_result(output)
    trials = {trial.case_id: trial for trial in result.trials}

    assert passed is True
    assert result.case_count == 10
    assert result.trial_count == result.passed_trials == 10
    assert all(trial.remote_objects_created == 0 for trial in result.trials)
    assert trials["EVAL-04"].validation_attempt_count == 2
    assert trials["EVAL-04"].first_attempt_passed is False
    assert trials["EVAL-07"].denied_tool_calls == 1
    assert trials["EVAL-09"].unsupported_tool_calls == 1
    assert trials["EVAL-09"].actual_route is ExpectedRoute.FAIL_SAFE
    assert trials["EVAL-08"].patch_applied is False
    assert trials["EVAL-08"].validation_executions == []
    assert {trial.case_id for trial in result.trials if trial.actual_route is ExpectedRoute.FAIL_SAFE} == {
        "EVAL-02",
        "EVAL-05",
        "EVAL-10",
        "EVAL-09",
    }
    assert all(record["backend"] == "FAKE" for trial in result.trials for record in trial.validation_executions)


async def test_live_agentcore_policy_covers_every_agent2_benchmark_route() -> None:
    root = Path(__file__).parents[2]
    suite = load_evaluation_suite(root / "config/evaluation/suite-v2.json")
    live_cases = [
        case.model_copy(update={"policy_path": "config/policies/agentcore-demo.json"}) for case in suite.cases
    ]
    live_suite = suite.model_copy(update={"cases": live_cases})

    trials = [await _run_deterministic_case(live_suite, case) for case in live_cases]

    assert all(trial.passed for trial in trials), {
        trial.case_id: [gate.name for gate in trial.hard_gates if not gate.passed]
        for trial in trials
        if not trial.passed
    }
