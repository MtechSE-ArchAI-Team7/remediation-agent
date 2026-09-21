from __future__ import annotations

from pathlib import Path

from remediation_agent.evaluation import aggregate_evaluations, load_evaluation
from scripts.run_evaluation import run_deterministic


async def test_division_by_zero_evaluation_is_bounded_and_repeatable(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    output = tmp_path / "evaluation.json"

    passed = await run_deterministic(root / "config/evaluation/division-by-zero.json", output)
    result = load_evaluation(output)

    assert passed is True
    assert result.passed_trials == 1
    assert result.trial_count == 1
    assert result.final_status == "DRAFT_PR_PREPARED"
    assert set(result.inspection_tools_called) == {
        "get_repository_tree",
        "get_file_contents",
        "search_code",
        "finish_inspection",
    }
    assert result.commit_pinned_successes >= 1
    assert {record["task_name"] for record in result.validation_executions} == {
        "javascript_syntax",
        "average_regression",
    }
    assert all(record["backend"] == "FAKE" for record in result.validation_executions)
    assert result.cleanup_succeeded is True
    assert result.remote_objects_created == 0

    aggregate = aggregate_evaluations([result, result])
    assert aggregate.trial_count == 2
    assert aggregate.passed_trials == 2
    assert all(metric.ratio == "2/2" for metric in aggregate.metrics)
