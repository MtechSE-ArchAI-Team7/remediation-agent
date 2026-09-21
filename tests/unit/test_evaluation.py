from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from remediation_agent.evaluation import (
    EvaluationManifest,
    load_evaluation_manifest,
    render_assessment_report,
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
