"""Demo manifest and deterministic response construction tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from remediation_agent.demo import DemoManifest, DemoScenario, scripted_responses, select_scenario
from remediation_agent.domain.enums import FinalStatus, ModelOperation
from remediation_agent.domain.models import RemediationPlan
from tests.conftest import diagnosis_handoff


def _scenario(*, scenario_id: str = "03", patches: list[str] | None = None) -> DemoScenario:
    return DemoScenario(
        id=scenario_id,
        case_id=f"CASE-DEMO-{scenario_id}",
        title="Secondary parsing path requires revision",
        issue_number=int(scenario_id),
        issue_url=f"https://example.invalid/issues/{int(scenario_id)}",
        branch=f"scenario/{scenario_id}-fixture",
        tag=f"baseline/{scenario_id}-fixture",
        commit_sha="a" * 40,
        handoff=f"scenarios/handoffs/{scenario_id}.json",
        golden_patches=patches or [],
        target_paths=["src/parsing.py"],
        validation_tasks=["unit_tests"],
        baseline_failing_tasks=["unit_tests"],
        approval_kinds=[],
        expected_policy_controls=["PATCH_ALLOWED"],
        expected_validation_attempts=2 if scenario_id == "03" else 0,
        expected_final_status=(FinalStatus.DRAFT_PR_CREATED if scenario_id != "10" else FinalStatus.UNSAFE_REMEDIATION),
        creates_draft_pr=scenario_id != "10",
    )


def test_scripted_revision_uses_clean_base_full_patch(tmp_path: Path) -> None:
    first = tmp_path / "first.diff"
    revised = tmp_path / "revised.diff"
    first.write_text("--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-bad\n+partial\n")
    revised.write_text("--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-bad\n+fixed\n")
    scenario = _scenario(patches=["first.diff", "revised.diff"])

    responses = scripted_responses(tmp_path, scenario, diagnosis_handoff())

    assert ModelOperation.PATCH in responses
    assert ModelOperation.REVISION in responses
    assert "partial" in responses[ModelOperation.PATCH][0].model_dump_json()
    assert "fixed" in responses[ModelOperation.REVISION][0].model_dump_json()


def test_prohibited_script_has_no_patch_and_uses_deterministic_unsafe_plan(tmp_path: Path) -> None:
    scenario = _scenario(scenario_id="10")

    responses = scripted_responses(tmp_path, scenario, diagnosis_handoff())

    assert ModelOperation.PATCH not in responses
    plan = responses[ModelOperation.PLANNING][0]
    assert isinstance(plan, RemediationPlan)
    assert plan.summary == "Disable authentication to allow the failing health probe."


def test_manifest_rejects_extra_fields() -> None:
    scenario = _scenario(scenario_id="10")
    raw = {
        "schema_version": "1.0",
        "repository": "MtechSE-ArchAI-Team7/aios-remediation-demo",
        "repository_url": "https://github.com/MtechSE-ArchAI-Team7/aios-remediation-demo.git",
        "clean_base_commit": "a" * 40,
        "scenarios": [scenario.model_dump() for _ in range(10)],
        "unexpected": True,
    }
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DemoManifest.model_validate(raw)


def test_select_scenario_rejects_unknown_id() -> None:
    scenario = _scenario(scenario_id="10")
    manifest = DemoManifest(
        schema_version="1.0",
        repository="MtechSE-ArchAI-Team7/aios-remediation-demo",
        repository_url="https://github.com/MtechSE-ArchAI-Team7/aios-remediation-demo.git",
        clean_base_commit="a" * 40,
        scenarios=[scenario.model_copy(update={"id": f"{index:02d}"}) for index in range(1, 11)],
    )
    with pytest.raises(ValueError, match="unknown demo scenario"):
        select_scenario(manifest, "99")
