"""Versioned contract and strict configuration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from remediation_agent.config import Settings
from remediation_agent.domain.models import DiagnosisHandoffV1, RemediationHandoffV1
from remediation_agent.policy.loader import PolicyLoadError, load_policy
from remediation_agent.policy.models import PolicyConfig
from tests.conftest import diagnosis_handoff


def test_diagnosis_handoff_is_strict_and_versioned() -> None:
    payload = diagnosis_handoff().model_dump(mode="json")
    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="unexpected"):
        DiagnosisHandoffV1.model_validate(payload)


def test_diagnosis_rejects_unknown_evidence_reference() -> None:
    payload = diagnosis_handoff().model_dump(mode="json")
    payload["diagnosis"]["evidence_ids"] = ["missing"]
    with pytest.raises(ValidationError, match="missing evidence IDs"):
        DiagnosisHandoffV1.model_validate(payload)


def test_handoff_json_schemas_expose_fixed_version() -> None:
    diagnosis_schema = DiagnosisHandoffV1.model_json_schema()
    remediation_schema = RemediationHandoffV1.model_json_schema()
    assert diagnosis_schema["properties"]["schema_version"]["const"] == "1.0"
    assert remediation_schema["properties"]["schema_version"]["const"] == "1.0"


def test_committed_json_schemas_match_models() -> None:
    schema_root = Path(__file__).parents[2] / "config" / "schemas"
    expected = {
        "diagnosis-handoff-v1.schema.json": DiagnosisHandoffV1.model_json_schema(),
        "remediation-handoff-v1.schema.json": RemediationHandoffV1.model_json_schema(),
        "remediation-policy.schema.json": PolicyConfig.model_json_schema(),
    }
    for name, schema in expected.items():
        assert json.loads((schema_root / name).read_text()) == schema


def test_settings_require_model_for_live_provider(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="AIOS_LLM_MODEL"):
        Settings(policy_file=tmp_path / "policy.json", llm_provider="openai")


def test_policy_unknown_fields_fail_closed(tmp_path: Path) -> None:
    policy_path = Path(__file__).parents[2] / "config" / "policies" / "demo.json"
    altered = policy_path.read_text().replace('"policy_id":', '"unknown": true, "policy_id":')
    target = tmp_path / "bad.json"
    target.write_text(altered)
    with pytest.raises(PolicyLoadError, match="invalid policy"):
        load_policy(target)


def test_policy_loader_rejects_symlink(tmp_path: Path) -> None:
    policy_path = Path(__file__).parents[2] / "config" / "policies" / "demo.json"
    linked = tmp_path / "linked-policy.json"
    linked.symlink_to(policy_path)
    with pytest.raises(PolicyLoadError, match="non-symlink"):
        load_policy(linked)
