"""Versioned contract and strict configuration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from remediation_agent.api.a2a_contracts import ProviderProbeRequestV1, ProviderProbeResultV1
from remediation_agent.config import Settings
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    ApprovalRequest,
    DiagnosisHandoffV1,
    DownstreamDeliveryReceiptV1,
    ExplainabilityTraceV1,
    RemediationHandoffV1,
)
from remediation_agent.evaluation import (
    EvaluationJudgeSuiteV1,
    EvaluationSuiteManifestV2,
    EvaluationSuiteResultV2,
    MemoryBenchmarkManifestV1,
    MemoryEvaluationResultV1,
)
from remediation_agent.policy.loader import PolicyLoadError, load_policy
from remediation_agent.policy.models import PolicyConfig
from tests.conftest import diagnosis_handoff

_OPENAI_CREDENTIAL_REFERENCE = "arn:aws:secretsmanager:ap-southeast-1:734849394833:secret:openai"
_GATEWAY_ARN = "arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:gateway/llm-gateway-with-inbound-auth-u8utldecju"


def test_diagnosis_handoff_is_strict_and_versioned() -> None:
    payload = diagnosis_handoff().model_dump(mode="json")
    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="unexpected"):
        DiagnosisHandoffV1.model_validate(payload)


def test_diagnosis_handoff_requires_and_normalizes_jira_ticket_id() -> None:
    payload = diagnosis_handoff().model_dump(mode="json")
    payload["jira_ticket_id"] = "ticket-111"
    assert DiagnosisHandoffV1.model_validate(payload).jira_ticket_id == "TICKET-111"

    del payload["jira_ticket_id"]
    with pytest.raises(ValidationError, match="jira_ticket_id"):
        DiagnosisHandoffV1.model_validate(payload)


@pytest.mark.parametrize("jira_ticket_id", ["TICKET", "-111", "TICKET-0", "TICKET-01", "TICKET 111"])
def test_diagnosis_handoff_rejects_invalid_jira_ticket_id(jira_ticket_id: str) -> None:
    payload = diagnosis_handoff().model_dump(mode="json")
    payload["jira_ticket_id"] = jira_ticket_id
    with pytest.raises(ValidationError, match="jira_ticket_id"):
        DiagnosisHandoffV1.model_validate(payload)


def test_ecommerce_demo_handoff_is_pinned_to_the_deployed_commit() -> None:
    path = Path(__file__).parents[2] / "demo-ui" / "src" / "scenarios" / "division-by-zero.json"

    handoff = DiagnosisHandoffV1.model_validate_json(path.read_text(encoding="utf-8"))

    assert handoff.case_id == "CASE-ECOM-AVG-001"
    assert handoff.jira_ticket_id == "TICKET-111"
    assert handoff.repository.url == "https://github.com/MtechSE-ArchAI-Team7/buggy-ecommerce-demo.git"
    assert handoff.repository.base_branch == "main"
    assert handoff.repository.commit_sha == "ae4d89601a5b858994ec88695d8c624ebc510750"
    assert handoff.supporting_evidence[0].source_locator == (
        "http://aios-ecommerce.ap-southeast-1.elasticbeanstalk.com/calculate-average/10/0"
    )
    assert "tests/calculate-average.test.js" in handoff.acceptance_criteria[3]


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
        "approval-decision-v1.schema.json": ApprovalDecisionV1.model_json_schema(),
        "approval-request-v1.schema.json": ApprovalRequest.model_json_schema(),
        "delivery-receipt-v1.schema.json": DownstreamDeliveryReceiptV1.model_json_schema(),
        "explainability-trace-v1.schema.json": ExplainabilityTraceV1.model_json_schema(),
        "provider-probe-request-v1.schema.json": ProviderProbeRequestV1.model_json_schema(),
        "provider-probe-result-v1.schema.json": ProviderProbeResultV1.model_json_schema(),
        "remediation-handoff-v1.schema.json": RemediationHandoffV1.model_json_schema(),
        "remediation-policy.schema.json": PolicyConfig.model_json_schema(),
        "evaluation-suite-v2.schema.json": EvaluationSuiteManifestV2.model_json_schema(),
        "evaluation-result-v2.schema.json": EvaluationSuiteResultV2.model_json_schema(),
        "evaluation-judge-v1.schema.json": EvaluationJudgeSuiteV1.model_json_schema(),
        "memory-benchmark-v1.schema.json": MemoryBenchmarkManifestV1.model_json_schema(),
        "memory-evaluation-result-v1.schema.json": MemoryEvaluationResultV1.model_json_schema(),
    }
    for name, schema in expected.items():
        assert json.loads((schema_root / name).read_text()) == schema


def test_settings_require_model_for_live_provider(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="AIOS_LLM_MODEL"):
        Settings(policy_file=tmp_path / "policy.json", llm_provider="openai", _env_file=None)  # type: ignore[call-arg]


def test_settings_treat_blank_optional_values_as_unset(tmp_path: Path) -> None:
    settings = Settings.model_validate(
        {
            "policy_file": tmp_path / "policy.json",
            "llm_provider": "fake",
            "llm_model": "",
            "aws_region": "",
            "github_repository": "",
            "github_token": "",
            "github_writes_enabled": False,
            "OPENAI_API_KEY": "",
            "DEEPSEEK_API_KEY": "",
            "postgres_dsn": "",
            "checkpoint_encryption_key": "",
        }
    )
    assert settings.llm_model is None
    assert settings.github_repository is None
    assert settings.openai_api_key is None
    assert settings.postgres_dsn is None


def test_incident_memory_enablement_requires_complete_dedicated_configuration(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="Incident-memory configuration is incomplete"):
        Settings(
            policy_file=tmp_path / "policy.json",
            llm_provider="fake",
            incident_memory_enabled=True,
            _env_file=None,
        )  # type: ignore[call-arg]

    settings = Settings(
        policy_file=tmp_path / "policy.json",
        llm_provider="fake",
        aws_region="ap-southeast-1",
        incident_memory_enabled=True,
        incident_memory_id="incident-memory-1",
        incident_memory_strategy_id="strategy-1",
        incident_memory_namespace="/aios/incidents/",
        _env_file=None,
    )  # type: ignore[call-arg]
    assert settings.require_incident_memory_configuration() == (
        "incident-memory-1",
        "strategy-1",
        "/aios/incidents/",
        "ap-southeast-1",
    )


def test_incident_memory_writes_require_retrieval_enablement(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="WRITES_ENABLED requires"):
        Settings(
            policy_file=tmp_path / "policy.json",
            llm_provider="fake",
            incident_memory_writes_enabled=True,
            _env_file=None,
        )  # type: ignore[call-arg]


def test_openai_settings_accept_either_local_key_or_hosted_secret_arn(tmp_path: Path) -> None:
    hosted = Settings(
        policy_file=tmp_path / "policy.json",
        llm_provider="openai",
        llm_model="gpt-5.6-terra",
        openai_secret_arn=_OPENAI_CREDENTIAL_REFERENCE,
        _env_file=None,
    )  # type: ignore[call-arg]
    local = Settings.model_validate(
        {
            "policy_file": tmp_path / "policy.json",
            "llm_provider": "openai",
            "llm_model": "gpt-5.6-terra",
            "OPENAI_API_KEY": "sk-local",
        }
    )

    assert hosted.openai_api_key is None
    assert hosted.openai_secret_arn is not None
    assert local.openai_api_key is not None


def test_openai_settings_reject_missing_local_key_and_hosted_secret(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="OPENAI_API_KEY or AIOS_OPENAI_SECRET_ARN"):
        Settings(
            policy_file=tmp_path / "policy.json",
            llm_provider="openai",
            llm_model="gpt-5.6-terra",
            _env_file=None,
        )  # type: ignore[call-arg]


def test_openai_gateway_settings_derive_the_only_permitted_base_url(tmp_path: Path) -> None:
    settings = Settings(
        policy_file=tmp_path / "policy.json",
        llm_provider="openai",
        llm_model="kei-openai-target/gpt-5.6-terra",
        aws_region="ap-southeast-1",
        openai_auth_mode="aws_iam_gateway",
        openai_gateway_arn=_GATEWAY_ARN,
        _env_file=None,
    )  # type: ignore[call-arg]

    assert settings.openai_gateway_base_url() == (
        "https://llm-gateway-with-inbound-auth-u8utldecju.gateway.bedrock-agentcore."
        "ap-southeast-1.amazonaws.com/inference/v1"
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"openai_gateway_arn": None}, "AIOS_OPENAI_GATEWAY_ARN is required"),
        ({"OPENAI_API_KEY": "sk-conflict"}, "API keys.*forbidden"),
        ({"openai_secret_arn": _OPENAI_CREDENTIAL_REFERENCE}, "API keys.*forbidden"),
        ({"openai_base_url": "https://example.test/v1"}, "AIOS_OPENAI_BASE_URL is forbidden"),
        ({"openai_gateway_arn": "not-an-arn"}, "valid AWS AgentCore gateway ARN"),
        (
            {
                "openai_gateway_arn": (
                    "arn:aws:bedrock-agentcore:us-east-1:734849394833:gateway/llm-gateway-with-inbound-auth-u8utldecju"
                )
            },
            "Region must match",
        ),
    ],
)
def test_openai_gateway_settings_fail_closed(tmp_path: Path, overrides: dict[str, object], message: str) -> None:
    values: dict[str, object] = {
        "policy_file": tmp_path / "policy.json",
        "llm_provider": "openai",
        "llm_model": "kei-openai-target/gpt-5.6-terra",
        "aws_region": "ap-southeast-1",
        "openai_auth_mode": "aws_iam_gateway",
        "openai_gateway_arn": _GATEWAY_ARN,
        "OPENAI_API_KEY": None,
        "openai_secret_arn": None,
        "openai_base_url": None,
    }
    values.update(overrides)
    with pytest.raises(ValidationError, match=message):
        Settings.model_validate(values)


@pytest.mark.parametrize("missing", ["github_token", "github_repository"])
def test_settings_require_complete_github_write_configuration(tmp_path: Path, missing: str) -> None:
    values: dict[str, object] = {
        "policy_file": tmp_path / "policy.json",
        "llm_provider": "fake",
        "github_writes_enabled": True,
        "github_token": "github_pat_" + "a" * 32,
        "github_repository": "example/demo",
    }
    values[missing] = None
    with pytest.raises(ValidationError, match="required when GitHub writes are enabled"):
        Settings.model_validate(values)


def test_agent4_delivery_is_disabled_by_default_and_fails_closed_when_incomplete(tmp_path: Path) -> None:
    settings = Settings(policy_file=tmp_path / "policy.json", llm_provider="fake", _env_file=None)  # type: ignore[call-arg]
    assert settings.agent4_delivery_enabled is False

    with pytest.raises(ValidationError, match="AIOS_AGENT4_RUNTIME_ARN and AIOS_AGENT4_REGION"):
        Settings(
            policy_file=tmp_path / "policy.json",
            llm_provider="fake",
            agent4_delivery_enabled=True,
            agent4_runtime_arn="arn:runtime",
            _env_file=None,
        )  # type: ignore[call-arg]


def test_production_runtime_requires_github_token_for_hosted_mcp(tmp_path: Path) -> None:
    settings = Settings(policy_file=tmp_path / "policy.json", llm_provider="fake", _env_file=None)  # type: ignore[call-arg]

    with pytest.raises(ValueError, match="hosted GitHub MCP inspection"):
        settings.require_github_token()

    configured = Settings.model_validate(
        {
            "policy_file": tmp_path / "policy.json",
            "llm_provider": "fake",
            "github_token": "github_pat_" + "a" * 32,
        }
    )
    assert configured.require_github_token() == "github_pat_" + "a" * 32


def test_policy_unknown_fields_fail_closed(tmp_path: Path) -> None:
    policy_path = Path(__file__).parents[2] / "config" / "policies" / "reference.json"
    altered = policy_path.read_text().replace('"policy_id":', '"unknown": true, "policy_id":')
    target = tmp_path / "bad.json"
    target.write_text(altered)
    with pytest.raises(PolicyLoadError, match="invalid policy"):
        load_policy(target)


def test_policy_loader_rejects_symlink(tmp_path: Path) -> None:
    policy_path = Path(__file__).parents[2] / "config" / "policies" / "reference.json"
    linked = tmp_path / "linked-policy.json"
    linked.symlink_to(policy_path)
    with pytest.raises(PolicyLoadError, match="non-symlink"):
        load_policy(linked)
