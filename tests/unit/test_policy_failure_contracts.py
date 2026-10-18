"""Operator safety settings reject missing, contradictory and excessive authority."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from remediation_agent.config import Settings
from remediation_agent.policy.loader import load_policy
from remediation_agent.policy.models import PolicyConfig, ValidationTaskConfig


@pytest.mark.parametrize(
    "update",
    [
        {"regression_test_ids": ["unmapped"]},
        {"source_syntax": "javascript"},
        {"kind": "BEHAVIORAL"},
        {"profile": "pytest"},
        {"kind": "BEHAVIORAL", "profile": "pytest"},
        {"argv": ["python", "nul\x00arg"]},
        {"argv": ["x" * 4097]},
        {"cwd": "../outside"},
        {"environment": {"bad-key": "value"}},
        {"environment": {"TOKEN": "fixture"}},
        {"environment": {"SAFE": "bad\x00value"}},
        {"environment": {"SAFE": "x" * 4097}},
        {"kind": "BEHAVIORAL", "profile": "pytest", "test_paths": ["src"]},
        {"kind": "BEHAVIORAL", "profile": "pytest", "test_paths": ["tests/../escape"]},
    ],
)
def test_invalid_validation_task_cannot_be_loaded(update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ValidationTaskConfig.model_validate(
            {"argv": ["python", "check.py"], "timeout_seconds": 10, "output_limit_bytes": 1024, **update}
        )


@pytest.mark.parametrize("fault", ["files", "diff", "unknown", "count", "timeout", "output"])
def test_policy_cross_field_limits_fail_closed(fault: str) -> None:
    base = load_policy(Path(__file__).parents[2] / "config/policies/reference.json").model_dump(mode="json")
    if fault == "files":
        base["limits"]["absolute_max_changed_files"] = 1
    elif fault == "diff":
        base["limits"]["absolute_max_diff_lines"] = 1
    elif fault == "unknown":
        base["default_validation_tasks"] = ["missing"]
    elif fault == "count":
        base["limits"]["max_validation_tasks_per_attempt"] = 1
    elif fault == "timeout":
        base["limits"]["max_task_timeout_seconds"] = 1
    else:
        base["limits"]["max_task_output_bytes"] = 1
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate(base)


@pytest.mark.parametrize(
    "update",
    [
        {"llm_provider": "bedrock", "llm_model": "fixture", "aws_region": None},
        {"github_repository": "bad/repository/path"},
        {"llm_provider": "deepseek", "llm_model": "fixture", "deepseek_api_key": None},
        {"llm_provider": "openai", "llm_model": "fixture", "openai_auth_mode": "aws_iam_gateway", "aws_region": None},
        {
            "llm_provider": "openai",
            "llm_model": "fixture",
            "openai_auth_mode": "api_key",
            "openai_api_key": "fixture",
            "openai_gateway_arn": "invalid",
        },
        {
            "llm_provider": "openai",
            "llm_model": "fixture",
            "openai_auth_mode": "aws_iam_gateway",
            "aws_region": "ap-southeast-1",
            "openai_gateway_arn": "invalid",
            "openai_base_url": "https://example.invalid",
        },
        {"openai_gateway_arn": "invalid"},
    ],
)
def test_missing_or_conflicting_provider_authority_is_rejected(
    update: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    for key in ["OPENAI_API_KEY", "DEEPSEEK_API_KEY", "AIOS_AWS_REGION"]:
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {"policy_file": Path("config/policies/reference.json"), "llm_provider": "fake", **update}
        )


def test_configuration_accessors_require_explicit_resources() -> None:
    settings = Settings.model_construct(policy_file=Path("config/policies/reference.json"), llm_provider="fake")
    for method in (
        settings.openai_gateway_base_url,
        settings.inspection_gateway_endpoint,
        settings.require_persistent_checkpointing,
        settings.require_agentcore_configuration,
        settings.require_agentcore_release_configuration,
    ):
        with pytest.raises(ValueError):
            method()
    configured = settings.model_copy(
        update={"agentcore_memory_id": "id", "runtime_secret_arn": "arn", "artifact_bucket": "bucket"}
    )
    assert configured.require_agentcore_configuration() == ("id", "arn", "bucket")
    from pydantic import SecretStr

    missing_key = settings.model_copy(update={"postgres_dsn": SecretStr("fixture")})
    with pytest.raises(ValueError, match="ENCRYPTION_KEY"):
        missing_key.require_persistent_checkpointing()
