"""Structured model adapter contract tests without live provider calls."""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel

from remediation_agent.adapters.models import ProviderStructuredModel, build_structured_model
from remediation_agent.config import Settings
from remediation_agent.domain.enums import ModelOperation
from remediation_agent.domain.models import InspectionPlan
from remediation_agent.ports.models import ModelRequest


class _Runnable:
    def __init__(self, responses: deque[object]) -> None:
        self.responses = responses

    async def ainvoke(self, input: object) -> object:
        _ = input
        value = self.responses.popleft()
        if isinstance(value, Exception):
            raise value
        return value


class _ChatModel:
    def __init__(self, responses: list[object]) -> None:
        self.responses = deque(responses)

    def with_structured_output(self, schema: type[BaseModel], *, include_raw: bool) -> _Runnable:
        _ = schema
        assert include_raw
        return _Runnable(self.responses)


async def test_schema_failure_receives_one_bounded_retry() -> None:
    model = ProviderStructuredModel(
        _ChatModel(
            [
                {"paths_to_read": [], "search_queries": []},
                {"paths_to_read": ["src/app.py"], "search_queries": [], "rationale": "Bounded read."},
            ]
        ),
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=1,
    )
    generation = await model.generate(
        ModelRequest(
            operation=ModelOperation.INSPECTION,
            prompt_version="test-v1",
            system_instruction="Return a typed inspection request.",
            payload={"repository_text": "untrusted"},
        ),
        InspectionPlan,
    )
    assert generation.value.paths_to_read == ["src/app.py"]
    assert generation.record.provider == "fake-chat"
    assert generation.record.input_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("provider", "key_name"),
    [("openai", "OPENAI_API_KEY"), ("deepseek", "DEEPSEEK_API_KEY")],
)
def test_local_provider_adapters_construct_without_network(
    monkeypatch: pytest.MonkeyPatch,
    provider: Literal["openai", "deepseek"],
    key_name: str,
) -> None:
    monkeypatch.setenv(key_name, "local-test-key")
    settings = Settings(
        policy_file=Path("config/policies/reference.json"),
        llm_provider=provider,
        llm_model="fixture-model",
    )
    adapter = build_structured_model(settings, max_output_tokens=128, max_format_retries=1)
    assert adapter.provider == provider
    assert adapter.model == "fixture-model"


def test_openai_key_is_loaded_from_dotenv_alias(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "AIOS_POLICY_FILE=config/policies/reference.json\n"
        "AIOS_LLM_PROVIDER=openai\n"
        "AIOS_LLM_MODEL=fixture-model\n"
        "OPENAI_API_KEY=dotenv-test-key\n"
    )
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(_env_file=env_file)  # type: ignore[call-arg]
    assert settings.openai_api_key is not None
    assert settings.openai_api_key.get_secret_value() == "dotenv-test-key"


def test_bedrock_converse_adapter_uses_current_constructor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import langchain_aws

    captured: dict[str, object] = {}

    class FakeBedrock:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def with_structured_output(self, schema: type[BaseModel], *, include_raw: bool) -> _Runnable:
            _ = schema, include_raw
            return _Runnable(deque())

    monkeypatch.setattr(langchain_aws, "ChatBedrockConverse", FakeBedrock)
    settings = Settings(
        policy_file=Path("config/policies/reference.json"),
        llm_provider="bedrock",
        llm_model="fixture-inference-profile",
        aws_region="ap-southeast-1",
    )
    adapter = build_structured_model(settings, max_output_tokens=256, max_format_retries=2)
    assert adapter.provider == "bedrock"
    assert captured["model"] == "fixture-inference-profile"
    assert captured["region_name"] == "ap-southeast-1"
