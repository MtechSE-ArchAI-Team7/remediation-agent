"""Structured model adapter contract tests without live provider calls."""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import BaseTool
from pydantic import BaseModel

from remediation_agent.adapters.models import ProviderStructuredModel, build_structured_model
from remediation_agent.config import Settings
from remediation_agent.domain.enums import ModelOperation
from remediation_agent.domain.models import InspectionPlan
from remediation_agent.ports.models import ModelRequest
from remediation_agent.tools import finish_inspection


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

    def bind_tools(self, tools: Sequence[BaseTool]) -> _Runnable:
        _ = tools
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


async def test_tool_turn_binds_tools_and_normalizes_call_metadata() -> None:
    response = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "finish_inspection",
                "args": {"rationale": "Enough evidence."},
                "id": "call-1",
                "type": "tool_call",
            }
        ],
        usage_metadata={"input_tokens": 11, "output_tokens": 7, "total_tokens": 18},
    )
    model = ProviderStructuredModel(
        _ChatModel([response]),
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=0,
    )
    request = ModelRequest(
        operation=ModelOperation.INSPECTION,
        prompt_version="test-v1",
        system_instruction="Inspect with tools.",
        payload={"handoff": "untrusted"},
    )

    message, record = await model.generate_tool_turn(request, [HumanMessage(content="inspect")], [finish_inspection])

    assert message.tool_calls[0]["name"] == "finish_inspection"
    assert record.input_tokens == 11
    assert record.output_tokens == 7
    assert not record.refused
    assert record.input_digest.startswith("sha256:")
    assert record.output_digest.startswith("sha256:")


async def test_tool_turn_records_provider_refusal_metadata() -> None:
    response = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "finish_inspection",
                "args": {"rationale": "Provider supplied a bounded call."},
                "id": "call-refusal-metadata",
                "type": "tool_call",
            }
        ],
        response_metadata={"stop_reason": "refusal"},
    )
    model = ProviderStructuredModel(
        _ChatModel([response]),
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=0,
    )
    request = ModelRequest(
        operation=ModelOperation.INSPECTION,
        prompt_version="test-v1",
        system_instruction="Inspect with tools.",
        payload={},
    )

    _, record = await model.generate_tool_turn(request, [HumanMessage(content="inspect")], [finish_inspection])

    assert record.refused


@pytest.mark.parametrize(
    "response",
    [
        AIMessage(content="No tool call."),
        AIMessage(
            content="",
            tool_calls=[
                {"name": "finish_inspection", "args": {"rationale": "one"}, "id": "one", "type": "tool_call"},
                {"name": "finish_inspection", "args": {"rationale": "two"}, "id": "two", "type": "tool_call"},
            ],
        ),
        AIMessage(
            content="",
            invalid_tool_calls=[
                {
                    "name": "finish_inspection",
                    "args": "not-json",
                    "id": "bad",
                    "error": "malformed",
                    "type": "invalid_tool_call",
                }
            ],
        ),
    ],
)
async def test_tool_turn_rejects_missing_multiple_and_malformed_calls(response: AIMessage) -> None:
    model = ProviderStructuredModel(
        _ChatModel([response]),
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=0,
    )
    request = ModelRequest(
        operation=ModelOperation.INSPECTION,
        prompt_version="test-v1",
        system_instruction="Inspect with tools.",
        payload={},
    )

    with pytest.raises(RuntimeError, match="bounded retries"):
        await model.generate_tool_turn(request, [HumanMessage(content="inspect")], [finish_inspection])


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
