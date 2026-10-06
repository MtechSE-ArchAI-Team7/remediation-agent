"""Structured model adapter contract tests without live provider calls."""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

import httpx
import pytest
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import BaseTool
from pydantic import BaseModel, SecretStr

from remediation_agent.adapters.models import ProviderStructuredModel, build_structured_model
from remediation_agent.api.a2a_contracts import ProviderProbeModelResult
from remediation_agent.config import Settings
from remediation_agent.domain.enums import ModelOperation, PolicyDecision, RiskLevel
from remediation_agent.domain.models import InspectionPlan, PatchCandidate, RemediationPlan, RiskAssessment
from remediation_agent.ports.models import ModelRequest, StructuredModelFailure
from remediation_agent.tools import finish_inspection

_OPENAI_CREDENTIAL_REFERENCE = "arn:aws:secretsmanager:ap-southeast-1:734849394833:secret:openai"
_GATEWAY_ARN = "arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:gateway/llm-gateway-with-inbound-auth-u8utldecju"


class _Runnable:
    def __init__(self, responses: deque[object], inputs: list[object] | None = None) -> None:
        self.responses = responses
        self.inputs = inputs if inputs is not None else []

    async def ainvoke(self, input: object) -> object:
        self.inputs.append(list(input) if isinstance(input, list) else input)
        _ = input
        value = self.responses.popleft()
        if isinstance(value, Exception):
            raise value
        return value


class _ChatModel:
    def __init__(self, responses: list[object]) -> None:
        self.responses = deque(responses)
        self.inputs: list[object] = []
        self.methods: list[str | None] = []

    def with_structured_output(
        self, schema: type[BaseModel], *, include_raw: bool, method: str | None = None
    ) -> _Runnable:
        _ = schema
        self.methods.append(method)
        assert include_raw
        return _Runnable(self.responses, self.inputs)

    def bind_tools(self, tools: Sequence[BaseTool]) -> _Runnable:
        _ = tools
        return _Runnable(self.responses, self.inputs)


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
    ("operation", "output_schema", "response"),
    [
        (
            ModelOperation.PLANNING,
            RemediationPlan,
            {
                "summary": "Bounded plan.",
                "steps": ["Patch the diagnosed behavior."],
                "target_paths": ["src/app.py"],
                "proposed_validation_tasks": ["unit_tests"],
                "rollback_strategy": "Revert the patch.",
                "evidence_ids": ["evidence-1"],
            },
        ),
        (
            ModelOperation.RISK,
            RiskAssessment,
            {
                "level": RiskLevel.LOW,
                "decision": PolicyDecision.ALLOW,
                "rationale": "Bounded change.",
            },
        ),
        (
            ModelOperation.PATCH,
            PatchCandidate,
            {
                "unified_diff": "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n",
                "rationale": "Bounded patch.",
            },
        ),
        (
            ModelOperation.REVISION,
            PatchCandidate,
            {
                "unified_diff": "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+revised\n",
                "rationale": "Bounded revision.",
            },
        ),
        (ModelOperation.AGENTCORE_SMOKE, ProviderProbeModelResult, {"status": "ok"}),
    ],
)
async def test_openai_structured_stages_use_function_calling_without_fallback(
    operation: ModelOperation,
    output_schema: type[BaseModel],
    response: object,
) -> None:
    chat_model = _ChatModel([response])
    model = ProviderStructuredModel(
        chat_model,
        provider="openai",
        model="gateway/model",
        timeout_seconds=1,
        retries=0,
    )

    await model.generate(
        ModelRequest(
            operation=operation,
            prompt_version="test-v1",
            system_instruction="Return the requested schema.",
            payload={},
        ),
        output_schema,
    )

    assert chat_model.methods == ["function_calling"]


async def test_transient_provider_connection_failure_receives_bounded_retry() -> None:
    class APIConnectionError(Exception):
        pass

    chat_model = _ChatModel(
        [
            APIConnectionError("temporary connection failure"),
            {"paths_to_read": ["src/app.py"], "search_queries": [], "rationale": "Bounded read."},
        ]
    )
    model = ProviderStructuredModel(
        chat_model,
        provider="openai",
        model="gateway/model",
        timeout_seconds=1,
        retries=1,
    )

    generation = await model.generate(
        ModelRequest(
            operation=ModelOperation.PLANNING,
            prompt_version="test-v1",
            system_instruction="Return a plan.",
            payload={},
        ),
        InspectionPlan,
    )

    assert generation.value.paths_to_read == ["src/app.py"]
    assert chat_model.methods == ["function_calling", "function_calling"]


@pytest.mark.parametrize("provider", ["bedrock", "deepseek"])
async def test_non_openai_structured_output_keeps_provider_default(provider: str) -> None:
    chat_model = _ChatModel([{"paths_to_read": ["src/app.py"], "search_queries": [], "rationale": "Bounded read."}])
    model = ProviderStructuredModel(
        chat_model,
        provider=provider,
        model="fixture-model",
        timeout_seconds=1,
        retries=0,
    )

    await model.generate(
        ModelRequest(
            operation=ModelOperation.PLANNING,
            prompt_version="test-v1",
            system_instruction="Return a plan.",
            payload={},
        ),
        InspectionPlan,
    )

    assert chat_model.methods == [None]


async def test_invalid_json_schema_failure_is_redacted_recorded_and_non_retryable() -> None:
    class BadRequestError(Exception):
        code = "invalid_json_schema"
        status_code = 400
        param = "text.format.schema"

    model = ProviderStructuredModel(
        _ChatModel([BadRequestError("secret provider body")]),
        provider="openai",
        model="gateway/model",
        timeout_seconds=1,
        retries=2,
    )

    with pytest.raises(StructuredModelFailure) as failure:
        await model.generate(
            ModelRequest(
                operation=ModelOperation.PLANNING,
                prompt_version="test-v1",
                system_instruction="Return a plan.",
                payload={},
            ),
            InspectionPlan,
        )

    record = failure.value.record
    assert record.outcome.value == "FAILED"
    assert record.error_code == "INVALID_JSON_SCHEMA"
    assert record.http_status == 400
    assert record.error_parameter == "text.format.schema"
    assert record.retryable is False
    assert "secret provider body" not in str(failure.value)


async def test_provider_reasoning_summary_is_redacted_and_recorded() -> None:
    response = AIMessage(
        content=[
            {
                "type": "reasoning",
                "summary": [{"type": "summary_text", "text": "Inspect the bounded target; token=do-not-persist"}],
            },
            {"type": "text", "text": "done"},
        ]
    )
    model = ProviderStructuredModel(
        _ChatModel(
            [
                {
                    "parsed": InspectionPlan(
                        paths_to_read=["src/app.py"],
                        search_queries=[],
                        rationale="Evidence is sufficient.",
                    ),
                    "raw": response,
                    "parsing_error": None,
                }
            ]
        ),
        provider="openai",
        model="gpt-5.6-terra",
        timeout_seconds=1,
        retries=0,
    )

    generation = await model.generate(
        ModelRequest(
            operation=ModelOperation.PLANNING,
            prompt_version="test-v1",
            system_instruction="Return a plan.",
            payload={},
        ),
        InspectionPlan,
    )

    assert generation.record.reasoning_summary == "Inspect the bounded target; [REDACTED]"


async def test_malformed_unified_diff_receives_one_bounded_format_retry() -> None:
    malformed = "--- a/server.js\n+++ b/server.js\n@@ -1 +1 @@\nold\n+new\n"
    valid = "--- a/server.js\n+++ b/server.js\n@@ -1 +1 @@\n-old\n+new\n"
    chat_model = _ChatModel(
        [
            {"unified_diff": malformed, "rationale": "First attempt."},
            {"unified_diff": valid, "rationale": "Recounted hunk."},
        ]
    )
    model = ProviderStructuredModel(
        chat_model,
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=1,
    )

    generation = await model.generate(
        ModelRequest(
            operation=ModelOperation.PATCH,
            prompt_version="test-v1",
            system_instruction="Return an exact unified diff.",
            payload={},
        ),
        PatchCandidate,
    )

    assert generation.value.unified_diff == valid
    assert generation.value.rationale == "Recounted hunk."
    assert len(chat_model.inputs) == 2
    first_messages = chat_model.inputs[0]
    retry_messages = chat_model.inputs[1]
    assert isinstance(first_messages, list)
    assert isinstance(retry_messages, list)
    assert len(first_messages) == 2
    assert len(retry_messages) == 3
    assert "Trusted patch-format retry 1" in retry_messages[-1][1]
    assert "HUNK_LINE_MISSING_PREFIX" in retry_messages[-1][1]
    assert "recount every source and target line exactly" in retry_messages[-1][1]
    assert malformed not in str(retry_messages)


async def test_each_malformed_patch_retry_receives_distinct_bounded_feedback() -> None:
    malformed = "--- a/server.js\n+++ b/server.js\n@@ -1 +1 @@\nold\n+new\n"
    valid = "--- a/server.js\n+++ b/server.js\n@@ -1 +1 @@\n-old\n+new\n"
    chat_model = _ChatModel(
        [
            {"unified_diff": malformed, "rationale": "First attempt."},
            {"unified_diff": malformed, "rationale": "Second attempt."},
            {"unified_diff": valid, "rationale": "Minimal complete patch."},
        ]
    )
    model = ProviderStructuredModel(
        chat_model,
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=2,
    )

    generation = await model.generate(
        ModelRequest(
            operation=ModelOperation.REVISION,
            prompt_version="test-v2",
            system_instruction="Return a complete replacement patch.",
            payload={},
        ),
        PatchCandidate,
    )

    assert generation.value.unified_diff == valid
    assert len(chat_model.inputs) == 3
    second_messages = chat_model.inputs[1]
    third_messages = chat_model.inputs[2]
    assert isinstance(second_messages, list)
    assert isinstance(third_messages, list)
    assert "Trusted patch-format retry 1" in second_messages[-1][1]
    assert "Trusted patch-format retry 2" in third_messages[-1][1]
    assert malformed not in str(second_messages)
    assert malformed not in str(third_messages)


async def test_patch_transport_normalization_accepts_outer_fence_and_crlf() -> None:
    fenced = "\r\n```diff\r\n--- a/server.js\r\n+++ b/server.js\r\n@@ -1 +1 @@\r\n-old\r\n+new\r\n```\r\n\r\n"
    model = ProviderStructuredModel(
        _ChatModel([{"unified_diff": fenced, "rationale": "Bounded fix."}]),
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=0,
    )

    generation = await model.generate(
        ModelRequest(
            operation=ModelOperation.PATCH,
            prompt_version="test-v2",
            system_instruction="Return an exact unified diff.",
            payload={},
        ),
        PatchCandidate,
    )

    assert generation.value.unified_diff == "--- a/server.js\n+++ b/server.js\n@@ -1 +1 @@\n-old\n+new\n"


async def test_patch_transport_normalization_recounts_hunk_metadata() -> None:
    fenced_malformed = "```patch\n--- a/server.js\n+++ b/server.js\n@@ -1,2 +1,2 @@\n-old\n+new\n```\n"
    model = ProviderStructuredModel(
        _ChatModel([{"unified_diff": fenced_malformed, "rationale": "Still malformed."}]),
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=0,
    )

    generation = await model.generate(
        ModelRequest(
            operation=ModelOperation.PATCH,
            prompt_version="test-v2",
            system_instruction="Return an exact unified diff.",
            payload={},
        ),
        PatchCandidate,
    )

    assert generation.value.unified_diff == "--- a/server.js\n+++ b/server.js\n@@ -1 +1 @@\n-old\n+new\n"


async def test_patch_transport_normalization_does_not_repair_invalid_body_lines() -> None:
    malformed = "--- a/server.js\n+++ b/server.js\n@@ -1 +1 @@\nold\n+new\n"
    model = ProviderStructuredModel(
        _ChatModel([{"unified_diff": malformed, "rationale": "Malformed body."}]),
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=0,
    )

    with pytest.raises(RuntimeError, match="HUNK_LINE_MISSING_PREFIX"):
        await model.generate(
            ModelRequest(
                operation=ModelOperation.PATCH,
                prompt_version="test-v2",
                system_instruction="Return an exact unified diff.",
                payload={},
            ),
            PatchCandidate,
        )


async def test_patch_transport_normalization_adds_missing_new_file_metadata() -> None:
    incomplete_git_patch = (
        "diff --git a/lib/calculate-average.js b/lib/calculate-average.js\n"
        "--- /dev/null\n"
        "+++ b/lib/calculate-average.js\n"
        "@@ -0,0 +1 @@\n"
        "+module.exports = {};\n"
    )
    model = ProviderStructuredModel(
        _ChatModel([{"unified_diff": incomplete_git_patch, "rationale": "Add helper."}]),
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=0,
    )

    generation = await model.generate(
        ModelRequest(
            operation=ModelOperation.PATCH,
            prompt_version="test-v2",
            system_instruction="Return an exact unified diff.",
            payload={},
        ),
        PatchCandidate,
    )

    assert generation.value.unified_diff == incomplete_git_patch.replace(
        "--- /dev/null\n", "new file mode 100644\n--- /dev/null\n"
    )


async def test_patch_transport_normalization_preserves_existing_file_metadata() -> None:
    complete_git_patch = (
        "diff --git a/lib/calculate-average.js b/lib/calculate-average.js\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/lib/calculate-average.js\n"
        "@@ -0,0 +1 @@\n"
        "+module.exports = {};\n"
    )
    model = ProviderStructuredModel(
        _ChatModel([{"unified_diff": complete_git_patch, "rationale": "Existing metadata."}]),
        provider="fake-chat",
        model="fixture-model",
        timeout_seconds=1,
        retries=0,
    )

    generation = await model.generate(
        ModelRequest(
            operation=ModelOperation.PATCH,
            prompt_version="test-v2",
            system_instruction="Return an exact unified diff.",
            payload={},
        ),
        PatchCandidate,
    )

    assert generation.value.unified_diff == complete_git_patch
    assert generation.value.unified_diff.count("new file mode ") == 1


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

        def with_structured_output(
            self, schema: type[BaseModel], *, include_raw: bool, method: str | None = None
        ) -> _Runnable:
            _ = schema, include_raw, method
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


def test_gpt_5_6_terra_uses_private_responses_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import langchain_openai

    captured: dict[str, object] = {}

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def with_structured_output(
            self, schema: type[BaseModel], *, include_raw: bool, method: str | None = None
        ) -> _Runnable:
            _ = schema, include_raw, method
            return _Runnable(deque())

    monkeypatch.setattr(langchain_openai, "ChatOpenAI", FakeOpenAI)
    settings = Settings(
        policy_file=Path("config/policies/reference.json"),
        llm_provider="openai",
        llm_model="gpt-5.6-terra",
        openai_secret_arn=_OPENAI_CREDENTIAL_REFERENCE,
        _env_file=None,
    )  # type: ignore[call-arg]

    adapter = build_structured_model(
        settings,
        max_output_tokens=4096,
        max_format_retries=2,
        openai_api_key=SecretStr("sk-hosted-secret"),
    )

    assert adapter.provider == "openai"
    assert captured["model"] == "gpt-5.6-terra"
    assert captured["max_completion_tokens"] == 4096
    assert captured["use_responses_api"] is True
    assert captured["store"] is False
    assert captured["reasoning"] == {"effort": "medium", "summary": "auto"}
    assert captured["output_version"] == "responses/v1"
    assert "temperature" not in captured
    assert captured["api_key"] == SecretStr("sk-hosted-secret")


async def test_qualified_gpt_5_6_gateway_model_retains_responses_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import langchain_openai

    captured: dict[str, object] = {}

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def with_structured_output(
            self, schema: type[BaseModel], *, include_raw: bool, method: str | None = None
        ) -> _Runnable:
            _ = schema, include_raw, method
            return _Runnable(deque())

    monkeypatch.setattr(langchain_openai, "ChatOpenAI", FakeOpenAI)
    settings = Settings(
        policy_file=Path("config/policies/reference.json"),
        llm_provider="openai",
        llm_model="kei-openai-target/gpt-5.6-terra",
        aws_region="ap-southeast-1",
        openai_auth_mode="aws_iam_gateway",
        openai_gateway_arn=_GATEWAY_ARN,
        _env_file=None,
    )  # type: ignore[call-arg]

    adapter = build_structured_model(settings, max_output_tokens=4096, max_format_retries=2)
    sync_client = captured["http_client"]
    async_client = captured["http_async_client"]
    assert isinstance(sync_client, httpx.Client)
    assert isinstance(async_client, httpx.AsyncClient)
    try:
        assert adapter.provider == "openai"
        assert captured["model"] == "kei-openai-target/gpt-5.6-terra"
        assert captured["max_completion_tokens"] == 4096
        assert captured["use_responses_api"] is True
        assert captured["store"] is False
        assert captured["reasoning"] == {"effort": "medium", "summary": "auto"}
        assert captured["output_version"] == "responses/v1"
        assert "temperature" not in captured
        assert captured["base_url"] == (
            "https://llm-gateway-with-inbound-auth-u8utldecju.gateway.bedrock-agentcore."
            "ap-southeast-1.amazonaws.com/inference/v1"
        )
        assert sync_client.follow_redirects is False
        assert async_client.follow_redirects is False
    finally:
        await adapter.aclose()

    assert sync_client.is_closed
    assert async_client.is_closed


async def test_application_startup_failure_closes_owned_gateway_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    app_module = importlib.import_module("remediation_agent.api.app")
    sync_client = httpx.Client()
    async_client = httpx.AsyncClient()
    adapter = ProviderStructuredModel(
        _ChatModel([]),
        provider="openai",
        model="kei-openai-target/gpt-5.6-terra",
        timeout_seconds=1,
        retries=0,
        http_client=sync_client,
        http_async_client=async_client,
    )
    settings = Settings.model_validate(
        {
            "policy_file": Path("config/policies/reference.json"),
            "llm_provider": "openai",
            "llm_model": "gpt-5.6-terra",
            "OPENAI_API_KEY": "sk-test",
            "postgres_dsn": "postgresql://test.invalid/db",
            "checkpoint_encryption_key": "a" * 32,
            "github_token": None,
            "github_writes_enabled": False,
        }
    )
    monkeypatch.setattr(app_module, "Settings", lambda: settings)
    monkeypatch.setattr(app_module, "build_structured_model", lambda *_args, **_kwargs: adapter)
    application = app_module.create_app()

    with pytest.raises(ValueError, match="hosted GitHub MCP inspection"):
        async with application.router.lifespan_context(application):
            pass

    assert sync_client.is_closed
    assert async_client.is_closed
