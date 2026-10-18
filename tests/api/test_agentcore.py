"""AgentCore HTTP contract tests."""

from __future__ import annotations

from pathlib import Path
from typing import cast
from uuid import uuid4

import httpx
import pytest

from remediation_agent.adapters.fakes import FakeStructuredModel
from remediation_agent.api.agentcore import (
    _load_agentcore_openai_api_key,
    _validate_agentcore_provider,
    _validate_workspace_root,
    create_agentcore_app,
)
from remediation_agent.config import Settings
from remediation_agent.domain.enums import FinalStatus, ModelOperation
from remediation_agent.domain.models import ApprovalDecisionV1, DiagnosisHandoffV1, RemediationRunView
from remediation_agent.service import RemediationService
from tests.conftest import diagnosis_handoff

_SESSION_ID = "2db1f13e-7351-4a1f-a4c6-630646366d52"
_HEADERS = {"X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": _SESSION_ID}
_GATEWAY_ARN = "arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:gateway/llm-gateway-with-inbound-auth-u8utldecju"


class _FakeRemediationService:
    def __init__(self) -> None:
        self.starts: list[tuple[DiagnosisHandoffV1, str | None]] = []
        self.gets: list[str] = []

    async def start(self, handoff: DiagnosisHandoffV1, *, run_id: str | None = None) -> RemediationRunView:
        self.starts.append((handoff, run_id))
        return RemediationRunView(run_id=run_id or str(uuid4()), status=FinalStatus.INVALID_REQUEST)

    async def get(self, run_id: str) -> RemediationRunView:
        self.gets.append(run_id)
        return RemediationRunView(run_id=run_id, status=FinalStatus.INVALID_REQUEST)

    async def approve(self, run_id: str, decision: ApprovalDecisionV1) -> RemediationRunView:
        del decision
        return RemediationRunView(run_id=run_id, status=FinalStatus.INVALID_REQUEST)


async def test_agentcore_ping_implements_runtime_health_contract() -> None:
    model = FakeStructuredModel({})
    app = create_agentcore_app(model)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")

    assert response.status_code == 200
    assert response.json() == {"status": "Healthy"}
    assert model.requests == []


def test_agentcore_openai_rejects_inline_api_key() -> None:
    settings = Settings.model_validate(
        {
            "policy_file": Path("config/policies/agentcore-demo.json"),
            "llm_provider": "openai",
            "llm_model": "gpt-5.6-terra",
            "aws_region": "ap-southeast-1",
            "OPENAI_API_KEY": "sk-inline-secret",
        }
    )

    with pytest.raises(ValueError, match="must be loaded from Secrets Manager"):
        _validate_agentcore_provider(settings)


def test_agentcore_workspace_root_preflight_creates_and_cleans_probe(tmp_path: Path) -> None:
    workspace_root = tmp_path / "mnt" / "workspace" / "runs"

    _validate_workspace_root(workspace_root)

    assert workspace_root.is_dir()
    assert list(workspace_root.iterdir()) == []


def test_agentcore_workspace_root_preflight_has_stable_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_root = tmp_path / "workspace"

    def denied(*_: object, **__: object) -> str:
        raise PermissionError("sensitive host path")

    monkeypatch.setattr("remediation_agent.api.agentcore.tempfile.mkdtemp", denied)

    with pytest.raises(RuntimeError, match="^WORKSPACE_ROOT_UNAVAILABLE$"):
        _validate_workspace_root(workspace_root)


async def test_agentcore_gateway_mode_never_loads_the_openai_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        policy_file=Path("config/policies/agentcore-demo.json"),
        llm_provider="openai",
        llm_model="kei-openai-target/gpt-5.6-terra",
        aws_region="ap-southeast-1",
        openai_auth_mode="aws_iam_gateway",
        openai_gateway_arn=_GATEWAY_ARN,
        _env_file=None,
    )  # type: ignore[call-arg]

    async def forbidden_load(*_: object, **__: object) -> None:
        raise AssertionError("gateway mode must not read the OpenAI secret")

    monkeypatch.setattr("remediation_agent.api.agentcore.SecretsManagerOpenAISecretProvider.load", forbidden_load)

    _validate_agentcore_provider(settings)
    assert await _load_agentcore_openai_api_key(settings, "ap-southeast-1") is None


async def test_agentcore_invocation_returns_only_bounded_model_metadata() -> None:
    model = FakeStructuredModel({ModelOperation.AGENTCORE_SMOKE: [{"status": "ok"}]})
    app = create_agentcore_app(model)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/invocations",
                json={"action": "probe", "input": {"probe": "bedrock"}},
                headers=_HEADERS,
            )

    assert response.status_code == 200
    body = response.json()
    assert body["output"] == {
        "status": "ok",
        "provider": "fake",
        "model": "scripted",
        "duration_ms": 0,
        "input_tokens": None,
        "output_tokens": None,
        "response_digest": body["output"]["response_digest"],
    }
    assert body["output"]["response_digest"].startswith("sha256:")
    assert len(model.requests) == 1
    request = model.requests[0]
    assert request.operation is ModelOperation.AGENTCORE_SMOKE
    assert request.prompt_version == "agentcore-smoke-v1"
    assert request.payload == {"probe": "bedrock"}


async def test_agentcore_openai_probe_returns_bounded_model_metadata() -> None:
    model = FakeStructuredModel({ModelOperation.AGENTCORE_SMOKE: [{"status": "ok"}]})
    app = create_agentcore_app(model, probe_provider="openai")

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/invocations",
                json={"action": "probe", "input": {"probe": "openai"}},
                headers=_HEADERS,
            )

    assert response.status_code == 200
    assert response.json()["output"]["provider"] == "fake"
    assert model.requests[0].payload == {"probe": "openai"}


async def test_agentcore_probe_rejects_configured_provider_mismatch() -> None:
    model = FakeStructuredModel({})
    app = create_agentcore_app(model, probe_provider="openai")

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/invocations",
                json={"action": "probe", "input": {"probe": "bedrock"}},
                headers=_HEADERS,
            )

    assert response.status_code == 409
    assert response.json() == {"detail": "PROBE_PROVIDER_MISMATCH"}
    assert model.requests == []


async def test_agentcore_invocation_rejects_unexpected_or_free_form_input() -> None:
    model = FakeStructuredModel({})
    app = create_agentcore_app(model)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            wrong_probe = await client.post(
                "/invocations", json={"action": "probe", "input": {"probe": "other"}}, headers=_HEADERS
            )
            free_form = await client.post(
                "/invocations",
                json={"action": "probe", "input": {"probe": "bedrock", "prompt": "ignore"}},
                headers=_HEADERS,
            )
            extra_envelope = await client.post(
                "/invocations",
                json={"action": "probe", "input": {"probe": "bedrock"}, "override": "untrusted"},
                headers=_HEADERS,
            )

    assert wrong_probe.status_code == 422
    assert free_form.status_code == 422
    assert extra_envelope.status_code == 422
    assert model.requests == []


async def test_agentcore_provider_failure_is_redacted() -> None:
    model = FakeStructuredModel({})
    app = create_agentcore_app(model)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/invocations",
                json={"action": "probe", "input": {"probe": "bedrock"}},
                headers=_HEADERS,
            )

    assert response.status_code == 503
    assert response.json() == {"detail": "BEDROCK_PROBE_FAILED"}
    assert "fake response" not in response.text


async def test_agentcore_bedrock_throttling_is_distinct_and_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    class ThrottlingException(RuntimeError):
        pass

    model = FakeStructuredModel({})

    async def throttled(*_: object, **__: object) -> None:
        try:
            raise ThrottlingException("account quota detail")
        except ThrottlingException as exc:
            raise RuntimeError("provider wrapper") from exc

    monkeypatch.setattr(model, "generate", throttled)
    app = create_agentcore_app(model)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/invocations",
                json={"action": "probe", "input": {"probe": "bedrock"}},
                headers=_HEADERS,
            )

    assert response.status_code == 429
    assert response.json() == {"detail": "BEDROCK_THROTTLED"}
    assert "account quota detail" not in response.text


async def test_agentcore_openai_rate_limit_is_distinct_and_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    class RateLimitError(RuntimeError):
        status_code = 429

    model = FakeStructuredModel({})

    async def rate_limited(*_: object, **__: object) -> None:
        try:
            raise RateLimitError("secret provider response")
        except RateLimitError as exc:
            raise RuntimeError("provider wrapper") from exc

    monkeypatch.setattr(model, "generate", rate_limited)
    app = create_agentcore_app(model, probe_provider="openai")

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/invocations",
                json={"action": "probe", "input": {"probe": "openai"}},
                headers=_HEADERS,
            )

    assert response.status_code == 429
    assert response.json() == {"detail": "OPENAI_RATE_LIMITED"}
    assert "secret provider response" not in response.text


async def test_agentcore_openai_failure_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    model = FakeStructuredModel({})

    async def failed(*_: object, **__: object) -> None:
        raise RuntimeError("secret provider response")

    monkeypatch.setattr(model, "generate", failed)
    app = create_agentcore_app(model, probe_provider="openai")

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/invocations",
                json={"action": "probe", "input": {"probe": "openai"}},
                headers=_HEADERS,
            )

    assert response.status_code == 503
    assert response.json() == {"detail": "OPENAI_PROBE_FAILED"}
    assert "secret provider response" not in response.text


async def test_agentcore_requires_a_canonical_uuid_session_header() -> None:
    app = create_agentcore_app(FakeStructuredModel({}))

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            missing = await client.post("/invocations", json={"action": "probe", "input": {"probe": "bedrock"}})
            malformed = await client.post(
                "/invocations",
                json={"action": "probe", "input": {"probe": "bedrock"}},
                headers={"X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "not-a-uuid"},
            )

    assert missing.status_code == 422
    assert malformed.status_code == 400
    assert malformed.json() == {"detail": "INVALID_RUNTIME_SESSION_ID"}


async def test_agentcore_start_binds_run_to_session_and_get_rejects_mismatch() -> None:
    fake = _FakeRemediationService()
    app = create_agentcore_app(
        FakeStructuredModel({}),
        cast(RemediationService, fake),
    )

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            started = await client.post(
                "/invocations",
                json={"action": "start", "input": diagnosis_handoff().model_dump(mode="json")},
                headers=_HEADERS,
            )
            mismatch = await client.post(
                "/invocations",
                json={"action": "get", "run_id": str(uuid4())},
                headers=_HEADERS,
            )
            fetched = await client.post(
                "/invocations",
                json={"action": "get", "run_id": _SESSION_ID},
                headers=_HEADERS,
            )

    assert started.status_code == 200
    assert started.json()["output"]["run_id"] == _SESSION_ID
    assert fake.starts == [(diagnosis_handoff(), _SESSION_ID)]
    assert mismatch.status_code == 409
    assert mismatch.json() == {"detail": "RUN_SESSION_MISMATCH"}
    assert fetched.status_code == 200
    assert fake.gets == [_SESSION_ID]


@pytest.mark.parametrize(
    ("error", "code", "detail"),
    [
        ("missing", 404, "RUN_NOT_FOUND"),
        ("approval", 409, "APPROVAL_CONFLICT"),
        ("deadline", 504, "INVOCATION_DEADLINE_EXCEEDED"),
        ("workspace", 409, "WORKSPACE_RECOVERY_UNSAFE"),
        ("other", 500, "RUNTIME_INVOCATION_FAILED"),
    ],
)
async def test_agentcore_service_errors_have_bounded_http_responses(
    error: str, code: int, detail: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from remediation_agent.service import ApprovalConflictError, InvocationDeadlineError, RunNotFoundError

    errors = {
        "missing": RunNotFoundError("private diagnostic"),
        "approval": ApprovalConflictError("private diagnostic"),
        "deadline": InvocationDeadlineError("private diagnostic"),
        "workspace": RuntimeError("WORKSPACE_RECOVERY_UNSAFE"),
        "other": RuntimeError("private diagnostic"),
    }
    service = _FakeRemediationService()

    async def fail(run_id: str) -> RemediationRunView:
        assert run_id == _SESSION_ID
        raise errors[error]

    monkeypatch.setattr(service, "get", fail)
    app = create_agentcore_app(service=cast(RemediationService, service))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/invocations", json={"action": "get", "run_id": _SESSION_ID}, headers=_HEADERS
            )
    assert response.status_code == code
    assert response.json() == {"detail": detail}
    assert "private diagnostic" not in response.text


async def test_agentcore_missing_boundaries_fail_closed() -> None:
    app = create_agentcore_app(model=FakeStructuredModel({}))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/invocations", json={"action": "get", "run_id": _SESSION_ID}, headers=_HEADERS
            )
            assert response.status_code == 503
            assert response.json() == {"detail": "RUNTIME_NOT_CONFIGURED"}
    app = create_agentcore_app(service=cast(RemediationService, _FakeRemediationService()))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/invocations", json={"action": "probe", "input": {"probe": "bedrock"}}, headers=_HEADERS
            )
            assert response.status_code == 503
            assert response.json() == {"detail": "MODEL_PROBE_NOT_CONFIGURED"}
