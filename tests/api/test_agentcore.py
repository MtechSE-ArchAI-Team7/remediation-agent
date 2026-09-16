"""Bedrock AgentCore smoke HTTP contract tests."""

from __future__ import annotations

from typing import cast
from uuid import uuid4

import httpx
import pytest

from remediation_agent.adapters.fakes import FakeStructuredModel
from remediation_agent.api.agentcore import create_agentcore_app
from remediation_agent.domain.enums import FinalStatus, ModelOperation
from remediation_agent.domain.models import ApprovalDecisionV1, DiagnosisHandoffV1, RemediationRunView
from remediation_agent.service import RemediationService
from tests.conftest import diagnosis_handoff

_SESSION_ID = "2db1f13e-7351-4a1f-a4c6-630646366d52"
_HEADERS = {"X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": _SESSION_ID}


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
