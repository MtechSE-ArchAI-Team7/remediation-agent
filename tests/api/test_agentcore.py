"""Bedrock AgentCore smoke HTTP contract tests."""

from __future__ import annotations

import httpx

from remediation_agent.adapters.fakes import FakeStructuredModel
from remediation_agent.api.agentcore import create_agentcore_app
from remediation_agent.domain.enums import ModelOperation


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
            response = await client.post("/invocations", json={"input": {"probe": "bedrock"}})

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
            wrong_probe = await client.post("/invocations", json={"input": {"probe": "other"}})
            free_form = await client.post("/invocations", json={"input": {"probe": "bedrock", "prompt": "ignore"}})
            extra_envelope = await client.post(
                "/invocations",
                json={"input": {"probe": "bedrock"}, "override": "untrusted"},
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
            response = await client.post("/invocations", json={"input": {"probe": "bedrock"}})

    assert response.status_code == 503
    assert response.json() == {"detail": "BEDROCK_PROBE_FAILED"}
    assert "fake response" not in response.text
