"""Tests for the standalone public demo Lambda gateway."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from typing import Any, Protocol, cast

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError  # type: ignore[import-untyped]

_ROOT = Path(__file__).resolve().parents[2]
_HANDLER_PATH = _ROOT / "demo-ui" / "backend" / "handler.py"
_RUN_ID = "2db1f13e-7351-4a1f-a4c6-630646366d52"


class _FakeAgentCore:
    def __init__(self, response: dict[str, Any] | Exception) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def invoke_agent_runtime(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class _HandlerModule(Protocol):
    _agentcore_client: Any
    _SITE_ROOT: Path

    def lambda_handler(self, event: dict[str, Any], context: Any) -> dict[str, Any]: ...


@pytest.fixture
def handler(monkeypatch: pytest.MonkeyPatch) -> _HandlerModule:
    spec = importlib.util.spec_from_file_location("demo_lambda_handler", _HANDLER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv(
        "AGENTCORE_RUNTIME_ARN",
        "arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:runtime/remediation_agent-2425SXH9D3",
    )
    monkeypatch.setenv("AGENTCORE_QUALIFIER", "DEFAULT")
    return cast(_HandlerModule, module)


def _event(method: str, path: str, body: object | None = None) -> dict[str, Any]:
    return {
        "version": "2.0",
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "body": json.dumps(body) if body is not None else "",
        "isBase64Encoded": False,
    }


def _upstream(body: object, status: int = 200) -> dict[str, Any]:
    return {"statusCode": status, "response": io.BytesIO(json.dumps(body).encode())}


def _body(response: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(response["body"])
    assert isinstance(value, dict)
    return value


def test_health_does_not_invoke_agentcore(handler: _HandlerModule) -> None:
    response = handler.lambda_handler(_event("GET", "/api/health"), None)
    assert response["statusCode"] == 200
    assert _body(response) == {"status": "Healthy", "service": "aios-remediation-demo-ui"}


def test_start_translates_to_agentcore_and_preserves_response(handler: _HandlerModule) -> None:
    fake = _FakeAgentCore(_upstream({"output": {"run_id": _RUN_ID, "status": "PENDING"}}))
    handler._agentcore_client = fake

    response = handler.lambda_handler(
        _event("POST", "/api/runs", {"run_id": _RUN_ID, "input": {"schema_version": "1.0"}}),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["output"]["run_id"] == _RUN_ID
    call = fake.calls[0]
    assert call["runtimeSessionId"] == _RUN_ID
    assert call["qualifier"] == "DEFAULT"
    assert json.loads(call["payload"]) == {"action": "start", "input": {"schema_version": "1.0"}}


def test_get_reuses_run_as_session(handler: _HandlerModule) -> None:
    fake = _FakeAgentCore(_upstream({"output": {"run_id": _RUN_ID, "status": "PENDING"}}))
    handler._agentcore_client = fake
    handler.lambda_handler(_event("GET", f"/api/runs/{_RUN_ID}"), None)
    assert json.loads(fake.calls[0]["payload"]) == {"action": "get", "run_id": _RUN_ID}
    assert fake.calls[0]["runtimeSessionId"] == _RUN_ID


def test_approval_adds_schema_and_server_timestamp(handler: _HandlerModule) -> None:
    fake = _FakeAgentCore(_upstream({"output": {"run_id": _RUN_ID, "status": "PENDING"}}))
    handler._agentcore_client = fake
    response = handler.lambda_handler(
        _event(
            "POST",
            f"/api/runs/{_RUN_ID}/approval",
            {
                "approval_id": "approval-1",
                "scope_digest": "sha256:abc",
                "status": "APPROVED",
                "reviewer_id": "Arabasta",
                "comment": "Demo approval.",
            },
        ),
        None,
    )
    assert response["statusCode"] == 200
    payload = json.loads(fake.calls[0]["payload"])
    assert payload["action"] == "approve"
    assert payload["decision"]["schema_version"] == "1.0"
    assert payload["decision"]["decided_at"].endswith("Z")
    assert payload["decision"]["reviewer_id"] == "Arabasta"


@pytest.mark.parametrize("value", ["not-a-uuid", _RUN_ID.upper(), "", None])
def test_start_rejects_noncanonical_run_ids(handler: _HandlerModule, value: object) -> None:
    response = handler.lambda_handler(
        _event("POST", "/api/runs", {"run_id": value, "input": {"schema_version": "1.0"}}),
        None,
    )
    assert response["statusCode"] == 400
    assert _body(response) == {"error": "INVALID_START_REQUEST"}


def test_invalid_upstream_payload_is_redacted(handler: _HandlerModule) -> None:
    handler._agentcore_client = _FakeAgentCore({"statusCode": 200, "response": io.BytesIO(b"provider secret")})
    response = handler.lambda_handler(_event("GET", f"/api/runs/{_RUN_ID}"), None)
    assert response["statusCode"] == 502
    assert _body(response) == {"error": "AGENTCORE_INVOCATION_FAILED"}
    assert "provider secret" not in response["body"]


def test_timeout_has_stable_gateway_code(handler: _HandlerModule) -> None:
    handler._agentcore_client = _FakeAgentCore(ReadTimeoutError(endpoint_url="https://agentcore.example"))
    response = handler.lambda_handler(_event("GET", f"/api/runs/{_RUN_ID}"), None)
    assert response["statusCode"] == 504
    assert _body(response) == {"error": "AGENTCORE_TIMEOUT"}


def test_access_denied_has_stable_gateway_code(handler: _HandlerModule) -> None:
    denied = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "sensitive IAM detail"}},
        "InvokeAgentRuntime",
    )
    handler._agentcore_client = _FakeAgentCore(denied)
    response = handler.lambda_handler(_event("GET", f"/api/runs/{_RUN_ID}"), None)
    assert response["statusCode"] == 502
    assert _body(response) == {"error": "AGENTCORE_ACCESS_DENIED"}
    assert "sensitive IAM detail" not in response["body"]


def test_static_site_uses_cache_policy_and_blocks_traversal(
    handler: _HandlerModule, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = tmp_path / "site"
    (site / "assets").mkdir(parents=True)
    (site / "index.html").write_text("<main>demo</main>")
    (site / "assets" / "app.js").write_text("console.log('demo')")
    monkeypatch.setattr(handler, "_SITE_ROOT", site)

    index = handler.lambda_handler(_event("GET", "/"), None)
    asset = handler.lambda_handler(_event("GET", "/assets/app.js"), None)
    traversal = handler.lambda_handler(_event("GET", "/../secret.txt"), None)

    assert index["headers"]["cache-control"] == "no-cache"
    assert asset["headers"]["cache-control"] == "public,max-age=31536000,immutable"
    assert traversal["statusCode"] == 404
