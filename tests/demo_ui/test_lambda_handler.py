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
_DIGEST = "sha256:" + "a" * 64


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


def _event(
    method: str,
    path: str,
    body: object | None = None,
    *,
    query: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "version": "2.0",
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "body": json.dumps(body) if body is not None else "",
        "isBase64Encoded": False,
        "queryStringParameters": query or {},
    }


def _upstream(body: object, status: int = 200) -> dict[str, Any]:
    return {"statusCode": status, "response": io.BytesIO(json.dumps(body).encode())}


def _task_response(state: str = "TASK_STATE_WORKING", *, direct: bool = False) -> dict[str, Any]:
    task = {
        "id": _RUN_ID,
        "contextId": _RUN_ID,
        "status": {"state": state},
        "artifacts": [],
    }
    return {
        "jsonrpc": "2.0",
        "id": "response-1",
        "result": task if direct else {"task": task},
    }


def _body(response: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(response["body"])
    assert isinstance(value, dict)
    return value


def test_health_does_not_invoke_agentcore(handler: _HandlerModule) -> None:
    response = handler.lambda_handler(_event("GET", "/api/health"), None)
    assert response["statusCode"] == 200
    assert _body(response) == {"status": "Healthy", "service": "aios-remediation-demo-ui"}


def test_start_translates_to_agentcore_and_preserves_response(handler: _HandlerModule) -> None:
    fake = _FakeAgentCore(_upstream(_task_response()))
    handler._agentcore_client = fake

    response = handler.lambda_handler(
        _event("POST", "/api/runs", {"run_id": _RUN_ID, "input": {"schema_version": "1.0"}}),
        None,
    )

    assert response["statusCode"] == 200
    output = _body(response)["output"]
    assert output["run_id"] == _RUN_ID
    assert output["failure_code"] is None
    call = fake.calls[0]
    assert call["runtimeSessionId"] == _RUN_ID
    assert call["qualifier"] == "DEFAULT"
    payload = json.loads(call["payload"])
    assert payload["method"] == "SendMessage"
    assert payload["params"]["message"]["contextId"] == _RUN_ID
    assert payload["params"]["message"]["parts"] == [
        {
            "data": {"schema_version": "1.0"},
            "mediaType": "application/vnd.aios.diagnosis-handoff.v1+json",
        }
    ]


def test_get_uses_separate_task_and_session_ids(handler: _HandlerModule) -> None:
    fake = _FakeAgentCore(_upstream(_task_response(direct=True)))
    handler._agentcore_client = fake
    handler.lambda_handler(
        _event("GET", f"/api/runs/{_RUN_ID}", query={"session_id": _RUN_ID}),
        None,
    )
    assert json.loads(fake.calls[0]["payload"])["method"] == "GetTask"
    assert json.loads(fake.calls[0]["payload"])["params"] == {"id": _RUN_ID}
    assert fake.calls[0]["runtimeSessionId"] == _RUN_ID


def test_list_runs_uses_a2a_list_tasks_and_returns_public_summaries(handler: _HandlerModule) -> None:
    summary = {
        "schema_version": "1.0",
        "task_id": _RUN_ID,
        "session_id": _RUN_ID,
        "case_id": "CASE-123",
        "jira_ticket_id": "TICKET-123",
        "repository": "owner/repository",
        "status": "AWAITING_APPROVAL",
        "created_at": "2026-09-23T00:00:00Z",
        "updated_at": "2026-09-23T00:01:00Z",
        "draft_pr_url": None,
        "artifact_count": 0.0,
        "stale": False,
    }
    envelope = {
        "jsonrpc": "2.0",
        "id": "response-1",
        "result": {
            "tasks": [{"id": _RUN_ID, "metadata": {"aios_run": summary}}],
            "nextPageToken": "",
            "pageSize": 1,
            "totalSize": 1,
        },
    }
    fake = _FakeAgentCore(_upstream(envelope))
    handler._agentcore_client = fake

    response = handler.lambda_handler(_event("GET", "/api/runs"), None)

    assert response["statusCode"] == 200
    assert _body(response)["output"] == {
        "schema_version": "1.0",
        "runs": [{**summary, "artifact_count": 0}],
    }
    payload = json.loads(fake.calls[0]["payload"])
    assert payload["method"] == "ListTasks"
    assert payload["params"] == {"pageSize": 20, "includeArtifacts": False}


def test_list_runs_rejects_malformed_public_summary(handler: _HandlerModule) -> None:
    envelope = {
        "jsonrpc": "2.0",
        "id": "response-1",
        "result": {"tasks": [{"id": _RUN_ID, "metadata": {"aios_run": {"session_id": "secret"}}}]},
    }
    handler._agentcore_client = _FakeAgentCore(_upstream(envelope))

    response = handler.lambda_handler(_event("GET", "/api/runs"), None)

    assert response["statusCode"] == 502
    assert _body(response) == {"error": "INVALID_A2A_RESPONSE"}


def test_list_runs_rejects_more_than_twenty_or_unknown_status(handler: _HandlerModule) -> None:
    summary = {
        "schema_version": "1.0",
        "task_id": _RUN_ID,
        "session_id": _RUN_ID,
        "case_id": None,
        "jira_ticket_id": None,
        "repository": None,
        "status": "SECRET_STATUS",
        "created_at": "2026-09-23T00:00:00Z",
        "updated_at": "2026-09-23T00:01:00Z",
        "draft_pr_url": None,
        "artifact_count": 0,
        "stale": False,
    }
    invalid_status = {
        "jsonrpc": "2.0",
        "id": "response-1",
        "result": {"tasks": [{"id": _RUN_ID, "metadata": {"aios_run": summary}}]},
    }
    handler._agentcore_client = _FakeAgentCore(_upstream(invalid_status))
    assert handler.lambda_handler(_event("GET", "/api/runs"), None)["statusCode"] == 502

    too_many = {"jsonrpc": "2.0", "id": "response-2", "result": {"tasks": [{}] * 21}}
    handler._agentcore_client = _FakeAgentCore(_upstream(too_many))
    assert handler.lambda_handler(_event("GET", "/api/runs"), None)["statusCode"] == 502


def test_artifact_preview_relays_typed_manifest_identity_without_object_path(handler: _HandlerModule) -> None:
    preview = {
        "schema_version": "1.0",
        "run_id": _RUN_ID,
        "name": "patch.diff",
        "media_type": "text/x-diff",
        "digest": _DIGEST,
        "content": "--- a/server.js\n+++ b/server.js",
        # A2A data parts use protobuf Struct, which serializes JSON integers as doubles.
        "size_bytes": 35.0,
        "truncated": False,
        "digest_verified": True,
    }
    envelope = {
        "jsonrpc": "2.0",
        "id": "response-1",
        "result": {
            "message": {
                "parts": [
                    {
                        "mediaType": "application/vnd.aios.artifact-preview-result.v1+json",
                        "data": preview,
                    }
                ]
            }
        },
    }
    fake = _FakeAgentCore(_upstream(envelope))
    handler._agentcore_client = fake

    response = handler.lambda_handler(
        _event(
            "POST",
            f"/api/runs/{_RUN_ID}/artifacts/preview",
            {"session_id": _RUN_ID, "artifact_name": "patch.diff", "digest": _DIGEST},
        ),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["output"] == {**preview, "size_bytes": 35}
    call = fake.calls[0]
    assert call["runtimeSessionId"] == _RUN_ID
    payload = json.loads(call["payload"])
    assert payload["params"]["message"]["parts"] == [
        {
            "data": {
                "schema_version": "1.0",
                "run_id": _RUN_ID,
                "artifact_name": "patch.diff",
                "digest": _DIGEST,
            },
            "mediaType": "application/vnd.aios.artifact-preview-request.v1+json",
        }
    ]
    assert "path" not in json.dumps(payload)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"session_id": _RUN_ID, "artifact_name": "patch.diff", "digest": "sha256:short"},
        {"session_id": "not-a-uuid", "artifact_name": "patch.diff", "digest": _DIGEST},
        {"session_id": _RUN_ID, "artifact_name": "", "digest": _DIGEST},
        {"session_id": _RUN_ID, "artifact_name": "patch.diff", "digest": _DIGEST, "path": "s3://bad"},
    ],
)
def test_artifact_preview_rejects_invalid_browser_requests(handler: _HandlerModule, body: object) -> None:
    response = handler.lambda_handler(
        _event("POST", f"/api/runs/{_RUN_ID}/artifacts/preview", body),
        None,
    )
    assert response["statusCode"] == 400
    assert _body(response) == {"error": "INVALID_ARTIFACT_PREVIEW_REQUEST"}


def test_artifact_preview_maps_bounded_runtime_failure(handler: _HandlerModule) -> None:
    envelope = _task_response(state="TASK_STATE_REJECTED")
    task = envelope["result"]["task"]
    task["status"]["message"] = {"parts": [{"mediaType": "text/plain", "text": "ARTIFACT_NOT_FOUND"}]}
    handler._agentcore_client = _FakeAgentCore(_upstream(envelope))

    response = handler.lambda_handler(
        _event(
            "POST",
            f"/api/runs/{_RUN_ID}/artifacts/preview",
            {"session_id": _RUN_ID, "artifact_name": "missing.json", "digest": _DIGEST},
        ),
        None,
    )

    assert response["statusCode"] == 404
    assert _body(response) == {"error": "ARTIFACT_NOT_FOUND"}


def test_checkpoint_explainability_part_is_normalized(handler: _HandlerModule) -> None:
    envelope = _task_response(state="TASK_STATE_INPUT_REQUIRED", direct=True)
    task = envelope["result"]
    assert isinstance(task, dict)
    task["status"] = {
        "state": "TASK_STATE_INPUT_REQUIRED",
        "message": {
            "parts": [
                {
                    "mediaType": "application/vnd.aios.approval-request.v1+json",
                    "data": {"approval_id": "approval-1"},
                },
                {
                    "mediaType": "application/vnd.aios.explainability-trace.v1+json",
                    "data": {"schema_version": "1.0", "run_id": _RUN_ID, "events": []},
                },
            ]
        },
    }
    handler._agentcore_client = _FakeAgentCore(_upstream(envelope))

    response = handler.lambda_handler(
        _event("GET", f"/api/runs/{_RUN_ID}", query={"session_id": _RUN_ID}),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["output"]["explainability"]["schema_version"] == "1.0"


def test_rejected_task_failure_code_is_normalized(handler: _HandlerModule) -> None:
    envelope = _task_response(state="TASK_STATE_REJECTED", direct=True)
    task = envelope["result"]
    assert isinstance(task, dict)
    task["status"] = {
        "state": "TASK_STATE_REJECTED",
        "message": {"parts": [{"mediaType": "text/plain", "text": "INVALID_DATA_PART"}]},
    }
    handler._agentcore_client = _FakeAgentCore(_upstream(envelope))

    response = handler.lambda_handler(
        _event("GET", f"/api/runs/{_RUN_ID}", query={"session_id": _RUN_ID}),
        None,
    )

    output = _body(response)["output"]
    assert output["status"] == "INVALID_REQUEST"
    assert output["failure_code"] == "INVALID_DATA_PART"


@pytest.mark.parametrize(
    "part",
    [
        {"mediaType": "text/plain", "text": "not bounded"},
        {"mediaType": "text/plain", "text": "A" * 129},
        {"mediaType": "application/json", "text": "INVALID_DATA_PART"},
        {"mediaType": "text/plain", "data": {"code": "INVALID_DATA_PART"}},
    ],
)
def test_malformed_failure_code_is_not_exposed(handler: _HandlerModule, part: dict[str, object]) -> None:
    envelope = _task_response(state="TASK_STATE_FAILED", direct=True)
    task = envelope["result"]
    assert isinstance(task, dict)
    task["status"] = {"state": "TASK_STATE_FAILED", "message": {"parts": [part]}}
    handler._agentcore_client = _FakeAgentCore(_upstream(envelope))

    response = handler.lambda_handler(
        _event("GET", f"/api/runs/{_RUN_ID}", query={"session_id": _RUN_ID}),
        None,
    )

    output = _body(response)["output"]
    assert output["status"] == "INTERNAL_ERROR"
    assert output["failure_code"] is None


def test_approval_adds_schema_and_server_timestamp(handler: _HandlerModule) -> None:
    fake = _FakeAgentCore(_upstream(_task_response()))
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
                "session_id": _RUN_ID,
            },
        ),
        None,
    )
    assert response["statusCode"] == 200
    payload = json.loads(fake.calls[0]["payload"])
    assert payload["method"] == "SendMessage"
    assert payload["params"]["message"]["taskId"] == _RUN_ID
    decision = payload["params"]["message"]["parts"][0]["data"]
    assert decision["schema_version"] == "1.0"
    assert decision["decided_at"].endswith("Z")
    assert decision["reviewer_id"] == "Arabasta"


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
    response = handler.lambda_handler(
        _event("GET", f"/api/runs/{_RUN_ID}", query={"session_id": _RUN_ID}),
        None,
    )
    assert response["statusCode"] == 502
    assert _body(response) == {"error": "AGENTCORE_INVOCATION_FAILED"}
    assert "provider secret" not in response["body"]


def test_timeout_has_stable_gateway_code(handler: _HandlerModule) -> None:
    handler._agentcore_client = _FakeAgentCore(ReadTimeoutError(endpoint_url="https://agentcore.example"))
    response = handler.lambda_handler(
        _event("GET", f"/api/runs/{_RUN_ID}", query={"session_id": _RUN_ID}),
        None,
    )
    assert response["statusCode"] == 504
    assert _body(response) == {"error": "AGENTCORE_TIMEOUT"}


def test_access_denied_has_stable_gateway_code(handler: _HandlerModule) -> None:
    denied = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "sensitive IAM detail"}},
        "InvokeAgentRuntime",
    )
    handler._agentcore_client = _FakeAgentCore(denied)
    response = handler.lambda_handler(
        _event("GET", f"/api/runs/{_RUN_ID}", query={"session_id": _RUN_ID}),
        None,
    )
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
