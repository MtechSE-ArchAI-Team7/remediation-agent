"""Public presentation gateway for the React demo and AgentCore runtime."""

from __future__ import annotations

import base64
import json
import mimetypes
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote
from uuid import UUID, uuid4

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, ReadTimeoutError

_SITE_ROOT = Path(__file__).with_name("site")
_RUN_PATH = re.compile(r"^/api/runs/([^/]+)$")
_APPROVAL_PATH = re.compile(r"^/api/runs/([^/]+)/approval$")
_MAX_AGENTCORE_RESPONSE_BYTES = 6_000_000
_DIAGNOSIS_MEDIA_TYPE = "application/vnd.aios.diagnosis-handoff.v1+json"
_APPROVAL_MEDIA_TYPE = "application/vnd.aios.approval-decision.v1+json"
_APPROVAL_REQUEST_MEDIA_TYPE = "application/vnd.aios.approval-request.v1+json"
_HANDOFF_MEDIA_TYPE = "application/vnd.aios.remediation-handoff.v1+json"
_DELIVERY_MEDIA_TYPE = "application/vnd.aios.delivery-receipt.v1+json"
_PROBE_REQUEST_MEDIA_TYPE = "application/vnd.aios.provider-probe-request.v1+json"
_PROBE_RESULT_MEDIA_TYPE = "application/vnd.aios.provider-probe-result.v1+json"
_agentcore_client: Any | None = None


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Handle Lambda Function URL API and static-site requests."""

    del context
    method = str(event.get("requestContext", {}).get("http", {}).get("method", "GET")).upper()
    path = unquote(str(event.get("rawPath", "/")))

    if path == "/api/health" and method == "GET":
        return _json_response(200, {"status": "Healthy", "service": "aios-remediation-demo-ui"})
    if path == "/api/probe" and method == "POST":
        session_id = str(uuid4())
        return _invoke(
            session_id,
            _send_message(
                session_id,
                _PROBE_REQUEST_MEDIA_TYPE,
                {"schema_version": "1.0", "probe": "openai"},
            ),
            response_kind="probe",
        )
    if path == "/api/runs" and method == "POST":
        body = _request_json(event)
        if isinstance(body, dict) and set(body) == {"run_id", "input"} and isinstance(body["input"], dict):
            run_id = _canonical_uuid(body["run_id"])
            if run_id is not None:
                return _invoke(
                    run_id,
                    _send_message(run_id, _DIAGNOSIS_MEDIA_TYPE, body["input"]),
                    response_kind="run",
                )
        return _json_response(400, {"error": "INVALID_START_REQUEST"})

    approval_match = _APPROVAL_PATH.fullmatch(path)
    if approval_match is not None and method == "POST":
        run_id = _canonical_uuid(approval_match.group(1))
        body = _request_json(event)
        decision = _approval_decision(body)
        session_id = _session_from_body(body)
        if run_id is None or decision is None or session_id is None:
            return _json_response(400, {"error": "INVALID_APPROVAL_REQUEST"})
        return _invoke(
            session_id,
            _send_message(session_id, _APPROVAL_MEDIA_TYPE, decision, task_id=run_id),
            response_kind="run",
        )

    run_match = _RUN_PATH.fullmatch(path)
    if run_match is not None and method == "GET":
        run_id = _canonical_uuid(run_match.group(1))
        if run_id is None:
            return _json_response(400, {"error": "INVALID_RUN_ID"})
        query = event.get("queryStringParameters")
        session_id = _canonical_uuid(query.get("session_id")) if isinstance(query, dict) else None
        if session_id is None:
            return _json_response(400, {"error": "INVALID_SESSION_ID"})
        return _invoke(
            session_id,
            {"jsonrpc": "2.0", "id": str(uuid4()), "method": "GetTask", "params": {"id": run_id}},
            response_kind="run",
        )

    if path.startswith("/api/"):
        return _json_response(404, {"error": "NOT_FOUND"})
    if method not in {"GET", "HEAD"}:
        return _json_response(405, {"error": "METHOD_NOT_ALLOWED"})
    return _static_response(path, head=method == "HEAD")


def _agentcore() -> Any:
    global _agentcore_client
    if _agentcore_client is None:
        region = os.environ.get("AGENTCORE_REGION", os.environ.get("AWS_REGION", "ap-southeast-1"))
        _agentcore_client = boto3.client(
            "bedrock-agentcore",
            region_name=region,
            config=Config(
                connect_timeout=10,
                read_timeout=880,
                retries={"max_attempts": 2, "mode": "standard"},
            ),
        )
    return _agentcore_client


def _invoke(session_id: str, payload: dict[str, Any], *, response_kind: str) -> dict[str, Any]:
    runtime_arn = os.environ.get("AGENTCORE_RUNTIME_ARN", "")
    if not runtime_arn:
        return _json_response(503, {"error": "GATEWAY_NOT_CONFIGURED"})
    try:
        response = _agentcore().invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            runtimeSessionId=session_id,
            qualifier=os.environ.get("AGENTCORE_QUALIFIER", "DEFAULT"),
            contentType="application/json",
            accept="application/json",
            payload=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        )
        body = response.get("response")
        raw = body.read(_MAX_AGENTCORE_RESPONSE_BYTES + 1) if hasattr(body, "read") else body
        if not isinstance(raw, bytes) or len(raw) > _MAX_AGENTCORE_RESPONSE_BYTES:
            return _json_response(502, {"error": "INVALID_AGENTCORE_RESPONSE"})
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return _json_response(502, {"error": "INVALID_AGENTCORE_RESPONSE"})
        status_code = response.get("statusCode", 200)
        if not isinstance(status_code, int) or status_code < 100 or status_code > 599:
            status_code = 502
        if status_code != 200:
            return _json_response(status_code, {"error": "AGENTCORE_INVOCATION_FAILED"})
        if "error" in parsed:
            return _json_response(502, {"error": "A2A_PROTOCOL_ERROR"})
        normalized = _normalize_probe(parsed) if response_kind == "probe" else _normalize_run(parsed, session_id)
        if normalized is None:
            return _json_response(502, {"error": "INVALID_A2A_RESPONSE"})
        return _json_response(200, {"output": normalized})
    except ReadTimeoutError:
        return _json_response(504, {"error": "AGENTCORE_TIMEOUT"})
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code in {"ThrottlingException", "TooManyRequestsException"}:
            return _json_response(429, {"error": "AGENTCORE_RATE_LIMITED"})
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedException"}:
            return _json_response(502, {"error": "AGENTCORE_ACCESS_DENIED"})
        return _json_response(502, {"error": "AGENTCORE_INVOCATION_FAILED"})
    except (BotoCoreError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return _json_response(502, {"error": "AGENTCORE_INVOCATION_FAILED"})


def _request_json(event: dict[str, Any]) -> object:
    raw = event.get("body", "")
    if not isinstance(raw, str):
        return None
    try:
        if event.get("isBase64Encoded"):
            raw = base64.b64decode(raw, validate=True).decode("utf-8")
        return json.loads(raw) if raw else {}
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _canonical_uuid(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return value if str(parsed) == value else None


def _approval_decision(body: object) -> dict[str, str] | None:
    if not isinstance(body, dict):
        return None
    required = {"approval_id", "scope_digest", "status", "reviewer_id"}
    if not required.issubset(body) or not set(body).issubset(required | {"comment", "session_id"}):
        return None
    if body.get("status") not in {"APPROVED", "REJECTED"}:
        return None
    values = {key: body.get(key) for key in required}
    if any(not isinstance(value, str) or not value.strip() for value in values.values()):
        return None
    comment = body.get("comment", "")
    if not isinstance(comment, str) or len(comment) > 2_000:
        return None
    return {
        "schema_version": "1.0",
        "approval_id": str(body["approval_id"]),
        "scope_digest": str(body["scope_digest"]),
        "status": str(body["status"]),
        "reviewer_id": str(body["reviewer_id"]),
        "decided_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "comment": comment,
    }


def _session_from_body(body: object) -> str | None:
    return _canonical_uuid(body.get("session_id")) if isinstance(body, dict) else None


def _send_message(
    context_id: str,
    media_type: str,
    data: dict[str, Any],
    *,
    task_id: str | None = None,
) -> dict[str, Any]:
    message: dict[str, Any] = {
        "messageId": str(uuid4()),
        "contextId": context_id,
        "role": "ROLE_USER",
        "parts": [{"data": data, "mediaType": media_type}],
    }
    if task_id is not None:
        message["taskId"] = task_id
    return {
        "jsonrpc": "2.0",
        "id": str(uuid4()),
        "method": "SendMessage",
        "params": {"message": message},
    }


def _normalize_probe(envelope: dict[str, Any]) -> dict[str, Any] | None:
    result = envelope.get("result")
    resource = result.get("message") if isinstance(result, dict) else None
    if not isinstance(resource, dict):
        return None
    return _data_part(resource.get("parts"), _PROBE_RESULT_MEDIA_TYPE)


def _normalize_run(envelope: dict[str, Any], session_id: str) -> dict[str, Any] | None:
    result_envelope = envelope.get("result")
    task = None
    if isinstance(result_envelope, dict):
        nested = result_envelope.get("task")
        task = nested if isinstance(nested, dict) else result_envelope
    if not isinstance(task, dict):
        return None
    task_id = task.get("id")
    if not isinstance(task_id, str) or _canonical_uuid(task_id) is None:
        return None
    status_record = task.get("status")
    state = status_record.get("state") if isinstance(status_record, dict) else None
    approval = None
    if isinstance(status_record, dict) and isinstance(status_record.get("message"), dict):
        approval = _data_part(status_record["message"].get("parts"), _APPROVAL_REQUEST_MEDIA_TYPE)
    result = None
    delivery = None
    artifacts = task.get("artifacts", [])
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            result = result or _data_part(artifact.get("parts"), _HANDOFF_MEDIA_TYPE)
            delivery = delivery or _data_part(artifact.get("parts"), _DELIVERY_MEDIA_TYPE)
    if isinstance(result, dict) and isinstance(result.get("final_status"), str):
        status = result["final_status"]
    else:
        status = {
            "TASK_STATE_SUBMITTED": "PENDING",
            "TASK_STATE_WORKING": "PENDING",
            "TASK_STATE_INPUT_REQUIRED": "AWAITING_APPROVAL",
            "TASK_STATE_REJECTED": "INVALID_REQUEST",
            "TASK_STATE_FAILED": "INTERNAL_ERROR",
        }.get(state)
    if status is None:
        return None
    return {
        "run_id": task_id,
        "task_id": task_id,
        "session_id": session_id,
        "status": status,
        "approval_request": approval,
        "result": result,
        "downstream_delivery": delivery,
    }


def _data_part(parts: object, media_type: str) -> dict[str, Any] | None:
    if not isinstance(parts, list):
        return None
    for part in parts:
        if isinstance(part, dict) and part.get("mediaType") == media_type and isinstance(part.get("data"), dict):
            return part["data"]
    return None


def _static_response(path: str, *, head: bool) -> dict[str, Any]:
    requested = "index.html" if path == "/" else path.lstrip("/")
    candidate = (_SITE_ROOT / requested).resolve()
    if not candidate.is_relative_to(_SITE_ROOT.resolve()):
        return _json_response(404, {"error": "NOT_FOUND"})
    if not candidate.is_file():
        if "." in Path(requested).name:
            return _json_response(404, {"error": "NOT_FOUND"})
        candidate = _SITE_ROOT / "index.html"
    if not candidate.is_file():
        return _json_response(503, {"error": "SITE_NOT_BUILT"})

    content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
    data = b"" if head else candidate.read_bytes()
    cache_control = "public,max-age=31536000,immutable" if requested.startswith("assets/") else "no-cache"
    headers = {"content-type": f"{content_type}; charset=utf-8", "cache-control": cache_control}
    text_types = {"application/javascript", "application/json", "image/svg+xml"}
    if content_type.startswith("text/") or content_type in text_types:
        return {"statusCode": 200, "headers": headers, "body": data.decode("utf-8")}
    return {
        "statusCode": 200,
        "headers": headers,
        "body": base64.b64encode(data).decode("ascii"),
        "isBase64Encoded": True,
    }


def _json_response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json; charset=utf-8", "cache-control": "no-store"},
        "body": json.dumps(body, separators=(",", ":")),
    }
