"""Optional AgentCore SigV4 A2A delivery adapter for Agent 4."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol, cast

import boto3  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]

from remediation_agent.api.a2a_contracts import REMEDIATION_HANDOFF_MEDIA_TYPE
from remediation_agent.domain.models import DownstreamDeliveryReceiptV1
from remediation_agent.ports.models import HandoffDeliveryRequest


class _ReadableBody(Protocol):
    def read(self) -> bytes: ...


class _AgentCoreClient(Protocol):
    def get_agent_card(self, **kwargs: object) -> Mapping[str, object]: ...

    def invoke_agent_runtime(self, **kwargs: object) -> Mapping[str, object]: ...


class AgentCoreA2ADelivery:
    """Discover and invoke one compatible Agent 4 runtime with SDK SigV4."""

    def __init__(
        self,
        runtime_arn: str,
        *,
        region_name: str,
        qualifier: str,
        timeout_seconds: float,
        client: _AgentCoreClient | None = None,
    ) -> None:
        self.runtime_arn = runtime_arn
        self.qualifier = qualifier
        self._client = client or cast(
            _AgentCoreClient,
            boto3.client(
                "bedrock-agentcore",
                region_name=region_name,
                config=Config(
                    connect_timeout=timeout_seconds,
                    read_timeout=timeout_seconds,
                    retries={"total_max_attempts": 1, "mode": "standard"},
                ),
            ),
        )
        self._timeout_seconds = timeout_seconds

    async def deliver(self, request: HandoffDeliveryRequest) -> DownstreamDeliveryReceiptV1:
        attempted_at = datetime.now(UTC)
        try:
            card_response = await asyncio.wait_for(
                asyncio.to_thread(
                    self._client.get_agent_card,
                    agentRuntimeArn=self.runtime_arn,
                    qualifier=self.qualifier,
                    runtimeSessionId=request.correlation_id,
                ),
                timeout=self._timeout_seconds,
            )
            _validate_agent4_card(card_response.get("agentCard"))
            envelope = _message_envelope(request)
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self._client.invoke_agent_runtime,
                    agentRuntimeArn=self.runtime_arn,
                    qualifier=self.qualifier,
                    runtimeSessionId=request.correlation_id,
                    contentType="application/json",
                    accept="application/json",
                    payload=json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(),
                ),
                timeout=self._timeout_seconds,
            )
            payload = _read_json_response(response)
            remote_task_id, remote_context_id = _remote_identifiers(payload)
            response_digest = _digest(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            return DownstreamDeliveryReceiptV1(
                delivery_id=request.delivery_id,
                message_id=request.message_id,
                attempted=True,
                succeeded=True,
                attempted_at=attempted_at,
                request_digest=request.request_digest,
                response_digest=response_digest,
                remote_task_id=remote_task_id,
                remote_context_id=remote_context_id,
            )
        except TimeoutError:
            code = "DOWNSTREAM_TIMEOUT"
        except ValueError as exc:
            code = str(exc) if str(exc).startswith("DOWNSTREAM_") else "DOWNSTREAM_MALFORMED_RESPONSE"
        except Exception:  # noqa: BLE001 - provider details must not enter checkpoints
            code = "DOWNSTREAM_INVOCATION_FAILED"
        return DownstreamDeliveryReceiptV1(
            delivery_id=request.delivery_id,
            message_id=request.message_id,
            attempted=True,
            succeeded=False,
            attempted_at=attempted_at,
            request_digest=request.request_digest,
            error_code=code,
        )


def _message_envelope(request: HandoffDeliveryRequest) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request.delivery_id,
        "method": "SendMessage",
        "params": {
            "message": {
                "messageId": request.message_id,
                "contextId": request.correlation_id,
                "role": "ROLE_USER",
                "parts": [
                    {
                        "data": request.handoff.model_dump(mode="json"),
                        "mediaType": REMEDIATION_HANDOFF_MEDIA_TYPE,
                    }
                ],
            }
        },
    }


def _validate_agent4_card(value: object) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("DOWNSTREAM_CARD_MALFORMED")
    interfaces = value.get("supportedInterfaces")
    skills = value.get("skills")
    if not isinstance(interfaces, list) or not any(
        isinstance(item, Mapping) and item.get("protocolBinding") == "JSONRPC" and item.get("protocolVersion") == "1.0"
        for item in interfaces
    ):
        raise ValueError("DOWNSTREAM_CARD_INCOMPATIBLE")
    if not isinstance(skills, list) or not any(
        isinstance(item, Mapping) and REMEDIATION_HANDOFF_MEDIA_TYPE in item.get("inputModes", []) for item in skills
    ):
        raise ValueError("DOWNSTREAM_CARD_INCOMPATIBLE")


def _read_json_response(response: Mapping[str, object]) -> dict[str, object]:
    if response.get("statusCode") != 200:
        raise ValueError("DOWNSTREAM_HTTP_ERROR")
    body = response.get("response")
    if not hasattr(body, "read"):
        raise ValueError("DOWNSTREAM_MALFORMED_RESPONSE")
    raw = cast(_ReadableBody, body).read()
    if len(raw) > 524_288:
        raise ValueError("DOWNSTREAM_RESPONSE_TOO_LARGE")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("DOWNSTREAM_MALFORMED_RESPONSE") from exc
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0" or "error" in payload:
        raise ValueError("DOWNSTREAM_JSONRPC_ERROR")
    return cast(dict[str, object], payload)


def _remote_identifiers(payload: dict[str, object]) -> tuple[str | None, str | None]:
    result = payload.get("result")
    if not isinstance(result, Mapping):
        raise ValueError("DOWNSTREAM_MALFORMED_RESPONSE")
    resource = result.get("task") or result.get("message")
    if not isinstance(resource, Mapping):
        raise ValueError("DOWNSTREAM_MALFORMED_RESPONSE")
    task_id = resource.get("id") or resource.get("taskId")
    context_id = resource.get("contextId")
    return (
        task_id if isinstance(task_id, str) else None,
        context_id if isinstance(context_id, str) else None,
    )


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()
