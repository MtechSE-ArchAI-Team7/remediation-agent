"""Tests for optional Agent 4 delivery over AgentCore A2A."""

from __future__ import annotations

import io
import json
from typing import Any

from remediation_agent.adapters.a2a_delivery import AgentCoreA2ADelivery
from remediation_agent.api.a2a_contracts import REMEDIATION_HANDOFF_MEDIA_TYPE
from remediation_agent.domain.enums import FinalStatus
from remediation_agent.domain.models import RemediationHandoffV1
from remediation_agent.ports.models import HandoffDeliveryRequest
from tests.conftest import diagnosis_handoff


class _Client:
    def __init__(self, *, compatible: bool = True, malformed: bool = False) -> None:
        self.compatible = compatible
        self.malformed = malformed
        self.card_calls: list[dict[str, Any]] = []
        self.invoke_calls: list[dict[str, Any]] = []

    def get_agent_card(self, **kwargs: Any) -> dict[str, object]:
        self.card_calls.append(kwargs)
        return {
            "agentCard": {
                "supportedInterfaces": [
                    {
                        "protocolBinding": "JSONRPC",
                        "protocolVersion": "1.0" if self.compatible else "0.3",
                    }
                ],
                "skills": [
                    {
                        "id": "verify_remediation",
                        "inputModes": [REMEDIATION_HANDOFF_MEDIA_TYPE],
                    }
                ],
            }
        }

    def invoke_agent_runtime(self, **kwargs: Any) -> dict[str, object]:
        self.invoke_calls.append(kwargs)
        if self.malformed:
            return {"statusCode": 200, "response": io.BytesIO(b"not-json")}
        return {
            "statusCode": 200,
            "response": io.BytesIO(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "delivery-1",
                        "result": {
                            "task": {
                                "id": "remote-task-1",
                                "contextId": "remote-context-1",
                            }
                        },
                    }
                ).encode()
            ),
        }


def _request() -> HandoffDeliveryRequest:
    source = diagnosis_handoff()
    handoff = RemediationHandoffV1(
        case_id=source.case_id,
        run_id="11111111-1111-4111-8111-111111111111",
        final_status=FinalStatus.DRAFT_PR_PREPARED,
        repository=source.repository,
    )
    return HandoffDeliveryRequest(
        delivery_id="delivery-1",
        message_id="message-1",
        correlation_id=handoff.run_id,
        request_digest="sha256:request",
        handoff=handoff,
    )


async def test_delivery_discovers_card_and_invokes_once_with_deterministic_ids() -> None:
    client = _Client()
    adapter = AgentCoreA2ADelivery(
        "arn:aws:bedrock-agentcore:region:account:runtime/agent4",
        region_name="ap-southeast-1",
        qualifier="DEFAULT",
        timeout_seconds=5,
        client=client,
    )

    receipt = await adapter.deliver(_request())

    assert receipt.succeeded is True
    assert receipt.delivery_id == "delivery-1"
    assert receipt.remote_task_id == "remote-task-1"
    assert len(client.card_calls) == 1
    assert len(client.invoke_calls) == 1
    payload = json.loads(client.invoke_calls[0]["payload"])
    assert payload["method"] == "SendMessage"
    assert payload["params"]["message"]["messageId"] == "message-1"
    assert payload["params"]["message"]["parts"][0]["mediaType"] == REMEDIATION_HANDOFF_MEDIA_TYPE


async def test_delivery_rejects_incompatible_card_without_invocation() -> None:
    client = _Client(compatible=False)
    adapter = AgentCoreA2ADelivery(
        "arn:runtime",
        region_name="ap-southeast-1",
        qualifier="DEFAULT",
        timeout_seconds=5,
        client=client,
    )

    receipt = await adapter.deliver(_request())

    assert receipt.succeeded is False
    assert receipt.error_code == "DOWNSTREAM_CARD_INCOMPATIBLE"
    assert client.invoke_calls == []


async def test_delivery_normalizes_malformed_jsonrpc_without_retry() -> None:
    client = _Client(malformed=True)
    adapter = AgentCoreA2ADelivery(
        "arn:runtime",
        region_name="ap-southeast-1",
        qualifier="DEFAULT",
        timeout_seconds=5,
        client=client,
    )

    receipt = await adapter.deliver(_request())

    assert receipt.succeeded is False
    assert receipt.error_code == "DOWNSTREAM_MALFORMED_RESPONSE"
    assert len(client.invoke_calls) == 1
