"""A2A Protocol 1.0 transport and lifecycle tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import httpx
import pytest
from a2a.types import a2a_pb2 as a2a_pb

from remediation_agent.adapters.fakes import FakeStructuredModel
from remediation_agent.api.a2a import build_agent_card, create_a2a_app
from remediation_agent.api.a2a_contracts import (
    APPROVAL_DECISION_MEDIA_TYPE,
    APPROVAL_REQUEST_MEDIA_TYPE,
    DIAGNOSIS_HANDOFF_MEDIA_TYPE,
    EXPLAINABILITY_TRACE_MEDIA_TYPE,
    PROVIDER_PROBE_REQUEST_MEDIA_TYPE,
    PROVIDER_PROBE_RESULT_MEDIA_TYPE,
    REMEDIATION_HANDOFF_MEDIA_TYPE,
)
from remediation_agent.api.a2a_executor import task_state_for_final_status
from remediation_agent.domain.enums import ApprovalStatus, FinalStatus, ModelOperation
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    ApprovalRequest,
    DiagnosisHandoffV1,
    ExplainabilityTraceV1,
    RemediationHandoffV1,
    RemediationRunView,
)
from remediation_agent.service import RemediationService
from tests.conftest import diagnosis_handoff

_SESSION_ID = "2db1f13e-7351-4a1f-a4c6-630646366d52"
_HEADERS = {
    "A2A-Version": "1.0",
    "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": _SESSION_ID,
}


class _FakeService:
    def __init__(self) -> None:
        self.starts: list[tuple[DiagnosisHandoffV1, str | None]] = []
        self.approvals: list[tuple[str, ApprovalDecisionV1]] = []

    async def start(self, handoff: DiagnosisHandoffV1, *, run_id: str | None = None) -> RemediationRunView:
        self.starts.append((handoff, run_id))
        assert run_id is not None
        return RemediationRunView(
            run_id=run_id,
            status=FinalStatus.AWAITING_APPROVAL,
            approval_request=_approval_request(),
            explainability=_trace(run_id, FinalStatus.AWAITING_APPROVAL),
        )

    async def approve(self, run_id: str, decision: ApprovalDecisionV1) -> RemediationRunView:
        self.approvals.append((run_id, decision))
        return RemediationRunView(
            run_id=run_id,
            status=FinalStatus.DRAFT_PR_PREPARED,
            result=_result(run_id),
            explainability=_trace(run_id, FinalStatus.DRAFT_PR_PREPARED),
        )

    async def get(self, run_id: str) -> RemediationRunView:
        raise AssertionError(f"A2A TaskStore handles retrieval, not the workflow service: {run_id}")


def _approval_request() -> ApprovalRequest:
    return ApprovalRequest(
        approval_id="approval-1",
        case_id="CASE-123",
        kind="PATCH",
        scope_digest="sha256:scope",
        summary="Review the patch.",
        reasons=["Sensitive path."],
        requested_at=datetime(2026, 9, 20, tzinfo=UTC),
    )


def _decision() -> ApprovalDecisionV1:
    return ApprovalDecisionV1(
        approval_id="approval-1",
        scope_digest="sha256:scope",
        status=ApprovalStatus.APPROVED,
        reviewer_id="reviewer-1",
        decided_at=datetime(2026, 9, 20, 0, 1, tzinfo=UTC),
    )


def _result(run_id: str) -> RemediationHandoffV1:
    source = diagnosis_handoff()
    return RemediationHandoffV1(
        case_id=source.case_id,
        run_id=run_id,
        final_status=FinalStatus.DRAFT_PR_PREPARED,
        repository=source.repository,
    )


def _trace(run_id: str, status: FinalStatus) -> ExplainabilityTraceV1:
    return ExplainabilityTraceV1(run_id=run_id, status=status)


def _send(data: dict[str, object], media_type: str, *, task_id: str | None = None) -> dict[str, object]:
    message: dict[str, object] = {
        "messageId": "11111111-1111-4111-8111-111111111111",
        "contextId": _SESSION_ID,
        "role": "ROLE_USER",
        "parts": [{"data": data, "mediaType": media_type}],
    }
    if task_id is not None:
        message["taskId"] = task_id
    return {"jsonrpc": "2.0", "id": "request-1", "method": "SendMessage", "params": {"message": message}}


async def test_agent_card_is_strict_a2a_v1_with_sigv4_and_two_skills() -> None:
    card = build_agent_card("https://runtime.example/")
    assert card.supported_interfaces[0].protocol_version == "1.0"
    assert card.supported_interfaces[0].protocol_binding == "JSONRPC"
    assert card.capabilities.streaming is True
    assert card.capabilities.push_notifications is False
    assert set(card.security_schemes) == {"aws_sigv4"}
    assert [skill.id for skill in card.skills] == ["remediate_repository", "runtime_readiness_probe"]


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (FinalStatus.PENDING, a2a_pb.TaskState.TASK_STATE_WORKING),
        (FinalStatus.AWAITING_APPROVAL, a2a_pb.TaskState.TASK_STATE_INPUT_REQUIRED),
        (FinalStatus.DRAFT_PR_PREPARED, a2a_pb.TaskState.TASK_STATE_COMPLETED),
        (FinalStatus.DRAFT_PR_CREATED, a2a_pb.TaskState.TASK_STATE_COMPLETED),
        (FinalStatus.INVALID_REQUEST, a2a_pb.TaskState.TASK_STATE_REJECTED),
        (FinalStatus.UNSUPPORTED_REMEDIATION_TYPE, a2a_pb.TaskState.TASK_STATE_REJECTED),
        (FinalStatus.NOT_IMPLEMENTED, a2a_pb.TaskState.TASK_STATE_REJECTED),
        (FinalStatus.HUMAN_ACTION_REQUIRED, a2a_pb.TaskState.TASK_STATE_REJECTED),
        (FinalStatus.UNSAFE_REMEDIATION, a2a_pb.TaskState.TASK_STATE_REJECTED),
        (FinalStatus.VALIDATION_FAILED, a2a_pb.TaskState.TASK_STATE_FAILED),
        (FinalStatus.INTERNAL_ERROR, a2a_pb.TaskState.TASK_STATE_FAILED),
        (FinalStatus.CLEANUP_FAILED, a2a_pb.TaskState.TASK_STATE_FAILED),
    ],
)
def test_status_mapping_is_deterministic(status: FinalStatus, expected: int) -> None:
    assert task_state_for_final_status(status) == expected


async def test_probe_is_a_bounded_message_only_interaction() -> None:
    model = FakeStructuredModel({ModelOperation.AGENTCORE_SMOKE: [{"status": "ok"}]})
    app = create_a2a_app(
        model,
        cast(RemediationService, _FakeService()),
        probe_provider="bedrock",
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/",
                headers=_HEADERS,
                json=_send(
                    {"schema_version": "1.0", "probe": "bedrock"},
                    PROVIDER_PROBE_REQUEST_MEDIA_TYPE,
                ),
            )
    assert response.status_code == 200
    message = response.json()["result"]["message"]
    assert "task" not in response.json()["result"]
    assert message["parts"][0]["mediaType"] == PROVIDER_PROBE_RESULT_MEDIA_TYPE
    assert message["parts"][0]["data"]["status"] == "ok"


async def test_hosted_probe_defaults_missing_agentcore_version_header_to_v1() -> None:
    model = FakeStructuredModel({ModelOperation.AGENTCORE_SMOKE: [{"status": "ok"}]})
    app = create_a2a_app(
        model,
        cast(RemediationService, _FakeService()),
        probe_provider="bedrock",
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/",
                headers={"X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": _SESSION_ID},
                json=_send(
                    {"schema_version": "1.0", "probe": "bedrock"},
                    PROVIDER_PROBE_REQUEST_MEDIA_TYPE,
                ),
            )

    assert response.status_code == 200
    assert response.json()["result"]["message"]["parts"][0]["data"]["status"] == "ok"


async def test_hosted_probe_does_not_override_explicit_legacy_version() -> None:
    model = FakeStructuredModel({ModelOperation.AGENTCORE_SMOKE: [{"status": "ok"}]})
    app = create_a2a_app(
        model,
        cast(RemediationService, _FakeService()),
        probe_provider="bedrock",
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/",
                headers={**_HEADERS, "A2A-Version": "0.3"},
                json=_send(
                    {"schema_version": "1.0", "probe": "bedrock"},
                    PROVIDER_PROBE_REQUEST_MEDIA_TYPE,
                ),
            )

    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32009


async def test_diagnosis_and_approval_share_task_but_not_runtime_session() -> None:
    service = _FakeService()
    app = create_a2a_app(
        FakeStructuredModel({}),
        cast(RemediationService, service),
        probe_provider="bedrock",
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            started = await client.post(
                "/",
                headers=_HEADERS,
                json=_send(diagnosis_handoff().model_dump(mode="json"), DIAGNOSIS_HANDOFF_MEDIA_TYPE),
            )
            started_task = started.json()["result"]["task"]
            task_id = started_task["id"]
            UUID(task_id)
            assert task_id != _SESSION_ID
            assert started_task["status"]["state"] == "TASK_STATE_INPUT_REQUIRED"
            assert started_task["status"]["message"]["parts"][0]["mediaType"] == APPROVAL_REQUEST_MEDIA_TYPE
            assert started_task["status"]["message"]["parts"][1]["mediaType"] == EXPLAINABILITY_TRACE_MEDIA_TYPE

            approved = await client.post(
                "/",
                headers=_HEADERS,
                json=_send(_decision().model_dump(mode="json"), APPROVAL_DECISION_MEDIA_TYPE, task_id=task_id),
            )
            completed = approved.json()["result"]["task"]
            fetched = await client.post(
                "/",
                headers=_HEADERS,
                json={"jsonrpc": "2.0", "id": "get-1", "method": "GetTask", "params": {"id": task_id}},
            )

    assert service.starts == [(diagnosis_handoff(), task_id)]
    assert service.approvals == [(task_id, _decision())]
    assert completed["status"]["state"] == "TASK_STATE_COMPLETED"
    assert completed["artifacts"][0]["parts"][0]["mediaType"] == REMEDIATION_HANDOFF_MEDIA_TYPE
    assert completed["artifacts"][0]["parts"][1]["mediaType"] == EXPLAINABILITY_TRACE_MEDIA_TYPE
    assert fetched.json()["result"]["id"] == task_id


async def test_stream_emits_created_task_before_working_status() -> None:
    app = create_a2a_app(
        FakeStructuredModel({}),
        cast(RemediationService, _FakeService()),
        probe_provider="bedrock",
    )
    request = _send(diagnosis_handoff().model_dump(mode="json"), DIAGNOSIS_HANDOFF_MEDIA_TYPE)
    request["method"] = "SendStreamingMessage"

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/", headers=_HEADERS, json=request)

    events = [
        json.loads(line.removeprefix("data: ")) for line in response.text.splitlines() if line.startswith("data: ")
    ]
    assert events[0]["result"]["task"]["status"]["state"] == "TASK_STATE_SUBMITTED"
    assert events[1]["result"]["statusUpdate"]["status"]["state"] == "TASK_STATE_WORKING"


async def test_malformed_data_and_cancel_are_rejected_without_workflow_execution() -> None:
    service = _FakeService()
    app = create_a2a_app(
        FakeStructuredModel({}),
        cast(RemediationService, service),
        probe_provider="bedrock",
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            malformed = await client.post(
                "/",
                headers=_HEADERS,
                json=_send({"schema_version": "1.0", "unexpected": True}, DIAGNOSIS_HANDOFF_MEDIA_TYPE),
            )
            task_id = malformed.json()["result"]["task"]["id"]
            cancelled = await client.post(
                "/",
                headers=_HEADERS,
                json={"jsonrpc": "2.0", "id": "cancel-1", "method": "CancelTask", "params": {"id": task_id}},
            )

    assert malformed.json()["result"]["task"]["status"]["state"] == "TASK_STATE_REJECTED"
    assert cancelled.json()["error"]["code"] == -32002
    assert service.starts == []
