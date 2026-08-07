"""HTTP boundary tests using an injected external-service-free graph."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from remediation_agent.api.app import create_app
from remediation_agent.domain.enums import ApprovalStatus, FinalStatus, PolicyDecision, RiskLevel
from remediation_agent.domain.models import ApprovalDecisionV1
from tests.conftest import build_test_service, diagnosis_handoff, scripted_responses


async def test_start_and_get_completed_remediation() -> None:
    service, *_ = build_test_service(scripted_responses())
    app = create_app(service)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/v1/remediations", json=diagnosis_handoff().model_dump(mode="json"))
            assert response.status_code == 202
            body = response.json()
            assert body["status"] == FinalStatus.DRAFT_PR_PREPARED

            fetched = await client.get(f"/v1/remediations/{body['run_id']}")
            assert fetched.status_code == 200
            assert fetched.json()["result"]["case_id"] == "CASE-123"
            assert (await client.get("/healthz")).json() == {"status": "ok"}
            assert (await client.get("/readyz")).json() == {"status": "ready"}


async def test_invalid_contract_and_unknown_run_return_typed_http_errors() -> None:
    service, *_ = build_test_service({})
    app = create_app(service)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            invalid = await client.post("/v1/remediations", json={"schema_version": "1.0"})
            assert invalid.status_code == 422
            missing = await client.get("/v1/remediations/not-a-uuid")
            assert missing.status_code == 404


async def test_approval_endpoint_resumes_checkpoint() -> None:
    service, *_ = build_test_service(
        scripted_responses(risk_level=RiskLevel.MEDIUM, risk_decision=PolicyDecision.ALLOW)
    )
    app = create_app(service)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            waiting_response = await client.post(
                "/v1/remediations",
                json=diagnosis_handoff().model_dump(mode="json"),
            )
            waiting = waiting_response.json()
            request = waiting["approval_request"]
            decision = ApprovalDecisionV1(
                approval_id=request["approval_id"],
                scope_digest=request["scope_digest"],
                status=ApprovalStatus.APPROVED,
                reviewer_id="api-reviewer",
                decided_at=datetime.now(UTC),
            )
            completed = await client.post(
                f"/v1/remediations/{waiting['run_id']}/approvals",
                json=decision.model_dump(mode="json"),
            )
            assert completed.status_code == 202
            assert completed.json()["status"] == FinalStatus.DRAFT_PR_PREPARED
