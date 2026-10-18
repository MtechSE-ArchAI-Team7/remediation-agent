"""HTTP boundary tests using an injected external-service-free graph."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from remediation_agent.api.app import create_app
from remediation_agent.domain.enums import ApprovalStatus, FinalStatus, PolicyDecision, RiskLevel
from remediation_agent.domain.models import ApprovalDecisionV1
from scripts.export_tool_catalog import render_tool_catalog_json
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
            assert (await client.get("/")).json() == {
                "name": "AIOS Resolution/Remediation Agent",
                "architecture": "one-agent-langgraph-workflow",
            }
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


async def test_tool_catalog_is_read_only_and_reports_stable_counts() -> None:
    service, model, repository, sandbox, pr_provider, artifacts, audit = build_test_service({})
    app = create_app(service)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/v1/tools")

    assert response.status_code == 200
    body = response.json()
    assert body == json.loads(render_tool_catalog_json())
    assert body["catalog_version"] == "1.1"
    assert body["total_tools"] == 17
    assert body["model_callable_tools"] == 4
    assert body["workflow_only_tools"] == 13
    assert len(body["tools"]) == 17
    model_tools = {
        item["operation"]: item["arguments"]
        for item in body["tools"]
        if item["execution_mode"] != "DETERMINISTIC_WORKFLOW"
    }
    assert model_tools == {
        "get_repository_tree": ["owner", "repo", "tree_sha", "recursive", "path_filter"],
        "get_file_contents": ["owner", "repo", "path", "ref", "sha", "fields"],
        "search_code": ["query", "sort", "order", "fields", "page", "perPage"],
        "finish_inspection": ["rationale"],
    }
    assert model.requests == []
    assert model.tool_turn_messages == []
    assert repository.created is False
    assert sandbox.applied_patches == []
    assert sandbox.tasks_run == []
    assert sandbox.destroyed is False
    assert pr_provider.requests == []
    assert artifacts.requests == []
    assert audit.requests == []


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


async def test_runtime_lifespan_releases_checkpoint_and_model_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager
    from pathlib import Path
    from unittest.mock import AsyncMock, MagicMock

    from pydantic import SecretStr

    import remediation_agent.api.app as api
    from remediation_agent.config import Settings

    settings = Settings(
        llm_provider="fake",
        policy_file=Path("config/policies/demo.json"),
        postgres_dsn=SecretStr("postgresql://fixture"),
        checkpoint_encryption_key=SecretStr("x" * 32),
        github_token=SecretStr("fixture"),
    )
    monkeypatch.setattr(api, "Settings", lambda: settings)
    closed = []
    checkpoint = object()

    @asynccontextmanager
    async def store(dsn: str, key: str) -> AsyncIterator[object]:
        assert dsn == "postgresql://fixture" and key == "x" * 32
        try:
            yield checkpoint
        finally:
            closed.append("checkpoint")

    monkeypatch.setattr(api, "postgres_checkpointer", store)
    model = MagicMock()
    model.aclose = AsyncMock()
    monkeypatch.setattr(api, "build_structured_model", MagicMock(return_value=model))
    boundaries = {}
    for name in (
        "GitHubAskpassCredentialProvider",
        "LocalGitRepository",
        "GitHubRemoteMcpInspectionTools",
        "DockerSandboxExecutor",
        "DraftPullRequestProvider",
        "LocalArtifactStore",
        "JsonlAuditSink",
        "WorkflowNodes",
        "build_graph",
        "RemediationService",
    ):
        boundary = MagicMock()
        boundaries[name] = boundary
        monkeypatch.setattr(api, name, boundary)
    app = api.create_app()
    with pytest.raises(RuntimeError, match="request failure"):
        async with app.router.lifespan_context(app):
            assert app.state.remediation_service is boundaries["RemediationService"].return_value
            assert boundaries["DraftPullRequestProvider"].call_args.kwargs["writes_enabled"] is False
            assert boundaries["build_graph"].call_args.args[1] is checkpoint
            raise RuntimeError("request failure")
    model.aclose.assert_awaited_once()
    assert closed == ["checkpoint"]


async def test_readiness_requires_runtime_and_healthy_checkpoint() -> None:
    from unittest.mock import AsyncMock

    service, *_ = build_test_service({})
    app = create_app(service)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/readyz")).status_code == 503
    async with app.router.lifespan_context(app):
        service.ready = AsyncMock(return_value=False)  # type: ignore[method-assign]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/readyz")
            assert response.status_code == 503
            assert response.json() == {"detail": "checkpoint store is not ready"}
