"""Opt-in PostgreSQL interrupt persistence test."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from remediation_agent.adapters.checkpoint import postgres_checkpointer
from remediation_agent.adapters.fakes import (
    FakePullRequestProvider,
    FakeRepository,
    FakeSandboxExecutor,
    FakeStructuredModel,
    MemoryArtifactStore,
    MemoryAuditSink,
)
from remediation_agent.domain.enums import ApprovalStatus, FinalStatus, PolicyDecision, RiskLevel
from remediation_agent.domain.models import ApprovalDecisionV1
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from remediation_agent.service import RemediationService
from remediation_agent.workflow.graph import build_graph
from remediation_agent.workflow.nodes import WorkflowNodes
from tests.conftest import diagnosis_handoff, scripted_responses

pytestmark = pytest.mark.integration


def _nodes() -> WorkflowNodes:
    policy = PolicyEngine(load_policy(Path(__file__).parents[2] / "config" / "policies" / "demo.json"))
    return WorkflowNodes(
        policy=policy,
        model=FakeStructuredModel(scripted_responses(risk_level=RiskLevel.MEDIUM, risk_decision=PolicyDecision.ALLOW)),
        repository=FakeRepository(files={"src/app.py": "value = int(raw)\n"}),
        sandbox=FakeSandboxExecutor(),
        pr_provider=FakePullRequestProvider(),
        artifact_store=MemoryArtifactStore(),
        audit_sink=MemoryAuditSink(),
        prompt_version="postgres-test-v1",
    )


async def test_interrupt_survives_checkpointer_recreation() -> None:
    dsn = os.getenv("AIOS_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("AIOS_TEST_POSTGRES_DSN is not configured")
    key = "0123456789abcdef0123456789abcdef"
    nodes = _nodes()
    async with postgres_checkpointer(dsn, key, setup=True) as checkpointer:
        first_service = RemediationService(build_graph(nodes, checkpointer), max_active_runs=1)
        waiting = await first_service.start(diagnosis_handoff())
    request = waiting.approval_request
    assert request is not None

    async with postgres_checkpointer(dsn, key) as recreated:
        second_service = RemediationService(build_graph(nodes, recreated), max_active_runs=1)
        completed = await second_service.approve(
            waiting.run_id,
            ApprovalDecisionV1(
                approval_id=request.approval_id,
                scope_digest=request.scope_digest,
                status=ApprovalStatus.APPROVED,
                reviewer_id="postgres-test",
                decided_at=datetime.now(UTC),
            ),
        )
    assert completed.status is FinalStatus.DRAFT_PR_PREPARED
