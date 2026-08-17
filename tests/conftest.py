"""Shared deterministic builders for remediation workflow tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from langchain_core.messages import AIMessage
from pydantic import BaseModel

from remediation_agent.adapters.checkpoint import in_memory_checkpointer
from remediation_agent.adapters.fakes import (
    FakeInspectionToolProvider,
    FakePullRequestProvider,
    FakeRepository,
    FakeSandboxExecutor,
    FakeStructuredModel,
    MemoryArtifactStore,
    MemoryAuditSink,
)
from remediation_agent.domain.enums import (
    ModelOperation,
    PolicyDecision,
    RemediationType,
    RepositoryProvider,
    RiskLevel,
    ValidationOutcome,
)
from remediation_agent.domain.models import (
    Diagnosis,
    DiagnosisHandoffV1,
    EvidenceRecord,
    InspectionPlan,
    PatchCandidate,
    RemediationPlan,
    RepositoryRef,
    RiskAssessment,
)
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from remediation_agent.ports.protocols import InspectionToolProvider
from remediation_agent.service import RemediationService
from remediation_agent.workflow.graph import build_graph
from remediation_agent.workflow.nodes import WorkflowNodes


def diagnosis_handoff(
    *,
    remediation_type: RemediationType = RemediationType.CODE,
    contradictions: list[str] | None = None,
) -> DiagnosisHandoffV1:
    return DiagnosisHandoffV1(
        case_id="CASE-123",
        issue_summary="Application rejects malformed user input.",
        remediation_type=remediation_type,
        diagnosis=Diagnosis(
            summary="An unhandled integer conversion raises ValueError.",
            confidence=0.94,
            evidence_ids=["evidence-1"],
            contradictions=contradictions or [],
        ),
        supporting_evidence=[
            EvidenceRecord(
                evidence_id="evidence-1",
                source_type="application_log",
                source_locator="logs/request-42",
                observed_at=datetime(2026, 8, 1, tzinfo=UTC),
                digest="sha256:evidence",
                excerpt="ValueError: invalid literal for int()",
            )
        ],
        acceptance_criteria=["Malformed values return a typed client error."],
        repository=RepositoryRef(
            provider=RepositoryProvider.LOCAL,
            url="fixture-repository",
            base_branch="main",
            commit_sha="a" * 40,
        ),
    )


def patch_for(path: str = "src/app.py", *, old: str = "value = int(raw)", new: str = "value = safe_int(raw)") -> str:
    return f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-{old}\n+{new}\n"


def scripted_responses(
    *,
    target_path: str = "src/app.py",
    target_paths: list[str] | None = None,
    plan_summary: str = "Handle invalid integer conversion.",
    risk_level: RiskLevel = RiskLevel.LOW,
    risk_decision: PolicyDecision = PolicyDecision.ALLOW,
    patch: str | None = None,
    revisions: list[str] | None = None,
    tasks: list[str] | None = None,
) -> dict[ModelOperation, list[BaseModel | dict[str, object]]]:
    configured_tasks = tasks or ["unit_tests"]
    responses: dict[ModelOperation, list[BaseModel | dict[str, object]]] = {
        ModelOperation.INSPECTION: [
            InspectionPlan(paths_to_read=[target_path], search_queries=["int("], rationale="Inspect evidence path.")
        ],
        ModelOperation.PLANNING: [
            RemediationPlan(
                summary=plan_summary,
                steps=["Implement the smallest evidence-backed change.", "Preserve and extend tests."],
                target_paths=target_paths or [target_path],
                proposed_validation_tasks=configured_tasks,
                rollback_strategy="Revert the proposed commit.",
                evidence_ids=["evidence-1"],
            )
        ],
        ModelOperation.RISK: [
            RiskAssessment(level=risk_level, decision=risk_decision, rationale="Bounded fixture change.")
        ],
        ModelOperation.PATCH: [PatchCandidate(unified_diff=patch or patch_for(target_path), rationale="Bounded fix.")],
    }
    if revisions:
        responses[ModelOperation.REVISION] = [
            PatchCandidate(unified_diff=value, rationale=f"Revision {index}.")
            for index, value in enumerate(revisions, start=1)
        ]
    return responses


def build_test_service(
    responses: dict[ModelOperation, list[BaseModel | dict[str, object]]],
    *,
    files: dict[str, str] | None = None,
    task_outcomes: dict[str, list[ValidationOutcome]] | None = None,
    cleanup_succeeds: bool = True,
    tampered_diff: str | None = None,
    tool_turns: list[AIMessage] | None = None,
    inspection_tool_provider: InspectionToolProvider | None = None,
    max_inspection_rounds: int | None = None,
    max_inspection_tool_calls: int | None = None,
    max_mcp_tool_timeout_seconds: int | None = None,
) -> tuple[
    RemediationService,
    FakeStructuredModel,
    FakeRepository,
    FakeSandboxExecutor,
    FakePullRequestProvider,
    MemoryArtifactStore,
    MemoryAuditSink,
]:
    policy_path = Path(__file__).parents[1] / "config" / "policies" / "reference.json"
    policy_config = load_policy(policy_path)
    limit_updates = {
        key: value
        for key, value in {
            "max_inspection_rounds": max_inspection_rounds,
            "max_inspection_tool_calls": max_inspection_tool_calls,
            "max_mcp_tool_timeout_seconds": max_mcp_tool_timeout_seconds,
        }.items()
        if value is not None
    }
    if limit_updates:
        policy_config = policy_config.model_copy(
            update={"limits": policy_config.limits.model_copy(update=limit_updates)}
        )
    policy = PolicyEngine(policy_config)
    model = FakeStructuredModel(responses, tool_turns=tool_turns or ())
    repository = FakeRepository(files=files or {"src/app.py": "value = int(raw)\n"})
    inspection_tools = inspection_tool_provider or FakeInspectionToolProvider(repository, policy)
    sandbox = FakeSandboxExecutor(
        task_outcomes,
        cleanup_succeeds=cleanup_succeeds,
        repository=repository,
        tampered_diff=tampered_diff,
    )
    pr_provider = FakePullRequestProvider()
    artifacts = MemoryArtifactStore()
    audit = MemoryAuditSink()
    nodes = WorkflowNodes(
        policy=policy,
        model=model,
        repository=repository,
        inspection_tools=inspection_tools,
        sandbox=sandbox,
        pr_provider=pr_provider,
        artifact_store=artifacts,
        audit_sink=audit,
        prompt_version="test-prompt-v1",
    )
    graph = build_graph(nodes, in_memory_checkpointer())
    return (
        RemediationService(graph, max_active_runs=2),
        model,
        repository,
        sandbox,
        pr_provider,
        artifacts,
        audit,
    )
