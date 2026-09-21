#!/usr/bin/env python3
"""Run the deterministic or opt-in hosted assessment evaluation."""

from __future__ import annotations

import argparse
import asyncio
import tarfile
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel

from remediation_agent.adapters.agentcore_sandbox import AgentCoreCodeInterpreterSandbox
from remediation_agent.adapters.checkpoint import in_memory_checkpointer
from remediation_agent.adapters.credentials import GitHubAskpassCredentialProvider
from remediation_agent.adapters.evidence import JsonlAuditSink, LocalArtifactStore
from remediation_agent.adapters.fakes import (
    FakeInspectionToolProvider,
    FakePullRequestProvider,
    FakeRepository,
    FakeSandboxExecutor,
    FakeStructuredModel,
    MemoryArtifactStore,
    MemoryAuditSink,
)
from remediation_agent.adapters.mcp import GitHubRemoteMcpInspectionTools
from remediation_agent.adapters.models import build_structured_model
from remediation_agent.adapters.pr import DraftPullRequestProvider
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.config import Settings
from remediation_agent.domain.enums import ModelOperation, PolicyDecision, RiskLevel
from remediation_agent.domain.models import (
    DiagnosisHandoffV1,
    InspectionPlan,
    PatchCandidate,
    RemediationPlan,
    RiskAssessment,
)
from remediation_agent.evaluation import (
    EvaluationManifest,
    EvaluationRun,
    aggregate_evaluations,
    load_evaluation,
    load_evaluation_manifest,
    render_assessment_report,
    score_evaluation,
    write_evaluation,
)
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from remediation_agent.service import RemediationService
from remediation_agent.workflow.graph import build_graph
from remediation_agent.workflow.nodes import WorkflowNodes

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "config/evaluation/division-by-zero.json"
DEFAULT_DETERMINISTIC = ROOT / ".artifacts/evaluation/deterministic/evaluation.json"
DEFAULT_HOSTED = ROOT / ".artifacts/evaluation/hosted/evaluation.json"
DEFAULT_REPORT = ROOT / "docs/ASSESSMENT_EVIDENCE.md"


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subparsers = command.add_subparsers(dest="command", required=True)
    for name in ("deterministic", "hosted"):
        child = subparsers.add_parser(name)
        child.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
        child.add_argument(
            "--output",
            type=Path,
            default=DEFAULT_DETERMINISTIC if name == "deterministic" else DEFAULT_HOSTED,
        )
    hosted = subparsers.choices["hosted"]
    hosted.add_argument("--trials", type=int, default=1)
    report = subparsers.add_parser("report")
    report.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    report.add_argument("--deterministic", type=Path, default=DEFAULT_DETERMINISTIC)
    report.add_argument("--hosted", type=Path, default=DEFAULT_HOSTED)
    report.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    return command


async def run_deterministic(manifest_path: Path, output: Path) -> bool:
    manifest, handoff = _load_inputs(manifest_path)
    policy = PolicyEngine(load_policy(ROOT / manifest.policy_path))
    responses = _scripted_responses(handoff)
    model = FakeStructuredModel(responses)
    repository = FakeRepository(
        files={
            "server.js": "const average = total / count;\n",
            "package.json": '{"name":"buggy-ecommerce-demo"}\n',
        },
        base_commit=cast(str, handoff.repository.commit_sha),
    )
    inspection = FakeInspectionToolProvider(repository, policy)
    sandbox = FakeSandboxExecutor(repository=repository)
    pr_provider = FakePullRequestProvider()
    artifacts = MemoryArtifactStore()
    audit = MemoryAuditSink()
    nodes = WorkflowNodes(
        policy=policy,
        model=model,
        repository=repository,
        inspection_tools=inspection,
        sandbox=sandbox,
        pr_provider=pr_provider,
        artifact_store=artifacts,
        audit_sink=audit,
        prompt_version="assessment-deterministic-v1",
        github_writes_enabled=False,
        github_repository=None,
    )
    service = RemediationService(
        build_graph(nodes, in_memory_checkpointer()),
        max_active_runs=1,
    )
    view = await service.start(handoff, run_id="00000000-0000-4000-8000-000000000001")
    evaluation = score_evaluation(
        manifest=manifest,
        mode="deterministic",
        view=view,
        source_commit=cast(str, handoff.repository.commit_sha),
        cleanup_succeeded=sandbox.destroyed and sandbox.cleanup_succeeds,
        remote_objects_created=len(repository.branches) + len(repository.commits) + len(repository.pushes),
        artifact_paths=[manifest_path, ROOT / manifest.handoff_path, ROOT / manifest.policy_path],
    )
    write_evaluation(output, evaluation)
    print(f"deterministic evaluation: {evaluation.passed_trials}/{evaluation.trial_count} -> {output}")
    return evaluation.passed


async def run_hosted(manifest_path: Path, output: Path, trials: int) -> bool:
    manifest, handoff = _load_inputs(manifest_path)
    if trials < 1 or trials > manifest.maximum_trials:
        raise ValueError(f"hosted trials must be between 1 and {manifest.maximum_trials}")
    settings = Settings()  # type: ignore[call-arg]
    if settings.llm_provider == "fake":
        raise ValueError("hosted evaluation requires a real model provider")
    if settings.aws_region is None:
        raise ValueError("AIOS_AWS_REGION is required for AgentCore Code Interpreter")
    github_token = settings.require_github_token()
    policy_config = load_policy(ROOT / manifest.policy_path)
    policy = PolicyEngine(policy_config)
    run_root = output.parent.resolve()
    workspace_root = run_root / "workspaces"
    artifact_root = run_root / "evidence"
    bundle = settings.code_interpreter_bundle
    if not bundle.is_file():
        bundle = run_root / "empty-validation-bundle.tar.gz"
        _empty_bundle(bundle)
    model = build_structured_model(
        settings,
        policy_config.limits.max_model_output_tokens,
        policy_config.limits.max_model_format_retries,
    )
    repository = LocalGitRepository(
        workspace_root,
        author_name=settings.git_author_name,
        author_email=settings.git_author_email,
        credential_provider=GitHubAskpassCredentialProvider(github_token),
    )
    # Both independent application gates are hard-off, regardless of ambient settings.
    pr_provider = DraftPullRequestProvider(token=None, writes_enabled=False)
    nodes = WorkflowNodes(
        policy=policy,
        model=model,
        repository=repository,
        inspection_tools=GitHubRemoteMcpInspectionTools(github_token, policy),
        sandbox=AgentCoreCodeInterpreterSandbox(
            workspace_root,
            region_name=settings.aws_region,
            code_interpreter_identifier=settings.code_interpreter_identifier,
            validation_bundle=bundle,
        ),
        pr_provider=pr_provider,
        artifact_store=LocalArtifactStore(artifact_root),
        audit_sink=JsonlAuditSink(artifact_root),
        prompt_version=settings.prompt_version,
        github_writes_enabled=False,
        github_repository=None,
    )
    service = RemediationService(build_graph(nodes, in_memory_checkpointer()), max_active_runs=1)
    evaluations: list[EvaluationRun] = []
    try:
        for trial in range(1, trials + 1):
            view = await service.start(handoff, run_id=f"00000000-0000-4000-8000-{trial + 1:012d}")
            cleanup_succeeded = bool(
                view.explainability
                and any(
                    event.event_type == "WORKSPACE_CLEANUP" and event.status == "OK"
                    for event in view.explainability.events
                )
            )
            evaluations.append(
                score_evaluation(
                    manifest=manifest,
                    mode="hosted",
                    view=view,
                    source_commit=cast(str, handoff.repository.commit_sha),
                    cleanup_succeeded=cleanup_succeeded,
                    remote_objects_created=(
                        1 if view.result and view.result.draft_pr and view.result.draft_pr.created else 0
                    ),
                    artifact_paths=[manifest_path, ROOT / manifest.handoff_path, ROOT / manifest.policy_path],
                )
            )
    finally:
        await model.aclose()
    evaluation = evaluations[0] if len(evaluations) == 1 else aggregate_evaluations(evaluations)
    write_evaluation(output, evaluation)
    print(f"hosted demonstration: {evaluation.passed_trials}/{evaluation.trial_count} -> {output}")
    return evaluation.passed


def write_report(args: argparse.Namespace) -> None:
    manifest = load_evaluation_manifest(args.manifest)
    deterministic = load_evaluation(args.deterministic) if args.deterministic.is_file() else None
    hosted = load_evaluation(args.hosted) if args.hosted.is_file() else None
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_assessment_report(manifest, deterministic, hosted), encoding="utf-8")
    print(f"assessment report -> {args.output}")


def _load_inputs(path: Path) -> tuple[EvaluationManifest, DiagnosisHandoffV1]:
    manifest = load_evaluation_manifest(path)
    handoff = DiagnosisHandoffV1.model_validate_json((ROOT / manifest.handoff_path).read_text(encoding="utf-8"))
    if handoff.case_id != manifest.scenario_id:
        raise ValueError("evaluation manifest scenario does not match the handoff")
    if handoff.repository.commit_sha is None:
        raise ValueError("evaluation handoff must pin an immutable commit")
    return manifest, handoff


def _scripted_responses(
    handoff: DiagnosisHandoffV1,
) -> dict[ModelOperation, list[BaseModel | dict[str, object]]]:
    evidence_ids = handoff.diagnosis.evidence_ids
    patch = (
        "--- a/server.js\n"
        "+++ b/server.js\n"
        "@@ -1 +1 @@\n"
        "-const average = total / count;\n"
        "+const average = count === 0 ? null : total / count;\n"
    )
    return {
        ModelOperation.INSPECTION: [
            InspectionPlan(
                paths_to_read=["server.js"],
                search_queries=["calculate-average"],
                rationale="Inspect pinned route.",
            )
        ],
        ModelOperation.PLANNING: [
            RemediationPlan(
                summary="Reject a zero divisor while preserving finite division.",
                steps=["Add the bounded guard.", "Run operator-owned JavaScript validations."],
                target_paths=["server.js"],
                proposed_validation_tasks=["javascript_syntax", "average_regression"],
                rollback_strategy="Discard the prepared patch.",
                evidence_ids=evidence_ids,
            )
        ],
        ModelOperation.RISK: [
            RiskAssessment(level=RiskLevel.LOW, decision=PolicyDecision.ALLOW, rationale="Autonomous fixture path.")
        ],
        ModelOperation.PATCH: [PatchCandidate(unified_diff=patch, rationale="Bounded zero-divisor guard.")],
    }


def _empty_bundle(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz"):
        pass


def main() -> int:
    args = parser().parse_args()
    if args.command == "report":
        write_report(args)
        return 0
    mode = cast(Literal["deterministic", "hosted"], args.command)
    passed = asyncio.run(
        run_deterministic(args.manifest, args.output)
        if mode == "deterministic"
        else run_hosted(args.manifest, args.output, args.trials)
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
