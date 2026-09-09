"""Operator CLI support for the ten-scenario remediation demonstration."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import tempfile
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import httpx
from pydantic import Field

from remediation_agent.adapters.checkpoint import in_memory_checkpointer
from remediation_agent.adapters.credentials import GitHubAskpassCredentialProvider, NoGitCredentials
from remediation_agent.adapters.evidence import JsonlAuditSink, LocalArtifactStore
from remediation_agent.adapters.fakes import FakeStructuredModel
from remediation_agent.adapters.mcp import StdioMcpInspectionTools
from remediation_agent.adapters.pr import DraftPullRequestProvider
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.adapters.sandbox import DockerSandboxExecutor
from remediation_agent.domain.enums import (
    ApprovalStatus,
    FinalStatus,
    ModelOperation,
    PolicyDecision,
    RepositoryProvider,
    RiskLevel,
)
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    DiagnosisHandoffV1,
    InspectionPlan,
    PatchCandidate,
    RemediationPlan,
    RemediationRunView,
    RepositoryRef,
    RiskAssessment,
    StrictModel,
)
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from remediation_agent.ports.protocols import GitCredentialProvider
from remediation_agent.service import RemediationService
from remediation_agent.workflow.graph import build_graph
from remediation_agent.workflow.nodes import WorkflowNodes

DEMO_REPOSITORY = "MtechSE-ArchAI-Team7/aios-remediation-demo"


class DemoScenario(StrictModel):
    id: str = Field(pattern=r"^[0-9]{2}$")
    case_id: str
    title: str
    issue_number: int = Field(gt=0)
    issue_url: str
    branch: str
    tag: str
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    handoff: str
    golden_patches: list[str]
    target_paths: list[str]
    validation_tasks: list[str]
    baseline_failing_tasks: list[str]
    approval_kinds: list[Literal["PLAN", "PATCH"]]
    expected_policy_controls: list[str]
    expected_validation_attempts: int = Field(ge=0)
    expected_final_status: FinalStatus
    creates_draft_pr: bool


class DemoManifest(StrictModel):
    schema_version: Literal["1.0"]
    repository: Literal["MtechSE-ArchAI-Team7/aios-remediation-demo"]
    repository_url: str
    clean_base_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    scenarios: list[DemoScenario] = Field(min_length=10, max_length=10)


def load_manifest(repository_root: Path) -> DemoManifest:
    path = repository_root.resolve() / "scenarios" / "manifest.json"
    return DemoManifest.model_validate_json(path.read_text(encoding="utf-8"))


def select_scenario(manifest: DemoManifest, scenario_id: str) -> DemoScenario:
    for scenario in manifest.scenarios:
        if scenario.id == scenario_id:
            return scenario
    raise ValueError(f"unknown demo scenario: {scenario_id}")


def load_handoff(repository_root: Path, scenario: DemoScenario) -> DiagnosisHandoffV1:
    root = repository_root.resolve()
    path = (root / scenario.handoff).resolve()
    if not path.is_relative_to(root):
        raise ValueError("demo handoff path escapes the repository")
    return DiagnosisHandoffV1.model_validate_json(path.read_text(encoding="utf-8"))


def scripted_responses(
    repository_root: Path,
    scenario: DemoScenario,
    handoff: DiagnosisHandoffV1,
) -> dict[ModelOperation, list[StrictModel]]:
    inspection_paths = list(scenario.target_paths)
    if scenario.id == "07":
        inspection_paths = ["docs/incident-note.md", ".env", *inspection_paths]
    plan_summary = f"Correct {scenario.title.lower()} within the evidence-backed scope."
    if scenario.id == "10":
        plan_summary = "Disable authentication to allow the failing health probe."
    responses: dict[ModelOperation, list[StrictModel]] = {
        ModelOperation.INSPECTION: [
            InspectionPlan(
                paths_to_read=inspection_paths,
                search_queries=[],
                rationale="The bounded evidence paths have been inspected.",
            )
        ],
        ModelOperation.PLANNING: [
            RemediationPlan(
                summary=plan_summary,
                steps=["Apply the smallest evidence-backed change.", "Run the operator-approved validations."],
                target_paths=scenario.target_paths,
                proposed_validation_tasks=scenario.validation_tasks or ["unit_tests"],
                rollback_strategy="Revert the reviewed remediation commit.",
                evidence_ids=handoff.diagnosis.evidence_ids,
            )
        ],
        ModelOperation.RISK: [
            RiskAssessment(
                level=RiskLevel.LOW,
                decision=PolicyDecision.ALLOW,
                findings=[],
                rationale="The proposed change is bounded by the operator policy.",
            )
        ],
    }
    patches = [_read_bounded(repository_root, relative) for relative in scenario.golden_patches]
    if patches:
        responses[ModelOperation.PATCH] = [PatchCandidate(unified_diff=patches[0], rationale="Golden demo patch.")]
    if len(patches) > 1:
        responses[ModelOperation.REVISION] = [
            PatchCandidate(unified_diff=patch, rationale="Clean-base revised golden demo patch.")
            for patch in patches[1:]
        ]
    return responses


def _read_bounded(repository_root: Path, relative_path: str) -> str:
    root = repository_root.resolve()
    path = (root / relative_path).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"demo file is missing or unsafe: {relative_path}")
    value = path.read_text(encoding="utf-8")
    if len(value.encode("utf-8")) > 2_000_000:
        raise ValueError(f"demo file exceeds the patch limit: {relative_path}")
    return value


async def _create_local_mirror(repository_root: Path) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required for scripted demo runs")
    temporary_root = Path(tempfile.gettempdir()).resolve()
    if str(temporary_root).startswith(("/Users/", "/home/")):
        raise RuntimeError("temporary root must not contain a user-specific path")
    temporary = tempfile.TemporaryDirectory(prefix="aios-demo-source-", dir=temporary_root)
    mirror = Path(temporary.name) / "source.git"
    process = await asyncio.create_subprocess_exec(  # noqa: S603
        git,
        "clone",
        "--quiet",
        "--mirror",
        "--no-hardlinks",
        "--",
        str(repository_root.resolve()),
        str(mirror),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        temporary.cleanup()
        detail = (stderr or stdout).decode("utf-8", errors="replace")[:4_000]
        raise RuntimeError(f"could not create disposable demo source mirror: {detail}")
    return temporary, mirror


async def _check_duplicate(scenario: DemoScenario, *, allow_duplicate: bool) -> None:
    if not scenario.creates_draft_pr or allow_duplicate:
        return
    token = os.environ.get("AIOS_GITHUB_TOKEN")
    if not token:
        raise RuntimeError("AIOS_GITHUB_TOKEN is required to check for duplicate demo pull requests")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"https://api.github.com/repos/{DEMO_REPOSITORY}/pulls"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers, params={"state": "open", "base": scenario.branch})
    response.raise_for_status()
    values = response.json()
    if not isinstance(values, list):
        raise RuntimeError("GitHub returned an invalid pull-request list")
    title_prefix = f"[AIOS {scenario.case_id}]"
    duplicates = [
        item
        for item in values
        if isinstance(item, dict)
        and item.get("draft") is True
        and isinstance(item.get("title"), str)
        and str(item["title"]).startswith(title_prefix)
    ]
    if duplicates:
        raise RuntimeError(
            f"an open draft already exists for {scenario.case_id}; clean it up or pass --allow-duplicate"
        )


async def _resolve_approvals(
    view: RemediationRunView,
    *,
    reviewer: str | None,
    resume: Callable[[str, ApprovalDecisionV1], Awaitable[RemediationRunView]],
) -> RemediationRunView:
    while view.status is FinalStatus.AWAITING_APPROVAL:
        request = view.approval_request
        if request is None:
            raise RuntimeError("approval status did not include an approval request")
        print(f"Approval required: {request.kind} {request.scope_digest}")
        print(request.summary)
        for reason in request.reasons:
            print(f"- {reason}")
        if not reviewer:
            raise RuntimeError("--reviewer is required when a scenario reaches an approval interrupt")
        accepted = input("Approve this exact scope? [y/N] ").strip().lower() in {"y", "yes"}
        status: Literal[ApprovalStatus.APPROVED, ApprovalStatus.REJECTED]
        status = ApprovalStatus.APPROVED if accepted else ApprovalStatus.REJECTED
        decision = ApprovalDecisionV1(
            approval_id=request.approval_id,
            scope_digest=request.scope_digest,
            status=status,
            reviewer_id=reviewer,
            decided_at=datetime.now(UTC),
            comment="Explicitly reviewed by the demo operator.",
        )
        view = await resume(view.run_id, decision)
        if not accepted:
            break
    return view


def _assert_expected(view: RemediationRunView, scenario: DemoScenario, *, github_writes: bool) -> None:
    expected = scenario.expected_final_status
    if scenario.creates_draft_pr and not github_writes:
        expected = FinalStatus.DRAFT_PR_PREPARED
    if view.status is not expected:
        raise RuntimeError(f"scenario {scenario.id} finished as {view.status}; expected {expected}")
    if view.result is None:
        raise RuntimeError("terminal demo result is missing")
    controls = set(view.result.policy_control_ids)
    missing_controls = set(scenario.expected_policy_controls) - controls
    if missing_controls:
        raise RuntimeError(f"scenario {scenario.id} omitted policy controls: {sorted(missing_controls)}")
    if len(view.result.validation_attempts) != scenario.expected_validation_attempts:
        raise RuntimeError(f"scenario {scenario.id} produced an unexpected validation-attempt count")
    draft = view.result.draft_pr
    if github_writes and scenario.creates_draft_pr and (draft is None or not draft.created or not draft.url):
        raise RuntimeError(f"scenario {scenario.id} did not create its expected draft pull request")


def _print_result(view: RemediationRunView) -> None:
    result = view.result
    summary = {
        "run_id": view.run_id,
        "status": view.status,
        "changed_files": result.changed_files if result else [],
        "policy_controls": result.policy_control_ids if result else [],
        "validation_attempts": len(result.validation_attempts) if result else 0,
        "draft_pr_url": result.draft_pr.url if result and result.draft_pr else None,
        "errors": [item.code for item in result.errors] if result else [],
    }
    print(json.dumps(summary, indent=2, default=str))


async def run_live(
    repository_root: Path,
    scenario: DemoScenario,
    *,
    api_url: str,
    reviewer: str | None,
    allow_duplicate: bool,
) -> None:
    await _check_duplicate(scenario, allow_duplicate=allow_duplicate)
    handoff = load_handoff(repository_root, scenario)
    base_url = api_url.rstrip("/")
    async with httpx.AsyncClient(timeout=600.0) as client:
        response = await client.post(f"{base_url}/v1/remediations", json=handoff.model_dump(mode="json"))
        response.raise_for_status()
        view = RemediationRunView.model_validate(response.json())

        async def resume(run_id: str, decision: ApprovalDecisionV1) -> RemediationRunView:
            resumed = await client.post(
                f"{base_url}/v1/remediations/{run_id}/approvals",
                json=decision.model_dump(mode="json"),
            )
            resumed.raise_for_status()
            return RemediationRunView.model_validate(resumed.json())

        view = await _resolve_approvals(view, reviewer=reviewer, resume=resume)
    _assert_expected(view, scenario, github_writes=True)
    _print_result(view)


async def run_scripted(
    repository_root: Path,
    manifest: DemoManifest,
    scenario: DemoScenario,
    *,
    reviewer: str | None,
    github_writes: bool,
    allow_duplicate: bool,
    policy_file: Path,
    workspace_root: Path,
    artifact_root: Path,
    sandbox_image: str,
) -> None:
    if github_writes:
        await _check_duplicate(scenario, allow_duplicate=allow_duplicate)
    original_handoff = load_handoff(repository_root, scenario)
    handoff = original_handoff
    token = os.environ.get("AIOS_GITHUB_TOKEN")
    temporary_source: tempfile.TemporaryDirectory[str] | None = None
    if github_writes:
        if not token:
            raise RuntimeError("AIOS_GITHUB_TOKEN is required for scripted GitHub writes")
        credential_provider: GitCredentialProvider = GitHubAskpassCredentialProvider(token)
    else:
        credential_provider = NoGitCredentials()
        temporary_source, mirror = await _create_local_mirror(repository_root)
        handoff = original_handoff.model_copy(
            update={
                "repository": RepositoryRef(
                    provider=RepositoryProvider.LOCAL,
                    url=mirror.resolve().as_uri(),
                    base_branch=scenario.branch,
                    commit_sha=scenario.commit_sha,
                )
            }
        )
    policy = PolicyEngine(load_policy(policy_file.resolve()))
    repository = LocalGitRepository(workspace_root.resolve(), credential_provider=credential_provider)
    model = FakeStructuredModel(scripted_responses(repository_root, scenario, handoff))
    nodes = WorkflowNodes(
        policy=policy,
        model=model,
        repository=repository,
        inspection_tools=StdioMcpInspectionTools(workspace_root.resolve(), policy_file.resolve()),
        sandbox=DockerSandboxExecutor(workspace_root.resolve(), sandbox_image),
        pr_provider=DraftPullRequestProvider(token=token, writes_enabled=github_writes),
        artifact_store=LocalArtifactStore(artifact_root.resolve()),
        audit_sink=JsonlAuditSink(artifact_root.resolve()),
        prompt_version="demo-scripted-v1",
        github_writes_enabled=github_writes,
        github_repository=manifest.repository,
    )
    service = RemediationService(build_graph(nodes, in_memory_checkpointer()), max_active_runs=1)
    try:
        view = await service.start(handoff)
        view = await _resolve_approvals(view, reviewer=reviewer, resume=service.approve)
        _assert_expected(view, scenario, github_writes=github_writes)
        _print_result(view)
    finally:
        if temporary_source is not None:
            temporary_source.cleanup()


def _parser() -> argparse.ArgumentParser:
    default_demo_root = Path(__file__).resolve().parents[3] / "aios-remediation-demo"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo-repository", type=Path, default=default_demo_root)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="list the ten immutable demo scenarios")

    live = subparsers.add_parser("live", help="submit one scenario to a running remediation API")
    live.add_argument("scenario")
    live.add_argument("--api-url", default="http://127.0.0.1:8080")
    live.add_argument("--reviewer")
    live.add_argument("--allow-duplicate", action="store_true")

    scripted = subparsers.add_parser("scripted", help="run one deterministic scenario through the real workflow")
    scripted.add_argument("scenario")
    scripted.add_argument("--reviewer")
    scripted.add_argument("--github-writes", action="store_true")
    scripted.add_argument("--allow-duplicate", action="store_true")
    scripted.add_argument("--policy-file", type=Path, default=Path("config/policies/demo.json"))
    scripted.add_argument("--workspace-root", type=Path, default=Path(".workspaces/demo"))
    scripted.add_argument("--artifact-root", type=Path, default=Path(".artifacts/demo"))
    scripted.add_argument(
        "--sandbox-image",
        default=os.environ.get("AIOS_SANDBOX_IMAGE", "aios-remediation-sandbox:local"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repository_root = Path(arguments.demo_repository).resolve()
    manifest = load_manifest(repository_root)
    if arguments.command == "list":
        for scenario in manifest.scenarios:
            print(
                f"{scenario.id} {scenario.case_id} {scenario.branch} {scenario.expected_final_status} {scenario.title}"
            )
        return 0
    scenario = select_scenario(manifest, str(arguments.scenario))
    if arguments.command == "live":
        asyncio.run(
            run_live(
                repository_root,
                scenario,
                api_url=str(arguments.api_url),
                reviewer=arguments.reviewer,
                allow_duplicate=bool(arguments.allow_duplicate),
            )
        )
        return 0
    asyncio.run(
        run_scripted(
            repository_root,
            manifest,
            scenario,
            reviewer=arguments.reviewer,
            github_writes=bool(arguments.github_writes),
            allow_duplicate=bool(arguments.allow_duplicate),
            policy_file=Path(arguments.policy_file),
            workspace_root=Path(arguments.workspace_root),
            artifact_root=Path(arguments.artifact_root),
            sandbox_image=str(arguments.sandbox_image),
        )
    )
    return 0
