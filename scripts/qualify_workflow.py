"""Opt-in generated workflow qualification. Never delivers a diagnosis or writes to GitHub.

Immutable application archives, real model/inspection/Git/sandbox, isolated test approvals,
and a strict simulated GitHub MCP boundary. This is release evidence, not a native replay.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import cast

from remediation_agent.adapters.agentcore_sandbox import AgentCoreCodeInterpreterSandbox
from remediation_agent.adapters.checkpoint import in_memory_checkpointer
from remediation_agent.adapters.evidence import JsonlAuditSink, LocalArtifactStore
from remediation_agent.adapters.models import build_structured_model
from remediation_agent.adapters.pr import DraftPullRequestProvider
from remediation_agent.adapters.pr_fixture import SimulatedGitHubPrMcp
from remediation_agent.adapters.provenance import LocalReleaseProvenance
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.adapters.sandbox import DockerSandboxExecutor
from remediation_agent.adapters.snapshot_inspection import SnapshotInspectionTools
from remediation_agent.config import Settings
from remediation_agent.domain.enums import ApprovalStatus, FinalStatus, RemediationType, RepositoryProvider
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    Diagnosis,
    DiagnosisHandoffV1,
    EvidenceRecord,
    RepositoryRef,
    WorkspaceRef,
)
from remediation_agent.domain.qualification import QualificationTrialV1, ReleaseQualificationV1
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from remediation_agent.ports.models import PublicationCheckRequest
from remediation_agent.service import RemediationService
from remediation_agent.workflow.graph import build_graph
from remediation_agent.workflow.nodes import WorkflowNodes
from remediation_agent.workflow.state import RemediationState

ROOT = Path(__file__).resolve().parents[1]


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def git(root: Path, *args: str) -> str:
    # Operator-owned fixture commands only; no model values or shell.
    environment = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_DATE": "2026-10-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-10-01T00:00:00Z",
    }
    return subprocess.run(  # noqa: S603 - fixed qualification fixture commands
        ["git", "-c", "core.hooksPath=/dev/null", *args],  # noqa: S607
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()  # noqa: S603,S607


class SnapshotRepository(LocalGitRepository):
    def __init__(self, root: Path, remote: Path):
        super().__init__(root)
        self.remote = remote

    async def create_workspace(self, ref: RepositoryRef) -> WorkspaceRef:
        return await super().create_workspace(ref.model_copy(update={"url": str(self.remote)}))

    async def publication_check(self, request: PublicationCheckRequest) -> str:
        return await super().publication_check(
            request.model_copy(update={"repository": request.repository.model_copy(update={"url": str(self.remote)})})
        )


def initialize_snapshot(directory: Path, case: str) -> tuple[Path, str, dict[str, str]]:
    snapshots = ROOT / "config/evaluation/release-snapshots"
    manifest = cast(dict[str, dict[str, str]], json.loads((snapshots / "manifest.json").read_text()))
    entry = manifest[case]
    archive = snapshots / entry["archive"]
    if sha(archive.read_bytes()) != entry["archive_digest"]:
        raise ValueError("QUALIFICATION_SNAPSHOT_DIGEST_MISMATCH")
    source = directory / "source"
    source.mkdir()
    with tarfile.open(archive) as stream:
        for member in stream.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError("UNSAFE_QUALIFICATION_SNAPSHOT")
            relative = Path(*path.parts[1:])
            if not member.isfile() or not relative.parts:
                continue
            payload = stream.extractfile(member)
            if payload is None:
                raise ValueError("INVALID_QUALIFICATION_SNAPSHOT")
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload.read())
    git(source, "init", "-b", "main")
    git(source, "config", "user.name", "AIOS isolated qualification")
    git(source, "config", "user.email", "qualification@example.invalid")
    git(source, "add", ".")
    git(source, "commit", "-m", "immutable qualification snapshot")
    base = git(source, "rev-parse", "HEAD")
    remote = directory / "remote.git"
    git(directory, "clone", "--bare", str(source), str(remote))
    return remote, base, entry


def handoff(case: str, base: str, snapshot: dict[str, str]) -> DiagnosisHandoffV1:
    # Explicit isolated test inputs, derived from the approved scope, never sent to a runtime endpoint.
    criteria = (
        [
            (
                "POST /purchase accepts numeric JSON below or equal to stock and atomically "
                "persists a decrement; reject overstock, malformed/string/form inputs and "
                "unknown products; survive restart and prevent concurrent overselling."
            )
        ]
        if case == "ah54"
        else [
            (
                "POST /checkout persists an order before returning the existing success "
                "response, totals multiple products using database prices, rejects invalid or "
                "unknown carts and failed writes, and retains orders after restart."
            ),
            (
                "The actual storefront waits for checkout confirmation, retains its cart on "
                "HTTP or network failure, and clears the cart and shows success only after "
                "persisted checkout succeeds."
            ),
        ]
    )
    return DiagnosisHandoffV1(
        case_id=f"QUALIFICATION-{case.upper()}",
        jira_ticket_id=f"QUALIFICATION-{case[2:]}",
        issue_summary=criteria[0],
        remediation_type=RemediationType.CODE,
        diagnosis=Diagnosis(
            summary=(
                "Purchase stock comparison rejects valid purchases."
                if case == "ah54"
                else (
                    "Checkout returns success without writing an order and the storefront "
                    "announces success before awaiting the response. Email, user association, "
                    "line items, inventory/idempotency and a specific order status are "
                    "explicitly out of scope."
                )
            ),
            confidence=0.99,
            evidence_ids=["snapshot"],
        ),
        supporting_evidence=[
            EvidenceRecord(
                evidence_id="snapshot",
                source_type="immutable_source",
                source_locator=snapshot["repository"] + "/commit/" + snapshot["source_commit"],
                observed_at=datetime(2026, 10, 1, tzinfo=UTC),
                digest=snapshot["archive_digest"],
                excerpt=(
                    "Inspect server.js, schema.sql, seed.sql, public/app.js, public/index.html "
                    "and package.json from the sealed source snapshot."
                ),
            )
        ],
        acceptance_criteria=criteria,
        repository=RepositoryRef(
            provider=RepositoryProvider.GITHUB, url=snapshot["repository"] + ".git", base_branch="main", commit_sha=base
        ),
    )


async def trial(case: str, backend: str, output: Path, settings: Settings) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aios-qualification-") as temporary:
        root = Path(temporary)
        remote, base, snapshot = initialize_snapshot(root, case)
        workspace_root = root / "workspaces"
        workspace_root.mkdir()
        repository = SnapshotRepository(workspace_root, remote)
        policy = PolicyEngine(load_policy(settings.policy_file))
        sandbox: DockerSandboxExecutor
        if backend == "code-interpreter":
            vendor = root / "empty-vendor.tar.gz"
            with tarfile.open(vendor, "w:gz"):
                pass
            sandbox = AgentCoreCodeInterpreterSandbox(
                workspace_root,
                region_name=settings.aws_region or "",
                behavioral_bundle=settings.behavioral_bundle,
                validation_bundle=vendor,
                code_interpreter_identifier=settings.code_interpreter_identifier,
            )
        else:
            sandbox = DockerSandboxExecutor(
                workspace_root, settings.sandbox_image, behavioral_bundle=settings.behavioral_bundle
            )
        model = build_structured_model(
            settings,
            max_output_tokens=policy.config.limits.max_model_output_tokens,
            max_format_retries=policy.config.limits.max_model_format_retries,
        )
        slug = "MtechSE-ArchAI-Team7/buggy-ecommerce-demo"

        def create_pr(value: dict[str, object]) -> dict[str, object]:
            commit = git(remote, "rev-parse", "refs/heads/" + str(value["head"]))
            return {
                "number": 1,
                "html_url": "https://github.com/" + slug + "/pull/1",
                "state": "open",
                "draft": True,
                "merged": False,
                "head": {"ref": value["head"], "sha": commit, "repo": {"full_name": slug}},
                "base": {"ref": "main", "sha": base, "repo": {"full_name": slug}},
            }

        publication = SimulatedGitHubPrMcp(ROOT / "config/contracts/github-pr-mcp-tools.json", create_pr)
        provider = DraftPullRequestProvider(
            token="isolated-qualification",  # noqa: S106 - in-process MCP transport only
            writes_enabled=True,
            transport=publication.transport(),
            timeout_seconds=policy.config.limits.max_mcp_tool_timeout_seconds,
        )
        nodes = WorkflowNodes(
            policy=policy,
            model=model,
            repository=repository,
            inspection_tools=SnapshotInspectionTools(repository, policy),
            sandbox=sandbox,
            pr_provider=provider,
            artifact_store=LocalArtifactStore(output),
            audit_sink=JsonlAuditSink(output),
            release_provenance=LocalReleaseProvenance(),
            prompt_version=settings.prompt_version,
            github_writes_enabled=True,
            github_repository=slug,
        )
        graph = build_graph(nodes, in_memory_checkpointer())
        service = RemediationService(graph, max_active_runs=1, invocation_timeout_seconds=840)
        try:
            view = await service.start(handoff(case, base, snapshot))
            for _ in range(8):
                if view.status is not FinalStatus.AWAITING_APPROVAL:
                    break
                request = view.approval_request
                assert request is not None
                print(
                    json.dumps(
                        {"case": case, "run": view.run_id, "stage": "isolated-test-approval", "kind": request.kind}
                    ),
                    flush=True,
                )
                view = await service.approve(
                    view.run_id,
                    ApprovalDecisionV1(
                        approval_id=request.approval_id,
                        scope_digest=request.scope_digest,
                        status=ApprovalStatus.APPROVED,
                        reviewer_id="isolated-test-only",
                        decided_at=datetime.now(UTC),
                        comment="Explicit qualification-only approval; no remote GitHub writes.",
                    ),
                )
            state = cast(
                RemediationState, (await graph.aget_state({"configurable": {"thread_id": view.run_id}})).values
            )
            result = {
                "case": case,
                "run_id": view.run_id,
                "backend": backend,
                "snapshot": snapshot,
                "status": view.status.value,
                "passed": view.status is FinalStatus.DRAFT_PR_CREATED,
                "policy_digest": sha(policy.config.model_dump_json().encode()),
                "assets_digest": sandbox.verification_fingerprint(),
                "model": settings.llm_model,
                "provider": settings.llm_provider,
                "prompt_version": settings.prompt_version,
                "model_configuration_digest": model.configuration_digest(),
                "locally_verified": state.get("locally_verified", False),
                "evidence_persisted": state.get("evidence_persisted", False),
                "cleanup_verified": bool(state.get("cleanup_result") and state["cleanup_result"].succeeded),
                "assertions_digests": sorted({e.assertions_digest for e in state.get("behavioral_evidence", [])}),
                "publication": state["publication_journal"].model_dump(mode="json")
                if state.get("publication_journal")
                else None,
                "errors": [e.model_dump(mode="json") for e in state.get("errors", [])],
                "gaps": state.get("verification_gaps", []),
            }
            (output / "trial.json").write_text(json.dumps(result, indent=2))
            print(json.dumps(result), flush=True)
            return result
        finally:
            await model.aclose()
            # Normal graph cleanup is asserted by the outcome; unexpected exceptions still remove local copies.


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=["docker", "code-interpreter"], required=True)
    parser.add_argument("--case", choices=["ah54", "ah56", "all"], default="all")
    parser.add_argument("--trials", type=int, choices=[1, 3], default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("AIOS_RUN_WORKFLOW_QUALIFICATION") != "1":
        raise SystemExit("Explicit AIOS_RUN_WORKFLOW_QUALIFICATION=1 required")
    settings = Settings.model_validate(
        {"OPENAI_API_KEY": None, "openai_secret_arn": None}
        if os.environ.get("AIOS_OPENAI_AUTH_MODE") == "aws_iam_gateway"
        else {}
    )
    if settings.llm_provider == "fake":
        raise SystemExit("Qualification requires the configured real provider")
    results = []
    for case in ["ah54", "ah56"] if args.case == "all" else [args.case]:
        for number in range(1, args.trials + 1):
            result = await trial(case, args.backend, args.output / f"{case}-{number}", settings)
            results.append(result)
            if not result["passed"]:
                raise SystemExit("QUALIFICATION_FAILED: " + case)
    args.output.mkdir(parents=True, exist_ok=True)
    source = os.environ.get("AIOS_QUALIFICATION_SOURCE_SHA")
    image = os.environ.get("AIOS_QUALIFICATION_IMAGE_DIGEST")
    runtime = os.environ.get("AIOS_QUALIFICATION_RUNTIME_CONFIGURATION_DIGEST")
    if source and image and runtime:
        for case in {str(r["case"]) for r in results}:
            selected = [r for r in results if r["case"] == case]
            first = selected[0]
            for key in ("policy_digest", "assets_digest", "model_configuration_digest", "prompt_version"):
                if len({str(r[key]) for r in selected}) != 1:
                    raise SystemExit("QUALIFICATION_INPUT_CHANGED: " + key)
            report = ReleaseQualificationV1.model_validate(
                {
                    "case": case,
                    "backend": args.backend,
                    "source_revision": source,
                    "image_digest": image,
                    "runtime_configuration_digest": runtime,
                    "policy_digest": first["policy_digest"],
                    "assets_digest": first["assets_digest"],
                    "model_configuration_digest": first["model_configuration_digest"],
                    "prompt_version": first["prompt_version"],
                    "snapshot_digest": cast(dict[str, str], first["snapshot"])["archive_digest"],
                    "qualified_at": datetime.now(UTC),
                    "trials": [_release_trial(r) for r in selected],
                }
            )
            (args.output / (case + "-qualification.json")).write_text(report.model_dump_json(indent=2))
    else:
        (args.output / "development-trials.json").write_text(json.dumps(results, indent=2))


def _release_trial(result: dict[str, object]) -> QualificationTrialV1:
    journal = cast(dict[str, object], result["publication"])
    receipts = cast(list[dict[str, object]], journal["receipts"])
    return QualificationTrialV1.model_validate(
        {
            "run_id": result["run_id"],
            "status": result["status"],
            "locally_verified": result["locally_verified"],
            "evidence_persisted": result["evidence_persisted"],
            "cleanup_verified": result["cleanup_verified"],
            "publication_verified": journal["verified"],
            "candidate_digest": journal["candidate_digest"],
            "commit_sha": receipts[-1]["commit_sha"],
            "assertions_digests": result["assertions_digests"],
        }
    )


if __name__ == "__main__":
    asyncio.run(main())
