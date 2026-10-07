"""Operator-owned prepare/cold-resume proof on the actual runtime session mount."""

from __future__ import annotations

import asyncio
import hashlib
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal
from uuid import UUID, uuid4

from remediation_agent.adapters.behavioral import _digest_files
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.adapters.sandbox import DockerSandboxExecutor
from remediation_agent.adapters.validation_storage import MANAGED_CEILING, diagnostic, footprint
from remediation_agent.domain.enums import ReleaseProvenanceStatus
from remediation_agent.domain.models import StrictModel, WorkspaceRef
from remediation_agent.domain.runtime_qualification import RuntimeQualificationRequestV1, RuntimeQualificationResultV1
from remediation_agent.policy.models import PolicyConfig
from remediation_agent.ports.models import ArtifactWriteRequest, BehavioralTaskRequest, PatchApplyRequest
from remediation_agent.ports.protocols import ArtifactStore, ReleaseProvenancePort
from remediation_agent.source import digest


class Fixture(StrictModel):
    repository: str
    source_commit: str
    archive: Literal["ah54.tar.gz", "ah56.tar.gz"]
    archive_digest: str
    patch_digest: str


class Prepared(StrictModel):
    session_id: str
    process_nonce: str
    base_commit: str
    clean_digest: str
    result: RuntimeQualificationResultV1


class RuntimeQualification:
    def __init__(
        self,
        *,
        workspace_root: Path,
        fixtures: Path,
        sandbox: DockerSandboxExecutor,
        policy: PolicyConfig,
        provenance: ReleaseProvenancePort,
        artifacts: ArtifactStore,
    ):
        self.root = workspace_root.resolve()
        self.fixtures = fixtures
        self.sandbox = sandbox
        self.policy = policy
        self.provenance = provenance
        self.artifacts = artifacts
        self.repository = LocalGitRepository(self.root)  # no remote or credential provider
        self.process_nonce = uuid4().hex
        self.lock = asyncio.Lock()

    async def execute(self, request: RuntimeQualificationRequestV1, session_id: str) -> RuntimeQualificationResultV1:
        if str(UUID(session_id)) != session_id:
            raise ValueError("INVALID_QUALIFICATION_SESSION")
        async with self.lock:
            async with asyncio.timeout(900):
                return await self._execute(request, session_id)

    async def _execute(self, request: RuntimeQualificationRequestV1, session: str) -> RuntimeQualificationResultV1:
        release = await self.provenance.resolve()
        if release.status is not ReleaseProvenanceStatus.VERIFIED:
            raise ValueError("QUALIFICATION_REQUIRES_VERIFIED_RELEASE")
        fixture = Fixture.model_validate(json.loads((self.fixtures / "manifest.json").read_text())[request.fixture])
        archive = self.fixtures / fixture.archive
        patch = (self.fixtures / (request.fixture + ".diff")).read_text()
        if (
            "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest() != fixture.archive_digest
            or digest(patch) != fixture.patch_digest
        ):
            raise ValueError("QUALIFICATION_FIXTURE_DIGEST_MISMATCH")
        policy_digest = digest(self.policy.model_dump_json())
        asset_digest = _digest_files(self.sandbox.behavioral_bundle)
        owned = self.root / ("qualification-" + request.qualification_id)
        journal = owned / "prepared.json"
        complete = owned / "completed.json"
        repo = owned / "repository"
        if owned.is_symlink() or repo.is_symlink() or journal.is_symlink() or complete.is_symlink():
            raise ValueError("UNSAFE_QUALIFICATION_PATH")
        prepared: Prepared | None = None
        if journal.exists():
            if journal.stat().st_size > 262144:
                raise ValueError("QUALIFICATION_RECEIPT_OVERSIZED")
            prepared = Prepared.model_validate_json(journal.read_text())
            previous = prepared.result
            if (
                prepared.session_id != session
                or previous.fixture != request.fixture
                or previous.policy_digest != policy_digest
                or previous.asset_digest != asset_digest
                or previous.fixture_digest != fixture.archive_digest
                or previous.candidate_digest != fixture.patch_digest
                or previous.release.model_dump(exclude={"verified_at"}) != release.model_dump(exclude={"verified_at"})
            ):
                raise ValueError("QUALIFICATION_BINDING_MISMATCH")
            if request.operation == "prepare":
                return previous
        if request.operation == "prepare":
            if owned.exists():
                raise ValueError("QUALIFICATION_INCOMPLETE_PREPARATION_USE_NEW_ID")
            size, _ = footprint(self.sandbox.scratch.managed_root)
            with tarfile.open(archive) as stream:
                members = stream.getmembers()
                projected = sum(m.size for m in members)
                if len(members) > 10000 or projected > 64 * 1024 * 1024 or size + projected * 3 > MANAGED_CEILING:
                    raise ValueError("QUALIFICATION_STORAGE_CAPACITY_EXCEEDED")
                repo.mkdir(parents=True, mode=0o700)
                for member in members:
                    path = PurePosixPath(member.name)
                    if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                        raise ValueError("UNSAFE_QUALIFICATION_FIXTURE")
                    relative = Path(*path.parts[1:])
                    if not member.isfile() or not relative.parts:
                        continue
                    payload = stream.extractfile(member)
                    if payload is None:
                        raise ValueError("INVALID_QUALIFICATION_FIXTURE")
                    target = repo / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(payload.read())
            for args in (
                ["init", "-b", "main"],
                ["add", "."],
                [
                    "-c",
                    "user.name=AIOS qualification",
                    "-c",
                    "user.email=qualification@example.invalid",
                    "commit",
                    "-m",
                    "bundled immutable fixture",
                ],
            ):
                await self.repository._run(["git", *args], cwd=repo)
            base = (await self.repository._run(["git", "rev-parse", "HEAD"], cwd=repo)).strip()
            binding = digest(
                json.dumps(
                    [
                        session,
                        request.qualification_id,
                        self.process_nonce,
                        base,
                        policy_digest,
                        asset_digest,
                        fixture.model_dump(),
                        release.model_dump(mode="json"),
                    ],
                    sort_keys=True,
                )
            )
            result = RuntimeQualificationResultV1(
                qualification_id=request.qualification_id,
                fixture=request.fixture,
                status="PREPARED",
                release=release,
                policy_digest=policy_digest,
                asset_digest=asset_digest,
                fixture_digest=fixture.archive_digest,
                candidate_digest=fixture.patch_digest,
                receipt_digest=binding,
                managed_filesystem=self.root.is_relative_to("/mnt/workspace"),
                completed_at=datetime.now(UTC),
            )
            prepared = Prepared(
                session_id=session,
                process_nonce=self.process_nonce,
                base_commit=base,
                clean_digest=digest(""),
                result=result,
            )
            journal.write_text(prepared.model_dump_json())
            await self.artifacts.write_bundle(
                ArtifactWriteRequest(
                    run_id=request.qualification_id,
                    files={"runtime-qualification-prepared.json": result.model_dump_json()},
                )
            )
            return result
        if prepared is None or request.receipt_digest != prepared.result.receipt_digest:
            raise ValueError("QUALIFICATION_PREPARED_RECEIPT_REQUIRED")
        if complete.exists():
            if complete.stat().st_size > 1048576:
                raise ValueError("QUALIFICATION_RESULT_OVERSIZED")
            return RuntimeQualificationResultV1.model_validate_json(complete.read_text())
        result = prepared.result.model_copy(
            update={"status": "FAILED", "process_restarted": prepared.process_nonce != self.process_nonce}
        )
        workspace = WorkspaceRef(workspace_id=owned.name, path=str(repo), base_commit=prepared.base_commit)
        try:
            if not result.process_restarted:
                raise ValueError("QUALIFICATION_REQUIRES_STOP_AND_COLD_RESUME")
            await self.repository.verify_workspace(workspace, prepared.clean_digest)
            await self.sandbox.apply_patch(PatchApplyRequest(workspace=workspace, unified_diff=patch))
            expected = (await self.repository.current_diff(workspace)).digest
            task_name = "purchase_regression" if request.fixture == "ah54" else "checkout_regression"
            task = self.policy.validation_tasks[task_name]
            execution = await self.sandbox.run_behavior(
                BehavioralTaskRequest(
                    workspace=workspace,
                    task_name=task_name,
                    task=task,
                    patch_digest=fixture.patch_digest,
                    run_id=request.qualification_id,
                )
            )
            result = result.model_copy(update={"evidence": execution.evidence, "storage": execution.storage})
            await self.repository.verify_workspace(workspace, expected)
            result = result.model_copy(update={"git_integrity_verified": True})
            proof = execution.evidence
            if (
                proof is None
                or not proof.cleanup_succeeded
                or execution.storage is None
                or execution.storage.failures
                or set(c.test_id for c in proof.base.cases) != set(task.required_test_ids)
                or set(c.test_id for c in proof.candidate.cases) != set(task.required_test_ids)
                or not any(c.outcome == "ASSERTION_FAILED" for c in proof.base.cases)
                or any(c.outcome not in {"PASSED", "ASSERTION_FAILED"} for c in proof.base.cases)
                or any(c.outcome != "PASSED" for c in proof.candidate.cases)
            ):
                raise ValueError("HOSTED_BEHAVIORAL_QUALIFICATION_FAILED")
            result = result.model_copy(update={"status": "PASSED"})
        except (OSError, RuntimeError, ValueError) as exc:
            result = result.model_copy(update={"failures": [diagnostic(exc, "hosted_qualification", "WORKSPACE")]})
        finally:
            cleanup = await asyncio.shield(self.sandbox.destroy(workspace))
            result = result.model_copy(
                update={"cleanup_verified": cleanup.succeeded, "completed_at": datetime.now(UTC)}
            )
            if not cleanup.succeeded:
                result = result.model_copy(
                    update={
                        "status": "FAILED",
                        "failures": [
                            *result.failures,
                            diagnostic(RuntimeError(cleanup.detail), "workspace_cleanup", "WORKSPACE"),
                        ],
                    }
                )
            manifest = await asyncio.shield(
                self.artifacts.write_bundle(
                    ArtifactWriteRequest(
                        run_id=request.qualification_id, files={"runtime-qualification.json": result.model_dump_json()}
                    )
                )
            )
            result = result.model_copy(update={"artifact_manifest": manifest})
            complete.write_text(result.model_dump_json())
        return result
