"""Prepare bounded disposable snapshots and validate trusted behavioral reports."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import tarfile
import time
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from remediation_agent.adapters.validation_storage import ValidationStorageError, _raise_io, diagnostic, footprint
from remediation_agent.domain.enums import ValidationCleanupStatus, ValidationOutcome
from remediation_agent.domain.models import (
    BehavioralEvidence,
    BehavioralReport,
    ValidationCleanupReceipt,
    ValidationDiagnostic,
    ValidationSnapshotRef,
    ValidationStorageEvidence,
)
from remediation_agent.ports.models import (
    ArtifactWriteRequest,
    BehavioralTaskExecution,
    BehavioralTaskRequest,
    ValidationCancelled,
    ValidationTaskRequest,
)

if TYPE_CHECKING:
    from remediation_agent.adapters.sandbox import DockerSandboxExecutor

_MAX_BYTES = 64 * 1024 * 1024
_ASSETS = Path(__file__).with_name("validation_assets")
_ECOMMERCE_PROFILES = {"ecommerce_checkout", "ecommerce_purchase"}


def _allowed(path: str) -> bool:
    from remediation_agent.adapters.agentcore_sandbox import _forbidden

    parts = PurePosixPath(path).parts
    return (
        bool(parts)
        and not _forbidden(path)
        and not any(item in {"node_modules", "__pycache__", ".pytest_cache", ".venv"} for item in parts)
    )


def _copy(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    total = 0
    count = 0
    entries: list[Path] = []
    for directory, directories, files in os.walk(source, followlinks=False, onerror=_raise_io):
        current = Path(directory)
        directories[:] = [name for name in directories if _allowed((current / name).relative_to(source).as_posix())]
        if any((current / name).is_symlink() for name in directories):
            raise ValueError("Behavioral snapshot contains a symlink")
        entries.extend(current / name for name in files)
        if len(entries) > 10000:
            raise ValueError("Behavioral snapshot exceeds fixed limits")
    for item in sorted(entries):
        relative = item.relative_to(source).as_posix()
        if not _allowed(relative):
            continue
        if item.is_symlink():
            raise ValueError("Behavioral snapshot contains a symlink")
        if item.is_file():
            total += item.stat().st_size
            count += 1
            if total > _MAX_BYTES or count > 10000:
                raise ValueError("Behavioral snapshot exceeds fixed limits")
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, destination)


def _extract(archive: Path, target: Path) -> None:
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        if len(members) > 10000 or sum(item.size for item in members) > _MAX_BYTES:
            raise ValueError("Base snapshot exceeds fixed limits")
        for item in members:
            path = PurePosixPath(item.name)
            if path.is_absolute() or ".." in path.parts or item.issym() or item.islnk():
                raise ValueError("Unsafe immutable base snapshot")
            if item.isfile() and _allowed(item.name):
                source = stream.extractfile(item)
                if source is None:
                    raise ValueError("Missing archive entry")
                destination = target / item.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source, destination.open("wb") as output:
                    shutil.copyfileobj(source, output)


def _digest_files(root: Path, *, ignore_bytecode: bool = False) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if ignore_bytecode and ("__pycache__" in path.parts or path.suffix == ".pyc"):
            continue
        if path.is_symlink():
            raise ValueError("Unsafe verification asset")
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
    return "sha256:" + digest.hexdigest()


async def run_behavioral_pair(
    sandbox: DockerSandboxExecutor, request: BehavioralTaskRequest
) -> BehavioralTaskExecution:
    started = time.monotonic()
    storage = ValidationStorageEvidence(task_name=request.task_name, attempt=request.attempt)
    executions = []
    reports: list[BehavioralReport] = []
    snapshots: list[ValidationSnapshotRef] = []
    cleaned: set[str] = set()
    lease: str | None = None
    operation = "preflight"
    resource = "WORKSPACE"
    assertion_digest = dependency_digest = ""
    cancelled = False
    try:
        root = sandbox._workspace(request.workspace)
        if request.task.profile is None:
            raise ValueError("Behavioral profile is absent")
        # Inspect sizes before writing any validation copies. Include archive and frozen tests.
        source_bytes, source_files = await asyncio.to_thread(footprint, root)
        projected = source_bytes * 4 + 4 * 1024 * 1024
        files = source_files * 4 + 100
        if sandbox.stage_host_bundle and request.task.profile in _ECOMMERCE_PROFILES:
            bundle_bytes, bundle_files = await asyncio.to_thread(footprint, sandbox.behavioral_bundle)
            projected += bundle_bytes
            files += bundle_files
            if request.task.profile == "ecommerce_checkout":
                with tarfile.open(sandbox.behavioral_bundle / "browser.tar.xz", "r:xz") as browser:
                    members = browser.getmembers()
                    projected += sum(item.size for item in members)
                    files += len(members)
        storage = storage.model_copy(update={"projected_scratch_bytes": projected, "projected_files": files})
        managed_bytes, scratch_free_bytes = await asyncio.to_thread(sandbox.scratch.preflight, projected, files)
        storage = storage.model_copy(update={"managed_bytes": managed_bytes, "scratch_free_bytes": scratch_free_bytes})
        # Git metadata must still identify the reviewed immutable base.
        head_exit, head, _, _ = await sandbox._run_capped(
            sandbox._git_argv(root, "rev-parse", "HEAD"),
            cwd=root,
            timeout=30,
            output_limit=1024,
        )
        if head_exit or head.strip() != request.workspace.base_commit:
            raise ValueError("WORKSPACE_INTEGRITY_FAILED: immutable Git HEAD is unavailable or changed")
        lease, pair_root = sandbox.scratch.create()
        resource, operation = "SCRATCH", "freeze_inputs"
        tree_exit, tree, _, truncated = await sandbox._run_capped(
            sandbox._git_argv(root, "ls-tree", "-rl", request.workspace.base_commit),
            cwd=root,
            timeout=30,
            output_limit=1024 * 1024,
        )
        sizes = [line.split("\t", 1)[0].split()[-1] for line in tree.splitlines()]
        if tree_exit or truncated or len(sizes) > 10000 or sum(int(s) for s in sizes if s.isdigit()) > _MAX_BYTES:
            raise ValueError("Immutable base exceeds behavioral snapshot limits")
        archive = pair_root / "base.tar"
        await sandbox._run(
            sandbox._git_argv(root, "archive", "--format=tar", f"--output={archive}", request.workspace.base_commit),
            cwd=root,
            timeout=60,
        )
        tests = pair_root / "assertions"
        tests.mkdir()
        for name in request.task.test_paths:
            source = root / name
            if not source.exists() or source.is_symlink() or not source.resolve().is_relative_to(root):
                raise ValueError(f"Behavioral test path is absent or unsafe: {name}")
            destination = tests / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                await asyncio.to_thread(_copy, source, destination)
            else:
                shutil.copyfile(source, destination)
        assets_digest = _digest_files(_ASSETS, ignore_bytecode=True)
        assertion_digest = (
            "sha256:"
            + hashlib.sha256(
                (_digest_files(tests) + assets_digest + request.task.model_dump_json()).encode()
            ).hexdigest()
        )
        dependency_digest = assets_digest
        if request.task.profile in _ECOMMERCE_PROFILES:
            manifest = sandbox.behavioral_bundle / "manifest.json"
            if not manifest.is_file() or manifest.is_symlink():
                raise ValueError("UNSUPPORTED_VALIDATION_ENVIRONMENT: offline e-commerce bundle is absent")
            dependency_digest = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
        for label in ["base"] if request.capability_only else ["base", "candidate"]:
            operation, resource = "stage_" + label, "SNAPSHOT"
            ref = sandbox.scratch.register(lease, label, request.workspace.workspace_id, request.workspace.base_commit)
            snapshots.append(ref)
            snapshot = Path(ref.path)
            snapshot.mkdir()
            if label == "base":
                await asyncio.to_thread(_extract, archive, snapshot)
            else:
                await asyncio.to_thread(_copy, root, snapshot)
            for name in request.task.test_paths:
                target = snapshot / name
                if target.is_dir():
                    shutil.rmtree(target)
                elif target.exists():
                    target.unlink()
            await asyncio.to_thread(_copy, tests, snapshot)
            reserved = snapshot / ".aios-verification"
            if reserved.exists():
                raise ValueError("Repository attempts to replace trusted validation assets")
            shutil.copytree(_ASSETS, reserved, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            # Docker needs mounted native assets; Code Interpreter streams them from the immutable image.
            if sandbox.stage_host_bundle and request.task.profile in _ECOMMERCE_PROFILES:
                shutil.copytree(sandbox.behavioral_bundle, reserved / "bundle", symlinks=False)
                if request.task.profile == "ecommerce_checkout":
                    from remediation_agent.adapters.validation_assets.runner import unpack_browser

                    await asyncio.to_thread(unpack_browser, reserved / "bundle", reserved / "browser-runtime")
            (reserved / "task.json").write_text(
                json.dumps(
                    {
                        "profile": request.task.profile,
                        "test_paths": request.task.test_paths,
                        "timeout": request.task.timeout_seconds,
                        "output_limit": request.task.output_limit_bytes,
                    }
                )
            )
            (snapshot / ".git").mkdir(exist_ok=True)
            profile_digest = _digest_files(snapshot)
            task = request.task.model_copy(
                update={"argv": ["python", "-I", ".aios-verification/runner.py"], "cwd": ".", "environment": {}}
            )
            operation, resource = "execute_" + label, "SESSION"
            execution = await sandbox.run_task(
                ValidationTaskRequest(
                    workspace=request.workspace,
                    snapshot=ref,
                    task_name=request.task_name,
                    task=task,
                    attempt=request.attempt,
                )
            )
            executions.append(execution)
            storage.cleanup.append(
                ValidationCleanupReceipt(
                    resource="SESSION",
                    resource_id=ref.workspace_id,
                    status=execution.execution.cleanup_status,
                    attempts=execution.execution.cleanup_attempts,
                    diagnostic=execution.execution.cleanup_diagnostic,
                )
            )
            result = execution.result
            operation, resource = "parse_" + label, "REPORT"
            if result.output_truncated or result.outcome in {ValidationOutcome.ERROR, ValidationOutcome.TIMED_OUT}:
                raise ValueError(f"Behavioral execution {result.outcome}: " + (result.stderr or result.stdout)[:2000])
            report = BehavioralReport.model_validate_json(result.stdout)
            reports.append(report)
            storage = storage.model_copy(update={"reports": list(reports)})
            if result.exit_code != (0 if all(c.outcome == "PASSED" for c in report.cases) else 1):
                raise ValueError("Behavioral report disagrees with executor exit status")
            if execution.execution.cleanup_status not in {
                ValidationCleanupStatus.SUCCEEDED,
                ValidationCleanupStatus.NOT_APPLICABLE,
            }:
                raise ValueError("Behavioral sandbox session cleanup failed")
            operation, resource = "integrity_" + label, "SNAPSHOT"
            if _digest_files(snapshot) != profile_digest:
                raise ValueError("Validation changed isolated source, assertions, or trusted assets")
            receipt = await sandbox.cleanup_snapshot(ref)
            storage.cleanup.append(receipt)
            cleaned.add(ref.workspace_id)
            if receipt.status is not ValidationCleanupStatus.SUCCEEDED:
                storage.failures.append(
                    receipt.diagnostic
                    or ValidationDiagnostic(
                        code="SNAPSHOT_CLEANUP_FAILED",
                        operation="snapshot_cleanup",
                        resource="SNAPSHOT",
                        detail="Owned snapshot cleanup failed",
                    )
                )
            # Retain each completed execution before another snapshot or repair can run.
            if sandbox.result_store is not None and request.run_id is not None:
                from remediation_agent.adapters.evidence import SecretRedactor

                await sandbox.result_store.write_bundle(
                    ArtifactWriteRequest(
                        run_id=request.run_id,
                        files={
                            f"validation-{request.task_name}-{request.attempt}-{label}.json": SecretRedactor().redact(
                                json.dumps(
                                    {
                                        "execution": execution.model_dump(mode="json"),
                                        "storage": storage.model_dump(mode="json"),
                                    }
                                )
                            )
                        },
                    )
                )
            if storage.failures:
                break
        if reports and reports[0].runtime_digest != reports[-1].runtime_digest:
            raise ValueError("Base/candidate runtime dependency fingerprints differ")
        if reports and request.task.profile not in _ECOMMERCE_PROFILES and reports[0].runtime_digest:
            dependency_digest = reports[0].runtime_digest
    except asyncio.CancelledError as exc:
        cancelled = True
        if isinstance(exc, ValidationCancelled):
            storage.cleanup.append(exc.receipt)
            if exc.receipt.diagnostic is not None:
                storage.failures.append(exc.receipt.diagnostic)
        storage.failures.append(
            ValidationDiagnostic(
                code="VALIDATION_CANCELLED",
                operation=operation,
                resource="SESSION",
                detail="Validation was cancelled; owned cleanup attempted.",
            )
        )
    except (OSError, RuntimeError, ValueError) as exc:
        storage.failures.insert(
            0, exc.diagnostic if isinstance(exc, ValidationStorageError) else diagnostic(exc, operation, resource)
        )
    finally:
        for ref in snapshots:
            if ref.workspace_id not in cleaned:
                try:
                    receipt = await asyncio.shield(sandbox.cleanup_snapshot(ref))
                    storage.cleanup.append(receipt)
                    if receipt.status is not ValidationCleanupStatus.SUCCEEDED:
                        storage.failures.append(
                            receipt.diagnostic
                            or ValidationDiagnostic(
                                code="SNAPSHOT_CLEANUP_FAILED",
                                operation="snapshot_cleanup",
                                resource="SNAPSHOT",
                                detail="Owned snapshot cleanup failed",
                            )
                        )
                except (OSError, RuntimeError, ValueError) as exc:
                    problem = diagnostic(exc, "snapshot_cleanup", "SNAPSHOT")
                    storage.failures.append(problem)
                    storage.cleanup.append(
                        ValidationCleanupReceipt(
                            resource="SNAPSHOT",
                            resource_id=ref.workspace_id,
                            status=ValidationCleanupStatus.FAILED,
                            diagnostic=problem,
                        )
                    )
        if lease is not None:
            try:
                if any(
                    owner in {ref.workspace_id for ref in snapshots} for owner in sandbox._active_containers.values()
                ):
                    raise RuntimeError("Scratch retained because validation processes may still be active")
                receipt = await asyncio.shield(sandbox.scratch.cleanup_lease(lease))
                storage.cleanup.append(receipt)
                if receipt.status is not ValidationCleanupStatus.SUCCEEDED:
                    storage.failures.append(
                        receipt.diagnostic
                        or ValidationDiagnostic(
                            code="SNAPSHOT_CLEANUP_FAILED",
                            operation="lease_cleanup",
                            resource="SCRATCH",
                            detail="Owned scratch cleanup failed",
                        )
                    )
            except (OSError, RuntimeError, ValueError) as exc:
                problem = diagnostic(exc, "lease_cleanup", "SCRATCH")
                storage.failures.append(problem)
                storage.cleanup.append(
                    ValidationCleanupReceipt(
                        resource="SCRATCH", resource_id=lease, status=ValidationCleanupStatus.FAILED, diagnostic=problem
                    )
                )
        storage = storage.model_copy(update={"duration_ms": int((time.monotonic() - started) * 1000)})
        if sandbox.result_store is not None and request.run_id is not None:
            from remediation_agent.adapters.evidence import SecretRedactor

            try:
                storage_name = f"validation-{request.task_name}-{request.attempt}-storage.json"
                await asyncio.shield(
                    sandbox.result_store.write_bundle(
                        ArtifactWriteRequest(
                            run_id=request.run_id,
                            files={storage_name: SecretRedactor().redact(storage.model_dump_json())},
                        )
                    )
                )
            except Exception as exc:  # noqa: BLE001 - artifact provider failures must not mask primary execution
                storage.failures.append(
                    diagnostic(RuntimeError(type(exc).__name__), "persist_validation_evidence", "REPORT")
                )
    if cancelled:
        raise asyncio.CancelledError
    evidence = None
    if len(reports) == (1 if request.capability_only else 2):
        evidence = BehavioralEvidence(
            task_name=request.task_name,
            attempt=request.attempt,
            base_commit=request.workspace.base_commit,
            patch_digest=request.patch_digest,
            assertions_digest=assertion_digest,
            dependency_digest=dependency_digest,
            base=reports[0],
            candidate=reports[-1],
            cleanup_succeeded=not storage.failures
            and all(
                c.status in {ValidationCleanupStatus.SUCCEEDED, ValidationCleanupStatus.NOT_APPLICABLE}
                for c in storage.cleanup
            ),
        )
    return BehavioralTaskExecution(evidence=evidence, executions=executions, storage=storage)
