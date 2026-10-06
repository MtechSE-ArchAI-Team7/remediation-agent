"""Prepare bounded disposable snapshots and validate trusted behavioral reports."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from remediation_agent.domain.enums import ValidationCleanupStatus, ValidationOutcome
from remediation_agent.domain.models import BehavioralEvidence, BehavioralReport, WorkspaceRef
from remediation_agent.ports.models import BehavioralTaskExecution, BehavioralTaskRequest, ValidationTaskRequest

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
    for directory, directories, files in os.walk(source, followlinks=False):
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
    root = sandbox._workspace(request.workspace)
    if request.task.profile is None:
        raise ValueError("Behavioral profile is absent")
    pair_root = Path(tempfile.mkdtemp(prefix="verification-", dir=sandbox.workspace_root))
    executions = []
    reports = []
    try:
        base, candidate = pair_root / "base", pair_root / "candidate"
        base.mkdir()
        candidate.mkdir()
        await asyncio.to_thread(_copy, root, candidate)
        # Bound the archive before materializing it. Git arguments never come from the model.
        tree_exit, tree, _, truncated = await sandbox._run_capped(
            sandbox._git_argv(root, "ls-tree", "-rl", request.workspace.base_commit),
            cwd=root,
            timeout=30,
            output_limit=1024 * 1024,
        )
        sizes = [line.split("\t", 1)[0].split()[-1] for line in tree.splitlines()]
        if (
            tree_exit != 0
            or truncated
            or len(sizes) > 10000
            or sum(int(size) for size in sizes if size.isdigit()) > _MAX_BYTES
        ):
            raise ValueError("Immutable base exceeds behavioral snapshot limits")
        archive = pair_root / "base.tar"
        await sandbox._run(
            sandbox._git_argv(root, "archive", "--format=tar", f"--output={archive}", request.workspace.base_commit),
            cwd=root,
            timeout=60,
        )
        await asyncio.to_thread(_extract, archive, base)
        tests = pair_root / "assertions"
        tests.mkdir()
        for name in request.task.test_paths:
            source = candidate / name
            if not source.exists():
                raise ValueError(f"Behavioral test path is absent: {name}")
            destination = tests / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                await asyncio.to_thread(_copy, source, destination)
            else:
                shutil.copyfile(source, destination)
        for name in request.task.test_paths:
            destination = base / name
            if destination.is_dir():
                shutil.rmtree(destination)
            elif destination.exists():
                destination.unlink()
        await asyncio.to_thread(_copy, tests, base)
        # Protect bootstrap overrides from the application snapshot. Assets are host-owned.
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
            if not manifest.is_file():
                raise ValueError("UNSUPPORTED_VALIDATION_ENVIRONMENT: offline e-commerce bundle is absent")
            dependency_digest = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
        snapshots = [("base", base)] if request.capability_only else [("base", base), ("candidate", candidate)]
        for label, snapshot in snapshots:
            reserved = snapshot / ".aios-verification"
            if reserved.exists():
                raise ValueError("Repository attempts to replace trusted validation assets")
            shutil.copytree(_ASSETS, reserved, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            if request.task.profile in _ECOMMERCE_PROFILES:
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
                update={
                    "argv": ["python", "-I", ".aios-verification/runner.py"],
                    "cwd": ".",
                    "environment": {},
                }
            )
            execution = await sandbox.run_task(
                ValidationTaskRequest(
                    workspace=WorkspaceRef(
                        workspace_id=f"verify-{label}-{request.workspace.workspace_id}"[:60],
                        path=str(snapshot),
                        base_commit=request.workspace.base_commit,
                    ),
                    task_name=request.task_name,
                    task=task,
                    attempt=request.attempt,
                )
            )
            executions.append(execution)
            if _digest_files(snapshot) != profile_digest:
                raise ValueError("Validation changed the isolated source, assertions, or trusted assets")
            result = execution.result
            if result.output_truncated or result.outcome in {ValidationOutcome.ERROR, ValidationOutcome.TIMED_OUT}:
                raise ValueError(f"Behavioral execution {result.outcome}: " + (result.stderr or result.stdout)[:2000])
            if execution.execution.cleanup_status not in {
                ValidationCleanupStatus.SUCCEEDED,
                ValidationCleanupStatus.NOT_APPLICABLE,
            }:
                raise ValueError("Behavioral sandbox cleanup failed")
            report = BehavioralReport.model_validate_json(result.stdout)
            expected_exit = 0 if all(item.outcome == "PASSED" for item in report.cases) else 1
            if result.exit_code != expected_exit:
                raise ValueError("Behavioral report disagrees with executor exit status")
            reports.append(report)
        if reports[0].runtime_digest != reports[-1].runtime_digest:
            raise ValueError("Base/candidate runtime dependency fingerprints differ")
        if request.task.profile not in _ECOMMERCE_PROFILES and reports[0].runtime_digest:
            dependency_digest = reports[0].runtime_digest
        return BehavioralTaskExecution(
            evidence=BehavioralEvidence(
                task_name=request.task_name,
                attempt=request.attempt,
                base_commit=request.workspace.base_commit,
                patch_digest=request.patch_digest,
                assertions_digest=assertion_digest,
                dependency_digest=dependency_digest,
                base=reports[0],
                candidate=reports[-1],
                cleanup_succeeded=True,
            ),
            executions=executions,
        )
    finally:
        # Destruction also stops any still-active containers associated with these snapshots.
        cleanup_failed = False
        for label in ("base", "candidate"):
            snapshot = pair_root / label
            if snapshot.exists():
                try:
                    cleaned = await sandbox.destroy(
                        WorkspaceRef(
                            workspace_id=f"verify-{label}-{request.workspace.workspace_id}"[:60],
                            path=str(snapshot),
                            base_commit=request.workspace.base_commit,
                        )
                    )
                    cleanup_failed = cleanup_failed or not cleaned.succeeded
                except (OSError, RuntimeError, ValueError):
                    cleanup_failed = True
        if cleanup_failed:
            raise RuntimeError("Behavioral snapshot cleanup failed")
        shutil.rmtree(pair_root)
