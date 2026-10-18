"""Real Git/snapshot lifecycle with controlled executor and filesystem faults."""

from __future__ import annotations

import asyncio
import errno
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from remediation_agent.adapters import behavioral
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.adapters.sandbox import DockerSandboxExecutor, SandboxError
from remediation_agent.adapters.validation_storage import ValidationScratch, ValidationStorageError
from remediation_agent.domain.enums import RepositoryProvider, ValidationCleanupStatus, ValidationOutcome
from remediation_agent.domain.models import WorkspaceRef
from remediation_agent.policy.models import ValidationTaskConfig
from remediation_agent.ports.models import BehavioralTaskRequest, SandboxTaskExecution, ValidationTaskRequest


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout.strip()  # noqa: S603,S607


@pytest.fixture
def checkout(tmp_path: Path) -> WorkspaceRef:
    root = tmp_path / "workspaces" / "reviewed"
    (root / "tests").mkdir(parents=True)
    (root / "app.js").write_text("broken\n")
    (root / "tests/regression.js").write_text("frozen assertion\n")
    git(root, "init", "-b", "main")
    git(root, "add", ".")
    git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "base")
    base = git(root, "rev-parse", "HEAD")
    (root / "app.js").write_text("fixed\n")
    return WorkspaceRef(workspace_id="reviewed", path=str(root), base_commit=base)


def request(checkout: WorkspaceRef) -> BehavioralTaskRequest:
    return BehavioralTaskRequest(
        workspace=checkout,
        task_name="regression",
        patch_digest="sha256:" + "a" * 64,
        task=ValidationTaskConfig(
            kind="BEHAVIORAL",
            profile="node_test",
            test_paths=["tests"],
            argv=["node", "--test"],
            timeout_seconds=10,
            output_limit_bytes=4096,
        ),
    )


class Reporter(DockerSandboxExecutor):
    malformed = False
    cancel = False

    async def run_task(self, request: ValidationTaskRequest) -> SandboxTaskExecution:
        root = self.validation_root(request)
        assert request.snapshot is not None
        if root.name == "candidate":
            assert not (root.parent / "base").exists(), "base must be removed before candidate staging"
        if self.cancel:
            raise asyncio.CancelledError
        failed = root.name == "base"
        output = (
            "bad report"
            if self.malformed
            else json.dumps(
                {"cases": [{"test_id": "regression", "outcome": "ASSERTION_FAILED" if failed else "PASSED"}]}
            )
        )
        from remediation_agent.domain.models import ValidationTaskResult

        return self._task_execution(
            request,
            ValidationTaskResult(
                task_name=request.task_name,
                outcome=ValidationOutcome.FAILED if failed else ValidationOutcome.PASSED,
                exit_code=int(failed),
                duration_ms=15,
                stdout=output,
            ),
            ValidationCleanupStatus.SUCCEEDED,
        )


def reporter(tmp_path: Path) -> Reporter:
    return Reporter(tmp_path / "workspaces", "unused", scratch_root=tmp_path / "scratch")


async def test_pair_is_sequential_and_never_deletes_reviewed_git(tmp_path: Path, checkout: WorkspaceRef) -> None:
    sandbox = reporter(tmp_path)
    result = await sandbox.run_behavior(request(checkout))
    assert result.evidence is not None and result.evidence.cleanup_succeeded
    assert result.storage is not None and not result.storage.failures
    assert len(result.executions) == 2 and len(result.storage.reports) == 2
    assert not list((tmp_path / "scratch").iterdir())
    await LocalGitRepository(tmp_path / "workspaces").verify_workspace(checkout)
    assert (Path(checkout.path) / "app.js").read_text() == "fixed\n"


def test_storage_quota_is_rejected_before_staging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import remediation_agent.adapters.validation_storage as storage

    guard = ValidationScratch(tmp_path / "scratch", tmp_path / "workspaces")
    monkeypatch.setattr(storage, "footprint", lambda root: (769 * 1024 * 1024, 10))
    with pytest.raises(ValidationStorageError, match="VALIDATION_STORAGE_EXHAUSTED"):
        guard.preflight(100, 2)
    assert not (tmp_path / "scratch").exists()


async def test_primary_failure_survives_cleanup_failure(
    tmp_path: Path, checkout: WorkspaceRef, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox = reporter(tmp_path)
    sandbox.malformed = True
    original = shutil.rmtree

    def fail(path: Path, *args: object, **kwargs: object) -> None:
        if path.name == "base" or path.name.startswith("pair-"):
            raise OSError(121, "simulated managed I/O failure")
        original(path)

    monkeypatch.setattr(shutil, "rmtree", fail)
    result = await sandbox.run_behavior(request(checkout))
    monkeypatch.setattr(shutil, "rmtree", original)
    assert result.evidence is None and len(result.executions) == 1
    assert result.executions[0].result.stdout == "bad report"
    assert result.storage is not None
    assert result.storage.failures[0].operation == "parse_base"
    assert any(f.errno == 121 for f in result.storage.failures[1:])
    assert any(c.status is ValidationCleanupStatus.FAILED and c.attempts == 3 for c in result.storage.cleanup)
    assert result.storage.duration_ms > 0
    assert (Path(checkout.path) / ".git").is_dir()


async def test_partial_copy_and_cancellation_clean_owned_snapshots(
    tmp_path: Path, checkout: WorkspaceRef, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox = reporter(tmp_path)

    def no_space(archive: Path, target: Path) -> None:
        (target / "partial").write_bytes(b"partial")
        raise OSError(errno.ENOSPC, "simulated quota")

    with monkeypatch.context() as m:
        m.setattr(behavioral, "_extract", no_space)
        result = await sandbox.run_behavior(request(checkout))
    assert result.storage is not None and result.storage.failures[0].code == "VALIDATION_STORAGE_EXHAUSTED"
    assert not list((tmp_path / "scratch").iterdir())
    sandbox.cancel = True
    with pytest.raises(asyncio.CancelledError):
        await sandbox.run_behavior(request(checkout))
    assert not list((tmp_path / "scratch").iterdir())
    assert (Path(checkout.path) / ".git").is_dir()


async def test_scratch_ownership_and_symlinks_cannot_target_repository(tmp_path: Path, checkout: WorkspaceRef) -> None:
    sandbox = reporter(tmp_path)
    sandbox.scratch.preflight(100, 2)
    lease, parent = sandbox.scratch.create()
    ref = sandbox.scratch.register(lease, "base", checkout.workspace_id, checkout.base_commit)
    Path(ref.path).mkdir()
    with pytest.raises(SandboxError, match="outside"):
        sandbox._workspace(WorkspaceRef(workspace_id=ref.workspace_id, path=ref.path, base_commit=ref.base_commit))
    with pytest.raises(ValueError, match="Unowned"):
        sandbox.scratch.resolve(ref.model_copy(update={"path": checkout.path}))
    Path(ref.path).rmdir()
    Path(ref.path).symlink_to(checkout.path, target_is_directory=True)
    receipt = await sandbox.scratch.cleanup_snapshot(ref)
    assert receipt.status is ValidationCleanupStatus.FAILED
    assert (Path(checkout.path) / ".git").is_dir()
    Path(ref.path).unlink()
    assert (await sandbox.scratch.cleanup_lease(lease)).status is ValidationCleanupStatus.SUCCEEDED
    assert not parent.exists()


async def test_workspace_health_rejects_missing_git(tmp_path: Path, checkout: WorkspaceRef) -> None:
    gitdir = Path(checkout.path) / ".git"
    gitdir.rename(gitdir.with_name("lost-git"))
    with pytest.raises(RuntimeError, match="Git metadata unavailable"):
        await LocalGitRepository(tmp_path / "workspaces").verify_workspace(checkout)


def test_storage_evidence_survives_strict_checkpoint_serialization() -> None:
    from remediation_agent.adapters.checkpoint import checkpoint_serializer
    from remediation_agent.domain.models import ValidationDiagnostic, ValidationStorageEvidence

    evidence = ValidationStorageEvidence(
        task_name="checkout_regression",
        attempt=1,
        duration_ms=99,
        failures=[
            ValidationDiagnostic(
                code="WORKSPACE_STORAGE_IO_ERROR", operation="stage_base", resource="SNAPSHOT", errno=121
            )
        ],
    )
    serializer = checkpoint_serializer()
    assert serializer.loads_typed(serializer.dumps_typed(evidence)) == evidence


async def test_owned_cleanup_retries_transient_error_then_is_idempotent(
    tmp_path: Path, checkout: WorkspaceRef, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox = reporter(tmp_path)
    original = shutil.rmtree
    calls = 0

    def transient(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise OSError(121, "temporary I/O error")
        original(path)

    monkeypatch.setattr(shutil, "rmtree", transient)
    assert (await sandbox.destroy(checkout)).succeeded
    assert calls == 3
    assert (await sandbox.destroy(checkout)).succeeded
    assert calls == 3


async def test_code_interpreter_streams_assets_without_host_browser_expansion(
    tmp_path: Path, checkout: WorkspaceRef
) -> None:
    import io
    import tarfile

    from remediation_agent.adapters.agentcore_sandbox import AgentCoreCodeInterpreterSandbox
    from tests.unit.test_agentcore_adapters import _FakeCodeInterpreter

    bundle = tmp_path / "immutable-assets"
    bundle.mkdir()
    (bundle / "manifest.json").write_text("{}")
    (bundle / "node").write_bytes(b"trusted node")
    (bundle / "browser.tar.xz").write_bytes(b"never expanded on host")

    class CapturingInterpreter(AgentCoreCodeInterpreterSandbox):
        malformed = False
        cancel = False

        async def run_task(self, request: ValidationTaskRequest) -> SandboxTaskExecution:
            root = self.validation_root(request)
            assert not (root / ".aios-verification/bundle").exists()
            assert not (root / ".aios-verification/browser-runtime").exists()
            archive = self._archive_workspace(root, include_bundle=True)
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as stream:
                assert ".aios-verification/bundle/node" in stream.getnames()
                assert ".aios-verification/bundle/browser.tar.xz" not in stream.getnames()
            return await Reporter.run_task(self, request)  # type: ignore[arg-type]

    sandbox = CapturingInterpreter(
        tmp_path / "workspaces",
        region_name="ap-southeast-1",
        client=_FakeCodeInterpreter(),
        behavioral_bundle=bundle,
        scratch_root=tmp_path / "scratch",
    )
    value = request(checkout)
    result = await sandbox.run_behavior(
        value.model_copy(update={"task": value.task.model_copy(update={"profile": "ecommerce_checkout"})})
    )
    assert result.evidence is not None and result.evidence.cleanup_succeeded, result.model_dump_json()
    assert result.storage is not None and result.storage.projected_scratch_bytes < 10 * 1024 * 1024
    assert not list((tmp_path / "scratch").iterdir())


async def test_approval_recovery_does_not_accept_present_but_corrupt_repository(
    tmp_path: Path, checkout: WorkspaceRef
) -> None:
    from remediation_agent.adapters.agentcore import AgentCoreWorkspaceRecovery
    from remediation_agent.domain.models import RepositoryRef

    repository = LocalGitRepository(tmp_path / "workspaces")
    (Path(checkout.path) / ".git").rename(Path(checkout.path) / "missing-git")
    with pytest.raises(RuntimeError, match="WORKSPACE_RECOVERY_UNSAFE"):
        await AgentCoreWorkspaceRecovery(repository).ensure(
            RepositoryRef(
                provider=RepositoryProvider.GITHUB, url="https://github.com/example/fixture", base_branch="main"
            ),
            checkout,
            recovery_is_safe=False,
            expected_diff="sha256:" + "0" * 64,
        )
    assert Path(checkout.path).is_dir()  # preserve failed candidate for evidence, never speculate a repair


@pytest.mark.parametrize("profile", ["ecommerce_purchase", "ecommerce_checkout"])
async def test_interpreter_uploads_complete_sealed_manifest_for_every_application_profile(
    tmp_path: Path, profile: str
) -> None:
    import hashlib

    from remediation_agent.adapters.agentcore_sandbox import AgentCoreCodeInterpreterSandbox
    from tests.unit.test_agentcore_adapters import _FakeCodeInterpreter

    workspace = tmp_path / "workspaces/reviewed"
    workspace.mkdir(parents=True)
    bundle = tmp_path / "image-assets"
    bundle.mkdir()
    browser = b"sealed browser archive"
    (bundle / "browser.tar.xz").write_bytes(browser)
    (bundle / "manifest.json").write_text(
        json.dumps({"files": {"browser.tar.xz": hashlib.sha256(browser).hexdigest()}})
    )
    vendor = tmp_path / "vendor.tar.gz"
    vendor.write_bytes(b"trusted vendor")
    client = _FakeCodeInterpreter()
    sandbox = AgentCoreCodeInterpreterSandbox(
        workspace.parent,
        region_name="ap-southeast-1",
        client=client,
        behavioral_bundle=bundle,
        validation_bundle=vendor,
        scratch_root=tmp_path / "scratch",
    )
    sandbox.scratch.preflight(100, 10)
    lease, _ = sandbox.scratch.create()
    snapshot = sandbox.scratch.register(lease, "base", "reviewed", "a" * 40)
    Path(snapshot.path).mkdir()
    try:
        await sandbox.run_task(
            ValidationTaskRequest(
                workspace=WorkspaceRef(workspace_id="reviewed", path=str(workspace), base_commit="a" * 40),
                snapshot=snapshot,
                task_name="regression",
                task=ValidationTaskConfig.model_validate(
                    {
                        "kind": "BEHAVIORAL",
                        "profile": profile,
                        "argv": ["python", "runner.py"],
                        "test_paths": [],
                        "timeout_seconds": 30,
                        "output_limit_bytes": 4096,
                    }
                ),
            )
        )
        assert any(
            "aios-trusted-browser.tar.xz" in str(call["arguments"])
            for call in client.invocations
            if call["name"] == "writeFiles"
        )
        assert not list(workspace.rglob("browser*"))
    finally:
        await sandbox.scratch.cleanup_lease(lease)


@pytest.mark.parametrize(
    "fault",
    [
        "exit",
        "truncated",
        "timeout",
        "cleanup",
        "mutation",
        "runtime",
        "reserved",
        "test_missing",
        "test_symlink",
        "head",
        "tree",
    ],
)
async def test_behavioral_failures_retain_diagnostics_and_clean_owned_state(
    tmp_path: Path, checkout: WorkspaceRef, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    sandbox = reporter(tmp_path)
    original = sandbox.run_task

    async def fail(value: ValidationTaskRequest) -> SandboxTaskExecution:
        result = await original(value)
        assert value.snapshot is not None
        if fault == "exit":
            return result.model_copy(update={"result": result.result.model_copy(update={"exit_code": 0})})
        if fault in {"truncated", "timeout"}:
            return result.model_copy(
                update={
                    "result": result.result.model_copy(
                        update={
                            "output_truncated": fault == "truncated",
                            "outcome": ValidationOutcome.TIMED_OUT,
                        }
                    )
                }
            )
        if fault == "cleanup":
            return result.model_copy(
                update={
                    "execution": result.execution.model_copy(
                        update={
                            "cleanup_status": ValidationCleanupStatus.FAILED,
                        }
                    )
                }
            )
        if fault == "mutation":
            (Path(value.snapshot.path) / "untrusted.txt").write_text("changed")
        if fault == "runtime":
            raw = json.loads(result.result.stdout)
            raw["runtime_digest"] = "sha256:" + ("a" if Path(value.snapshot.path).name == "base" else "b") * 64
            return result.model_copy(update={"result": result.result.model_copy(update={"stdout": json.dumps(raw)})})
        return result

    monkeypatch.setattr(sandbox, "run_task", fail)
    if fault == "reserved":
        (Path(checkout.path) / ".aios-verification").mkdir()
        (Path(checkout.path) / ".aios-verification/untrusted").write_text("replace trusted assets")
    if fault == "test_missing":
        shutil.rmtree(Path(checkout.path) / "tests")
    if fault == "test_symlink":
        shutil.rmtree(Path(checkout.path) / "tests")
        (Path(checkout.path) / "tests").symlink_to(tmp_path)
    if fault in {"head", "tree"}:
        original_capped = sandbox._run_capped

        async def capped(
            argv: list[str], *, cwd: Path, timeout: float, output_limit: int
        ) -> tuple[int, str, str, bool]:
            if (fault == "head" and "rev-parse" in argv) or (fault == "tree" and "ls-tree" in argv):
                return 1, "", "failed", False
            return await original_capped(argv, cwd=cwd, timeout=timeout, output_limit=output_limit)

        monkeypatch.setattr(sandbox, "_run_capped", capped)
    result = await sandbox.run_behavior(request(checkout))
    assert result.storage is not None and result.storage.failures, result.model_dump_json()
    assert result.evidence is None or not result.evidence.cleanup_succeeded
    assert not list((tmp_path / "scratch").glob("pair-*"))
    assert (Path(checkout.path) / ".git").is_dir()


async def test_behavioral_file_assertions_capability_and_artifact_failures(
    tmp_path: Path, checkout: WorkspaceRef
) -> None:
    from remediation_agent.adapters.evidence import LocalArtifactStore
    from remediation_agent.domain.models import ArtifactManifest
    from remediation_agent.ports.models import ArtifactWriteRequest

    class FailingStore(LocalArtifactStore):
        async def write_bundle(self, request: ArtifactWriteRequest) -> ArtifactManifest:
            raise OSError(errno.ENOSPC, "no space")

    sandbox = reporter(tmp_path)
    value = request(checkout)
    value = value.model_copy(
        update={
            "capability_only": True,
            "run_id": "fixture",
            "task": value.task.model_copy(update={"test_paths": ["tests/regression.js"]}),
        }
    )
    successful = await sandbox.run_behavior(value)
    assert successful.evidence is not None and len(successful.executions) == 1
    sandbox.result_store = FailingStore(tmp_path / "artifacts")
    failed = await sandbox.run_behavior(value)
    assert failed.storage is not None and failed.storage.failures
    assert any(f.operation == "persist_validation_evidence" for f in failed.storage.failures)
    assert not list((tmp_path / "scratch").glob("pair-*"))


def test_snapshot_size_and_asset_symlink_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import tarfile

    source = tmp_path / "source"
    source.mkdir()
    (source / "large").write_bytes(b"xx")
    monkeypatch.setattr(behavioral, "_MAX_BYTES", 1)
    with pytest.raises(ValueError, match="limits"):
        behavioral._copy(source, tmp_path / "copy")
    archive = tmp_path / "base.tar"
    with tarfile.open(archive, "w") as stream:
        entry = tarfile.TarInfo("large")
        entry.size = 2
        stream.addfile(entry, io.BytesIO(b"xx"))
    with pytest.raises(ValueError, match="limits"):
        behavioral._extract(archive, tmp_path / "base")
    (source / "link").symlink_to(source / "large")
    with pytest.raises(ValueError, match="asset"):
        behavioral._digest_files(source)


@pytest.mark.parametrize(
    "fault", ["root_link", "nested_link", "count", "overlap", "writable", "capacity", "lease", "absent"]
)
def test_storage_ownership_capacity_and_count_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    from remediation_agent.adapters import validation_storage as storage

    managed = tmp_path / "managed"
    managed.mkdir()
    scratch = tmp_path / "scratch"
    if fault == "root_link":
        scratch.symlink_to(managed)
        with pytest.raises(ValueError):
            ValidationScratch(scratch, managed)
        with pytest.raises(ValueError):
            storage.footprint(scratch)
        return
    if fault == "nested_link":
        (managed / "link").symlink_to(tmp_path)
        with pytest.raises(ValueError):
            storage.footprint(managed)
        return
    if fault == "count":
        (managed / "file").write_text("data")
        with pytest.raises(ValueError):
            storage.footprint(managed, max_files=0)
        return
    if fault == "overlap":
        with pytest.raises(ValueError):
            ValidationScratch(managed / "scratch", managed)
        return
    guard = ValidationScratch(scratch, managed)
    if fault == "writable":
        scratch.mkdir(mode=0o777)
        scratch.chmod(0o777)
        with pytest.raises(ValueError):
            guard.preflight(1, 1)
        return
    if fault == "capacity":
        from collections import namedtuple

        usage = namedtuple("usage", "total used free")
        monkeypatch.setattr(shutil, "disk_usage", lambda path: usage(1, 1, 0))
        with pytest.raises(ValidationStorageError):
            guard.preflight(1, 1)
        return
    guard.preflight(1, 1)
    if fault == "lease":
        with pytest.raises(ValueError):
            guard.register("unknown", "base", "owner", "a" * 40)
    else:
        lease, _ = guard.create()
        ref = guard.register(lease, "base", "owner", "a" * 40)
        with pytest.raises(ValueError, match="absent"):
            guard.resolve(ref)


async def test_cleanup_unknown_lease_and_missing_owned_snapshot(tmp_path: Path) -> None:
    (tmp_path / "managed").mkdir()
    guard = ValidationScratch(tmp_path / "scratch", tmp_path / "managed")
    guard.preflight(1, 1)
    with pytest.raises(ValueError):
        await guard.cleanup_lease("unknown")
    lease, _ = guard.create()
    ref = guard.register(lease, "base", "owner", "a" * 40)
    assert (await guard.cleanup_snapshot(ref)).status is ValidationCleanupStatus.SUCCEEDED
    assert (await guard.cleanup_lease(lease)).status is ValidationCleanupStatus.SUCCEEDED
