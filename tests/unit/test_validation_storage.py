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
