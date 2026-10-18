"""Sandbox process output is bounded while it is being consumed."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from remediation_agent.adapters.sandbox import DockerSandboxExecutor
from remediation_agent.domain.models import WorkspaceRef
from remediation_agent.policy.models import ValidationTaskConfig
from remediation_agent.ports.models import ValidationTaskRequest


async def test_subprocess_output_is_streamed_with_combined_cap(tmp_path: Path) -> None:
    return_code, stdout, stderr, truncated = await DockerSandboxExecutor._run_capped(
        [sys.executable, "-c", "import sys; print('x' * 10000); print('y' * 10000, file=sys.stderr)"],
        cwd=tmp_path,
        timeout=5,
        output_limit=1_024,
    )
    assert return_code == 0
    assert len(stdout.encode()) + len(stderr.encode()) == 1_024
    assert truncated


@pytest.mark.parametrize("behavioral", [False, True])
async def test_docker_task_argv_enforces_isolation_and_read_only_git(
    tmp_path: Path,
    behavioral: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_root = tmp_path / "workspaces"
    workspace_path = workspace_root / "run"
    (workspace_path / ".git").mkdir(parents=True)
    captured: list[str] = []
    executor = DockerSandboxExecutor(workspace_root, "sandbox-image:test")

    async def fake_run(
        argv: list[str],
        *,
        cwd: Path,
        timeout: float,
        output_limit: int,
    ) -> tuple[int, str, str, bool]:
        _ = cwd, timeout, output_limit
        captured.extend(argv)
        return 0, "ok", "", False

    monkeypatch.setattr(executor, "_run_capped", fake_run)
    execution = await executor.run_task(
        ValidationTaskRequest(
            workspace=WorkspaceRef(workspace_id="run", path=str(workspace_path), base_commit="a" * 40),
            task_name="unit_tests",
            task=ValidationTaskConfig(
                kind="BEHAVIORAL" if behavioral else "STATIC",
                profile="pytest" if behavioral else None,
                test_paths=["tests"] if behavioral else [],
                argv=["python", "-m", "pytest", "-q"],
                timeout_seconds=30,
                output_limit_bytes=4_096,
            ),
        )
    )
    assert execution.result.exit_code == 0
    assert execution.execution.backend == "DOCKER"
    assert ["--network", "none"] == captured[captured.index("--network") : captured.index("--network") + 2]
    assert f"{workspace_path}:/workspace:{'ro' if behavioral else 'rw'}" in captured
    assert "--read-only" in captured
    assert ["--cap-drop", "ALL"] == captured[captured.index("--cap-drop") : captured.index("--cap-drop") + 2]
    assert "no-new-privileges" in captured
    assert f"{workspace_path / '.git'}:/workspace/.git:ro" in captured
    assert captured[-5:] == ["sandbox-image:test", "python", "-m", "pytest", "-q"]


async def test_restore_scopes_git_safe_directory_to_validated_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_root = tmp_path / "workspaces"
    workspace_path = workspace_root / "run"
    workspace_path.mkdir(parents=True)
    executor = DockerSandboxExecutor(workspace_root, "unused")
    calls: list[list[str]] = []

    async def fake_run(argv: list[str], *, cwd: Path, timeout: float) -> None:
        assert cwd == workspace_path
        assert timeout == 60.0
        calls.append(argv)

    monkeypatch.setattr(executor, "_run", fake_run)
    await executor.restore_base(WorkspaceRef(workspace_id="run", path=str(workspace_path), base_commit="a" * 40))

    safe_config = ["git", "-c", f"safe.directory={workspace_path}"]
    assert calls == [
        [*safe_config, "reset", "--hard", "a" * 40],
        [*safe_config, "clean", "-fdx"],
    ]


@pytest.mark.parametrize(
    "fault,removed", [("timeout", True), ("timeout", False), ("runtime", True), ("runtime", False), ("exit", True)]
)
async def test_executor_failure_cleanup_is_observable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str, removed: bool
) -> None:
    from remediation_agent.domain.enums import ValidationCleanupStatus

    root = tmp_path / "workspaces/run"
    (root / ".git").mkdir(parents=True)
    executor = DockerSandboxExecutor(root.parent, "fixture")

    async def fail(argv: list[str], *, cwd: Path, timeout: float, output_limit: int) -> tuple[int, str, str, bool]:
        if fault == "exit":
            return 1, "assertion failed", "", False
        if fault == "timeout":
            raise TimeoutError
        raise RuntimeError("lost response")

    async def cleanup(name: str, cwd: Path) -> bool:
        return removed

    monkeypatch.setattr(executor, "_run_capped", fail)
    monkeypatch.setattr(executor, "_remove_container", cleanup)
    value = ValidationTaskRequest(
        workspace=WorkspaceRef(workspace_id="run", path=str(root), base_commit="a" * 40),
        task_name="check",
        task=ValidationTaskConfig(
            argv=["python", "check.py"], timeout_seconds=30, output_limit_bytes=4096, environment={"FIXTURE": "1"}
        ),
    )
    if fault == "runtime":
        with pytest.raises(RuntimeError):
            await executor.run_task(value)
    else:
        result = await executor.run_task(value)
        assert result.result.outcome != "PASSED"
        assert (result.execution.cleanup_status == ValidationCleanupStatus.SUCCEEDED) == removed
    assert bool(executor._active_containers) == (not removed)


@pytest.mark.parametrize("fault", ["missing", "symlink", "escape"])
async def test_invalid_validation_workdir_never_executes(tmp_path: Path, fault: str) -> None:
    from remediation_agent.adapters.sandbox import SandboxError

    root = tmp_path / "workspaces/run"
    root.mkdir(parents=True)
    (root / "link").symlink_to(tmp_path)
    sandbox = DockerSandboxExecutor(root.parent, "fixture")
    task = ValidationTaskConfig(argv=["python", "check.py"], timeout_seconds=30, output_limit_bytes=4096)
    task = task.model_copy(update={"cwd": {"missing": "missing", "symlink": "link", "escape": "../.."}[fault]})
    with pytest.raises(SandboxError):
        await sandbox.run_task(
            ValidationTaskRequest(
                workspace=WorkspaceRef(workspace_id="run", path=str(root), base_commit="a" * 40),
                task_name="check",
                task=task,
            )
        )
    assert not sandbox._active_containers


async def test_destroy_retains_workspace_when_process_cannot_be_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "workspaces/run"
    root.mkdir(parents=True)
    sandbox = DockerSandboxExecutor(root.parent, "fixture")
    sandbox._active_containers.update({"owned": "run", "unrelated": "other"})

    async def fail(name: str, cwd: Path) -> bool:
        assert name == "owned"
        return False

    monkeypatch.setattr(sandbox, "_remove_container", fail)
    workspace = WorkspaceRef(workspace_id="run", path=str(root), base_commit="a" * 40)
    assert not (await sandbox.destroy(workspace)).succeeded and root.exists()
    assert len(sandbox._active_containers) == 2
    assert (await sandbox.collect_artifacts(workspace)).artifacts == []
