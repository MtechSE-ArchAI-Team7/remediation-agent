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


async def test_docker_task_argv_enforces_isolation_and_read_only_git(
    tmp_path: Path,
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
                argv=["python", "-m", "pytest", "-q"],
                timeout_seconds=30,
                output_limit_bytes=4_096,
            ),
        )
    )
    assert execution.result.exit_code == 0
    assert execution.execution.backend == "DOCKER"
    assert ["--network", "none"] == captured[captured.index("--network") : captured.index("--network") + 2]
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
