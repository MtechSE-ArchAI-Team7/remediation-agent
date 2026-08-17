"""Opt-in real-container validation and full remediation workflow tests."""

from __future__ import annotations

import json
import shutil
import stat
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from remediation_agent.adapters.checkpoint import in_memory_checkpointer
from remediation_agent.adapters.evidence import JsonlAuditSink, LocalArtifactStore
from remediation_agent.adapters.fakes import FakeInspectionToolProvider, FakeStructuredModel
from remediation_agent.adapters.pr import DraftPullRequestProvider
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.adapters.sandbox import DockerSandboxExecutor
from remediation_agent.domain.enums import FinalStatus, RepositoryProvider, ValidationOutcome
from remediation_agent.domain.models import RepositoryRef, WorkspaceRef
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from remediation_agent.policy.models import ValidationTaskConfig
from remediation_agent.ports.models import ValidationTaskRequest
from remediation_agent.service import RemediationService
from remediation_agent.workflow.graph import build_graph
from remediation_agent.workflow.nodes import WorkflowNodes
from tests.conftest import diagnosis_handoff, scripted_responses

pytestmark = pytest.mark.integration

_SANDBOX_IMAGE = "aios-remediation-sandbox:local"
_CONTAINER_PREFIX = "aios-remediation-"


@dataclass
class _DockerHarness:
    executable: str
    workspace_ids: set[str] = field(default_factory=set)

    def track(self, workspace_id: str) -> None:
        self.workspace_ids.add(workspace_id)

    def container_ids(self, workspace_id: str) -> list[str]:
        prefix = f"{_CONTAINER_PREFIX}{workspace_id[:30]}-"
        completed = subprocess.run(  # noqa: S603 - resolved Docker executable and fixed inspection arguments
            [self.executable, "ps", "-aq", "--filter", f"name={prefix}"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            return []
        return [item for item in completed.stdout.splitlines() if item]

    def remove_containers(self) -> None:
        for workspace_id in self.workspace_ids:
            for container_id in self.container_ids(workspace_id):
                subprocess.run(  # noqa: S603 - removes only containers created for a tracked test workspace
                    [self.executable, "rm", "--force", container_id],
                    check=False,
                    capture_output=True,
                    text=True,
                )


@pytest.fixture(scope="module")
def docker_executable() -> str:
    executable = shutil.which("docker")
    if executable is None:
        pytest.skip("Docker CLI is unavailable; install Docker and run `make sandbox-build`")
    server = subprocess.run(  # noqa: S603 - resolved Docker executable and fixed inspection arguments
        [executable, "version", "--format", "{{.Server.Version}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if server.returncode != 0 or not server.stdout.strip():
        pytest.skip("Docker daemon is unavailable; start Docker and run `make sandbox-build`")
    image = subprocess.run(  # noqa: S603 - resolved Docker executable and fixed image inspection arguments
        [executable, "image", "inspect", _SANDBOX_IMAGE],
        check=False,
        capture_output=True,
        text=True,
    )
    if image.returncode != 0:
        pytest.skip(f"Docker image {_SANDBOX_IMAGE} is unavailable; run `make sandbox-build`")
    return executable


@pytest.fixture
def docker_harness(docker_executable: str) -> Iterator[_DockerHarness]:
    harness = _DockerHarness(docker_executable)
    try:
        yield harness
    finally:
        harness.remove_containers()


class _ContainerReadableRepository(LocalGitRepository):
    """Make only test-owned workspaces accessible to the sandbox container UID."""

    def __init__(self, workspace_root: Path, harness: _DockerHarness) -> None:
        super().__init__(workspace_root)
        self.harness = harness
        self.last_workspace: WorkspaceRef | None = None

    async def create_workspace(self, ref: RepositoryRef) -> WorkspaceRef:
        workspace = await super().create_workspace(ref)
        _grant_container_access(Path(workspace.path))
        self.harness.track(workspace.workspace_id)
        self.last_workspace = workspace
        return workspace


def _git(cwd: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("Git is required for the Docker integration tests")
    completed = subprocess.run(  # noqa: S603 - resolved Git executable and test-owned arguments
        [executable, *arguments],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _fixture_repository(root: Path) -> tuple[Path, str]:
    repository = root / "source"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "AIOS Integration Test")
    _git(repository, "config", "user.email", "integration@example.invalid")
    (repository / "src").mkdir()
    (repository / "tests").mkdir()
    (repository / "src" / "app.py").write_text(
        "def parse_int(raw: str) -> int | None:\n    return int(raw)\n",
        encoding="utf-8",
    )
    (repository / "tests" / "test_app.py").write_text(
        "from src.app import parse_int\n\n\n"
        "def test_invalid_input_returns_none() -> None:\n"
        '    assert parse_int("invalid") is None\n',
        encoding="utf-8",
    )
    _git(repository, "add", "src/app.py", "tests/test_app.py")
    _git(repository, "commit", "-m", "fixture")
    return repository, _git(repository, "rev-parse", "HEAD")


def _grant_container_access(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            continue
        mode = path.stat().st_mode
        if path.is_dir():
            path.chmod(mode | stat.S_IRWXG | stat.S_IRWXO)
        else:
            path.chmod(mode | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)


def _workspace(tmp_path: Path, harness: _DockerHarness, name: str) -> tuple[DockerSandboxExecutor, WorkspaceRef]:
    workspace_root = tmp_path / "workspaces"
    workspace_path = workspace_root / name
    (workspace_path / ".git").mkdir(parents=True)
    _grant_container_access(workspace_root)
    workspace = WorkspaceRef(workspace_id=name, path=str(workspace_path), base_commit="a" * 40)
    harness.track(workspace.workspace_id)
    return DockerSandboxExecutor(workspace_root, _SANDBOX_IMAGE), workspace


def _task(argv: list[str], *, timeout: int = 10, output_limit: int = 65_536) -> ValidationTaskConfig:
    return ValidationTaskConfig(
        argv=argv,
        cwd=".",
        environment={},
        timeout_seconds=timeout,
        output_limit_bytes=output_limit,
        retryable=False,
    )


async def test_full_workflow_restores_base_and_passes_revised_patch(
    tmp_path: Path,
    docker_harness: _DockerHarness,
) -> None:
    source, commit = _fixture_repository(tmp_path)
    workspace_root = tmp_path / "workspaces"
    artifact_root = tmp_path / "artifacts"
    repository = _ContainerReadableRepository(workspace_root, docker_harness)
    sandbox = DockerSandboxExecutor(workspace_root, _SANDBOX_IMAGE)
    policy = PolicyEngine(load_policy(Path(__file__).parents[2] / "config" / "policies" / "reference.json"))
    failing_patch = (
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,2 +1,5 @@\n"
        " def parse_int(raw: str) -> int | None:\n"
        "-    return int(raw)\n"
        "+    try:\n"
        "+        return int(raw)\n"
        "+    except ValueError:\n"
        "+        return -1\n"
    )
    passing_patch = failing_patch.replace("+        return -1\n", "+        return None\n")
    model = FakeStructuredModel(
        scripted_responses(
            target_path="src/app.py",
            plan_summary="Return a typed absence for invalid integer input.",
            patch=failing_patch,
            revisions=[passing_patch],
            tasks=["unit_tests"],
        )
    )
    nodes = WorkflowNodes(
        policy=policy,
        model=model,
        repository=repository,
        inspection_tools=FakeInspectionToolProvider(repository, policy),
        sandbox=sandbox,
        pr_provider=DraftPullRequestProvider(writes_enabled=False),
        artifact_store=LocalArtifactStore(artifact_root),
        audit_sink=JsonlAuditSink(artifact_root),
        prompt_version="docker-integration-v1",
        github_writes_enabled=False,
    )
    service = RemediationService(build_graph(nodes, in_memory_checkpointer()), max_active_runs=1)
    handoff = diagnosis_handoff().model_copy(
        update={
            "repository": RepositoryRef(
                provider=RepositoryProvider.LOCAL,
                url=source.as_uri(),
                base_branch="main",
                commit_sha=commit,
            )
        }
    )

    result = await service.start(handoff)

    assert result.status is FinalStatus.DRAFT_PR_PREPARED
    assert result.result is not None
    assert [attempt.outcome for attempt in result.result.validation_attempts] == [
        ValidationOutcome.FAILED,
        ValidationOutcome.PASSED,
    ]
    assert [attempt.results[0].exit_code for attempt in result.result.validation_attempts] == [1, 0]
    assert result.result.changed_files == ["src/app.py"]
    assert result.result.failed_attempt_summaries == ["Attempt 1: FAILED"]
    assert result.result.rollback_instructions is not None
    assert result.result.draft_pr is not None
    assert result.result.draft_pr.created is False
    assert result.result.artifact_manifest is not None
    artifact_names = {item.name for item in result.result.artifact_manifest.artifacts}
    assert artifact_names == {
        "audit.jsonl",
        "draft-pr.json",
        "model-calls.json",
        "patch.diff",
        "result.json",
        "rollback.json",
        "validation.json",
    }
    run_directory = artifact_root / result.run_id
    assert all((run_directory / name).is_file() for name in artifact_names)
    assert "return None" in (run_directory / "patch.diff").read_text(encoding="utf-8")
    validation = json.loads((run_directory / "validation.json").read_text(encoding="utf-8"))
    assert [item["outcome"] for item in validation] == ["FAILED", "PASSED"]
    audit_events = [
        json.loads(line) for line in (run_directory / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert audit_events
    assert all(
        current["previous_hash"] == previous["event_hash"]
        for previous, current in zip(audit_events, audit_events[1:], strict=False)
    )
    assert repository.last_workspace is not None
    assert not Path(repository.last_workspace.path).exists()
    assert docker_harness.container_ids(repository.last_workspace.workspace_id) == []


async def test_real_container_enforces_non_root_network_and_git_isolation(
    tmp_path: Path,
    docker_harness: _DockerHarness,
) -> None:
    executor, workspace = _workspace(tmp_path, docker_harness, "isolation")
    probe = "\n".join(
        [
            "import os, socket",
            "from pathlib import Path",
            "assert os.geteuid() != 0",
            "probe = Path('workspace-probe')",
            "probe.write_text('ok')",
            "probe.unlink()",
            "try:",
            "    Path('.git/write-probe').write_text('blocked')",
            "except OSError:",
            "    pass",
            "else:",
            "    raise AssertionError('.git was writable')",
            "try:",
            "    socket.create_connection(('1.1.1.1', 53), timeout=0.25)",
            "except OSError:",
            "    pass",
            "else:",
            "    raise AssertionError('outbound networking was available')",
        ]
    )
    try:
        result = await executor.run_task(
            ValidationTaskRequest(
                workspace=workspace,
                task_name="isolation_probe",
                task=_task(["python", "-c", probe]),
            )
        )
        assert result.outcome is ValidationOutcome.PASSED
        assert result.exit_code == 0
    finally:
        cleanup = await executor.destroy(workspace)
        assert cleanup.succeeded
    assert docker_harness.container_ids(workspace.workspace_id) == []


async def test_real_container_maps_failure_and_caps_combined_output(
    tmp_path: Path,
    docker_harness: _DockerHarness,
) -> None:
    executor, workspace = _workspace(tmp_path, docker_harness, "failure-output")
    try:
        failed = await executor.run_task(
            ValidationTaskRequest(
                workspace=workspace,
                task_name="known_failure",
                task=_task(["python", "-c", "raise SystemExit(7)"]),
            )
        )
        capped = await executor.run_task(
            ValidationTaskRequest(
                workspace=workspace,
                task_name="bounded_output",
                task=_task(
                    [
                        "python",
                        "-c",
                        "import sys; print('x' * 4096); print('y' * 4096, file=sys.stderr)",
                    ],
                    output_limit=1_024,
                ),
            )
        )
        assert failed.outcome is ValidationOutcome.FAILED
        assert failed.exit_code == 7
        assert capped.outcome is ValidationOutcome.PASSED
        assert capped.output_truncated
        assert len(capped.stdout.encode()) + len(capped.stderr.encode()) == 1_024
    finally:
        cleanup = await executor.destroy(workspace)
        assert cleanup.succeeded
    assert docker_harness.container_ids(workspace.workspace_id) == []


async def test_real_container_timeout_forces_removal(
    tmp_path: Path,
    docker_harness: _DockerHarness,
) -> None:
    executor, workspace = _workspace(tmp_path, docker_harness, "timeout")
    try:
        result = await executor.run_task(
            ValidationTaskRequest(
                workspace=workspace,
                task_name="bounded_timeout",
                task=_task(["python", "-c", "import time; time.sleep(30)"], timeout=1),
            )
        )
        assert result.outcome is ValidationOutcome.TIMED_OUT
        assert result.exit_code is None
        assert docker_harness.container_ids(workspace.workspace_id) == []
    finally:
        cleanup = await executor.destroy(workspace)
        assert cleanup.succeeded
    assert docker_harness.container_ids(workspace.workspace_id) == []
