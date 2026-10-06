"""Local fixture-repository integration tests; no network or production repository is used."""

from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from remediation_agent.adapters.repository import LocalGitRepository, RepositoryError
from remediation_agent.adapters.sandbox import DockerSandboxExecutor, SandboxError
from remediation_agent.domain.enums import RepositoryProvider
from remediation_agent.domain.models import RepositoryRef
from remediation_agent.ports.models import (
    BranchRequest,
    CommitRequest,
    PatchApplyRequest,
    PublicationCheckRequest,
    PublicationError,
    PushRequest,
    ReadFileRequest,
    SearchRequest,
)
from tests.conftest import patch_for

pytestmark = pytest.mark.integration


def _git(cwd: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("Git is required for this integration test")
    completed = subprocess.run(  # noqa: S603 - fixed executable and test-owned arguments
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
    _git(repository, "config", "user.name", "AIOS Test")
    _git(repository, "config", "user.email", "test@example.invalid")
    (repository / "src").mkdir()
    (repository / "src" / "app.py").write_text("value = int(raw)\n")
    _git(repository, "add", "src/app.py")
    _git(repository, "commit", "-m", "fixture")
    return repository, _git(repository, "rev-parse", "HEAD")


async def test_clone_inspect_patch_restore_and_cleanup(tmp_path: Path) -> None:
    source, commit = _fixture_repository(tmp_path)
    workspace_root = tmp_path / "workspaces"
    repository = LocalGitRepository(workspace_root)
    workspace = await repository.create_workspace(
        RepositoryRef(
            provider=RepositoryProvider.LOCAL,
            url=str(source),
            base_branch="main",
            commit_sha=commit,
        )
    )
    content = await repository.read_file(
        ReadFileRequest(workspace=workspace, relative_path="src/app.py", max_bytes=1_024)
    )
    search = await repository.search(
        SearchRequest(workspace=workspace, query="int(", max_results=5, max_file_bytes=1_024)
    )
    assert content.content == "value = int(raw)\n"
    assert search.hits[0].relative_path == "src/app.py"

    sandbox = DockerSandboxExecutor(workspace_root, "unused-for-patch-test")
    patch = patch_for() + "--- /dev/null\n+++ b/tests/test_app.py\n@@ -0,0 +1 @@\n+def test_invalid(): pass\n"
    await sandbox.apply_patch(PatchApplyRequest(workspace=workspace, unified_diff=patch))
    assert Path(workspace.path, "src", "app.py").read_text() == "value = safe_int(raw)\n"
    current_diff = await repository.current_diff(workspace)
    assert "tests/test_app.py" in current_diff.unified_diff
    branch_request = BranchRequest(workspace=workspace, branch_name="aios/remediation/test")
    await repository.create_branch(branch_request)
    await repository.create_branch(branch_request)
    commit_request = CommitRequest(workspace=workspace, message="fix: bounded fixture remediation")
    first_commit = await repository.commit(commit_request)
    repeated_commit = await repository.commit(commit_request)
    assert repeated_commit.commit_sha == first_commit.commit_sha
    await sandbox.restore_base(workspace)
    assert Path(workspace.path, "src", "app.py").read_text() == "value = int(raw)\n"
    assert not Path(workspace.path, "tests", "test_app.py").exists()
    cleanup = await sandbox.destroy(workspace)
    assert cleanup.succeeded
    assert not Path(workspace.path).exists()


async def test_repository_rejects_traversal_and_symlink_reads(tmp_path: Path) -> None:
    source, commit = _fixture_repository(tmp_path)
    repository = LocalGitRepository(tmp_path / "workspaces")
    workspace = await repository.create_workspace(
        RepositoryRef(
            provider=RepositoryProvider.LOCAL,
            url=str(source),
            base_branch="main",
            commit_sha=commit,
        )
    )
    with pytest.raises(RepositoryError, match="traversal"):
        await repository.read_file(ReadFileRequest(workspace=workspace, relative_path="../outside", max_bytes=1_024))
    Path(workspace.path, "link.py").symlink_to(Path(workspace.path, "src", "app.py"))
    with pytest.raises(RepositoryError, match="symlink"):
        await repository.read_file(ReadFileRequest(workspace=workspace, relative_path="link.py", max_bytes=1_024))
    sandbox = DockerSandboxExecutor(tmp_path / "workspaces", "unused-for-patch-test")
    with pytest.raises(SandboxError, match="symlink"):
        await sandbox.apply_patch(PatchApplyRequest(workspace=workspace, unified_diff=patch_for("link.py")))


async def test_real_git_recovers_lost_push_response_and_rejects_changed_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, base = _fixture_repository(tmp_path)
    remote = tmp_path / "remote.git"
    _git(tmp_path, "clone", "--bare", str(source), str(remote))
    ref = RepositoryRef(provider=RepositoryProvider.LOCAL, url=str(remote), base_branch="main", commit_sha=base)
    repository = LocalGitRepository(tmp_path / "workspaces")
    workspace = await repository.create_workspace(ref)
    sandbox = DockerSandboxExecutor(tmp_path / "workspaces", "unused-for-git-proof")
    try:
        await sandbox.apply_patch(PatchApplyRequest(workspace=workspace, unified_diff=patch_for()))
        tree = await repository.publication_check(PublicationCheckRequest(workspace=workspace, repository=ref))
        branch = "aios/remediation/recovery"
        await repository.create_branch(BranchRequest(workspace=workspace, branch_name=branch))
        commit_request = CommitRequest(
            workspace=workspace,
            message="fix: reproducible",
            expected_tree=tree,
            authored_at=datetime(2026, 10, 1, tzinfo=UTC),
        )
        commit = await repository.commit(commit_request)
        assert await repository.commit(commit_request) == commit
        original = repository._run
        lost = False

        async def lose_response(argv: list[str], **kwargs):  # type: ignore[no-untyped-def]
            nonlocal lost
            result = await original(argv, **kwargs)
            if "push" in argv and not lost:
                lost = True
                raise RepositoryError("simulated lost push acknowledgement")
            return result

        monkeypatch.setattr(repository, "_run", lose_response)
        push = PushRequest(workspace=workspace, branch_name=branch, expected_commit=commit.commit_sha)
        with pytest.raises(RepositoryError, match="lost push"):
            await repository.push(push)
        assert (await repository.push(push)).pushed
        assert _git(remote, "rev-parse", "refs/heads/" + branch) == commit.commit_sha
        (source / "README.md").write_text("upstream advanced\n")
        _git(source, "add", "README.md")
        _git(source, "commit", "-m", "new upstream base")
        _git(source, "push", str(remote), "main")
        with pytest.raises(PublicationError, match="BASE_CHANGED"):
            await repository.publication_check(
                PublicationCheckRequest(workspace=workspace, repository=ref, expected_tree=tree)
            )
    finally:
        assert (await sandbox.destroy(workspace)).succeeded
