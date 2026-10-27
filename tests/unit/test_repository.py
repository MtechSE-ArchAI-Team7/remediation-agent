"""Local fixture-repository integration tests; no network or production repository is used."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
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
    TreeRequest,
)
from tests.conftest import patch_for


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


@pytest.mark.parametrize("path", ["../outside", "/absolute", ".git/config", "nul\x00file", "missing"])
async def test_invalid_reads_are_bounded_failures(tmp_path: Path, path: str) -> None:
    source, commit = _fixture_repository(tmp_path)
    adapter = LocalGitRepository(tmp_path / "workspaces")
    workspace = await adapter.create_workspace(
        RepositoryRef(provider=RepositoryProvider.LOCAL, url=str(source), base_branch="main", commit_sha=commit)
    )
    with pytest.raises(RepositoryError):
        await adapter.read_file(ReadFileRequest(workspace=workspace, relative_path=path, max_bytes=10))
    await adapter.remove_workspace(workspace)


async def test_tree_search_limits_forbidden_binary_large_and_symlink_files(tmp_path: Path) -> None:
    source, commit = _fixture_repository(tmp_path)
    adapter = LocalGitRepository(tmp_path / "workspaces")
    workspace = await adapter.create_workspace(
        RepositoryRef(provider=RepositoryProvider.LOCAL, url=str(source), base_branch="main", commit_sha=commit)
    )
    root = Path(workspace.path)
    (root / "binary").write_bytes(b"\xff")
    (root / "large").write_text("x" * 100)
    (root / "link").symlink_to(root / "src/app.py")
    (root / "secret").mkdir()
    (root / "secret/value").write_text("int(")
    full = await adapter.list_tree(
        TreeRequest(workspace=workspace, max_entries=100, forbidden_path_patterns=["secret*"])
    )
    assert "link [symlink]" in full.entries and "src/" in full.entries
    assert not full.truncated and not any("secret" in p or ".git" in p for p in full.entries)
    limited = await adapter.list_tree(TreeRequest(workspace=workspace, max_entries=1))
    assert limited.truncated and len(limited.entries) == 1
    matches = await adapter.search(
        SearchRequest(
            workspace=workspace, query="int(", max_results=1, max_file_bytes=50, forbidden_path_patterns=["secret*"]
        )
    )
    assert matches.truncated and matches.hits[0].relative_path == "src/app.py"
    assert not (
        await adapter.search(SearchRequest(workspace=workspace, query="absent", max_results=5, max_file_bytes=50))
    ).hits
    with pytest.raises(RepositoryError, match="UTF-8"):
        await adapter.read_file(ReadFileRequest(workspace=workspace, relative_path="binary", max_bytes=10))
    assert (await adapter.read_file(ReadFileRequest(workspace=workspace, relative_path="large", max_bytes=2))).truncated
    with pytest.raises(RepositoryError, match="not a file"):
        await adapter.read_file(ReadFileRequest(workspace=workspace, relative_path="src", max_bytes=10))
    with pytest.raises(RepositoryError, match="not a directory"):
        await adapter.list_tree(TreeRequest(workspace=workspace, relative_path="src/app.py", max_entries=1))
    await adapter.remove_workspace(workspace)


async def test_clone_mismatch_removes_partial_workspace(tmp_path: Path) -> None:
    source, _ = _fixture_repository(tmp_path)
    root = tmp_path / "workspaces"
    adapter = LocalGitRepository(root)
    with pytest.raises(RepositoryError, match="immutable commit"):
        await adapter.create_workspace(
            RepositoryRef(provider=RepositoryProvider.LOCAL, url=str(source), base_branch="main", commit_sha="f" * 40)
        )
    assert not list(root.iterdir())


async def test_publication_rejects_changed_tree_remote_and_commit(tmp_path: Path) -> None:
    source, commit = _fixture_repository(tmp_path)
    adapter = LocalGitRepository(tmp_path / "workspaces")
    ref = RepositoryRef(provider=RepositoryProvider.LOCAL, url=str(source), base_branch="main", commit_sha=commit)
    workspace = await adapter.create_workspace(ref)
    with pytest.raises(PublicationError, match="TREE_CHANGED"):
        await adapter.publication_check(
            PublicationCheckRequest(workspace=workspace, repository=ref, expected_tree="f" * 40)
        )
    wrong = ref.model_copy(update={"url": str(tmp_path / "different")})
    with pytest.raises(PublicationError, match="REPOSITORY_MISMATCH"):
        await adapter.publication_check(PublicationCheckRequest(workspace=workspace, repository=wrong))
    with pytest.raises(PublicationError, match="TREE_CHANGED"):
        await adapter.commit(CommitRequest(workspace=workspace, message="fix", expected_tree="f" * 40))
    with pytest.raises(RepositoryError, match="empty or unrelated"):
        await adapter.commit(CommitRequest(workspace=workspace, message="not the original commit"))
    with pytest.raises(RepositoryError, match="remote name"):
        await adapter.push(PushRequest(workspace=workspace, branch_name="main", remote="--evil"))
    with pytest.raises(PublicationError, match="COMMIT_MISMATCH"):
        await adapter.push(PushRequest(workspace=workspace, branch_name="main", expected_commit="f" * 40))
    with pytest.raises(RepositoryError, match="digest changed"):
        await adapter.verify_workspace(workspace, "sha256:wrong")
    (Path(workspace.path) / ".git").rename(Path(workspace.path) / "lost-git")
    with pytest.raises(RepositoryError, match="metadata unavailable"):
        await adapter.verify_workspace(workspace)
    await adapter.remove_workspace(workspace)


async def test_subprocess_output_timeout_failure_and_cancellation(tmp_path: Path) -> None:
    # Output and exit-code checks must allow interpreter startup with coverage enabled.
    adapter = LocalGitRepository(tmp_path, command_timeout_seconds=5, max_command_output_bytes=10)
    with pytest.raises(RepositoryError, match="output limit"):
        await adapter._run([sys.executable, "-c", "print('x'*100)"], cwd=tmp_path)
    with pytest.raises(RepositoryError, match="failed"):
        await adapter._run([sys.executable, "-c", "raise SystemExit(1)"], cwd=tmp_path)
    timeout_adapter = LocalGitRepository(tmp_path, command_timeout_seconds=0.05, max_command_output_bytes=10)
    with pytest.raises(RepositoryError, match="timed out"):
        await timeout_adapter._run([sys.executable, "-c", "import time; time.sleep(5)"], cwd=tmp_path)
    task = asyncio.create_task(adapter._run([sys.executable, "-c", "import time; time.sleep(5)"], cwd=tmp_path))
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_workspace_and_cleanup_cannot_escape(tmp_path: Path) -> None:
    from remediation_agent.domain.models import WorkspaceRef

    root = tmp_path / "workspaces"
    root.mkdir()
    adapter = LocalGitRepository(root)
    for path in (tmp_path, root, root / "missing"):
        with pytest.raises(RepositoryError):
            adapter.validate_workspace(WorkspaceRef(workspace_id="fixture", path=str(path), base_commit="a" * 40))
    linked = root / "linked"
    linked.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(RepositoryError, match="symlink"):
        adapter.validate_workspace(WorkspaceRef(workspace_id="fixture", path=str(linked), base_commit="a" * 40))
    for path in (tmp_path, root, linked):
        with pytest.raises(RepositoryError, match="cleanup"):
            adapter._safe_remove_workspace(path)
    with pytest.raises(RepositoryError, match="configuration outside"):
        adapter._git_environment(tmp_path)


@pytest.mark.parametrize("fault", ["none", "head", "truncated", "uninspected", "create", "exists", "symlink", "tamper"])
async def test_edit_compilation_binds_source_and_checks_applied_content(tmp_path: Path, fault: str) -> None:
    from remediation_agent.domain.models import EditProposal, InspectionArtifact, SourceEdit
    from remediation_agent.ports.models import CandidateVerifyRequest, EditCompileRequest
    from remediation_agent.source import EditConstructionError, digest, source_artifact

    source, commit = _fixture_repository(tmp_path)
    adapter = LocalGitRepository(tmp_path / "workspaces")
    workspace = await adapter.create_workspace(
        RepositoryRef(provider=RepositoryProvider.LOCAL, url=str(source), base_branch="main", commit_sha=commit)
    )
    original = "value = int(raw)\n"
    artifact = source_artifact("src/app.py", original)
    create = fault in {"create", "exists", "symlink"}
    path = "src/new.py" if fault == "create" else "src/link/new.py" if fault == "symlink" else "src/app.py"
    edit = SourceEdit(
        path=path,
        create=create,
        base_content_digest=digest("" if create else original),
        start_line=1,
        end_line=1 if create else 2,
        expected_content="" if create else original,
        replacement="value = 0\n",
    )
    value = EditCompileRequest(
        workspace=workspace,
        proposal=EditProposal(edits=[edit], rationale="Bounded fixture repair"),
        artifacts=[]
        if fault == "uninspected"
        else [
            artifact,
            InspectionArtifact(kind="TREE", locator=".", digest="sha256:" + "a" * 64, content="src/app.py"),
        ],
        allowed_paths=[path],
        max_file_bytes=1 if fault == "truncated" else 4096,
    )
    if fault == "head":
        value = value.model_copy(update={"workspace": workspace.model_copy(update={"base_commit": "0" * 40})})
    if fault == "symlink":
        (Path(workspace.path) / "src/link").symlink_to(tmp_path)
    try:
        if fault in {"head", "truncated", "uninspected", "exists", "symlink"}:
            with pytest.raises((RepositoryError, EditConstructionError)):
                await adapter.compile_edits(value)
        else:
            compiled = await adapter.compile_edits(value)
            await DockerSandboxExecutor(tmp_path / "workspaces", "unused").apply_patch(
                PatchApplyRequest(workspace=workspace, unified_diff=compiled.candidate.unified_diff)
            )
            check = CandidateVerifyRequest(workspace=workspace, receipts=compiled.receipts)
            await adapter.verify_candidate(check)
            if fault == "tamper":
                (Path(workspace.path) / path).write_text("tampered\n")
                with pytest.raises(RepositoryError, match="CANDIDATE_MISMATCH"):
                    await adapter.verify_candidate(check)
    finally:
        await adapter.remove_workspace(workspace)
