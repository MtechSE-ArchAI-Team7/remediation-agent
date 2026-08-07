"""Restricted local Git repository adapter."""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import os
import shutil
import tempfile
from pathlib import Path

from remediation_agent.domain.models import RepositoryRef, WorkspaceRef
from remediation_agent.ports.models import (
    BranchRequest,
    BranchResult,
    CommitRequest,
    CommitResult,
    DiffResult,
    FileContent,
    PushRequest,
    PushResult,
    ReadFileRequest,
    SearchHit,
    SearchRequest,
    SearchResult,
    TreeRequest,
    TreeResult,
)


class RepositoryError(RuntimeError):
    """Raised when a typed repository operation fails."""


class LocalGitRepository:
    """Use fixed Git operations and bounded Python filesystem inspection."""

    def __init__(
        self,
        workspace_root: Path,
        command_timeout_seconds: float = 120.0,
        *,
        author_name: str = "AIOS Remediation Agent",
        author_email: str = "aios-remediation@users.noreply.github.com",
        max_command_output_bytes: int = 4_194_304,
    ) -> None:
        self.workspace_root = workspace_root.resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.command_timeout_seconds = command_timeout_seconds
        self.author_name = author_name
        self.author_email = author_email
        self.max_command_output_bytes = max_command_output_bytes

    async def create_workspace(self, ref: RepositoryRef) -> WorkspaceRef:
        workspace_path = Path(tempfile.mkdtemp(prefix="remediation-", dir=self.workspace_root)).resolve()
        command = [
            "git",
            "clone",
            "--no-hardlinks",
            "--single-branch",
            "--branch",
            ref.base_branch,
            "--",
            ref.url,
            str(workspace_path),
        ]
        try:
            await self._run(command, cwd=self.workspace_root)
            if ref.commit_sha:
                branch_commit = (await self._run(["git", "rev-parse", "HEAD"], cwd=workspace_path)).strip()
                if not branch_commit.lower().startswith(ref.commit_sha.lower()):
                    raise RepositoryError("base branch no longer points at the supplied immutable commit")
                await self._run(["git", "checkout", "--detach", ref.commit_sha], cwd=workspace_path)
            base_commit = (await self._run(["git", "rev-parse", "HEAD"], cwd=workspace_path)).strip()
            if ref.commit_sha and not base_commit.lower().startswith(ref.commit_sha.lower()):
                raise RepositoryError("checked-out commit does not match requested immutable base")
        except Exception:
            self._safe_remove_workspace(workspace_path)
            raise
        return WorkspaceRef(workspace_id=workspace_path.name, path=str(workspace_path), base_commit=base_commit)

    async def list_tree(self, request: TreeRequest) -> TreeResult:
        root = self._workspace_root(request.workspace)
        start = self._resolve_path(root, request.relative_path, allow_directory=True)
        entries: list[str] = []
        truncated = False
        for current_root, directories, files in os.walk(start, followlinks=False):
            current = Path(current_root)
            directories[:] = sorted(
                name
                for name in directories
                if name != ".git"
                and not self._is_forbidden(
                    (current / name).relative_to(root).as_posix(),
                    request.forbidden_path_patterns,
                )
            )
            for name in [*directories, *sorted(files)]:
                candidate = current / name
                relative = candidate.relative_to(root).as_posix()
                if self._is_forbidden(relative, request.forbidden_path_patterns):
                    continue
                if candidate.is_symlink():
                    relative += " [symlink]"
                elif candidate.is_dir():
                    relative += "/"
                entries.append(relative)
                if len(entries) >= request.max_entries:
                    truncated = True
                    return TreeResult(entries=entries, truncated=truncated)
        return TreeResult(entries=entries, truncated=truncated)

    async def read_file(self, request: ReadFileRequest) -> FileContent:
        root = self._workspace_root(request.workspace)
        path = self._resolve_path(root, request.relative_path, allow_directory=False)
        raw = path.read_bytes()
        truncated = len(raw) > request.max_bytes
        bounded = raw[: request.max_bytes]
        try:
            content = bounded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RepositoryError(f"file is not UTF-8 text: {request.relative_path}") from exc
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        return FileContent(
            relative_path=path.relative_to(root).as_posix(),
            content=content,
            digest=digest,
            truncated=truncated,
        )

    async def search(self, request: SearchRequest) -> SearchResult:
        root = self._workspace_root(request.workspace)
        hits: list[SearchHit] = []
        truncated = False
        for current_root, directories, files in os.walk(root, followlinks=False):
            current = Path(current_root)
            directories[:] = sorted(
                name
                for name in directories
                if name != ".git"
                and not self._is_forbidden(
                    (current / name).relative_to(root).as_posix(),
                    request.forbidden_path_patterns,
                )
            )
            for name in sorted(files):
                path = Path(current_root) / name
                relative = path.relative_to(root).as_posix()
                if self._is_forbidden(relative, request.forbidden_path_patterns):
                    continue
                if path.is_symlink() or path.stat().st_size > request.max_file_bytes:
                    continue
                try:
                    lines = path.read_text(encoding="utf-8").splitlines()
                except (OSError, UnicodeDecodeError):
                    continue
                for line_number, line in enumerate(lines, start=1):
                    if request.query in line:
                        hits.append(SearchHit(relative_path=relative, line_number=line_number, line=line[:2_000]))
                        if len(hits) >= request.max_results:
                            truncated = True
                            return SearchResult(query=request.query, hits=hits, truncated=truncated)
        return SearchResult(query=request.query, hits=hits, truncated=truncated)

    async def current_diff(self, workspace: WorkspaceRef) -> DiffResult:
        root = self._workspace_root(workspace)
        await self._run(["git", "add", "--intent-to-add", "--all", "--", "."], cwd=root)
        diff = await self._run(["git", "diff", "--no-ext-diff", "--binary", "HEAD", "--"], cwd=root)
        return DiffResult(unified_diff=diff, digest="sha256:" + hashlib.sha256(diff.encode()).hexdigest())

    async def create_branch(self, request: BranchRequest) -> BranchResult:
        root = self._workspace_root(request.workspace)
        current = (await self._run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root)).strip()
        if current == request.branch_name:
            return BranchResult(branch_name=request.branch_name)
        await self._run(["git", "switch", "-c", request.branch_name], cwd=root)
        return BranchResult(branch_name=request.branch_name)

    async def commit(self, request: CommitRequest) -> CommitResult:
        root = self._workspace_root(request.workspace)
        await self._run(["git", "add", "--all", "--", "."], cwd=root)
        status = (await self._run(["git", "status", "--porcelain"], cwd=root)).strip()
        if not status:
            existing_message = (await self._run(["git", "log", "-1", "--pretty=%s"], cwd=root)).strip()
            if existing_message != request.message:
                raise RepositoryError("refused to create an empty or unrelated commit")
            sha = (await self._run(["git", "rev-parse", "HEAD"], cwd=root)).strip()
            return CommitResult(commit_sha=sha)
        await self._run(
            [
                "git",
                "-c",
                f"user.name={self.author_name}",
                "-c",
                f"user.email={self.author_email}",
                "commit",
                "-m",
                request.message,
            ],
            cwd=root,
        )
        sha = (await self._run(["git", "rev-parse", "HEAD"], cwd=root)).strip()
        return CommitResult(commit_sha=sha)

    async def push(self, request: PushRequest) -> PushResult:
        root = self._workspace_root(request.workspace)
        await self._run(["git", "push", "--set-upstream", request.remote, request.branch_name], cwd=root)
        return PushResult(remote=request.remote, branch_name=request.branch_name, pushed=True)

    def validate_workspace(self, workspace: WorkspaceRef) -> Path:
        return self._workspace_root(workspace)

    def _workspace_root(self, workspace: WorkspaceRef) -> Path:
        unresolved = Path(workspace.path)
        if unresolved.is_symlink():
            raise RepositoryError("workspace root cannot be a symlink")
        root = unresolved.resolve()
        if not root.is_relative_to(self.workspace_root) or root == self.workspace_root:
            raise RepositoryError("workspace is outside the configured workspace root")
        if not root.is_dir() or root.is_symlink():
            raise RepositoryError("workspace does not exist or is a symlink")
        return root

    @staticmethod
    def _resolve_path(root: Path, relative_path: str, *, allow_directory: bool) -> Path:
        if "\x00" in relative_path:
            raise RepositoryError("path contains NUL")
        requested = Path(relative_path)
        if requested.is_absolute() or ".." in requested.parts or (requested.parts and requested.parts[0] == ".git"):
            raise RepositoryError("path traversal is not allowed")
        candidate = root / requested
        cursor = root
        for part in requested.parts:
            cursor /= part
            if cursor.is_symlink():
                raise RepositoryError(f"symlink access is not allowed: {relative_path}")
        try:
            stat_result = candidate.lstat()
        except OSError as exc:
            raise RepositoryError(f"repository path is unavailable: {relative_path}") from exc
        if candidate.is_symlink():
            raise RepositoryError(f"symlink access is not allowed: {relative_path}")
        resolved = candidate.resolve()
        if not resolved.is_relative_to(root):
            raise RepositoryError("resolved path escapes the workspace")
        if allow_directory and not resolved.is_dir():
            raise RepositoryError(f"path is not a directory: {relative_path}")
        if not allow_directory and not resolved.is_file():
            raise RepositoryError(f"path is not a file: {relative_path}")
        _ = stat_result
        return resolved

    async def _run(self, argv: list[str], *, cwd: Path) -> str:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=self._git_environment(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_stream = process.stdout
        stderr_stream = process.stderr
        if stdout_stream is None or stderr_stream is None:
            process.kill()
            await process.wait()
            raise RepositoryError("repository subprocess output pipes were not created")
        remaining = self.max_command_output_bytes
        truncated = False
        budget_lock = asyncio.Lock()

        async def drain(stream: asyncio.StreamReader) -> bytes:
            nonlocal remaining, truncated
            retained = bytearray()
            while chunk := await stream.read(8_192):
                async with budget_lock:
                    keep = min(remaining, len(chunk))
                    retained.extend(chunk[:keep])
                    remaining -= keep
                    if keep < len(chunk):
                        truncated = True
            return bytes(retained)

        async def collect() -> tuple[bytes, bytes]:
            stdout, stderr, _ = await asyncio.gather(
                drain(stdout_stream),
                drain(stderr_stream),
                process.wait(),
            )
            return stdout, stderr

        try:
            stdout, stderr = await asyncio.wait_for(collect(), timeout=self.command_timeout_seconds)
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise RepositoryError(f"repository operation timed out: {argv[0]}") from exc
        if truncated:
            raise RepositoryError("repository operation exceeded the configured output limit")
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace")[:4_000]
            raise RepositoryError(f"repository operation failed ({process.returncode}): {detail}")
        return stdout.decode("utf-8", errors="replace")

    @staticmethod
    def _is_forbidden(path: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)

    @staticmethod
    def _git_environment() -> dict[str, str]:
        return {
            "GIT_ASKPASS": "/bin/false",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }

    def _safe_remove_workspace(self, path: Path) -> None:
        if path.parent != self.workspace_root or path == self.workspace_root or path.is_symlink():
            raise RepositoryError("refused cleanup outside the configured workspace root")
        if path.is_dir():
            shutil.rmtree(path)
