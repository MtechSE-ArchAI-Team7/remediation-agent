"""Deterministic fake adapters used by tests and academic demonstrations."""

from __future__ import annotations

import fnmatch
import hashlib
import time
from collections import deque
from collections.abc import Mapping, Sequence

from pydantic import BaseModel

from remediation_agent.domain.enums import ModelOperation, ValidationOutcome
from remediation_agent.domain.models import (
    ArtifactManifest,
    CleanupResult,
    DraftPrMetadata,
    ModelCallRecord,
    RepositoryRef,
    ValidationTaskResult,
    WorkspaceRef,
)
from remediation_agent.ports.models import (
    ArtifactWriteRequest,
    AuditWriteRequest,
    BranchRequest,
    BranchResult,
    CommitRequest,
    CommitResult,
    CreatedDraftPr,
    DiffResult,
    DraftPrRequest,
    FileContent,
    ModelGeneration,
    ModelRequest,
    PatchApplyRequest,
    PatchApplyResult,
    PreparedDraftPr,
    PushRequest,
    PushResult,
    ReadFileRequest,
    SearchHit,
    SearchRequest,
    SearchResult,
    TModel,
    TreeRequest,
    TreeResult,
    ValidationTaskRequest,
)


class FakeStructuredModel:
    """Return scripted structured outputs by operation."""

    def __init__(self, responses: Mapping[ModelOperation, Sequence[BaseModel | dict[str, object]]]) -> None:
        self._responses = {operation: deque(values) for operation, values in responses.items()}
        self.requests: list[ModelRequest] = []

    async def generate(self, request: ModelRequest, output_schema: type[TModel]) -> ModelGeneration[TModel]:
        self.requests.append(request)
        queue = self._responses.get(request.operation)
        if not queue:
            raise RuntimeError(f"no fake response configured for {request.operation}")
        started = time.monotonic()
        raw = queue.popleft()
        value = raw if isinstance(raw, output_schema) else output_schema.model_validate(raw)
        duration_ms = int((time.monotonic() - started) * 1_000)
        input_text = request.model_dump_json()
        output_text = value.model_dump_json()
        record = ModelCallRecord(
            operation=request.operation,
            provider="fake",
            model="scripted",
            prompt_version=request.prompt_version,
            duration_ms=duration_ms,
            input_digest=_digest(input_text),
            output_digest=_digest(output_text),
        )
        return ModelGeneration(value=value, record=record)


class FakeRepository:
    def __init__(self, *, files: Mapping[str, str] | None = None, base_commit: str = "a" * 40) -> None:
        self.files = dict(files or {})
        self.base_commit = base_commit
        self.workspace = WorkspaceRef(
            workspace_id="fake-workspace",
            path="fake-workspace",
            base_commit=base_commit,
        )
        self.created = False
        self.read_paths: list[str] = []
        self.search_queries: list[str] = []
        self.branches: list[str] = []
        self.commits: list[str] = []
        self.pushes: list[str] = []
        self.current_diff_value = ""

    async def create_workspace(self, ref: RepositoryRef) -> WorkspaceRef:
        _ = ref
        self.created = True
        return self.workspace

    async def list_tree(self, request: TreeRequest) -> TreeResult:
        entries = [
            path
            for path in sorted(self.files)
            if not _is_git_internal(path) and not _matches_any(path, request.forbidden_path_patterns)
        ]
        return TreeResult(entries=entries[: request.max_entries], truncated=len(entries) > request.max_entries)

    async def read_file(self, request: ReadFileRequest) -> FileContent:
        self.read_paths.append(request.relative_path)
        content = self.files[request.relative_path]
        raw = content.encode()
        bounded = raw[: request.max_bytes]
        return FileContent(
            relative_path=request.relative_path,
            content=bounded.decode(),
            digest=_digest(content),
            truncated=len(raw) > request.max_bytes,
        )

    async def search(self, request: SearchRequest) -> SearchResult:
        self.search_queries.append(request.query)
        hits: list[SearchHit] = []
        for path, content in sorted(self.files.items()):
            if _is_git_internal(path) or _matches_any(path, request.forbidden_path_patterns):
                continue
            for number, line in enumerate(content.splitlines(), start=1):
                if request.query in line:
                    hits.append(SearchHit(relative_path=path, line_number=number, line=line))
        truncated = len(hits) > request.max_results
        return SearchResult(query=request.query, hits=hits[: request.max_results], truncated=truncated)

    async def current_diff(self, workspace: WorkspaceRef) -> DiffResult:
        _ = workspace
        return DiffResult(unified_diff=self.current_diff_value, digest=_digest(self.current_diff_value))

    async def create_branch(self, request: BranchRequest) -> BranchResult:
        self.branches.append(request.branch_name)
        return BranchResult(branch_name=request.branch_name)

    async def commit(self, request: CommitRequest) -> CommitResult:
        self.commits.append(request.message)
        return CommitResult(commit_sha="b" * 40)

    async def push(self, request: PushRequest) -> PushResult:
        self.pushes.append(request.branch_name)
        return PushResult(remote=request.remote, branch_name=request.branch_name, pushed=True)


class FakeSandboxExecutor:
    def __init__(
        self,
        task_outcomes: Mapping[str, Sequence[ValidationOutcome]] | None = None,
        *,
        cleanup_succeeds: bool = True,
        repository: FakeRepository | None = None,
        tampered_diff: str | None = None,
    ) -> None:
        self._outcomes = {name: deque(values) for name, values in (task_outcomes or {}).items()}
        self.applied_patches: list[str] = []
        self.restores = 0
        self.tasks_run: list[str] = []
        self.destroyed = False
        self.cleanup_succeeds = cleanup_succeeds
        self.repository = repository
        self.tampered_diff = tampered_diff

    async def apply_patch(self, request: PatchApplyRequest) -> PatchApplyResult:
        self.applied_patches.append(request.unified_diff)
        if self.repository:
            self.repository.current_diff_value = request.unified_diff
        return PatchApplyResult(applied=True, detail="Fake patch applied.")

    async def restore_base(self, workspace: WorkspaceRef) -> None:
        _ = workspace
        self.restores += 1
        if self.repository:
            self.repository.current_diff_value = ""

    async def run_task(self, request: ValidationTaskRequest) -> ValidationTaskResult:
        self.tasks_run.append(request.task_name)
        if self.repository and self.tampered_diff:
            self.repository.current_diff_value = self.tampered_diff
        queue = self._outcomes.get(request.task_name)
        outcome = queue.popleft() if queue else ValidationOutcome.PASSED
        exit_code = 0 if outcome is ValidationOutcome.PASSED else 1
        return ValidationTaskResult(
            task_name=request.task_name,
            outcome=outcome,
            exit_code=exit_code,
            duration_ms=1,
            stdout=f"fake {request.task_name}: {outcome}",
        )

    async def collect_artifacts(self, workspace: WorkspaceRef) -> ArtifactManifest:
        return ArtifactManifest(run_id=workspace.workspace_id, artifacts=[])

    async def destroy(self, workspace: WorkspaceRef) -> CleanupResult:
        _ = workspace
        self.destroyed = True
        return CleanupResult(
            succeeded=self.cleanup_succeeds,
            detail="Fake workspace destroyed." if self.cleanup_succeeds else "Fake workspace cleanup failed.",
        )


class FakePullRequestProvider:
    def __init__(self, *, create: bool = False) -> None:
        self.create = create
        self.requests: list[DraftPrRequest] = []

    async def prepare(self, request: DraftPrRequest) -> PreparedDraftPr:
        self.requests.append(request)
        return PreparedDraftPr(metadata=DraftPrMetadata(payload=request.payload))

    async def create_draft(self, request: DraftPrRequest) -> CreatedDraftPr:
        self.requests.append(request)
        if not self.create:
            raise RuntimeError("fake GitHub writes are disabled")
        return CreatedDraftPr(
            metadata=DraftPrMetadata(
                payload=request.payload,
                created=True,
                provider_id="42",
                url="https://example.invalid/pull/42",
            )
        )


class MemoryArtifactStore:
    def __init__(self) -> None:
        self.requests: list[ArtifactWriteRequest] = []

    async def write_bundle(self, request: ArtifactWriteRequest) -> ArtifactManifest:
        self.requests.append(request)
        return ArtifactManifest(run_id=request.run_id, artifacts=[])


class MemoryAuditSink:
    def __init__(self) -> None:
        self.requests: list[AuditWriteRequest] = []

    async def write(self, request: AuditWriteRequest) -> None:
        self.requests.append(request)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _is_git_internal(path: str) -> bool:
    return path == ".git" or path.startswith(".git/")
