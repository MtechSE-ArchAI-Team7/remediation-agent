"""Deterministic fake adapters used by automated tests."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import time
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Literal, cast
from urllib.parse import urlsplit

from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.tools import BaseTool
from pydantic import BaseModel

from remediation_agent.adapters.snapshot_inspection import SnapshotInspectionTools
from remediation_agent.domain.enums import (
    MemoryRetrievalStatus,
    MemoryWriteStatus,
    ModelOperation,
    ValidationBackend,
    ValidationCleanupStatus,
    ValidationOutcome,
)
from remediation_agent.domain.models import (
    ArtifactManifest,
    BehavioralCaseResult,
    BehavioralEvidence,
    BehavioralReport,
    CapabilityReportV1,
    CleanupResult,
    DraftPrMetadata,
    EditProposal,
    IncidentMemoryRetrievalV1,
    IncidentMemoryWriteReceiptV1,
    InspectionArtifact,
    InspectionPlan,
    InspectionToolResponse,
    ModelCallRecord,
    PatchCandidate,
    RepositoryRef,
    SourceEdit,
    ValidationExecutionRecord,
    ValidationTaskResult,
    WorkspaceRef,
)
from remediation_agent.ports.models import (
    ArtifactReadError,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactWriteRequest,
    AuditWriteRequest,
    BehavioralTaskExecution,
    BehavioralTaskRequest,
    BranchRequest,
    BranchResult,
    CandidateVerifyRequest,
    CommitRequest,
    CommitResult,
    CreatedDraftPr,
    DiffResult,
    DraftPrRequest,
    EditCompileRequest,
    EditCompileResult,
    FileContent,
    IncidentMemoryRetrievalRequest,
    IncidentMemoryStoreRequest,
    ModelGeneration,
    ModelRequest,
    PatchApplyRequest,
    PatchApplyResult,
    PreparedDraftPr,
    PublicationCheckRequest,
    PushRequest,
    PushResult,
    ReadFileRequest,
    SandboxExecutionProfile,
    SandboxTaskExecution,
    SearchHit,
    SearchRequest,
    SearchResult,
    TModel,
    TreeRequest,
    TreeResult,
    ValidationTaskRequest,
)
from remediation_agent.source import compile_edits


class FakeStructuredModel:
    """Return scripted structured outputs by operation."""

    def configuration_digest(self) -> str:
        return "sha256:fake-model-configuration"

    def __init__(
        self,
        responses: Mapping[ModelOperation, Sequence[BaseModel | dict[str, object]]],
        *,
        tool_turns: Sequence[AIMessage] = (),
    ) -> None:
        self._responses = {operation: deque(values) for operation, values in responses.items()}
        self._tool_turns = deque(tool_turns)
        self._inspection_script_loaded = bool(tool_turns)
        self.requests: list[ModelRequest] = []
        self.tool_turn_messages: list[list[BaseMessage]] = []

    async def generate(self, request: ModelRequest, output_schema: type[TModel]) -> ModelGeneration[TModel]:
        self.requests.append(request)
        queue = self._responses.get(request.operation)
        if not queue:
            raise RuntimeError(f"no fake response configured for {request.operation}")
        started = time.monotonic()
        raw = queue.popleft()
        # Old deterministic routing fixtures use diffs; production providers only emit EditProposal.
        if output_schema is EditProposal and (
            isinstance(raw, PatchCandidate) or isinstance(raw, dict) and "unified_diff" in raw
        ):
            from unidiff.patch import PatchSet

            legacy = raw if isinstance(raw, PatchCandidate) else PatchCandidate.model_validate(raw)
            artifacts = [
                InspectionArtifact.model_validate(a)
                for a in cast(list[object], request.payload.get("inspection_artifacts", []))
            ]
            by_path = {a.locator: a for a in artifacts}
            edits = []
            for file in PatchSet(legacy.unified_diff.splitlines(keepends=True)):
                artifact = by_path.get(file.path)
                for hunk in file:
                    edits.append(
                        SourceEdit(
                            path=file.path,
                            base_content_digest=artifact.base_content_digest
                            if artifact and artifact.base_content_digest
                            else "sha256:" + "0" * 64,
                            start_line=max(1, hunk.source_start),
                            end_line=max(1, hunk.source_start) + hunk.source_length,
                            expected_content="".join(line.value for line in hunk if not line.is_added),
                            replacement="".join(line.value for line in hunk if not line.is_removed),
                        )
                    )
            raw = EditProposal(
                edits=edits, rationale=legacy.rationale, proposed_validation_tasks=legacy.proposed_validation_tasks
            )
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

    async def generate_tool_turn(
        self,
        request: ModelRequest,
        messages: Sequence[BaseMessage],
        tools: Sequence[BaseTool],
    ) -> tuple[AIMessage, ModelCallRecord]:
        self.requests.append(request)
        self.tool_turn_messages.append(list(messages))
        if not self._inspection_script_loaded:
            self._load_inspection_script(request)
        if not self._tool_turns:
            raise RuntimeError("no fake inspection tool turn configured")
        allowed_tools = {tool.name for tool in tools}
        message = self._tool_turns.popleft()
        if len(message.tool_calls) == 1 and message.tool_calls[0]["name"] not in allowed_tools:
            # Preserve the invalid call so workflow security tests exercise the workflow boundary.
            pass
        input_text = json.dumps(
            {
                "request": request.model_dump(mode="json"),
                "message_count": len(messages),
                "tools": sorted(allowed_tools),
            },
            sort_keys=True,
        )
        record = ModelCallRecord(
            operation=request.operation,
            provider="fake",
            model="scripted",
            prompt_version=request.prompt_version,
            duration_ms=0,
            input_digest=_digest(input_text),
            output_digest=_digest(message.model_dump_json()),
            input_tokens=_token_value(message, "input_tokens"),
            output_tokens=_token_value(message, "output_tokens"),
            refused=_fake_refused(message),
        )
        return message, record

    def _load_inspection_script(self, request: ModelRequest) -> None:
        self._inspection_script_loaded = True
        queue = self._responses.get(ModelOperation.INSPECTION)
        if not queue:
            return
        raw = queue.popleft()
        plan = raw if isinstance(raw, InspectionPlan) else InspectionPlan.model_validate(raw)
        target = request.payload.get("inspection_target")
        if not isinstance(target, Mapping):
            raise RuntimeError("fake inspection request omitted its authorized target")
        owner = str(target.get("owner", ""))
        repo = str(target.get("repo", ""))
        commit_sha = str(target.get("commit_sha", ""))
        calls: list[tuple[str, dict[str, object]]] = [
            (
                "get_repository_tree",
                {"owner": owner, "repo": repo, "tree_sha": commit_sha, "recursive": True},
            )
        ]
        calls.extend(
            (
                "get_file_contents",
                {"owner": owner, "repo": repo, "path": path, "sha": commit_sha},
            )
            for path in plan.paths_to_read
        )
        calls.extend(("search_code", {"query": f"{query} repo:{owner}/{repo}"}) for query in plan.search_queries)
        calls.append(("finish_inspection", {"rationale": plan.rationale}))
        self._tool_turns.extend(
            AIMessage(
                content="",
                tool_calls=[{"name": name, "args": arguments, "id": f"fake-call-{index}", "type": "tool_call"}],
            )
            for index, (name, arguments) in enumerate(calls, start=1)
        )


class FakeIncidentMemory:
    """Credential-free advisory-memory fake with observable idempotent writes."""

    def __init__(
        self,
        retrieval: IncidentMemoryRetrievalV1 | None = None,
        *,
        write_status: MemoryWriteStatus = MemoryWriteStatus.STORED,
    ) -> None:
        self.retrieval = retrieval
        self.write_status = write_status
        self.retrieve_requests: list[IncidentMemoryRetrievalRequest] = []
        self.store_requests: list[IncidentMemoryStoreRequest] = []
        self._tokens: set[str] = set()

    async def retrieve(self, request: IncidentMemoryRetrievalRequest) -> IncidentMemoryRetrievalV1:
        self.retrieve_requests.append(request)
        return self.retrieval or IncidentMemoryRetrievalV1(
            status=MemoryRetrievalStatus.NO_MATCH,
            query_digest=_digest(request.model_dump_json()),
            duration_ms=1,
        )

    async def store(self, request: IncidentMemoryStoreRequest) -> IncidentMemoryWriteReceiptV1:
        self.store_requests.append(request)
        if request.idempotency_token in self._tokens:
            status = MemoryWriteStatus.ALREADY_EXISTS
        else:
            self._tokens.add(request.idempotency_token)
            status = self.write_status
        return IncidentMemoryWriteReceiptV1(
            status=status,
            incident_id=request.record.incident_id,
            duration_ms=1,
            error_code="FAKE_MEMORY_WRITE_ERROR" if status is MemoryWriteStatus.ERROR else None,
        )


class FakeInspectionToolProvider(SnapshotInspectionTools):
    """Test specialization; a FakeRepository supplies fixture bytes instead of real Git."""


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

    async def compile_edits(self, request: EditCompileRequest) -> EditCompileResult:
        candidate, receipts = compile_edits(request.proposal, request.artifacts, self.files, set(request.allowed_paths))
        return EditCompileResult(candidate=candidate, receipts=receipts)

    async def verify_candidate(self, request: CandidateVerifyRequest) -> None:
        # The fake sandbox models the exact diff; real Git integration checks actual file digests.
        _ = request

    async def current_diff(self, workspace: WorkspaceRef) -> DiffResult:
        _ = workspace
        return DiffResult(unified_diff=self.current_diff_value, digest=_digest(self.current_diff_value))

    async def verify_workspace(self, workspace: WorkspaceRef, expected_diff: str | None = None) -> None:
        if expected_diff is not None and (await self.current_diff(workspace)).digest != expected_diff:
            raise RuntimeError("WORKSPACE_INTEGRITY_FAILED: expected workspace digest changed")

    async def publication_check(self, request: PublicationCheckRequest) -> str:
        return request.expected_tree or _digest(self.current_diff_value)

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
        apply_failures: Sequence[str] | None = None,
    ) -> None:
        self._outcomes = {name: deque(values) for name, values in (task_outcomes or {}).items()}
        self._apply_failures = deque(apply_failures or ())
        self.applied_patches: list[str] = []
        self.restores = 0
        self.tasks_run: list[str] = []
        self.destroyed = False
        self.cleanup_succeeds = cleanup_succeeds
        self.repository = repository
        self.tampered_diff = tampered_diff

    def execution_profile(self) -> SandboxExecutionProfile:
        return SandboxExecutionProfile(
            backend=ValidationBackend.FAKE,
            executor_id="fake-sandbox",
            enforced_controls=["OPERATOR_DEFINED_TASK", "DETERMINISTIC_TEST_DOUBLE"],
        )

    def verification_fingerprint(self) -> str:
        return "sha256:fake-verification-assets"

    async def probe_capability(self, request: BehavioralTaskRequest) -> CapabilityReportV1:
        return CapabilityReportV1(
            task_name=request.task_name,
            available=True,
            base_commit=request.workspace.base_commit,
            startup_verified=True,
            cleanup_verified=True,
            assertions_digest="sha256:fake-assertions",
            dependency_digest="sha256:fake-dependencies",
            runtime_digest="sha256:fake-runtime",
        )

    async def check_patch(self, request: PatchApplyRequest) -> None:
        _ = request

    async def apply_patch(self, request: PatchApplyRequest) -> PatchApplyResult:
        self.applied_patches.append(request.unified_diff)
        if self._apply_failures:
            raise RuntimeError(self._apply_failures.popleft())
        if self.repository:
            self.repository.current_diff_value = request.unified_diff
        return PatchApplyResult(applied=True, detail="Fake patch applied.")

    async def restore_base(self, workspace: WorkspaceRef) -> None:
        _ = workspace
        self.restores += 1
        if self.repository:
            self.repository.current_diff_value = ""

    async def run_task(self, request: ValidationTaskRequest) -> SandboxTaskExecution:
        self.tasks_run.append(request.task_name)
        if self.repository and self.tampered_diff:
            self.repository.current_diff_value = self.tampered_diff
        queue = self._outcomes.get(request.task_name)
        outcome = queue.popleft() if queue else ValidationOutcome.PASSED
        exit_code = 0 if outcome is ValidationOutcome.PASSED else 1
        result = ValidationTaskResult(
            task_name=request.task_name,
            outcome=outcome,
            exit_code=exit_code,
            duration_ms=1,
            stdout=f"fake {request.task_name}: {outcome}",
        )
        profile = self.execution_profile()
        return SandboxTaskExecution(
            result=result,
            execution=ValidationExecutionRecord(
                attempt=request.attempt,
                task_name=request.task_name,
                backend=profile.backend,
                executor_id=profile.executor_id,
                input_digest=_digest(request.model_dump_json()),
                enforced_controls=profile.enforced_controls,
                cleanup_status=ValidationCleanupStatus.NOT_APPLICABLE,
                outcome=result.outcome,
                duration_ms=result.duration_ms,
            ),
        )

    async def run_behavior(self, request: BehavioralTaskRequest) -> BehavioralTaskExecution:
        result = await self.run_task(request)
        outcome: Literal["PASSED", "ASSERTION_FAILED"] = (
            "PASSED" if result.result.outcome is ValidationOutcome.PASSED else "ASSERTION_FAILED"
        )
        ids = request.task.required_test_ids or ["regression"]
        return BehavioralTaskExecution(
            evidence=BehavioralEvidence(
                task_name=request.task_name,
                attempt=request.attempt,
                base_commit=request.workspace.base_commit,
                patch_digest=request.patch_digest,
                assertions_digest=_digest("fake-assertions"),
                dependency_digest=_digest("fake-dependencies"),
                base=BehavioralReport(
                    cases=[BehavioralCaseResult(test_id=name, outcome="ASSERTION_FAILED") for name in ids]
                ),
                candidate=BehavioralReport(cases=[BehavioralCaseResult(test_id=name, outcome=outcome) for name in ids]),
                cleanup_succeeded=True,
            ),
            executions=[result],
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

    async def check_readiness(self, repository: RepositoryRef, slug: str | None) -> None:
        _ = repository, slug

    async def prepare(self, request: DraftPrRequest) -> PreparedDraftPr:
        self.requests.append(request)
        return PreparedDraftPr(metadata=DraftPrMetadata(payload=request.payload))

    async def verify_draft(self, request: DraftPrRequest) -> CreatedDraftPr:
        return await self.create_draft(request)

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


class MemoryArtifactReader:
    def __init__(self, contents: Mapping[tuple[str, str], str] | None = None) -> None:
        self.contents = dict(contents or {})
        self.requests: list[ArtifactReadRequest] = []

    async def read(self, request: ArtifactReadRequest) -> ArtifactReadResult:
        self.requests.append(request)
        content = self.contents.get((request.run_id, request.artifact.name))
        if content is None:
            raise ArtifactReadError("ARTIFACT_NOT_FOUND")
        return ArtifactReadResult(
            name=request.artifact.name,
            media_type=request.artifact.media_type,
            digest=request.artifact.digest,
            content=content,
            size_bytes=len(content.encode("utf-8")),
            truncated=False,
            digest_verified=True,
        )


class MemoryAuditSink:
    def __init__(self) -> None:
        self.requests: list[AuditWriteRequest] = []

    async def write(self, request: AuditWriteRequest) -> None:
        self.requests.append(request)


def _tool_response(response: InspectionToolResponse) -> tuple[str, dict[str, object]]:
    structured = response.model_dump(mode="json")
    return response.model_dump_json(), {"structured_content": structured}


def _token_value(message: AIMessage, key: str) -> int | None:
    usage = message.usage_metadata
    if not isinstance(usage, Mapping):
        return None
    value = usage.get(key)
    return value if isinstance(value, int) and value >= 0 else None


def _fake_refused(message: AIMessage) -> bool:
    reason = str(
        message.response_metadata.get(
            "stop_reason",
            message.response_metadata.get("stopReason", ""),
        )
    ).lower()
    return "refus" in reason


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _is_git_internal(path: str) -> bool:
    return path == ".git" or path.startswith(".git/")


def _fake_github_target(repository: RepositoryRef) -> tuple[str, str]:
    parts = [part for part in urlsplit(repository.url).path.split("/") if part]
    if len(parts) != 2:
        raise ValueError("fake inspection requires a GitHub owner/repository URL")
    return parts[0], parts[1].removesuffix(".git")
