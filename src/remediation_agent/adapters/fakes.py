"""Deterministic fake adapters used by automated tests."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import time
from collections import deque
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel

from remediation_agent.adapters.evidence import SecretRedactor
from remediation_agent.domain.enums import (
    InspectionToolStatus,
    ModelOperation,
    PolicyDecision,
    ValidationBackend,
    ValidationCleanupStatus,
    ValidationOutcome,
)
from remediation_agent.domain.models import (
    ArtifactManifest,
    CleanupResult,
    DraftPrMetadata,
    GetFileContentsArgs,
    GetRepositoryTreeArgs,
    InspectionArtifact,
    InspectionPlan,
    InspectionToolResponse,
    ModelCallRecord,
    RepositoryRef,
    SearchCodeArgs,
    ValidationExecutionRecord,
    ValidationTaskResult,
    WorkspaceRef,
)
from remediation_agent.policy.engine import PolicyEngine
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
from remediation_agent.ports.protocols import RepositoryInspectionPort


class FakeStructuredModel:
    """Return scripted structured outputs by operation."""

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


class FakeInspectionToolProvider:
    """In-process test double with the same three schemas as GitHub's MCP server."""

    def __init__(self, repository: RepositoryInspectionPort, policy: PolicyEngine) -> None:
        self.repository = repository
        self.policy = policy
        self.redactor = SecretRedactor()
        self.sessions_started = 0
        self.sessions_closed = 0

    @asynccontextmanager
    async def session(
        self,
        repository: RepositoryRef,
        workspace: WorkspaceRef,
    ) -> AsyncIterator[Sequence[BaseTool]]:
        self.sessions_started += 1
        owner, repo = _fake_github_target(repository)

        async def get_repository_tree(
            owner: str,
            repo: str,
            tree_sha: str | None = None,
            recursive: bool = False,
            path_filter: str | None = None,
        ) -> tuple[str, dict[str, object]]:
            _ = recursive
            rejection = self._target_rejection(owner, repo, repository, workspace, tree_sha)
            relative_path = path_filter or "."
            if rejection is None:
                rejection = self._path_rejection(relative_path)
            if rejection:
                return _tool_response(rejection)
            try:
                result = await self.repository.list_tree(
                    TreeRequest(
                        workspace=workspace,
                        relative_path=relative_path,
                        max_entries=self.policy.config.limits.max_tree_entries,
                        forbidden_path_patterns=self.policy.config.paths.forbidden,
                    )
                )
                content = self.redactor.redact("\n".join(result.entries))
                response = InspectionToolResponse(
                    status=InspectionToolStatus.SUCCEEDED,
                    artifact=InspectionArtifact(
                        kind="TREE",
                        locator=relative_path,
                        content=content,
                        digest=self.policy.digest_text(content),
                        truncated=result.truncated,
                    ),
                )
            except (KeyError, OSError, RuntimeError, ValueError) as exc:
                response = self._failed(str(exc))
            return _tool_response(response)

        async def get_file_contents(
            owner: str,
            repo: str,
            path: str | None = None,
            ref: str | None = None,
            sha: str | None = None,
            fields: list[str] | None = None,
        ) -> tuple[str, dict[str, object]]:
            _ = fields
            rejection = self._target_rejection(owner, repo, repository, workspace, sha)
            if rejection is None and ref is not None:
                rejection = InspectionToolResponse(
                    status=InspectionToolStatus.DENIED,
                    error_code="MUTABLE_REF_DENIED",
                    detail="Mutable Git refs are not permitted for inspection.",
                )
            relative_path = path or "."
            if rejection is None:
                rejection = self._path_rejection(relative_path)
            if rejection:
                return _tool_response(rejection)
            try:
                result = await self.repository.read_file(
                    ReadFileRequest(
                        workspace=workspace,
                        relative_path=relative_path,
                        max_bytes=self.policy.config.limits.max_file_bytes,
                    )
                )
                content = self.redactor.redact(result.content)
                response = InspectionToolResponse(
                    status=InspectionToolStatus.SUCCEEDED,
                    artifact=InspectionArtifact(
                        kind="FILE",
                        locator=result.relative_path,
                        content=content,
                        digest=self.policy.digest_text(content),
                        truncated=result.truncated,
                    ),
                )
            except (KeyError, OSError, RuntimeError, ValueError) as exc:
                response = self._failed(str(exc))
            return _tool_response(response)

        async def search_code(
            query: str,
            sort: str | None = None,
            order: str | None = None,
            fields: list[str] | None = None,
            page: int = 1,
            perPage: int = 30,
        ) -> tuple[str, dict[str, object]]:
            _ = (sort, order, fields, page, perPage)
            qualifier = f"repo:{owner}/{repo}"
            if query.count(qualifier) != 1 or "org:" in query or "user:" in query:
                return _tool_response(
                    InspectionToolResponse(
                        status=InspectionToolStatus.DENIED,
                        error_code="SEARCH_SCOPE_DENIED",
                        detail="Code search must contain exactly the assigned repo qualifier.",
                    )
                )
            local_query = query.replace(qualifier, "").strip()
            try:
                result = await self.repository.search(
                    SearchRequest(
                        workspace=workspace,
                        query=local_query,
                        max_results=self.policy.config.limits.max_search_results,
                        max_file_bytes=self.policy.config.limits.max_file_bytes,
                        forbidden_path_patterns=self.policy.config.paths.forbidden,
                    )
                )
                content = self.redactor.redact("\n".join(dict.fromkeys(hit.relative_path for hit in result.hits)))
                response = InspectionToolResponse(
                    status=InspectionToolStatus.SUCCEEDED,
                    artifact=InspectionArtifact(
                        kind="SEARCH",
                        locator=query,
                        content=content,
                        digest=self.policy.digest_text(content),
                        truncated=result.truncated,
                    ),
                )
            except (OSError, RuntimeError, ValueError) as exc:
                response = self._failed(str(exc))
            return _tool_response(response)

        tools = [
            StructuredTool.from_function(
                coroutine=get_repository_tree,
                name="get_repository_tree",
                description="List a bounded repository tree.",
                args_schema=GetRepositoryTreeArgs,
                response_format="content_and_artifact",
            ),
            StructuredTool.from_function(
                coroutine=get_file_contents,
                name="get_file_contents",
                description="Read one bounded repository file.",
                args_schema=GetFileContentsArgs,
                response_format="content_and_artifact",
            ),
            StructuredTool.from_function(
                coroutine=search_code,
                name="search_code",
                description="Search bounded repository text.",
                args_schema=SearchCodeArgs,
                response_format="content_and_artifact",
            ),
        ]
        try:
            yield tools
        finally:
            self.sessions_closed += 1

    def _path_rejection(self, relative_path: str) -> InspectionToolResponse | None:
        if relative_path == ".":
            return None
        try:
            decision = self.policy.classify_path(relative_path)
        except ValueError as exc:
            return InspectionToolResponse(
                status=InspectionToolStatus.DENIED,
                error_code="UNSAFE_PATH",
                detail=self.redactor.redact(str(exc)),
            )
        if decision is PolicyDecision.DENY:
            return InspectionToolResponse(
                status=InspectionToolStatus.DENIED,
                error_code="PATH_DENIED",
                detail="Repository path is forbidden by operator policy.",
            )
        return None

    def _failed(self, detail: str) -> InspectionToolResponse:
        return InspectionToolResponse(
            status=InspectionToolStatus.ERROR,
            error_code="INSPECTION_OPERATION_FAILED",
            detail=self.redactor.redact(detail),
        )

    @staticmethod
    def _target_rejection(
        owner: str,
        repo: str,
        repository: RepositoryRef,
        workspace: WorkspaceRef,
        commit_sha: str | None,
    ) -> InspectionToolResponse | None:
        expected_owner, expected_repo = _fake_github_target(repository)
        if owner != expected_owner or repo != expected_repo:
            return InspectionToolResponse(
                status=InspectionToolStatus.DENIED,
                error_code="REPOSITORY_SCOPE_DENIED",
                detail="Inspection is restricted to the assigned repository.",
            )
        if commit_sha != workspace.base_commit:
            return InspectionToolResponse(
                status=InspectionToolStatus.DENIED,
                error_code="IMMUTABLE_REF_REQUIRED",
                detail="Inspection must use the assigned commit SHA.",
            )
        return None


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

    def execution_profile(self) -> SandboxExecutionProfile:
        return SandboxExecutionProfile(
            backend=ValidationBackend.FAKE,
            executor_id="fake-sandbox",
            enforced_controls=["OPERATOR_DEFINED_TASK", "DETERMINISTIC_TEST_DOUBLE"],
        )

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
