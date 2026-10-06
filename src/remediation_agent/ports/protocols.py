"""Protocols for side effects and model calls."""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractAsyncContextManager
from typing import Protocol

from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.tools import BaseTool
from pydantic import BaseModel

from remediation_agent.domain.models import (
    ArtifactManifest,
    CapabilityReportV1,
    CleanupResult,
    DownstreamDeliveryReceiptV1,
    IncidentMemoryRetrievalV1,
    IncidentMemoryWriteReceiptV1,
    ModelCallRecord,
    ReleaseProvenanceV1,
    RepositoryRef,
    WorkspaceRef,
)
from remediation_agent.ports.models import (
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
    HandoffDeliveryRequest,
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
    SearchRequest,
    SearchResult,
    TModel,
    TreeRequest,
    TreeResult,
    ValidationTaskRequest,
)


class RepositoryInspectionPort(Protocol):
    async def list_tree(self, request: TreeRequest) -> TreeResult: ...

    async def read_file(self, request: ReadFileRequest) -> FileContent: ...

    async def search(self, request: SearchRequest) -> SearchResult: ...


class RepositoryWorkspacePort(Protocol):
    async def publication_check(self, request: PublicationCheckRequest) -> str: ...

    async def compile_edits(self, request: EditCompileRequest) -> EditCompileResult: ...

    async def verify_candidate(self, request: CandidateVerifyRequest) -> None: ...

    async def create_workspace(self, ref: RepositoryRef) -> WorkspaceRef: ...

    async def current_diff(self, workspace: WorkspaceRef) -> DiffResult: ...

    async def create_branch(self, request: BranchRequest) -> BranchResult: ...

    async def commit(self, request: CommitRequest) -> CommitResult: ...

    async def push(self, request: PushRequest) -> PushResult: ...


class RepositoryPort(RepositoryInspectionPort, RepositoryWorkspacePort, Protocol):
    """Compatibility protocol for adapters that implement both boundaries."""


class GitCredentialProvider(Protocol):
    """Provide process-local Git authentication without persisting credentials."""

    def environment_for(self, remote_url: str) -> dict[str, str]: ...

    def redact(self, value: str) -> str: ...


class InspectionToolProvider(Protocol):
    def session(
        self,
        repository: RepositoryRef,
        workspace: WorkspaceRef,
    ) -> AbstractAsyncContextManager[Sequence[BaseTool]]: ...


class SandboxExecutor(Protocol):
    def verification_fingerprint(self) -> str: ...

    async def probe_capability(self, request: BehavioralTaskRequest) -> CapabilityReportV1: ...

    async def check_patch(self, request: PatchApplyRequest) -> None: ...

    def execution_profile(self) -> SandboxExecutionProfile: ...

    async def apply_patch(self, request: PatchApplyRequest) -> PatchApplyResult: ...

    async def restore_base(self, workspace: WorkspaceRef) -> None: ...

    async def run_task(self, request: ValidationTaskRequest) -> SandboxTaskExecution: ...

    async def run_behavior(self, request: BehavioralTaskRequest) -> BehavioralTaskExecution: ...

    async def collect_artifacts(self, workspace: WorkspaceRef) -> ArtifactManifest: ...

    async def destroy(self, workspace: WorkspaceRef) -> CleanupResult: ...


class StructuredModel(Protocol):
    def configuration_digest(self) -> str: ...

    async def generate(self, request: ModelRequest, output_schema: type[TModel]) -> ModelGeneration[TModel]: ...

    async def generate_tool_turn(
        self,
        request: ModelRequest,
        messages: Sequence[BaseMessage],
        tools: Sequence[BaseTool],
    ) -> tuple[AIMessage, ModelCallRecord]: ...


class ReleaseProvenancePort(Protocol):
    async def resolve(self) -> ReleaseProvenanceV1: ...


class PullRequestProvider(Protocol):
    async def check_readiness(self, repository: RepositoryRef, slug: str | None) -> None: ...

    async def verify_draft(self, request: DraftPrRequest) -> CreatedDraftPr: ...

    async def prepare(self, request: DraftPrRequest) -> PreparedDraftPr: ...

    async def create_draft(self, request: DraftPrRequest) -> CreatedDraftPr: ...


class ArtifactStore(Protocol):
    async def write_bundle(self, request: ArtifactWriteRequest) -> ArtifactManifest: ...


class ArtifactReader(Protocol):
    async def read(self, request: ArtifactReadRequest) -> ArtifactReadResult: ...


class AuditSink(Protocol):
    async def write(self, request: AuditWriteRequest) -> None: ...


class HandoffDeliveryPort(Protocol):
    """Deliver a completed handoff without granting workflow mutation authority."""

    async def deliver(self, request: HandoffDeliveryRequest) -> DownstreamDeliveryReceiptV1: ...


class IncidentMemoryPort(Protocol):
    """Advisory long-term memory boundary controlled entirely by the host."""

    async def retrieve(self, request: IncidentMemoryRetrievalRequest) -> IncidentMemoryRetrievalV1: ...

    async def store(self, request: IncidentMemoryStoreRequest) -> IncidentMemoryWriteReceiptV1: ...


class ReadinessProbe(Protocol):
    async def ready(self) -> bool: ...


class WorkspaceRecoveryPort(Protocol):
    """Recover an absent disposable workspace from its immutable repository reference."""

    async def ensure(
        self,
        repository: RepositoryRef,
        workspace: WorkspaceRef,
        *,
        recovery_is_safe: bool,
    ) -> WorkspaceRef: ...


class StructuredOutputRunnable(Protocol):
    async def ainvoke(self, input: object) -> BaseModel: ...
