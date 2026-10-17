"""Typed requests and results passed through infrastructure ports."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, TypeVar

from pydantic import BaseModel, Field

from remediation_agent.domain.enums import ModelOperation, ValidationBackend
from remediation_agent.domain.models import (
    ArtifactManifest,
    ArtifactRef,
    BehavioralEvidence,
    CleanupResult,
    DraftPrMetadata,
    DraftPrPayload,
    EditProposal,
    EditReceipt,
    IncidentMemoryRecordV1,
    InspectionArtifact,
    ModelCallRecord,
    NonEmptyStr,
    PatchCandidate,
    RemediationHandoffV1,
    RepositoryRef,
    StrictModel,
    ValidationCleanupReceipt,
    ValidationExecutionRecord,
    ValidationSnapshotRef,
    ValidationStorageEvidence,
    ValidationTaskResult,
    WorkspaceRef,
)
from remediation_agent.policy.models import ValidationTaskConfig

TModel = TypeVar("TModel", bound=BaseModel)
type ArtifactReadErrorCode = Literal[
    "ARTIFACT_NOT_FOUND",
    "ARTIFACT_ACCESS_DENIED",
    "ARTIFACT_TOO_LARGE",
    "ARTIFACT_INTEGRITY_FAILED",
    "ARTIFACT_PREVIEW_UNSUPPORTED",
]


class ArtifactReadError(RuntimeError):
    """Bounded artifact-preview failure safe to translate at transport boundaries."""

    def __init__(self, code: ArtifactReadErrorCode) -> None:
        super().__init__(code)
        self.code = code


class PublicationError(RuntimeError):
    """Safe typed publication failure; transport data must not enter evidence."""

    def __init__(
        self, code: str, *, retryable: bool = False, records: list[PublicationCallRecord] | None = None
    ) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.records = list(records or [])


class PatchApplicabilityError(RuntimeError):
    """Canonical patch could not be applied; distinct from sandbox infrastructure failure."""


class StructuredModelFailure(RuntimeError):
    """Safe structured-provider failure carrying one bounded audit record."""

    def __init__(self, message: str, *, record: ModelCallRecord) -> None:
        super().__init__(message)
        self.record = record


class TreeRequest(StrictModel):
    workspace: WorkspaceRef
    relative_path: str = "."
    max_entries: int = Field(gt=0)
    forbidden_path_patterns: list[str] = Field(default_factory=list, max_length=100)


class TreeResult(StrictModel):
    entries: list[str]
    truncated: bool


class ReadFileRequest(StrictModel):
    workspace: WorkspaceRef
    relative_path: NonEmptyStr
    max_bytes: int = Field(gt=0)


class FileContent(StrictModel):
    relative_path: NonEmptyStr
    content: str
    digest: NonEmptyStr
    truncated: bool


class SearchRequest(StrictModel):
    workspace: WorkspaceRef
    query: NonEmptyStr
    max_results: int = Field(gt=0)
    max_file_bytes: int = Field(gt=0)
    forbidden_path_patterns: list[str] = Field(default_factory=list, max_length=100)


class SearchHit(StrictModel):
    relative_path: NonEmptyStr
    line_number: int = Field(gt=0)
    line: str


class SearchResult(StrictModel):
    query: NonEmptyStr
    hits: list[SearchHit]
    truncated: bool


class DiffResult(StrictModel):
    unified_diff: str
    digest: NonEmptyStr


class EditCompileRequest(StrictModel):
    workspace: WorkspaceRef
    proposal: EditProposal
    artifacts: list[InspectionArtifact]
    allowed_paths: list[str]
    max_file_bytes: int = Field(gt=0)


class EditCompileResult(StrictModel):
    candidate: PatchCandidate
    receipts: list[EditReceipt]


class CandidateVerifyRequest(StrictModel):
    workspace: WorkspaceRef
    receipts: list[EditReceipt]


class PublicationCheckRequest(StrictModel):
    workspace: WorkspaceRef
    repository: RepositoryRef
    expected_tree: str | None = None
    check_remote: bool = True


class BranchRequest(StrictModel):
    workspace: WorkspaceRef
    branch_name: NonEmptyStr


class BranchResult(StrictModel):
    branch_name: NonEmptyStr


class CommitRequest(StrictModel):
    workspace: WorkspaceRef
    message: NonEmptyStr
    expected_tree: str | None = None
    authored_at: datetime | None = None


class CommitResult(StrictModel):
    commit_sha: NonEmptyStr


class PushRequest(StrictModel):
    workspace: WorkspaceRef
    expected_commit: str | None = None
    remote: NonEmptyStr = "origin"
    branch_name: NonEmptyStr


class PushResult(StrictModel):
    remote: NonEmptyStr
    branch_name: NonEmptyStr
    pushed: bool


class SandboxRequest(StrictModel):
    workspace: WorkspaceRef


class PatchApplyRequest(StrictModel):
    workspace: WorkspaceRef
    unified_diff: str = Field(min_length=1, max_length=2_000_000)


class PatchApplyResult(StrictModel):
    applied: bool
    detail: NonEmptyStr


class ValidationTaskRequest(StrictModel):
    workspace: WorkspaceRef
    snapshot: ValidationSnapshotRef | None = None
    task_name: NonEmptyStr
    task: ValidationTaskConfig
    attempt: int = Field(default=1, ge=1)


class SandboxExecutionProfile(StrictModel):
    backend: ValidationBackend
    executor_id: NonEmptyStr
    enforced_controls: list[NonEmptyStr] = Field(min_length=1, max_length=20)


class BehavioralTaskRequest(ValidationTaskRequest):
    run_id: str | None = None
    capability_only: bool = False
    patch_digest: NonEmptyStr


class BehavioralTaskExecution(StrictModel):
    evidence: BehavioralEvidence | None = None
    executions: list[SandboxTaskExecution] = Field(default_factory=list, max_length=2)
    storage: ValidationStorageEvidence | None = None


class SandboxTaskExecution(StrictModel):
    result: ValidationTaskResult
    execution: ValidationExecutionRecord


class ValidationCancelled(asyncio.CancelledError):
    def __init__(self, receipt: ValidationCleanupReceipt):
        self.receipt = receipt
        super().__init__("Validation cancelled; session cleanup recorded")


class BehavioralExecutionFailure(RuntimeError):
    def __init__(self, result: BehavioralTaskExecution):
        self.result = result
        detail = (
            "; ".join(f.code + ": " + f.detail for f in result.storage.failures)
            if result.storage
            else "Behavioral evidence is absent"
        )
        super().__init__(detail[:4000])


BehavioralTaskExecution.model_rebuild()


class ModelRequest(StrictModel):
    operation: ModelOperation
    prompt_version: NonEmptyStr
    system_instruction: NonEmptyStr
    payload: dict[str, object]


class IncidentMemoryRetrievalRequest(StrictModel):
    repository: NonEmptyStr
    remediation_type: NonEmptyStr
    issue_summary: str = Field(min_length=1, max_length=10_000)
    diagnosis_summary: str = Field(min_length=1, max_length=20_000)
    requested_at: datetime


class IncidentMemoryStoreRequest(StrictModel):
    record: IncidentMemoryRecordV1
    idempotency_token: NonEmptyStr


@dataclass(frozen=True)
class ModelGeneration[TModel: BaseModel]:
    value: TModel
    record: ModelCallRecord


class DraftPrRequest(StrictModel):
    expected_commit: str | None = None
    expected_base_commit: str | None = None
    repository: RepositoryRef
    repository_slug: str | None = None
    payload: DraftPrPayload
    idempotency_key: NonEmptyStr


class PreparedDraftPr(StrictModel):
    metadata: DraftPrMetadata


class PublicationCallRecord(StrictModel):
    """Bounded transport evidence, converted to domain audit events before checkpointing."""

    transport: Literal["github_mcp"] = "github_mcp"
    operation: Literal["discovery", "list_pull_requests", "create_pull_request", "pull_request_read"]
    started_at: datetime
    completed_at: datetime
    result_code: str = Field(pattern=r"^[A-Z0-9_]{1,100}$")
    input_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    output_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class PublicationReadiness(StrictModel):
    records: list[PublicationCallRecord] = Field(default_factory=list, max_length=5)


class CreatedDraftPr(StrictModel):
    metadata: DraftPrMetadata
    records: list[PublicationCallRecord] = Field(default_factory=list, max_length=5)


class ArtifactWriteRequest(StrictModel):
    run_id: NonEmptyStr
    files: dict[str, str]


class ArtifactReadRequest(StrictModel):
    run_id: NonEmptyStr
    artifact: ArtifactRef
    max_object_bytes: int = Field(gt=0)
    max_preview_bytes: int = Field(gt=0)


class ArtifactReadResult(StrictModel):
    name: NonEmptyStr
    media_type: NonEmptyStr
    digest: NonEmptyStr
    content: str
    size_bytes: int = Field(ge=0)
    truncated: bool
    digest_verified: bool


class AuditWriteRequest(StrictModel):
    run_id: NonEmptyStr
    jsonl: str


class HandoffDeliveryRequest(StrictModel):
    """Stable input for one optional downstream A2A delivery attempt."""

    delivery_id: NonEmptyStr
    message_id: NonEmptyStr
    correlation_id: NonEmptyStr
    request_digest: NonEmptyStr
    handoff: RemediationHandoffV1


class ArtifactCollectionResult(StrictModel):
    manifest: ArtifactManifest
    cleanup: CleanupResult | None = None
