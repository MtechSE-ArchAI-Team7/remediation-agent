"""Typed requests and results passed through infrastructure ports."""

from __future__ import annotations

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
    IncidentMemoryRecordV1,
    ModelCallRecord,
    NonEmptyStr,
    RemediationHandoffV1,
    RepositoryRef,
    StrictModel,
    ValidationExecutionRecord,
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


class BranchRequest(StrictModel):
    workspace: WorkspaceRef
    branch_name: NonEmptyStr


class BranchResult(StrictModel):
    branch_name: NonEmptyStr


class CommitRequest(StrictModel):
    workspace: WorkspaceRef
    message: NonEmptyStr


class CommitResult(StrictModel):
    commit_sha: NonEmptyStr


class PushRequest(StrictModel):
    workspace: WorkspaceRef
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
    task_name: NonEmptyStr
    task: ValidationTaskConfig
    attempt: int = Field(default=1, ge=1)


class SandboxExecutionProfile(StrictModel):
    backend: ValidationBackend
    executor_id: NonEmptyStr
    enforced_controls: list[NonEmptyStr] = Field(min_length=1, max_length=20)


class BehavioralTaskRequest(ValidationTaskRequest):
    patch_digest: NonEmptyStr


class BehavioralTaskExecution(StrictModel):
    evidence: BehavioralEvidence
    executions: list[SandboxTaskExecution] = Field(min_length=1, max_length=2)


class SandboxTaskExecution(StrictModel):
    result: ValidationTaskResult
    execution: ValidationExecutionRecord


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
    repository: RepositoryRef
    repository_slug: str | None = None
    payload: DraftPrPayload
    idempotency_key: NonEmptyStr


class PreparedDraftPr(StrictModel):
    metadata: DraftPrMetadata


class CreatedDraftPr(StrictModel):
    metadata: DraftPrMetadata


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
