"""Typed requests and results passed through infrastructure ports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

from pydantic import BaseModel, Field

from remediation_agent.domain.enums import ModelOperation
from remediation_agent.domain.models import (
    ArtifactManifest,
    CleanupResult,
    DraftPrMetadata,
    DraftPrPayload,
    ModelCallRecord,
    NonEmptyStr,
    RemediationHandoffV1,
    RepositoryRef,
    StrictModel,
    WorkspaceRef,
)
from remediation_agent.policy.models import ValidationTaskConfig

TModel = TypeVar("TModel", bound=BaseModel)


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


class ModelRequest(StrictModel):
    operation: ModelOperation
    prompt_version: NonEmptyStr
    system_instruction: NonEmptyStr
    payload: dict[str, object]


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
