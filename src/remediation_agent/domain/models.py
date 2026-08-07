"""Pydantic domain models and versioned inter-agent handoffs."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from remediation_agent.domain.enums import (
    ApprovalStatus,
    FinalStatus,
    PolicyDecision,
    RemediationType,
    RepositoryProvider,
    RiskLevel,
    ValidationOutcome,
    WorkspaceStatus,
)

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
IdentifierStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
RepositoryPathStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
SearchQueryStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


class StrictModel(BaseModel):
    """Base model that fails closed on unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidenceRecord(StrictModel):
    evidence_id: IdentifierStr
    source_type: IdentifierStr
    source_locator: str = Field(min_length=1, max_length=2_048)
    observed_at: datetime
    digest: NonEmptyStr
    excerpt: str = Field(default="", max_length=10_000)


class Diagnosis(StrictModel):
    summary: str = Field(min_length=1, max_length=20_000)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[NonEmptyStr] = Field(min_length=1)
    contradictions: list[str] = Field(default_factory=list, max_length=20)
    unresolved_questions: list[str] = Field(default_factory=list, max_length=20)


class RepositoryRef(StrictModel):
    provider: RepositoryProvider
    url: str = Field(min_length=1, max_length=2_048)
    base_branch: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$",
    )
    commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{7,64}$")

    @field_validator("base_branch")
    @classmethod
    def base_branch_is_canonical(cls, value: str) -> str:
        if ".." in value or "//" in value or value.endswith((".", "/")):
            raise ValueError("base branch is not a safe canonical Git ref")
        return value

    @model_validator(mode="after")
    def url_does_not_embed_credentials(self) -> RepositoryRef:
        parsed = urlsplit(self.url)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("repository URL must not contain embedded credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("repository URL must not contain query parameters or fragments")
        return self


class DiagnosisHandoffV1(StrictModel):
    """Provisional versioned handoff from Agent 2 to Agent 3."""

    schema_version: Literal["1.0"] = "1.0"
    case_id: IdentifierStr
    issue_summary: str = Field(min_length=1, max_length=10_000)
    remediation_type: RemediationType
    diagnosis: Diagnosis
    supporting_evidence: list[EvidenceRecord] = Field(min_length=1, max_length=100)
    acceptance_criteria: list[NonEmptyStr] = Field(min_length=1, max_length=20)
    repository: RepositoryRef
    upstream_correlation_id: str | None = None
    upstream_audit_refs: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def evidence_references_exist(self) -> DiagnosisHandoffV1:
        available = {item.evidence_id for item in self.supporting_evidence}
        missing = set(self.diagnosis.evidence_ids) - available
        if missing:
            raise ValueError(f"diagnosis references missing evidence IDs: {sorted(missing)}")
        return self


class InspectionPlan(StrictModel):
    paths_to_read: list[RepositoryPathStr] = Field(default_factory=list, max_length=20)
    search_queries: list[SearchQueryStr] = Field(default_factory=list, max_length=10)
    rationale: NonEmptyStr


class InspectionArtifact(StrictModel):
    kind: Literal["TREE", "FILE", "SEARCH"]
    locator: NonEmptyStr
    content: str
    digest: NonEmptyStr
    truncated: bool = False
    untrusted: bool = True


class RemediationPlan(StrictModel):
    summary: NonEmptyStr
    steps: list[NonEmptyStr] = Field(min_length=1, max_length=20)
    target_paths: list[NonEmptyStr] = Field(min_length=1, max_length=20)
    proposed_validation_tasks: list[NonEmptyStr] = Field(min_length=1, max_length=10)
    rollback_strategy: NonEmptyStr
    evidence_ids: list[NonEmptyStr] = Field(min_length=1)


class RiskFinding(StrictModel):
    code: NonEmptyStr
    level: RiskLevel
    summary: NonEmptyStr
    evidence_ids: list[str] = Field(default_factory=list)


class RiskAssessment(StrictModel):
    level: RiskLevel
    decision: PolicyDecision
    findings: list[RiskFinding] = Field(default_factory=list)
    rationale: NonEmptyStr


class PatchCandidate(StrictModel):
    unified_diff: str = Field(min_length=1, max_length=2_000_000)
    rationale: NonEmptyStr
    proposed_validation_tasks: list[str] = Field(default_factory=list, max_length=10)


class PatchPolicyResult(StrictModel):
    decision: PolicyDecision
    risk_level: RiskLevel
    changed_files: list[str]
    changed_lines: int = Field(ge=0)
    reasons: list[NonEmptyStr]
    control_ids: list[NonEmptyStr]
    scope_digest: NonEmptyStr


class ApprovalRequest(StrictModel):
    approval_id: NonEmptyStr
    case_id: NonEmptyStr
    kind: Literal["PLAN", "PATCH"]
    scope_digest: NonEmptyStr
    summary: NonEmptyStr
    reasons: list[NonEmptyStr]
    requested_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING


class ApprovalDecisionV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    approval_id: NonEmptyStr
    scope_digest: NonEmptyStr
    status: Literal[ApprovalStatus.APPROVED, ApprovalStatus.REJECTED]
    reviewer_id: NonEmptyStr
    decided_at: datetime
    comment: str = Field(default="", max_length=2_000)


class ValidationTaskResult(StrictModel):
    task_name: NonEmptyStr
    outcome: ValidationOutcome
    exit_code: int | None = None
    duration_ms: int = Field(ge=0)
    stdout: str = ""
    stderr: str = ""
    output_truncated: bool = False


class ValidationAttempt(StrictModel):
    attempt: int = Field(ge=1)
    patch_digest: NonEmptyStr
    results: list[ValidationTaskResult]
    outcome: ValidationOutcome


class WorkspaceRef(StrictModel):
    workspace_id: NonEmptyStr
    path: NonEmptyStr
    base_commit: NonEmptyStr
    status: WorkspaceStatus = WorkspaceStatus.READY


class RollbackInstructions(StrictModel):
    summary: NonEmptyStr
    before_commit: list[NonEmptyStr]
    after_commit: list[NonEmptyStr]
    limitations: list[str] = Field(default_factory=list)


class DraftPrPayload(StrictModel):
    title: NonEmptyStr
    body: NonEmptyStr
    head_branch: NonEmptyStr
    base_branch: NonEmptyStr
    draft: Literal[True] = True


class DraftPrMetadata(StrictModel):
    payload: DraftPrPayload
    created: bool = False
    provider_id: str | None = None
    url: str | None = None


class ArtifactRef(StrictModel):
    name: NonEmptyStr
    path: NonEmptyStr
    digest: NonEmptyStr
    media_type: NonEmptyStr


class ArtifactManifest(StrictModel):
    run_id: NonEmptyStr
    artifacts: list[ArtifactRef] = Field(default_factory=list)


class CleanupResult(StrictModel):
    succeeded: bool
    detail: NonEmptyStr


class ModelCallRecord(StrictModel):
    operation: NonEmptyStr
    provider: NonEmptyStr
    model: NonEmptyStr
    prompt_version: NonEmptyStr
    duration_ms: int = Field(ge=0)
    input_digest: NonEmptyStr
    output_digest: NonEmptyStr
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    refused: bool = False


class ErrorRecord(StrictModel):
    code: NonEmptyStr
    stage: NonEmptyStr
    message: NonEmptyStr
    retryable: bool = False


class AuditEvent(StrictModel):
    event_id: NonEmptyStr
    timestamp: datetime
    actor: NonEmptyStr
    case_id: NonEmptyStr
    run_id: NonEmptyStr
    event_type: NonEmptyStr
    result_code: NonEmptyStr
    detail: str
    policy_version: NonEmptyStr
    prompt_version: NonEmptyStr
    input_digest: NonEmptyStr
    output_digest: NonEmptyStr
    previous_hash: NonEmptyStr
    event_hash: NonEmptyStr


class RemediationHandoffV1(StrictModel):
    """Provisional versioned handoff from Agent 3 to Agent 4."""

    schema_version: Literal["1.0"] = "1.0"
    case_id: NonEmptyStr
    run_id: NonEmptyStr
    final_status: FinalStatus
    repository: RepositoryRef
    base_commit: str | None = None
    proposed_branch: str | None = None
    proposed_commit: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    diff_digest: str | None = None
    remediation_plan_summary: str | None = None
    risk_summary: str | None = None
    policy_control_ids: list[str] = Field(default_factory=list)
    approvals: list[ApprovalDecisionV1] = Field(default_factory=list)
    validation_attempts: list[ValidationAttempt] = Field(default_factory=list)
    failed_attempt_summaries: list[str] = Field(default_factory=list)
    residual_risks: list[str] = Field(default_factory=list)
    rollback_instructions: RollbackInstructions | None = None
    draft_pr: DraftPrMetadata | None = None
    artifact_manifest: ArtifactManifest | None = None
    audit_bundle_ref: ArtifactRef | None = None
    errors: list[ErrorRecord] = Field(default_factory=list)


class RemediationRunView(StrictModel):
    """Public API view of a running, interrupted, or completed remediation."""

    run_id: NonEmptyStr
    status: FinalStatus
    approval_request: ApprovalRequest | None = None
    result: RemediationHandoffV1 | None = None
