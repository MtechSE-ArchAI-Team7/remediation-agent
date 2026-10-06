"""Pydantic domain models and versioned inter-agent handoffs."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from remediation_agent.domain.enums import (
    ApprovalStatus,
    FinalStatus,
    InspectionToolStatus,
    MemoryAdmissionType,
    MemoryRetrievalStatus,
    MemoryWriteStatus,
    ModelCallOutcome,
    OperationalToolAvailability,
    OperationalToolCategory,
    OperationalToolEffect,
    OperationalToolExecutionMode,
    PolicyDecision,
    ReleaseProvenanceStatus,
    RemediationType,
    RepositoryProvider,
    RiskLevel,
    ValidationBackend,
    ValidationCleanupStatus,
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
    jira_ticket_id: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[A-Za-z][A-Za-z0-9_]*-[1-9][0-9]*$",
    )
    issue_summary: str = Field(min_length=1, max_length=10_000)
    remediation_type: RemediationType
    diagnosis: Diagnosis
    supporting_evidence: list[EvidenceRecord] = Field(min_length=1, max_length=100)
    acceptance_criteria: list[NonEmptyStr] = Field(min_length=1, max_length=20)
    repository: RepositoryRef
    upstream_correlation_id: str | None = None
    upstream_audit_refs: list[str] = Field(default_factory=list)

    @field_validator("jira_ticket_id", mode="before")
    @classmethod
    def normalize_jira_ticket_id(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

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


class InspectionToolResponse(StrictModel):
    status: InspectionToolStatus
    artifact: InspectionArtifact | None = None
    error_code: str | None = Field(default=None, max_length=200)
    detail: str = Field(default="", max_length=4_000)

    @model_validator(mode="after")
    def successful_response_has_artifact(self) -> InspectionToolResponse:
        if self.status is InspectionToolStatus.SUCCEEDED and self.artifact is None:
            raise ValueError("successful inspection tool response requires an artifact")
        if self.status is not InspectionToolStatus.SUCCEEDED and self.artifact is not None:
            raise ValueError("denied or failed inspection tool response cannot contain an artifact")
        return self


class FinishInspectionArgs(StrictModel):
    rationale: str = Field(min_length=1, max_length=4_000)


class GetRepositoryTreeArgs(StrictModel):
    owner: str = Field(min_length=1, max_length=100)
    repo: str = Field(min_length=1, max_length=100)
    tree_sha: str | None = Field(default=None, min_length=7, max_length=64)
    recursive: bool = False
    path_filter: RepositoryPathStr | None = None


class GetFileContentsArgs(StrictModel):
    owner: str = Field(min_length=1, max_length=100)
    repo: str = Field(min_length=1, max_length=100)
    path: RepositoryPathStr | None = None
    ref: str | None = Field(default=None, min_length=1, max_length=300)
    sha: str | None = Field(default=None, min_length=7, max_length=64)
    fields: list[str] | None = Field(default=None, max_length=20)


class SearchCodeArgs(StrictModel):
    query: str = Field(min_length=1, max_length=256)
    sort: Literal["indexed"] | None = None
    order: Literal["asc", "desc"] | None = None
    fields: list[str] | None = Field(default=None, max_length=20)
    page: int = Field(default=1, ge=1, le=1)
    perPage: int = Field(default=30, ge=1, le=100)


class OperationalToolDescriptor(StrictModel):
    """Public metadata for one implemented, policy-bounded operation."""

    tool_id: IdentifierStr
    operation: IdentifierStr
    boundary: IdentifierStr
    category: OperationalToolCategory
    execution_mode: OperationalToolExecutionMode
    effect: OperationalToolEffect
    availability: OperationalToolAvailability
    description: str = Field(min_length=1, max_length=1_000)
    arguments: tuple[NonEmptyStr, ...] = Field(default_factory=tuple, max_length=20)
    controls: tuple[NonEmptyStr, ...] = Field(min_length=1, max_length=10)


class InspectionToolCallRecord(StrictModel):
    call_id: IdentifierStr
    tool_name: IdentifierStr
    arguments: dict[str, object] = Field(max_length=4)
    status: InspectionToolStatus
    result_digest: NonEmptyStr


class VerificationCriterion(StrictModel):
    """A proposed mapping; only deterministic execution can establish coverage."""

    criterion_id: IdentifierStr
    scope: Literal["LOCAL", "POST_DEPLOYMENT"] = "LOCAL"
    task_name: IdentifierStr | None = None
    test_ids: list[IdentifierStr] = Field(default_factory=list, max_length=40)
    reason: str = Field(default="", max_length=2000)


class RequestContract(StrictModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str = Field(min_length=1, max_length=500, pattern=r"^/[^\s?#]*$")
    content_type: str = Field(min_length=1, max_length=100)
    field_types: dict[IdentifierStr, IdentifierStr] = Field(default_factory=dict, max_length=30)
    example_body: str = Field(default="", max_length=4000)
    expected_responses: list[str] = Field(min_length=1, max_length=20)
    state_changes: list[str] = Field(default_factory=list, max_length=20)
    prerequisites: list[str] = Field(default_factory=list, max_length=20)
    evidence_paths: list[RepositoryPathStr] = Field(min_length=1, max_length=20)


class BehavioralCaseResult(StrictModel):
    test_id: IdentifierStr
    outcome: Literal["PASSED", "ASSERTION_FAILED", "SETUP_ERROR", "SKIPPED"]
    detail: str = Field(default="", max_length=2000)


class BehavioralReport(StrictModel):
    cases: list[BehavioralCaseResult] = Field(min_length=1, max_length=200)
    runtime_digest: IdentifierStr | None = None

    @model_validator(mode="after")
    def unique_tests(self) -> BehavioralReport:
        if len({case.test_id for case in self.cases}) != len(self.cases):
            raise ValueError("duplicate test IDs in behavioral report")
        return self


class BehavioralEvidence(StrictModel):
    task_name: IdentifierStr
    attempt: int = Field(ge=1)
    base_commit: IdentifierStr
    patch_digest: IdentifierStr
    assertions_digest: IdentifierStr
    dependency_digest: IdentifierStr
    base: BehavioralReport
    candidate: BehavioralReport
    cleanup_succeeded: bool


class VerificationObservation(StrictModel):
    task_name: IdentifierStr
    test_id: IdentifierStr
    classification: Literal[
        "FIX_DEMONSTRATED", "INTRODUCED_REGRESSION", "OBSERVED_BASELINE_FAILURE", "PASSED_BOTH", "INCONCLUSIVE"
    ]


class VerificationBriefV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: IdentifierStr
    base_commit: str | None = None
    patch_digest: str | None = None
    criteria: dict[IdentifierStr, str] = Field(default_factory=dict, max_length=20)
    coverage: list[VerificationCriterion] = Field(default_factory=list, max_length=20)
    request_contracts: list[RequestContract] = Field(default_factory=list, max_length=20)
    behavioral_evidence: list[BehavioralEvidence] = Field(default_factory=list, max_length=120)
    locally_verified: bool = False
    pending_agent4_checks: list[str] = Field(default_factory=list, max_length=20)
    limitations: list[str] = Field(default_factory=list, max_length=50)
    unresolved_risks: list[str] = Field(default_factory=list, max_length=100)
    observations: list[VerificationObservation] = Field(default_factory=list, max_length=10000)


class RemediationPlan(StrictModel):
    summary: NonEmptyStr
    steps: list[NonEmptyStr] = Field(min_length=1, max_length=20)
    target_paths: list[NonEmptyStr] = Field(min_length=1, max_length=20)
    proposed_validation_tasks: list[NonEmptyStr] = Field(min_length=1, max_length=10)
    verification: list[VerificationCriterion] = Field(default_factory=list, max_length=20)
    request_contracts: list[RequestContract] = Field(default_factory=list, max_length=20)
    rollback_strategy: NonEmptyStr
    unresolved_requirements: list[str] = Field(default_factory=list, max_length=20)
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
    unified_diff: str = Field(
        min_length=1,
        max_length=2_000_000,
        description=(
            "One complete syntactically valid unified diff whose hunk source and target counts exactly match "
            "the context, removed, and added lines in each hunk body."
        ),
    )
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


class ValidationExecutionRecord(StrictModel):
    """Redacted proof of the deterministic boundary used for one validation task."""

    attempt: int = Field(ge=1)
    task_name: NonEmptyStr
    backend: ValidationBackend
    executor_id: NonEmptyStr
    input_digest: NonEmptyStr
    session_digest: str | None = None
    enforced_controls: list[IdentifierStr] = Field(min_length=1, max_length=20)
    cleanup_status: ValidationCleanupStatus
    outcome: ValidationOutcome
    duration_ms: int = Field(ge=0)


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
    reasoning_summary: str | None = Field(default=None, max_length=4_000)
    outcome: ModelCallOutcome = ModelCallOutcome.SUCCEEDED
    error_code: str | None = Field(default=None, max_length=200)
    http_status: int | None = Field(default=None, ge=100, le=599)
    error_parameter: str | None = Field(default=None, max_length=200)
    retryable: bool = False

    @model_validator(mode="after")
    def failure_metadata_matches_outcome(self) -> ModelCallRecord:
        failure_fields = (self.error_code, self.http_status, self.error_parameter)
        if self.outcome is ModelCallOutcome.FAILED and self.error_code is None:
            raise ValueError("failed model calls require an error code")
        if self.outcome is ModelCallOutcome.SUCCEEDED and (
            any(value is not None for value in failure_fields) or self.retryable
        ):
            raise ValueError("successful model calls cannot contain failure metadata")
        return self


class ReleaseProvenanceV1(StrictModel):
    """Bounded release identity resolved by the operator-owned runtime adapter."""

    schema_version: Literal["1.0"] = "1.0"
    status: ReleaseProvenanceStatus
    release_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    source_revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    image_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    runtime_arn: str | None = Field(default=None, min_length=1, max_length=2_048)
    runtime_id: str | None = Field(default=None, min_length=1, max_length=200)
    runtime_version: str | None = Field(default=None, pattern=r"^[1-9][0-9]{0,4}$")
    region: str | None = Field(default=None, pattern=r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$")
    verified_at: datetime
    verification_method: Literal["LOCAL", "AGENTCORE_CONTROL_PLANE"]
    error_code: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def verified_agentcore_release_is_complete(self) -> ReleaseProvenanceV1:
        agentcore_fields = (
            self.release_id,
            self.source_revision,
            self.image_digest,
            self.runtime_arn,
            self.runtime_id,
            self.runtime_version,
            self.region,
        )
        if self.status is ReleaseProvenanceStatus.VERIFIED and any(value is None for value in agentcore_fields):
            raise ValueError("verified AgentCore release provenance requires every identity field")
        if self.status is ReleaseProvenanceStatus.LOCAL and self.verification_method != "LOCAL":
            raise ValueError("local provenance must use the LOCAL verification method")
        if self.status not in {ReleaseProvenanceStatus.LOCAL, ReleaseProvenanceStatus.VERIFIED} and not self.error_code:
            raise ValueError("unverified release provenance requires an error code")
        return self


class IncidentValidationSummary(StrictModel):
    task_name: IdentifierStr
    outcome: ValidationOutcome


class IncidentMemoryRecordV1(StrictModel):
    """Bounded long-term incident summary; never raw source, prompts, or patches."""

    schema_version: Literal["1.0"] = "1.0"
    incident_id: IdentifierStr
    repository: IdentifierStr
    source_commit: str = Field(pattern=r"^[0-9a-fA-F]{7,64}$")
    incident_signature: str = Field(min_length=1, max_length=1_000)
    root_cause: str = Field(min_length=1, max_length=2_000)
    remediation_summary: str = Field(min_length=1, max_length=2_000)
    changed_paths: list[RepositoryPathStr] = Field(min_length=1, max_length=20)
    validation: list[IncidentValidationSummary] = Field(min_length=1, max_length=20)
    rollback_summary: str = Field(min_length=1, max_length=2_000)
    residual_risks: list[str] = Field(default_factory=list, max_length=20)
    policy_version: IdentifierStr
    prompt_version: IdentifierStr
    model_provider: IdentifierStr
    model_name: IdentifierStr
    evidence_ids: list[IdentifierStr] = Field(min_length=1, max_length=100)
    evidence_digests: list[NonEmptyStr] = Field(min_length=1, max_length=100)
    admission_type: MemoryAdmissionType
    created_at: datetime


class IncidentMemoryMatchV1(StrictModel):
    incident_id: IdentifierStr
    admission_type: MemoryAdmissionType
    score: float = Field(ge=0.0, le=1.0)
    age_days: float = Field(ge=0.0, le=30.0)
    repository: IdentifierStr
    incident_signature: str = Field(min_length=1, max_length=1_000)
    root_cause: str = Field(min_length=1, max_length=2_000)
    remediation_summary: str = Field(min_length=1, max_length=2_000)
    changed_paths: list[RepositoryPathStr] = Field(default_factory=list, max_length=20)
    validation: list[IncidentValidationSummary] = Field(default_factory=list, max_length=20)
    rollback_summary: str = Field(default="Not supplied.", min_length=1, max_length=2_000)
    residual_risks: list[str] = Field(default_factory=list, max_length=20)


class IncidentMemoryRetrievalV1(StrictModel):
    status: MemoryRetrievalStatus
    query_digest: NonEmptyStr
    matches: list[IncidentMemoryMatchV1] = Field(default_factory=list, max_length=3)
    duration_ms: int = Field(ge=0)
    error_code: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def result_shape_matches_status(self) -> IncidentMemoryRetrievalV1:
        if self.status is MemoryRetrievalStatus.RETRIEVED and not self.matches:
            raise ValueError("RETRIEVED memory status requires at least one match")
        if self.status is not MemoryRetrievalStatus.RETRIEVED and self.matches:
            raise ValueError("only RETRIEVED memory status may contain matches")
        return self


class IncidentMemoryWriteReceiptV1(StrictModel):
    status: MemoryWriteStatus
    incident_id: str | None = Field(default=None, max_length=200)
    duration_ms: int = Field(ge=0)
    error_code: str | None = Field(default=None, max_length=200)


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


class ExplainabilityEvent(StrictModel):
    """One redacted, presentation-safe decision or side-effect record."""

    sequence: int = Field(ge=1)
    timestamp: datetime
    stage: IdentifierStr
    actor_type: Literal["DETERMINISTIC", "MODEL_ASSISTED", "TOOL", "HUMAN"]
    event_type: IdentifierStr
    status: IdentifierStr
    summary: str = Field(max_length=4_000)
    policy_control_ids: list[IdentifierStr] = Field(default_factory=list, max_length=20)


class ExplainabilityEvidenceRef(StrictModel):
    """Repository evidence metadata that deliberately excludes file contents."""

    kind: Literal["TREE", "FILE", "SEARCH"]
    locator: str = Field(min_length=1, max_length=2_048)
    digest: NonEmptyStr
    truncated: bool = False


class ExplainabilityTraceV1(StrictModel):
    """Bounded trace for operator explanation without prompts or hidden reasoning."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: IdentifierStr
    status: FinalStatus
    events: list[ExplainabilityEvent] = Field(default_factory=list, max_length=200)
    inspection_tool_calls: list[InspectionToolCallRecord] = Field(default_factory=list, max_length=100)
    evidence: list[ExplainabilityEvidenceRef] = Field(default_factory=list, max_length=100)
    model_calls: list[ModelCallRecord] = Field(default_factory=list, max_length=100)
    validation_executions: list[ValidationExecutionRecord] = Field(default_factory=list, max_length=100)
    memory_retrieval: IncidentMemoryRetrievalV1 | None = None
    memory_write: IncidentMemoryWriteReceiptV1 | None = None


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


class DownstreamDeliveryReceiptV1(StrictModel):
    """Bounded evidence for the optional Agent 4 A2A delivery attempt."""

    schema_version: Literal["1.0"] = "1.0"
    delivery_id: NonEmptyStr
    message_id: NonEmptyStr
    attempted: bool
    succeeded: bool
    attempted_at: datetime
    request_digest: NonEmptyStr
    response_digest: str | None = None
    remote_task_id: str | None = Field(default=None, max_length=200)
    remote_context_id: str | None = Field(default=None, max_length=200)
    error_code: str | None = Field(default=None, max_length=200)


class RemediationRunView(StrictModel):
    """Public API view of a running, interrupted, or completed remediation."""

    run_id: NonEmptyStr
    status: FinalStatus
    approval_request: ApprovalRequest | None = None
    result: RemediationHandoffV1 | None = None
    downstream_delivery: DownstreamDeliveryReceiptV1 | None = None
    explainability: ExplainabilityTraceV1 | None = None
