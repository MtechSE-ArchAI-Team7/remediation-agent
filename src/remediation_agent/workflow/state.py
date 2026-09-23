"""Shared state for the one Resolution/Remediation Agent."""

from __future__ import annotations

from typing import TypedDict

from remediation_agent.domain.enums import FinalStatus, ValidationOutcome, WorkspaceStatus
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    ApprovalRequest,
    ArtifactManifest,
    AuditEvent,
    CleanupResult,
    DiagnosisHandoffV1,
    DownstreamDeliveryReceiptV1,
    DraftPrMetadata,
    ErrorRecord,
    IncidentMemoryRetrievalV1,
    IncidentMemoryWriteReceiptV1,
    InspectionArtifact,
    InspectionPlan,
    InspectionToolCallRecord,
    ModelCallRecord,
    PatchCandidate,
    PatchPolicyResult,
    RemediationHandoffV1,
    RemediationPlan,
    RiskAssessment,
    RollbackInstructions,
    ValidationAttempt,
    ValidationExecutionRecord,
    ValidationTaskResult,
    WorkspaceRef,
)


class RemediationState(TypedDict, total=False):
    agent_id: str
    case_id: str
    run_id: str
    thread_id: str
    prompt_version: str
    policy_version: str
    handoff: DiagnosisHandoffV1

    workspace: WorkspaceRef
    workspace_status: WorkspaceStatus
    inspection_plan: InspectionPlan
    inspection_artifacts: list[InspectionArtifact]
    inspection_tool_calls: list[InspectionToolCallRecord]
    incident_memory_retrieval: IncidentMemoryRetrievalV1

    remediation_plan: RemediationPlan
    risk_assessment: RiskAssessment
    approval_request: ApprovalRequest
    approval_history: list[ApprovalDecisionV1]

    patch_candidate: PatchCandidate
    patch_policy: PatchPolicyResult
    changed_files: list[str]
    current_diff: str
    diff_digest: str
    validation_baseline_digest: str

    selected_validation_tasks: list[str]
    current_validation_results: list[ValidationTaskResult]
    validation_execution_records: list[ValidationExecutionRecord]
    validation_attempts: list[ValidationAttempt]
    validation_outcome: ValidationOutcome
    attempt_counter: int
    max_validation_attempts: int
    repair_outcome: ValidationOutcome
    revision_context: str

    residual_risks: list[str]
    rollback_instructions: RollbackInstructions
    draft_pr: DraftPrMetadata
    proposed_branch: str
    proposed_commit: str
    artifact_manifest: ArtifactManifest
    cleanup_result: CleanupResult
    incident_memory_write: IncidentMemoryWriteReceiptV1

    model_calls: list[ModelCallRecord]
    errors: list[ErrorRecord]
    audit_events: list[AuditEvent]
    final_status: FinalStatus
    final_handoff: RemediationHandoffV1
    downstream_delivery: DownstreamDeliveryReceiptV1
