"""Workflow-stage functions for the single remediation agent."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from langgraph.types import interrupt

from remediation_agent.adapters.evidence import AuditTrail
from remediation_agent.domain.enums import (
    ApprovalStatus,
    FinalStatus,
    ModelOperation,
    PolicyDecision,
    RemediationType,
    RiskLevel,
    ValidationOutcome,
    WorkspaceStatus,
)
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    ApprovalRequest,
    ArtifactManifest,
    ArtifactRef,
    AuditEvent,
    CleanupResult,
    DraftPrPayload,
    ErrorRecord,
    InspectionArtifact,
    InspectionPlan,
    PatchCandidate,
    RemediationHandoffV1,
    RemediationPlan,
    RiskAssessment,
    RollbackInstructions,
    ValidationAttempt,
    ValidationTaskResult,
)
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.ports.models import (
    ArtifactWriteRequest,
    AuditWriteRequest,
    BranchRequest,
    CommitRequest,
    DraftPrRequest,
    ModelRequest,
    PatchApplyRequest,
    PushRequest,
    ReadFileRequest,
    SearchRequest,
    TreeRequest,
    ValidationTaskRequest,
)
from remediation_agent.ports.protocols import (
    ArtifactStore,
    AuditSink,
    PullRequestProvider,
    RepositoryPort,
    SandboxExecutor,
    StructuredModel,
)
from remediation_agent.prompts import (
    INSPECTION_SYSTEM_PROMPT,
    PATCH_SYSTEM_PROMPT,
    PLANNING_SYSTEM_PROMPT,
    RISK_SYSTEM_PROMPT,
)
from remediation_agent.workflow.state import RemediationState

_SUPPORTED_TYPES = {RemediationType.CODE, RemediationType.CONFIGURATION}
_HUMAN_ONLY_TYPES = {
    RemediationType.ACCOUNT_UNLOCK,
    RemediationType.PASSWORD_RESET,
    RemediationType.ACCESS_PROVISIONING,
    RemediationType.PRIVILEGED_ACCESS,
    RemediationType.PRODUCTION_CHANGE,
}


class WorkflowNodes:
    """Dependency-injected workflow stages; this is not an agent or supervisor."""

    def __init__(
        self,
        *,
        policy: PolicyEngine,
        model: StructuredModel,
        repository: RepositoryPort,
        sandbox: SandboxExecutor,
        pr_provider: PullRequestProvider,
        artifact_store: ArtifactStore,
        audit_sink: AuditSink,
        prompt_version: str,
        github_writes_enabled: bool = False,
        github_repository: str | None = None,
    ) -> None:
        self.policy = policy
        self.model = model
        self.repository = repository
        self.sandbox = sandbox
        self.pr_provider = pr_provider
        self.artifact_store = artifact_store
        self.audit_sink = audit_sink
        self.prompt_version = prompt_version
        self.github_writes_enabled = github_writes_enabled and policy.config.github.writes_enabled
        self.github_repository = github_repository
        self.audit = AuditTrail(policy.config.version, prompt_version)

    async def validate_intake(self, state: RemediationState) -> dict[str, object]:
        handoff = state["handoff"]
        try:
            self.policy.validate_repository(handoff.repository)
        except ValueError as exc:
            return {
                "agent_id": "resolution-remediation-agent",
                "case_id": handoff.case_id,
                "final_status": FinalStatus.INVALID_REQUEST,
                "attempt_counter": 0,
                "max_validation_attempts": self.policy.config.limits.max_validation_attempts,
                "errors": [ErrorRecord(code="REPOSITORY_NOT_ALLOWED", stage="intake", message=str(exc))],
                "audit_events": self._event(state, "INTAKE_REJECTED", "DENY", str(exc)),
            }
        events = self._event(state, "INTAKE_VALIDATED", "OK", "Versioned diagnosis handoff accepted.")
        return {
            "agent_id": "resolution-remediation-agent",
            "case_id": handoff.case_id,
            "final_status": FinalStatus.PENDING,
            "attempt_counter": 0,
            "max_validation_attempts": self.policy.config.limits.max_validation_attempts,
            "approval_history": [],
            "inspection_artifacts": [],
            "validation_attempts": [],
            "model_calls": [],
            "errors": [],
            "residual_risks": [],
            "audit_events": events,
            "workspace_status": WorkspaceStatus.NOT_CREATED,
        }

    async def classify_scope(self, state: RemediationState) -> dict[str, object]:
        if state["final_status"] is not FinalStatus.PENDING:
            return {}
        remediation_type = state["handoff"].remediation_type
        if remediation_type in _SUPPORTED_TYPES:
            status = FinalStatus.PENDING
            detail = f"Remediation type {remediation_type} is supported by the prototype."
        elif remediation_type in _HUMAN_ONLY_TYPES:
            status = FinalStatus.HUMAN_ACTION_REQUIRED
            detail = f"Remediation type {remediation_type} requires a deferred human workflow."
        else:
            status = FinalStatus.UNSUPPORTED_REMEDIATION_TYPE
            detail = f"Remediation type {remediation_type} is not implemented."
        return {
            "final_status": status,
            "audit_events": self._event(state, "SCOPE_CLASSIFIED", status, detail),
        }

    async def inspect_repository(self, state: RemediationState) -> dict[str, object]:
        if state["final_status"] is not FinalStatus.PENDING:
            return {}
        handoff = state["handoff"]
        workspace = None
        try:
            workspace = await self.repository.create_workspace(handoff.repository)
            request = ModelRequest(
                operation=ModelOperation.INSPECTION,
                prompt_version=self.prompt_version,
                system_instruction=INSPECTION_SYSTEM_PROMPT,
                payload={"handoff": handoff.model_dump(mode="json")},
            )
            generated = await self.model.generate(request, InspectionPlan)
            artifacts: list[InspectionArtifact] = []
            tree = await self.repository.list_tree(
                TreeRequest(
                    workspace=workspace,
                    max_entries=self.policy.config.limits.max_tree_entries,
                    forbidden_path_patterns=self.policy.config.paths.forbidden,
                )
            )
            artifacts.append(
                InspectionArtifact(
                    kind="TREE",
                    locator=".",
                    content="\n".join(tree.entries),
                    digest=self.policy.digest_text("\n".join(tree.entries)),
                    truncated=tree.truncated,
                )
            )
            context_bytes = len(artifacts[0].content.encode("utf-8"))
            for path in generated.value.paths_to_read:
                if self.policy.classify_path(path) is PolicyDecision.DENY:
                    continue
                if context_bytes >= self.policy.config.limits.max_context_bytes:
                    break
                file_content = await self.repository.read_file(
                    ReadFileRequest(
                        workspace=workspace,
                        relative_path=path,
                        max_bytes=self.policy.config.limits.max_file_bytes,
                    )
                )
                artifact = InspectionArtifact(
                    kind="FILE",
                    locator=file_content.relative_path,
                    content=self.audit.redactor.redact(file_content.content),
                    digest=self.policy.digest_text(self.audit.redactor.redact(file_content.content)),
                    truncated=file_content.truncated,
                )
                if context_bytes + len(artifact.content.encode("utf-8")) > self.policy.config.limits.max_context_bytes:
                    break
                artifacts.append(artifact)
                context_bytes += len(artifact.content.encode("utf-8"))
            for query in generated.value.search_queries:
                if context_bytes >= self.policy.config.limits.max_context_bytes:
                    break
                result = await self.repository.search(
                    SearchRequest(
                        workspace=workspace,
                        query=query,
                        max_results=self.policy.config.limits.max_search_results,
                        max_file_bytes=self.policy.config.limits.max_file_bytes,
                        forbidden_path_patterns=self.policy.config.paths.forbidden,
                    )
                )
                content = self.audit.redactor.redact(
                    "\n".join(f"{hit.relative_path}:{hit.line_number}:{hit.line}" for hit in result.hits)
                )
                if context_bytes + len(content.encode("utf-8")) > self.policy.config.limits.max_context_bytes:
                    break
                artifacts.append(
                    InspectionArtifact(
                        kind="SEARCH",
                        locator=query,
                        content=content,
                        digest=self.policy.digest_text(content),
                        truncated=result.truncated,
                    )
                )
                context_bytes += len(content.encode("utf-8"))
        except (OSError, RuntimeError, ValueError) as exc:
            update = self._failure(state, "INSPECTION_FAILED", "inspect_repository", str(exc))
            if workspace is not None:
                update["workspace"] = workspace
                update["workspace_status"] = WorkspaceStatus.READY
            return update
        return {
            "workspace": workspace,
            "workspace_status": WorkspaceStatus.READY,
            "inspection_plan": generated.value,
            "inspection_artifacts": artifacts,
            "model_calls": [*state.get("model_calls", []), generated.record],
            "audit_events": self._event(
                state,
                "REPOSITORY_INSPECTED",
                "OK",
                f"Collected {len(artifacts)} bounded untrusted inspection artifacts.",
            ),
        }

    async def create_plan(self, state: RemediationState) -> dict[str, object]:
        if state["final_status"] is not FinalStatus.PENDING:
            return {}
        try:
            generated = await self.model.generate(
                ModelRequest(
                    operation=ModelOperation.PLANNING,
                    prompt_version=self.prompt_version,
                    system_instruction=PLANNING_SYSTEM_PROMPT,
                    payload={
                        "handoff": state["handoff"].model_dump(mode="json"),
                        "inspection_artifacts": [
                            item.model_dump(mode="json") for item in state["inspection_artifacts"]
                        ],
                    },
                ),
                RemediationPlan,
            )
            available_evidence = {item.evidence_id for item in state["handoff"].supporting_evidence}
            if not set(generated.value.evidence_ids).issubset(available_evidence):
                raise ValueError("model plan references evidence IDs not present in the diagnosis handoff")
        except (RuntimeError, ValueError) as exc:
            return self._failure(state, "PLAN_FAILED", "create_plan", str(exc))
        return {
            "remediation_plan": generated.value,
            "model_calls": [*state.get("model_calls", []), generated.record],
            "audit_events": self._event(state, "PLAN_CREATED", "OK", generated.value.summary),
        }

    async def assess_risk(self, state: RemediationState) -> dict[str, object]:
        if state["final_status"] is not FinalStatus.PENDING or "remediation_plan" not in state:
            return {}
        try:
            generated = await self.model.generate(
                ModelRequest(
                    operation=ModelOperation.RISK,
                    prompt_version=self.prompt_version,
                    system_instruction=RISK_SYSTEM_PROMPT,
                    payload={
                        "handoff": state["handoff"].model_dump(mode="json"),
                        "plan": state["remediation_plan"].model_dump(mode="json"),
                    },
                ),
                RiskAssessment,
            )
            assessment = self.policy.assess_plan(state["handoff"], state["remediation_plan"], generated.value)
        except (RuntimeError, ValueError) as exc:
            return self._failure(state, "RISK_FAILED", "assess_risk", str(exc))

        update: dict[str, object] = {
            "risk_assessment": assessment,
            "model_calls": [*state.get("model_calls", []), generated.record],
            "audit_events": self._event(
                state,
                "RISK_ASSESSED",
                assessment.decision,
                f"{assessment.rationale}; controls: {', '.join(item.code for item in assessment.findings)}",
            ),
        }
        if assessment.decision is PolicyDecision.DENY:
            update["final_status"] = FinalStatus.UNSAFE_REMEDIATION
            update["residual_risks"] = [assessment.rationale]
        elif assessment.decision is PolicyDecision.REQUIRE_APPROVAL:
            scope = self.policy.digest_text(state["remediation_plan"].model_dump_json())
            update["approval_request"] = self._approval_request(state, "PLAN", scope, assessment.rationale)
            update["final_status"] = FinalStatus.AWAITING_APPROVAL
        return update

    async def plan_approval(self, state: RemediationState) -> dict[str, object]:
        return self._approval_interrupt(state)

    async def generate_patch(self, state: RemediationState) -> dict[str, object]:
        if state["final_status"] is not FinalStatus.PENDING:
            return {}
        operation = ModelOperation.PATCH if state.get("attempt_counter", 0) == 0 else ModelOperation.REVISION
        try:
            generated = await self.model.generate(
                ModelRequest(
                    operation=operation,
                    prompt_version=self.prompt_version,
                    system_instruction=PATCH_SYSTEM_PROMPT,
                    payload={
                        "handoff": state["handoff"].model_dump(mode="json"),
                        "plan": state["remediation_plan"].model_dump(mode="json"),
                        "inspection_artifacts": [
                            item.model_dump(mode="json") for item in state["inspection_artifacts"]
                        ],
                        "previous_attempts": [
                            item.model_dump(mode="json") for item in state.get("validation_attempts", [])
                        ],
                        "revision_context": state.get("revision_context", ""),
                    },
                ),
                PatchCandidate,
            )
        except (RuntimeError, ValueError) as exc:
            return self._failure(state, "PATCH_GENERATION_FAILED", "generate_patch", str(exc))
        return {
            "patch_candidate": generated.value,
            "model_calls": [*state.get("model_calls", []), generated.record],
            "audit_events": self._event(state, "PATCH_GENERATED", "OK", generated.value.rationale),
        }

    async def preflight_patch(self, state: RemediationState) -> dict[str, object]:
        if state["final_status"] is not FinalStatus.PENDING or "patch_candidate" not in state:
            return {}
        result = self.policy.preflight_patch(state["patch_candidate"].unified_diff)
        planned_paths = {
            self.policy.normalize_path(path)
            for path in state["remediation_plan"].target_paths
            if self.policy.classify_path(path) is not PolicyDecision.DENY
        }
        unplanned_paths = sorted(set(result.changed_files) - planned_paths)
        if unplanned_paths and result.decision is not PolicyDecision.DENY:
            reasons = [
                reason
                for reason, control in zip(result.reasons, result.control_ids, strict=True)
                if control != "PATCH_ALLOWED"
            ]
            controls = [control for control in result.control_ids if control != "PATCH_ALLOWED"]
            result = result.model_copy(
                update={
                    "decision": PolicyDecision.REQUIRE_APPROVAL,
                    "risk_level": RiskLevel.HIGH,
                    "reasons": [
                        *reasons,
                        f"Patch expands beyond the reviewed plan: {', '.join(unplanned_paths)}",
                    ],
                    "control_ids": [*controls, "UNPLANNED_PATH_APPROVAL"],
                }
            )
        update: dict[str, object] = {
            "patch_policy": result,
            "changed_files": result.changed_files,
            "current_diff": state["patch_candidate"].unified_diff,
            "diff_digest": result.scope_digest,
            "audit_events": self._event(
                state,
                "PATCH_PREFLIGHT",
                result.decision,
                f"{'; '.join(result.reasons)}; controls: {', '.join(result.control_ids)}",
            ),
        }
        if result.decision is PolicyDecision.DENY:
            update["final_status"] = FinalStatus.UNSAFE_REMEDIATION
            update["repair_outcome"] = ValidationOutcome.ERROR
            update["residual_risks"] = result.reasons
        elif result.decision is PolicyDecision.REQUIRE_APPROVAL:
            approved_scopes = {
                item.scope_digest
                for item in state.get("approval_history", [])
                if item.status is ApprovalStatus.APPROVED
            }
            if result.scope_digest not in approved_scopes:
                update["approval_request"] = self._approval_request(
                    state,
                    "PATCH",
                    result.scope_digest,
                    "; ".join(result.reasons),
                )
                update["final_status"] = FinalStatus.AWAITING_APPROVAL
        return update

    async def patch_approval(self, state: RemediationState) -> dict[str, object]:
        return self._approval_interrupt(state)

    async def apply_patch(self, state: RemediationState) -> dict[str, object]:
        if state["final_status"] is not FinalStatus.PENDING:
            return {}
        try:
            result = await self.sandbox.apply_patch(
                PatchApplyRequest(workspace=state["workspace"], unified_diff=state["patch_candidate"].unified_diff)
            )
            if not result.applied:
                raise RuntimeError(result.detail)
            applied_diff = await self.repository.current_diff(state["workspace"])
            applied_policy = self.policy.preflight_patch(applied_diff.unified_diff)
            if applied_policy.decision is PolicyDecision.DENY:
                raise RuntimeError("applied workspace diff failed deterministic post-apply policy")
            if applied_policy.changed_files != state["patch_policy"].changed_files:
                raise RuntimeError("applied workspace diff does not match the preflighted file scope")
        except (OSError, RuntimeError, ValueError) as exc:
            update = self._failure(state, "PATCH_APPLY_FAILED", "apply_patch", str(exc))
            update["repair_outcome"] = ValidationOutcome.ERROR
            return update
        return {
            "workspace_status": WorkspaceStatus.PATCHED,
            "current_diff": applied_diff.unified_diff,
            "changed_files": applied_policy.changed_files,
            "diff_digest": applied_diff.digest,
            "validation_baseline_digest": applied_diff.digest,
            "audit_events": self._event(state, "PATCH_APPLIED", "OK", result.detail),
        }

    async def select_validation_tasks(self, state: RemediationState) -> dict[str, object]:
        proposed = [
            *state["remediation_plan"].proposed_validation_tasks,
            *state["patch_candidate"].proposed_validation_tasks,
        ]
        selected = self.policy.select_validation_tasks(proposed, state["changed_files"])
        return {
            "selected_validation_tasks": selected,
            "audit_events": self._event(
                state,
                "VALIDATION_SELECTED",
                "OK",
                f"Selected operator-defined tasks: {', '.join(selected)}",
            ),
        }

    async def run_validation(self, state: RemediationState) -> dict[str, object]:
        results: list[ValidationTaskResult] = []
        for name in state["selected_validation_tasks"]:
            task = self.policy.validation_task(name)
            try:
                result = await self.sandbox.run_task(
                    ValidationTaskRequest(workspace=state["workspace"], task_name=name, task=task)
                )
            except (OSError, RuntimeError, ValueError) as exc:
                result = ValidationTaskResult(
                    task_name=name,
                    outcome=ValidationOutcome.ERROR,
                    duration_ms=0,
                    stderr=str(exc),
                )
            results.append(result)
        try:
            post_validation_diff = await self.repository.current_diff(state["workspace"])
            if post_validation_diff.digest != state["validation_baseline_digest"]:
                results.append(
                    ValidationTaskResult(
                        task_name="workspace_integrity",
                        outcome=ValidationOutcome.ERROR,
                        duration_ms=0,
                        stderr="Validation tasks modified the approved workspace diff.",
                    )
                )
        except (OSError, RuntimeError, ValueError) as exc:
            results.append(
                ValidationTaskResult(
                    task_name="workspace_integrity",
                    outcome=ValidationOutcome.ERROR,
                    duration_ms=0,
                    stderr=f"Could not verify the post-validation workspace diff: {exc}",
                )
            )
        results = [
            item.model_copy(
                update={
                    "stdout": self.audit.redactor.redact(item.stdout),
                    "stderr": self.audit.redactor.redact(item.stderr),
                }
            )
            for item in results
        ]
        outcome = (
            ValidationOutcome.PASSED
            if results and all(item.outcome is ValidationOutcome.PASSED for item in results)
            else ValidationOutcome.FAILED
        )
        attempt_number = state.get("attempt_counter", 0) + 1
        attempt = ValidationAttempt(
            attempt=attempt_number,
            patch_digest=state["diff_digest"],
            results=results,
            outcome=outcome,
        )
        return {
            "attempt_counter": attempt_number,
            "current_validation_results": results,
            "validation_attempts": [*state.get("validation_attempts", []), attempt],
            "validation_outcome": outcome,
            "audit_events": self._event(
                state,
                "VALIDATION_COMPLETED",
                outcome,
                f"Validation attempt {attempt_number} completed with {outcome}.",
            ),
        }

    async def evaluate_validation(self, state: RemediationState) -> dict[str, object]:
        outcome = state["validation_outcome"]
        if outcome is ValidationOutcome.PASSED:
            return {
                "repair_outcome": ValidationOutcome.PASSED,
                "audit_events": self._event(state, "VALIDATION_EVALUATED", "PASS", "All required tasks passed."),
            }
        if state["attempt_counter"] >= state["max_validation_attempts"]:
            return {
                "repair_outcome": ValidationOutcome.FAILED,
                "final_status": FinalStatus.VALIDATION_FAILED,
                "residual_risks": [
                    *state.get("residual_risks", []),
                    "Validation failed and the configured repair-attempt limit was exhausted.",
                ],
                "audit_events": self._event(
                    state,
                    "VALIDATION_EVALUATED",
                    "EXHAUSTED",
                    "Configured validation-attempt limit reached.",
                ),
            }
        return {
            "repair_outcome": ValidationOutcome.FAILED,
            "audit_events": self._event(
                state,
                "VALIDATION_EVALUATED",
                "REVISE",
                "Validation failed; a clean-base revision is permitted.",
            ),
        }

    async def restore_base(self, state: RemediationState) -> dict[str, object]:
        try:
            await self.sandbox.restore_base(state["workspace"])
        except (OSError, RuntimeError, ValueError) as exc:
            update = self._failure(state, "RESTORE_FAILED", "restore_base", str(exc))
            update["repair_outcome"] = ValidationOutcome.ERROR
            return update
        return {
            "workspace_status": WorkspaceStatus.RESTORED,
            "current_diff": "",
            "changed_files": [],
            "audit_events": self._event(state, "WORKSPACE_RESTORED", "OK", "Workspace restored to immutable base."),
        }

    async def prepare_revision(self, state: RemediationState) -> dict[str, object]:
        latest = state["validation_attempts"][-1]
        context = json.dumps(latest.model_dump(mode="json"), sort_keys=True)
        return {
            "revision_context": context,
            "final_status": FinalStatus.PENDING,
            "audit_events": self._event(state, "REVISION_PREPARED", "OK", "Prepared bounded validation evidence."),
        }

    async def build_evidence(self, state: RemediationState) -> dict[str, object]:
        patch = state.get("patch_candidate")
        before = ["Restore the disposable workspace to the recorded immutable base commit."]
        if patch:
            before.append("Reverse the reviewed patch with `git apply -R` only inside the disposable workspace.")
        if state["handoff"].remediation_type is RemediationType.CONFIGURATION and state.get("current_diff"):
            removed_lines = [
                line[1:]
                for line in state["current_diff"].splitlines()
                if line.startswith("-") and not line.startswith("---")
            ][:10]
            if removed_lines:
                original_values = self.audit.redactor.redact(" | ".join(removed_lines))[:2_000]
                before.append(f"Restore the prior reviewed configuration value(s): {original_values}")
        rollback = RollbackInstructions(
            summary="Rollback applies only to the proposed repository change; no production rollback is executed.",
            before_commit=before,
            after_commit=["Create a reviewed revert commit for the proposed remediation commit."],
            limitations=["Production deployment and rollback execution are outside this agent's authority."],
        )
        return {
            "rollback_instructions": rollback,
            "audit_events": self._event(state, "ROLLBACK_PREPARED", "OK", rollback.summary),
        }

    async def prepare_pr(self, state: RemediationState) -> dict[str, object]:
        if state.get("repair_outcome") is not ValidationOutcome.PASSED:
            return {}
        handoff = state["handoff"]
        branch = _branch_name(handoff.case_id, state["run_id"])
        payload = DraftPrPayload(
            title=f"[AIOS {handoff.case_id}] {state['remediation_plan'].summary}"[:240],
            body=self._pr_body(state),
            head_branch=branch,
            base_branch=handoff.repository.base_branch,
        )
        request = DraftPrRequest(
            repository=handoff.repository,
            repository_slug=self.github_repository,
            payload=payload,
            idempotency_key=f"{state['run_id']}:{state['diff_digest']}",
        )
        try:
            prepared = await self.pr_provider.prepare(request)
        except (OSError, RuntimeError, ValueError) as exc:
            return self._failure(state, "DRAFT_PR_PREPARE_FAILED", "prepare_pr", str(exc))
        update: dict[str, object] = {
            "draft_pr": prepared.metadata,
            "proposed_branch": branch,
            "final_status": FinalStatus.DRAFT_PR_PREPARED,
            "audit_events": self._event(state, "DRAFT_PR_PREPARED", "OK", "Draft pull-request payload prepared."),
        }
        if not self.github_writes_enabled:
            return update
        try:
            await self.repository.create_branch(BranchRequest(workspace=state["workspace"], branch_name=branch))
            commit = await self.repository.commit(
                CommitRequest(workspace=state["workspace"], message=f"fix: remediate {handoff.case_id}")
            )
            update["proposed_commit"] = commit.commit_sha
            await self.repository.push(PushRequest(workspace=state["workspace"], branch_name=branch))
            created = await self.pr_provider.create_draft(request)
        except (OSError, RuntimeError, ValueError) as exc:
            update["errors"] = [
                *state.get("errors", []),
                ErrorRecord(
                    code="DRAFT_PR_CREATE_FAILED",
                    stage="prepare_pr",
                    message=self.audit.redactor.redact(str(exc)),
                    retryable=True,
                ),
            ]
            update["residual_risks"] = [
                *state.get("residual_risks", []),
                "Draft PR creation did not complete; a remote branch may require human cleanup.",
            ]
            return update
        update.update(
            {
                "draft_pr": created.metadata,
                "final_status": FinalStatus.DRAFT_PR_CREATED,
            }
        )
        return update

    async def cleanup(self, state: RemediationState) -> dict[str, object]:
        workspace = state.get("workspace")
        if workspace is None:
            return {}
        try:
            result = await self.sandbox.destroy(workspace)
        except (OSError, RuntimeError, ValueError) as exc:
            result = CleanupResult(succeeded=False, detail=f"Workspace cleanup failed: {exc}")
        result = result.model_copy(update={"detail": self.audit.redactor.redact(result.detail)})
        update: dict[str, object] = {
            "cleanup_result": result,
            "workspace_status": WorkspaceStatus.DESTROYED if result.succeeded else WorkspaceStatus.CLEANUP_FAILED,
            "audit_events": self._event(
                state,
                "WORKSPACE_CLEANUP",
                "OK" if result.succeeded else "FAILED",
                result.detail,
            ),
        }
        if not result.succeeded:
            update["final_status"] = FinalStatus.CLEANUP_FAILED
            update["residual_risks"] = [*state.get("residual_risks", []), result.detail]
        return update

    async def finalize(self, state: RemediationState) -> dict[str, object]:
        events = self._event(state, "RUN_FINALIZED", state["final_status"], "Remediation run finalized.")
        errors = list(state.get("errors", []))
        preliminary_handoff = self._build_handoff(state, None, None, errors)
        artifact_files = self._artifact_files(state, events, preliminary_handoff)
        manifest = state.get("artifact_manifest")
        try:
            await self.audit_sink.write(AuditWriteRequest(run_id=state["run_id"], jsonl=self.audit.to_jsonl(events)))
            manifest = await self.artifact_store.write_bundle(
                ArtifactWriteRequest(run_id=state["run_id"], files=artifact_files)
            )
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(
                ErrorRecord(
                    code="ARTIFACT_WRITE_FAILED",
                    stage="finalize",
                    message=self.audit.redactor.redact(str(exc)),
                )
            )

        audit_ref: ArtifactRef | None = None
        if manifest:
            audit_ref = next((item for item in manifest.artifacts if item.name == "audit.jsonl"), None)
        handoff = self._build_handoff(state, manifest, audit_ref, errors)
        return {
            "audit_events": events,
            "artifact_manifest": manifest,
            "errors": errors,
            "final_handoff": handoff,
        }

    def _build_handoff(
        self,
        state: RemediationState,
        manifest: ArtifactManifest | None,
        audit_ref: ArtifactRef | None,
        errors: list[ErrorRecord],
    ) -> RemediationHandoffV1:
        workspace = state.get("workspace")
        plan = state.get("remediation_plan")
        risk = state.get("risk_assessment")
        risk_control_ids = [item.code for item in risk.findings] if risk else []
        patch_control_ids = state["patch_policy"].control_ids if state.get("patch_policy") else []
        return RemediationHandoffV1(
            case_id=state["case_id"],
            run_id=state["run_id"],
            final_status=state["final_status"],
            repository=state["handoff"].repository,
            base_commit=workspace.base_commit if workspace else None,
            proposed_branch=state.get("proposed_branch"),
            proposed_commit=state.get("proposed_commit"),
            changed_files=state.get("changed_files", []),
            diff_digest=state.get("diff_digest"),
            remediation_plan_summary=plan.summary if plan else None,
            risk_summary=risk.rationale if risk else None,
            policy_control_ids=sorted({*risk_control_ids, *patch_control_ids}),
            approvals=state.get("approval_history", []),
            validation_attempts=state.get("validation_attempts", []),
            failed_attempt_summaries=[
                f"Attempt {item.attempt}: {item.outcome}"
                for item in state.get("validation_attempts", [])
                if item.outcome is not ValidationOutcome.PASSED
            ],
            residual_risks=state.get("residual_risks", []),
            rollback_instructions=state.get("rollback_instructions"),
            draft_pr=state.get("draft_pr"),
            artifact_manifest=manifest,
            audit_bundle_ref=audit_ref,
            errors=errors,
        )

    def _approval_interrupt(self, state: RemediationState) -> dict[str, object]:
        request = state["approval_request"]
        raw = interrupt(request.model_dump(mode="json"))
        decision = ApprovalDecisionV1.model_validate(raw)
        if decision.approval_id != request.approval_id or decision.scope_digest != request.scope_digest:
            return self._failure(state, "APPROVAL_SCOPE_MISMATCH", "approval", "Approval does not match exact scope.")
        status = (
            FinalStatus.PENDING if decision.status is ApprovalStatus.APPROVED else FinalStatus.HUMAN_ACTION_REQUIRED
        )
        return {
            "approval_history": [*state.get("approval_history", []), decision],
            "final_status": status,
            "audit_events": self._event(
                state,
                "APPROVAL_DECIDED",
                decision.status,
                f"Approval {decision.status} by {decision.reviewer_id} for exact scope.",
            ),
        }

    def _approval_request(
        self,
        state: RemediationState,
        kind: Literal["PLAN", "PATCH"],
        scope_digest: str,
        summary: str,
    ) -> ApprovalRequest:
        return ApprovalRequest(
            approval_id=str(uuid4()),
            case_id=state["case_id"],
            kind=kind,
            scope_digest=scope_digest,
            summary=summary,
            reasons=[summary],
            requested_at=datetime.now(UTC),
        )

    def _failure(self, state: RemediationState, code: str, stage: str, message: str) -> dict[str, object]:
        redacted_message = self.audit.redactor.redact(message)
        return {
            "final_status": FinalStatus.INTERNAL_ERROR,
            "errors": [*state.get("errors", []), ErrorRecord(code=code, stage=stage, message=redacted_message)],
            "audit_events": self._event(state, code, "ERROR", redacted_message),
        }

    def _event(
        self,
        state: RemediationState,
        event_type: str,
        result_code: object,
        detail: str,
    ) -> list[AuditEvent]:
        existing = state.get("audit_events", [])
        event = self.audit.event(
            existing,
            case_id=state.get("case_id", state["handoff"].case_id),
            run_id=state["run_id"],
            event_type=event_type,
            result_code=str(result_code),
            detail=detail,
        )
        return [*existing, event]

    def _artifact_files(
        self,
        state: RemediationState,
        events: list[AuditEvent],
        handoff: RemediationHandoffV1,
    ) -> dict[str, str]:
        files = {
            "audit.jsonl": "".join(item.model_dump_json() + "\n" for item in events),
            "result.json": handoff.model_dump_json(indent=2),
            "validation.json": json.dumps(
                [item.model_dump(mode="json") for item in state.get("validation_attempts", [])],
                indent=2,
                default=str,
            ),
            "model-calls.json": json.dumps(
                [item.model_dump(mode="json") for item in state.get("model_calls", [])],
                indent=2,
                default=str,
            ),
        }
        if state.get("current_diff"):
            files["patch.diff"] = state["current_diff"]
        if state.get("rollback_instructions"):
            files["rollback.json"] = state["rollback_instructions"].model_dump_json(indent=2)
        if state.get("draft_pr"):
            files["draft-pr.json"] = state["draft_pr"].model_dump_json(indent=2)
        return files

    @staticmethod
    def _pr_body(state: RemediationState) -> str:
        handoff = state["handoff"]
        evidence = "\n".join(
            f"- `{item.evidence_id}` — {item.source_type} at `{item.source_locator}` ({item.digest})"
            for item in handoff.supporting_evidence
        )
        validation_lines: list[str] = []
        for attempt in state.get("validation_attempts", []):
            validation_lines.append(f"- Attempt {attempt.attempt}: {attempt.outcome}")
            validation_lines.extend(
                f"  - `{result.task_name}`: {result.outcome}; exit={result.exit_code}; duration={result.duration_ms} ms"
                for result in attempt.results
            )
        validation = "\n".join(validation_lines)
        changed = "\n".join(f"- `{path}`" for path in state.get("changed_files", []))
        residual = "\n".join(f"- {risk}" for risk in state.get("residual_risks", [])) or "- None identified"
        approvals = (
            "\n".join(
                f"- {item.status} by `{item.reviewer_id}` for `{item.scope_digest}`"
                for item in state.get("approval_history", [])
            )
            or "- No pre-PR approval was required by policy."
        )
        patch_policy = state.get("patch_policy")
        risk_assessment = state.get("risk_assessment")
        patch_controls = patch_policy.control_ids if patch_policy else []
        risk_controls = [item.code for item in risk_assessment.findings] if risk_assessment else []
        policy_controls = (
            "\n".join(f"- `{control}`" for control in sorted({*patch_controls, *risk_controls}))
            or "- No elevated control triggered."
        )
        return (
            "## Issue and diagnosis\n\n"
            f"{handoff.issue_summary}\n\n{handoff.diagnosis.summary}\n\n"
            "## Supporting evidence\n\n"
            f"{evidence}\n\n"
            "## Remediation plan\n\n"
            f"{state['remediation_plan'].summary}\n\n"
            "## Changed files\n\n"
            f"{changed}\n\n"
            "## Validation evidence\n\n"
            f"{validation}\n\n"
            "## Residual risks\n\n"
            f"{residual}\n\n"
            "## Policy controls\n\n"
            f"{policy_controls}\n\n"
            "## Rollback\n\n"
            f"{state['rollback_instructions'].summary}\n\n"
            "## Approvals and review\n\n"
            f"{approvals}\n\n"
            "This is an AI-prepared draft. Human review and approval are required. It must not be merged "
            "automatically.\n"
        )


def _branch_name(case_id: str, run_id: str) -> str:
    safe_case = re.sub(r"[^a-zA-Z0-9._-]+", "-", case_id).strip("-").lower() or "case"
    return f"aios/remediation/{safe_case}-{run_id[:8]}"[:200]
