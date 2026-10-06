"""Application service for starting, inspecting, and resuming remediation runs."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from typing import cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command, StateSnapshot

from remediation_agent.adapters.evidence import AuditTrail, SecretRedactor
from remediation_agent.domain.enums import ApprovalStatus, FinalStatus
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    ApprovalRequest,
    DiagnosisHandoffV1,
    DownstreamDeliveryReceiptV1,
    ErrorRecord,
    RemediationHandoffV1,
    RemediationRunView,
)
from remediation_agent.explainability import build_explainability_trace
from remediation_agent.ports.models import AuditWriteRequest, HandoffDeliveryRequest
from remediation_agent.ports.protocols import AuditSink, HandoffDeliveryPort, WorkspaceRecoveryPort
from remediation_agent.workflow.state import RemediationState


class RunNotFoundError(LookupError):
    """Raised when no checkpoint exists for a requested run."""


class ApprovalConflictError(ValueError):
    """Raised when an approval cannot be applied to the current interrupt."""


class InvocationDeadlineError(TimeoutError):
    """Raised when an AgentCore invocation reaches its bounded execution deadline."""


CompiledRemediationGraph = CompiledStateGraph[
    RemediationState,
    None,
    RemediationState,
    RemediationState,
]


class RemediationService:
    """Thin lifecycle boundary around one compiled LangGraph workflow."""

    def __init__(
        self,
        graph: CompiledRemediationGraph,
        *,
        max_active_runs: int,
        redactor: SecretRedactor | None = None,
        actor_id: str | None = None,
        invocation_timeout_seconds: float | None = None,
        workspace_recovery: WorkspaceRecoveryPort | None = None,
        handoff_delivery: HandoffDeliveryPort | None = None,
        delivery_audit_sink: AuditSink | None = None,
    ) -> None:
        self.graph = graph
        self._run_slots = asyncio.Semaphore(max_active_runs)
        self._redactor = redactor or SecretRedactor()
        self._actor_id = actor_id
        self._invocation_timeout_seconds = invocation_timeout_seconds
        self._workspace_recovery = workspace_recovery
        self._handoff_delivery = handoff_delivery
        self._delivery_audit_sink = delivery_audit_sink

    async def start(self, handoff: DiagnosisHandoffV1, *, run_id: str | None = None) -> RemediationRunView:
        run_id = run_id or str(uuid4())
        self._validate_run_id(run_id)
        redacted_handoff = DiagnosisHandoffV1.model_validate(self._redact_data(handoff.model_dump(mode="python")))
        if await self._exists(run_id):
            snapshot = await self._snapshot(run_id)
            if snapshot.values.get("handoff") != redacted_handoff:
                raise ApprovalConflictError("RUN_INPUT_MISMATCH")
            return await self.get(run_id)
        initial_state: RemediationState = {
            "run_id": run_id,
            "thread_id": run_id,
            "handoff": redacted_handoff,
        }
        return await self._invoke(initial_state, run_id)

    async def approve(self, run_id: str, decision: ApprovalDecisionV1) -> RemediationRunView:
        self._validate_run_id(run_id)
        snapshot = await self._snapshot(run_id)
        state = cast(RemediationState, snapshot.values)
        if "release_provenance" not in state or "execution_binding" not in state:
            raise ApprovalConflictError("REVALIDATION_REQUIRED")
        redacted_decision = ApprovalDecisionV1.model_validate(self._redact_data(decision.model_dump(mode="python")))
        request = self._pending_approval(state, snapshot)
        if request is None:
            if self._is_matching_approval_retry(state, redacted_decision):
                if redacted_decision.status is ApprovalStatus.APPROVED and snapshot.next:
                    return await self._invoke(None, run_id)
                return await self._view_with_delivery(state, run_id, approval_request=None)
            raise ApprovalConflictError("run is not waiting for approval")
        if (
            redacted_decision.approval_id != request.approval_id
            or redacted_decision.scope_digest != request.scope_digest
        ):
            raise ApprovalConflictError("approval ID and scope digest must match the pending interrupt")
        if redacted_decision.decided_at < request.requested_at:
            raise ApprovalConflictError("approval decision cannot predate the approval request")
        if self._workspace_recovery is not None and "workspace" in state:
            recovered = await self._workspace_recovery.ensure(
                state["handoff"].repository,
                state["workspace"],
                recovery_is_safe=self._workspace_recovery_is_safe(state),
            )
            if recovered != state["workspace"]:
                await self.graph.aupdate_state(self._config(run_id), {"workspace": recovered})
        return await self._invoke(Command(resume=redacted_decision.model_dump(mode="json")), run_id)

    async def retry_publication(self, run_id: str, candidate_digest: str) -> RemediationRunView:
        self._validate_run_id(run_id)
        snapshot = await self._snapshot(run_id)
        state = cast(RemediationState, snapshot.values)
        journal = state.get("publication_journal")
        if journal is not None and journal.verified and state.get("final_status") is FinalStatus.DRAFT_PR_CREATED:
            return await self.get(run_id)
        if (
            snapshot.next
            or journal is None
            or state.get("execution_binding") is None
            or not state.get("locally_verified")
            or not state.get("evidence_persisted")
            or candidate_digest != journal.candidate_digest
            or candidate_digest != state.get("diff_digest")
            or not any(f.category == "PUBLICATION_FAILURE" for f in state.get("workflow_failures", []))
        ):
            raise ApprovalConflictError("PUBLICATION_RETRY_REVALIDATION_REQUIRED")
        await self.graph.aupdate_state(
            self._config(run_id), {"final_status": FinalStatus.PENDING}, as_node="build_evidence"
        )
        return await self._invoke(None, run_id)

    async def get(self, run_id: str) -> RemediationRunView:
        self._validate_run_id(run_id)
        snapshot = await self._snapshot(run_id)
        state = cast(RemediationState, snapshot.values)
        return await self._view_with_delivery(
            state,
            run_id,
            approval_request=self._pending_approval(state, snapshot),
        )

    async def ready(self) -> bool:
        """Probe the configured checkpointer without creating remediation state."""

        try:
            await self.graph.aget_state(self._config("readiness-probe"))
        except Exception:  # noqa: BLE001 - readiness must normalize checkpointer/provider failures
            return False
        return True

    async def _invoke(self, value: RemediationState | Command[object] | None, run_id: str) -> RemediationRunView:
        config = self._config(run_id)
        async with self._run_slots:
            try:
                if self._invocation_timeout_seconds is None:
                    raw = await self.graph.ainvoke(value, config=config)
                else:
                    async with asyncio.timeout(self._invocation_timeout_seconds):
                        raw = await self.graph.ainvoke(value, config=config)
            except TimeoutError as exc:
                return await self._finish_after_deadline(run_id, exc)
        state = cast(RemediationState, raw)
        snapshot = await self._snapshot(run_id)
        if snapshot.values:
            state = cast(RemediationState, snapshot.values)
        return await self._view_with_delivery(
            state,
            run_id,
            approval_request=self._pending_approval(state, snapshot),
        )

    async def _finish_after_deadline(self, run_id: str, cause: TimeoutError) -> RemediationRunView:
        """Resume at the normal cleanup boundary after cancelling an overlong stage."""

        config = self._config(run_id)
        snapshot = await self.graph.aget_state(config)
        if not snapshot.values:
            raise InvocationDeadlineError("remediation invocation exceeded its execution deadline") from cause
        state = cast(RemediationState, snapshot.values)
        for task in snapshot.tasks:
            if task.name not in {"analysis_workflow", "repair_workflow"} or not isinstance(task.state, dict):
                continue
            child_snapshot = await self.graph.aget_state(task.state)
            if child_snapshot.values:
                state = cast(RemediationState, child_snapshot.values)
                break
        handoff = state.get("handoff")
        if handoff is None:
            raise InvocationDeadlineError("remediation invocation exceeded its execution deadline") from cause
        message = "The AgentCore invocation deadline expired; the workspace was routed through cleanup."
        next_node = next(iter(snapshot.next), None)
        if next_node is None:
            raise InvocationDeadlineError("remediation invocation exceeded its execution deadline") from cause
        deadline_update = cast(
            RemediationState,
            {
                **state,
                "case_id": state.get("case_id", handoff.case_id),
                "final_status": FinalStatus.INTERNAL_ERROR,
                "errors": [
                    *state.get("errors", []),
                    ErrorRecord(
                        code="INVOCATION_DEADLINE_EXCEEDED",
                        stage="runtime",
                        message=message,
                        retryable=True,
                    ),
                ],
                "residual_risks": [*state.get("residual_risks", []), message],
            },
        )
        await self.graph.aupdate_state(config, deadline_update, as_node=next_node)
        try:
            async with asyncio.timeout(30.0):
                raw = await self.graph.ainvoke(None, config=config)
        except TimeoutError as exc:
            raise InvocationDeadlineError("deadline cleanup did not complete") from exc
        completed = cast(RemediationState, raw)
        completed_snapshot = await self._snapshot(run_id)
        if completed_snapshot.values:
            completed = cast(RemediationState, completed_snapshot.values)
        return await self._view_with_delivery(
            completed,
            run_id,
            approval_request=self._pending_approval(completed, completed_snapshot),
        )

    async def _snapshot(self, run_id: str) -> StateSnapshot:
        snapshot = await self.graph.aget_state(self._config(run_id))
        if not snapshot.values:
            raise RunNotFoundError(f"remediation run not found: {run_id}")
        return snapshot

    def _view(
        self,
        state: RemediationState,
        run_id: str,
        *,
        approval_request: ApprovalRequest | None,
    ) -> RemediationRunView:
        result: RemediationHandoffV1 | None = state.get("final_handoff")
        status = (
            FinalStatus.AWAITING_APPROVAL
            if approval_request is not None
            else state.get("final_status", FinalStatus.INTERNAL_ERROR)
        )
        return RemediationRunView(
            run_id=run_id,
            status=status,
            approval_request=approval_request,
            result=result,
            downstream_delivery=state.get("downstream_delivery"),
            explainability=build_explainability_trace(
                state,
                run_id=run_id,
                status=status,
                approval_request=approval_request,
                redactor=self._redactor,
            ),
        )

    async def _view_with_delivery(
        self,
        state: RemediationState,
        run_id: str,
        *,
        approval_request: ApprovalRequest | None,
    ) -> RemediationRunView:
        view = self._view(state, run_id, approval_request=approval_request)
        if (
            self._handoff_delivery is None
            or view.status is not FinalStatus.DRAFT_PR_CREATED
            or not (state.get("publication_journal") and state["publication_journal"].verified)
            or view.result is None
        ):
            return view
        existing = view.downstream_delivery
        if existing is not None and existing.attempted:
            return view

        canonical = json.dumps(view.result.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        request_digest = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        delivery_id = existing.delivery_id if existing else str(uuid5(NAMESPACE_URL, f"aios-agent4:{run_id}"))
        message_id = existing.message_id if existing else str(uuid5(NAMESPACE_URL, f"aios-agent4-message:{run_id}"))
        pending = existing or DownstreamDeliveryReceiptV1(
            delivery_id=delivery_id,
            message_id=message_id,
            attempted=False,
            succeeded=False,
            attempted_at=datetime.now(UTC),
            request_digest=request_digest,
            error_code="DELIVERY_PENDING",
        )
        try:
            await self.graph.aupdate_state(
                self._config(run_id),
                {"downstream_delivery": pending},
            )
            receipt = await self._handoff_delivery.deliver(
                HandoffDeliveryRequest(
                    delivery_id=delivery_id,
                    message_id=message_id,
                    correlation_id=run_id,
                    request_digest=request_digest,
                    handoff=view.result,
                )
            )
            if (
                receipt.delivery_id != delivery_id
                or receipt.message_id != message_id
                or receipt.request_digest != request_digest
            ):
                raise ValueError("delivery receipt does not match the request")
        except Exception:  # noqa: BLE001 - delivery failure is supplementary and bounded
            receipt = DownstreamDeliveryReceiptV1(
                delivery_id=delivery_id,
                message_id=message_id,
                attempted=True,
                succeeded=False,
                attempted_at=datetime.now(UTC),
                request_digest=request_digest,
                error_code="DOWNSTREAM_DELIVERY_FAILED",
            )
        try:
            audit_events = state.get("audit_events", [])
            if self._delivery_audit_sink is not None:
                trail = AuditTrail(
                    state.get("policy_version", "unknown"),
                    state.get("prompt_version", "unknown"),
                    self._redactor,
                )
                delivery_event = trail.event(
                    audit_events,
                    case_id=view.result.case_id,
                    run_id=run_id,
                    event_type="DOWNSTREAM_A2A_DELIVERY",
                    result_code="SUCCEEDED" if receipt.succeeded else receipt.error_code or "FAILED",
                    detail=json.dumps(receipt.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
                    input_value=request_digest,
                    output_value=receipt.response_digest or receipt.error_code or "",
                )
                audit_events = [*audit_events, delivery_event]
            await self.graph.aupdate_state(
                self._config(run_id),
                {
                    "downstream_delivery": receipt,
                    "audit_events": audit_events,
                },
            )
            if self._delivery_audit_sink is not None:
                await self._delivery_audit_sink.write(
                    AuditWriteRequest(
                        run_id=run_id,
                        jsonl=AuditTrail.to_jsonl(audit_events),
                    )
                )
        except Exception:  # noqa: BLE001 - never alter the remediation outcome for receipt persistence
            receipt = receipt.model_copy(update={"error_code": receipt.error_code or "DELIVERY_RECEIPT_NOT_PERSISTED"})
        return view.model_copy(update={"downstream_delivery": receipt})

    def _config(self, run_id: str) -> RunnableConfig:
        configurable = {"thread_id": run_id}
        if self._actor_id is not None:
            configurable["actor_id"] = self._actor_id
        return {"configurable": configurable}

    async def _exists(self, run_id: str) -> bool:
        snapshot = await self.graph.aget_state(self._config(run_id))
        return bool(snapshot.values)

    @staticmethod
    def _workspace_recovery_is_safe(state: RemediationState) -> bool:
        return (
            state.get("final_status") is FinalStatus.AWAITING_APPROVAL
            and "validation_baseline_digest" not in state
            and "proposed_commit" not in state
        )

    @staticmethod
    def _pending_approval(state: RemediationState, snapshot: StateSnapshot) -> ApprovalRequest | None:
        for graph_interrupt in reversed(snapshot.interrupts):
            try:
                return ApprovalRequest.model_validate(graph_interrupt.value)
            except ValueError:
                continue
        return state.get("approval_request") if state.get("final_status") is FinalStatus.AWAITING_APPROVAL else None

    @staticmethod
    def _is_matching_approval_retry(state: RemediationState, decision: ApprovalDecisionV1) -> bool:
        """Accept only a semantically identical retry of a decision already checkpointed."""

        return any(
            existing.approval_id == decision.approval_id
            and existing.scope_digest == decision.scope_digest
            and existing.status is decision.status
            and existing.reviewer_id == decision.reviewer_id
            and existing.comment == decision.comment
            for existing in state.get("approval_history", [])
        )

    @staticmethod
    def _validate_run_id(run_id: str) -> None:
        try:
            UUID(run_id)
        except ValueError as exc:
            raise RunNotFoundError(f"invalid remediation run ID: {run_id}") from exc

    def _redact_data(self, value: object) -> object:
        if isinstance(value, str):
            return self._redactor.redact(value)
        if isinstance(value, dict):
            return {key: self._redact_data(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact_data(item) for item in value]
        return value
