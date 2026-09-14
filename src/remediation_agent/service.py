"""Application service for starting, inspecting, and resuming remediation runs."""

from __future__ import annotations

import asyncio
from typing import cast
from uuid import UUID, uuid4

from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command, StateSnapshot

from remediation_agent.adapters.evidence import SecretRedactor
from remediation_agent.domain.enums import FinalStatus
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    ApprovalRequest,
    DiagnosisHandoffV1,
    RemediationHandoffV1,
    RemediationRunView,
)
from remediation_agent.workflow.state import RemediationState


class RunNotFoundError(LookupError):
    """Raised when no checkpoint exists for a requested run."""


class ApprovalConflictError(ValueError):
    """Raised when an approval cannot be applied to the current interrupt."""


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
    ) -> None:
        self.graph = graph
        self._run_slots = asyncio.Semaphore(max_active_runs)
        self._redactor = redactor or SecretRedactor()

    async def start(self, handoff: DiagnosisHandoffV1) -> RemediationRunView:
        run_id = str(uuid4())
        redacted_handoff = DiagnosisHandoffV1.model_validate(self._redact_data(handoff.model_dump(mode="python")))
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
        request = self._pending_approval(state, snapshot)
        if request is None:
            raise ApprovalConflictError("run is not waiting for approval")
        redacted_decision = ApprovalDecisionV1.model_validate(self._redact_data(decision.model_dump(mode="python")))
        if (
            redacted_decision.approval_id != request.approval_id
            or redacted_decision.scope_digest != request.scope_digest
        ):
            raise ApprovalConflictError("approval ID and scope digest must match the pending interrupt")
        if redacted_decision.decided_at < request.requested_at:
            raise ApprovalConflictError("approval decision cannot predate the approval request")
        return await self._invoke(Command(resume=redacted_decision.model_dump(mode="json")), run_id)

    async def get(self, run_id: str) -> RemediationRunView:
        self._validate_run_id(run_id)
        snapshot = await self._snapshot(run_id)
        state = cast(RemediationState, snapshot.values)
        return self._view(state, run_id, approval_request=self._pending_approval(state, snapshot))

    async def ready(self) -> bool:
        """Probe the configured checkpointer without creating remediation state."""

        try:
            await self.graph.aget_state(self._config("readiness-probe"))
        except Exception:  # noqa: BLE001 - readiness must normalize checkpointer/provider failures
            return False
        return True

    async def _invoke(self, value: RemediationState | Command[object], run_id: str) -> RemediationRunView:
        config = self._config(run_id)
        async with self._run_slots:
            raw = await self.graph.ainvoke(value, config=config)
        state = cast(RemediationState, raw)
        snapshot = await self._snapshot(run_id)
        if snapshot.values:
            state = cast(RemediationState, snapshot.values)
        return self._view(state, run_id, approval_request=self._pending_approval(state, snapshot))

    async def _snapshot(self, run_id: str) -> StateSnapshot:
        snapshot = await self.graph.aget_state(self._config(run_id))
        if not snapshot.values:
            raise RunNotFoundError(f"remediation run not found: {run_id}")
        return snapshot

    @staticmethod
    def _view(
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
        )

    @staticmethod
    def _config(run_id: str) -> RunnableConfig:
        return {"configurable": {"thread_id": run_id}}

    @staticmethod
    def _pending_approval(state: RemediationState, snapshot: StateSnapshot) -> ApprovalRequest | None:
        for graph_interrupt in reversed(snapshot.interrupts):
            try:
                return ApprovalRequest.model_validate(graph_interrupt.value)
            except ValueError:
                continue
        return state.get("approval_request") if state.get("final_status") is FinalStatus.AWAITING_APPROVAL else None

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
