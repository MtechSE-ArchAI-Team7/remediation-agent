"""A2A Protocol 1.0 executor for the single remediation workflow."""

from __future__ import annotations

import logging
from typing import cast

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import a2a_pb2 as a2a_pb
from google.protobuf import json_format  # type: ignore[import-untyped]
from pydantic import ValidationError

from remediation_agent.api.a2a_contracts import (
    APPROVAL_DECISION_MEDIA_TYPE,
    APPROVAL_REQUEST_MEDIA_TYPE,
    DIAGNOSIS_HANDOFF_MEDIA_TYPE,
    EXPLAINABILITY_TRACE_MEDIA_TYPE,
    PROVIDER_PROBE_REQUEST_MEDIA_TYPE,
    PROVIDER_PROBE_RESULT_MEDIA_TYPE,
    REMEDIATION_HANDOFF_MEDIA_TYPE,
    ProviderProbeModelResult,
    ProviderProbeRequestV1,
    ProviderProbeResultV1,
)
from remediation_agent.domain.enums import FinalStatus, ModelOperation
from remediation_agent.domain.models import ApprovalDecisionV1, DiagnosisHandoffV1, RemediationRunView
from remediation_agent.ports.models import ModelRequest
from remediation_agent.ports.protocols import StructuredModel
from remediation_agent.service import ApprovalConflictError, RemediationService, RunNotFoundError

_LOGGER = logging.getLogger(__name__)
_PROMPT_VERSION = "agentcore-smoke-v1"

_COMPLETED = {FinalStatus.DRAFT_PR_PREPARED, FinalStatus.DRAFT_PR_CREATED}
_REJECTED = {
    FinalStatus.INVALID_REQUEST,
    FinalStatus.UNSUPPORTED_REMEDIATION_TYPE,
    FinalStatus.NOT_IMPLEMENTED,
    FinalStatus.HUMAN_ACTION_REQUIRED,
    FinalStatus.UNSAFE_REMEDIATION,
}
_FAILED = {FinalStatus.VALIDATION_FAILED, FinalStatus.INTERNAL_ERROR, FinalStatus.CLEANUP_FAILED}


class RemediationA2AExecutor(AgentExecutor):
    """Translate A2A messages into calls on the existing remediation service."""

    def __init__(
        self,
        service: RemediationService | None,
        *,
        model: StructuredModel | None = None,
        probe_provider: str | None = None,
    ) -> None:
        self._service = service
        self._model = model
        self._probe_provider = probe_provider

    def configure(
        self,
        service: RemediationService,
        *,
        model: StructuredModel | None,
        probe_provider: str | None,
    ) -> None:
        """Bind dependencies constructed by the hosted application lifespan."""

        self._service = service
        self._model = model
        self._probe_provider = probe_provider

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id = context.task_id
        context_id = context.context_id
        if task_id is None or context_id is None:
            raise RuntimeError("A2A request context is missing generated identifiers")

        try:
            media_type, payload = _validated_data_part(context)
        except ValueError as exc:
            await self._reject_transport(task_id, context_id, event_queue, "INVALID_DATA_PART")
            _LOGGER.info("Rejected malformed A2A input: %s", type(exc).__name__)
            return

        if media_type == PROVIDER_PROBE_REQUEST_MEDIA_TYPE:
            try:
                probe = await self._provider_probe(task_id, context_id, payload)
            except (ValidationError, ValueError):
                await self._reject_transport(task_id, context_id, event_queue, "INVALID_PROVIDER_PROBE")
                return
            except Exception:  # noqa: BLE001 - provider failures are exposed only as a bounded task code
                updater = TaskUpdater(event_queue, task_id, context_id)
                await event_queue.enqueue_event(
                    a2a_pb.Task(
                        id=task_id,
                        context_id=context_id,
                        status=a2a_pb.TaskStatus(state=a2a_pb.TaskState.TASK_STATE_SUBMITTED),
                    )
                )
                await updater.failed(_status_message(updater, "PROVIDER_PROBE_FAILED"))
                return
            await event_queue.enqueue_event(probe)
            return

        updater = TaskUpdater(event_queue, task_id, context_id)
        await event_queue.enqueue_event(
            a2a_pb.Task(
                id=task_id,
                context_id=context_id,
                status=a2a_pb.TaskStatus(state=a2a_pb.TaskState.TASK_STATE_SUBMITTED),
            )
        )
        await updater.start_work()

        if self._service is None:
            await updater.failed(_status_message(updater, "RUNTIME_NOT_CONFIGURED"))
            return

        try:
            if media_type == DIAGNOSIS_HANDOFF_MEDIA_TYPE:
                handoff = DiagnosisHandoffV1.model_validate(payload)
                view = await self._service.start(handoff, run_id=task_id)
            elif media_type == APPROVAL_DECISION_MEDIA_TYPE:
                decision = ApprovalDecisionV1.model_validate(payload)
                view = await self._service.approve(task_id, decision)
            else:
                await updater.reject(_status_message(updater, "UNSUPPORTED_MEDIA_TYPE"))
                return
        except ValidationError:
            await updater.reject(_status_message(updater, "INVALID_DATA_PART"))
            return
        except ApprovalConflictError:
            await updater.reject(_status_message(updater, "APPROVAL_CONFLICT"))
            return
        except RunNotFoundError:
            await updater.reject(_status_message(updater, "TASK_NOT_FOUND"))
            return
        except Exception:  # noqa: BLE001 - external and workflow failures are normalized
            _LOGGER.exception("A2A remediation execution failed")
            await updater.failed(_status_message(updater, "RUNTIME_INVOCATION_FAILED"))
            return

        await self._publish_view(updater, view)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        del context, event_queue
        from a2a.utils.errors import TaskNotCancelableError

        raise TaskNotCancelableError

    async def _publish_view(self, updater: TaskUpdater, view: RemediationRunView) -> None:
        if view.status is FinalStatus.AWAITING_APPROVAL:
            request = view.approval_request
            if request is None:
                await updater.failed(_status_message(updater, "MISSING_APPROVAL_REQUEST"))
                return
            parts = [_data_part(request.model_dump(mode="json"), APPROVAL_REQUEST_MEDIA_TYPE)]
            if view.explainability is not None:
                parts.append(_data_part(view.explainability.model_dump(mode="json"), EXPLAINABILITY_TRACE_MEDIA_TYPE))
            message = updater.new_agent_message(parts)
            await updater.requires_input(message)
            return

        if view.result is None:
            await updater.failed(_status_message(updater, "MISSING_REMEDIATION_HANDOFF"))
            return

        artifact_parts = [_data_part(view.result.model_dump(mode="json"), REMEDIATION_HANDOFF_MEDIA_TYPE)]
        if view.explainability is not None:
            artifact_parts.append(
                _data_part(view.explainability.model_dump(mode="json"), EXPLAINABILITY_TRACE_MEDIA_TYPE)
            )
        if view.downstream_delivery is not None:
            from remediation_agent.api.a2a_contracts import DELIVERY_RECEIPT_MEDIA_TYPE

            artifact_parts.append(
                _data_part(view.downstream_delivery.model_dump(mode="json"), DELIVERY_RECEIPT_MEDIA_TYPE)
            )
        await updater.add_artifact(
            artifact_parts,
            artifact_id=f"remediation-handoff-{view.run_id}",
            name="remediation_handoff_v1",
            last_chunk=True,
        )
        message = _status_message(updater, view.status.value)
        task_state = task_state_for_final_status(view.status)
        if task_state == a2a_pb.TaskState.TASK_STATE_COMPLETED:
            await updater.complete(message)
        elif task_state == a2a_pb.TaskState.TASK_STATE_REJECTED:
            await updater.reject(message)
        elif task_state == a2a_pb.TaskState.TASK_STATE_FAILED:
            await updater.failed(message)
        else:
            await updater.failed(_status_message(updater, "INVALID_WORKFLOW_STATUS"))

    async def _provider_probe(
        self,
        task_id: str,
        context_id: str,
        payload: dict[str, object],
    ) -> a2a_pb.Message:
        request = ProviderProbeRequestV1.model_validate(payload)
        if self._model is None or self._probe_provider is None:
            raise RuntimeError("provider probe is not configured")
        if request.probe != self._probe_provider:
            raise ValueError("provider probe does not match the configured provider")
        generation = await self._model.generate(
            ModelRequest(
                operation=ModelOperation.AGENTCORE_SMOKE,
                prompt_version=_PROMPT_VERSION,
                system_instruction=(
                    "This is a bounded infrastructure smoke probe. Return status exactly 'ok' in the requested "
                    "schema. Do not add commentary, call tools, or use external data."
                ),
                payload={"probe": request.probe},
            ),
            ProviderProbeModelResult,
        )
        record = generation.record
        result = ProviderProbeResultV1(
            status=generation.value.status,
            provider=record.provider,
            model=record.model,
            duration_ms=record.duration_ms,
            input_tokens=record.input_tokens,
            output_tokens=record.output_tokens,
            response_digest=record.output_digest,
        )
        return a2a_pb.Message(
            role=a2a_pb.Role.ROLE_AGENT,
            task_id=task_id,
            context_id=context_id,
            message_id=f"probe-{task_id}",
            parts=[_data_part(result.model_dump(mode="json"), PROVIDER_PROBE_RESULT_MEDIA_TYPE)],
        )

    @staticmethod
    async def _reject_transport(
        task_id: str,
        context_id: str,
        event_queue: EventQueue,
        code: str,
    ) -> None:
        updater = TaskUpdater(event_queue, task_id, context_id)
        await event_queue.enqueue_event(
            a2a_pb.Task(
                id=task_id,
                context_id=context_id,
                status=a2a_pb.TaskStatus(state=a2a_pb.TaskState.TASK_STATE_SUBMITTED),
            )
        )
        await updater.reject(_status_message(updater, code))


def _validated_data_part(context: RequestContext) -> tuple[str, dict[str, object]]:
    message = context.message
    if message is None or len(message.parts) != 1:
        raise ValueError("exactly one A2A data part is required")
    part = message.parts[0]
    if part.WhichOneof("content") != "data" or not part.media_type:
        raise ValueError("a typed A2A data part is required")
    payload = cast(
        dict[str, object],
        json_format.MessageToDict(part.data, preserving_proto_field_name=True),
    )
    return part.media_type, payload


def _data_part(payload: dict[str, object], media_type: str) -> a2a_pb.Part:
    part = a2a_pb.Part(media_type=media_type)
    json_format.ParseDict(payload, part.data)
    return part


def _status_message(updater: TaskUpdater, code: str) -> a2a_pb.Message:
    return updater.new_agent_message([a2a_pb.Part(text=code, media_type="text/plain")])


def task_state_for_final_status(status: FinalStatus) -> int:
    """Map workflow outcomes to A2A states without free-form routing."""

    if status in _COMPLETED:
        return a2a_pb.TaskState.TASK_STATE_COMPLETED
    if status is FinalStatus.AWAITING_APPROVAL:
        return a2a_pb.TaskState.TASK_STATE_INPUT_REQUIRED
    if status in _REJECTED:
        return a2a_pb.TaskState.TASK_STATE_REJECTED
    if status in _FAILED:
        return a2a_pb.TaskState.TASK_STATE_FAILED
    return a2a_pb.TaskState.TASK_STATE_WORKING
