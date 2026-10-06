"""A2A Protocol 1.0 executor for the single remediation workflow."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import cast
from urllib.parse import urlsplit

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskStore, TaskUpdater
from a2a.types import a2a_pb2 as a2a_pb
from google.protobuf import json_format  # type: ignore[import-untyped]
from pydantic import ValidationError

from remediation_agent.api.a2a_contracts import (
    APPROVAL_DECISION_MEDIA_TYPE,
    APPROVAL_REQUEST_MEDIA_TYPE,
    ARTIFACT_PREVIEW_REQUEST_MEDIA_TYPE,
    ARTIFACT_PREVIEW_RESULT_MEDIA_TYPE,
    DIAGNOSIS_HANDOFF_MEDIA_TYPE,
    EXPLAINABILITY_TRACE_MEDIA_TYPE,
    PROVIDER_PROBE_REQUEST_MEDIA_TYPE,
    PROVIDER_PROBE_RESULT_MEDIA_TYPE,
    PUBLICATION_RETRY_MEDIA_TYPE,
    REMEDIATION_HANDOFF_MEDIA_TYPE,
    RUN_SUMMARY_METADATA_KEY,
    ArtifactPreviewRequestV1,
    ArtifactPreviewResultV1,
    ProviderProbeModelResult,
    ProviderProbeRequestV1,
    ProviderProbeResultV1,
    RemediationRunSummaryV1,
)
from remediation_agent.domain.enums import FinalStatus, ModelOperation, ReleaseProvenanceStatus
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    DiagnosisHandoffV1,
    PublicationRetryRequestV1,
    RemediationHandoffV1,
    RemediationRunView,
)
from remediation_agent.ports.models import ArtifactReadError, ArtifactReadRequest, ModelRequest
from remediation_agent.ports.protocols import ArtifactReader, ReleaseProvenancePort, StructuredModel
from remediation_agent.service import ApprovalConflictError, RemediationService, RunNotFoundError

_LOGGER = logging.getLogger(__name__)
_PROMPT_VERSION = "agentcore-smoke-v1"
_MAX_ARTIFACT_OBJECT_BYTES = 1_048_576
_MAX_ARTIFACT_PREVIEW_BYTES = 262_144

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
        artifact_reader: ArtifactReader | None = None,
        release_provenance: ReleaseProvenancePort | None = None,
        task_store: TaskStore | None = None,
    ) -> None:
        self._service = service
        self._model = model
        self._probe_provider = probe_provider
        self._artifact_reader = artifact_reader
        self._release_provenance = release_provenance
        self._task_store = task_store

    def configure(
        self,
        service: RemediationService,
        *,
        model: StructuredModel | None,
        probe_provider: str | None,
        artifact_reader: ArtifactReader | None,
        release_provenance: ReleaseProvenancePort | None,
    ) -> None:
        """Bind dependencies constructed by the hosted application lifespan."""

        self._service = service
        self._model = model
        self._probe_provider = probe_provider
        self._artifact_reader = artifact_reader
        self._release_provenance = release_provenance

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

        if media_type == ARTIFACT_PREVIEW_REQUEST_MEDIA_TYPE:
            try:
                preview = await self._artifact_preview(context, task_id, context_id, payload)
            except ValidationError:
                await self._reject_transport(task_id, context_id, event_queue, "INVALID_ARTIFACT_PREVIEW_REQUEST")
                return
            except ArtifactReadError as exc:
                await self._reject_transport(task_id, context_id, event_queue, exc.code)
                return
            except Exception:  # noqa: BLE001 - artifact failures expose only bounded codes
                _LOGGER.exception("A2A artifact preview failed")
                await self._reject_transport(task_id, context_id, event_queue, "ARTIFACT_PREVIEW_FAILED")
                return
            await event_queue.enqueue_event(preview)
            return

        try:
            if media_type == DIAGNOSIS_HANDOFF_MEDIA_TYPE:
                handoff = DiagnosisHandoffV1.model_validate(payload)
                summary = _new_run_summary(context, task_id, handoff)
            elif media_type == PUBLICATION_RETRY_MEDIA_TYPE:
                retry = PublicationRetryRequestV1.model_validate(payload)
                if retry.run_id != task_id:
                    await self._reject_transport(task_id, context_id, event_queue, "PUBLICATION_RUN_MISMATCH")
                    return
                summary = _resumed_run_summary(context, task_id)
            elif media_type == APPROVAL_DECISION_MEDIA_TYPE:
                decision = ApprovalDecisionV1.model_validate(payload)
                summary = _resumed_run_summary(context, task_id)
            else:
                updater = TaskUpdater(event_queue, task_id, context_id)
                await event_queue.enqueue_event(
                    a2a_pb.Task(
                        id=task_id,
                        context_id=context_id,
                        status=a2a_pb.TaskStatus(state=a2a_pb.TaskState.TASK_STATE_SUBMITTED),
                    )
                )
                await updater.reject(_status_message(updater, "UNSUPPORTED_MEDIA_TYPE"))
                return
        except ValidationError:
            await self._reject_transport(task_id, context_id, event_queue, "INVALID_DATA_PART")
            return

        updater = TaskUpdater(event_queue, task_id, context_id)
        await event_queue.enqueue_event(
            a2a_pb.Task(
                id=task_id,
                context_id=context_id,
                status=a2a_pb.TaskStatus(state=a2a_pb.TaskState.TASK_STATE_SUBMITTED),
                metadata={RUN_SUMMARY_METADATA_KEY: summary.model_dump(mode="json")},
            )
        )
        await updater.start_work()

        if self._service is None:
            await _publish_failure(
                updater,
                summary,
                FinalStatus.INTERNAL_ERROR,
                "RUNTIME_NOT_CONFIGURED",
                a2a_pb.TaskState.TASK_STATE_FAILED,
            )
            return

        try:
            if media_type == DIAGNOSIS_HANDOFF_MEDIA_TYPE:
                view = await self._service.start(handoff, run_id=task_id)
            elif media_type == PUBLICATION_RETRY_MEDIA_TYPE:
                view = await self._service.retry_publication(task_id, retry.candidate_digest)
            else:
                view = await self._service.approve(task_id, decision)
        except ValidationError:
            await _publish_failure(
                updater,
                summary,
                FinalStatus.INVALID_REQUEST,
                "INVALID_DATA_PART",
                a2a_pb.TaskState.TASK_STATE_REJECTED,
            )
            return
        except ApprovalConflictError:
            await _publish_failure(
                updater,
                summary,
                FinalStatus.INVALID_REQUEST,
                "APPROVAL_CONFLICT",
                a2a_pb.TaskState.TASK_STATE_REJECTED,
            )
            return
        except RunNotFoundError:
            await _publish_failure(
                updater,
                summary,
                FinalStatus.INVALID_REQUEST,
                "TASK_NOT_FOUND",
                a2a_pb.TaskState.TASK_STATE_REJECTED,
            )
            return
        except Exception:  # noqa: BLE001 - external and workflow failures are normalized
            _LOGGER.exception("A2A remediation execution failed")
            await _publish_failure(
                updater,
                summary,
                FinalStatus.INTERNAL_ERROR,
                "RUNTIME_INVOCATION_FAILED",
                a2a_pb.TaskState.TASK_STATE_FAILED,
            )
            return

        await self._publish_view(updater, view, summary)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        del context, event_queue
        from a2a.utils.errors import TaskNotCancelableError

        raise TaskNotCancelableError

    async def _publish_view(
        self,
        updater: TaskUpdater,
        view: RemediationRunView,
        previous: RemediationRunSummaryV1,
    ) -> None:
        summary = _updated_run_summary(previous, view)
        metadata = {RUN_SUMMARY_METADATA_KEY: summary.model_dump(mode="json")}
        if view.status is FinalStatus.AWAITING_APPROVAL:
            request = view.approval_request
            if request is None:
                await _publish_failure(
                    updater,
                    previous,
                    FinalStatus.INTERNAL_ERROR,
                    "MISSING_APPROVAL_REQUEST",
                    a2a_pb.TaskState.TASK_STATE_FAILED,
                )
                return
            parts = [_data_part(request.model_dump(mode="json"), APPROVAL_REQUEST_MEDIA_TYPE)]
            if view.explainability is not None:
                parts.append(_data_part(view.explainability.model_dump(mode="json"), EXPLAINABILITY_TRACE_MEDIA_TYPE))
            message = updater.new_agent_message(parts)
            await updater.update_status(a2a_pb.TaskState.TASK_STATE_INPUT_REQUIRED, message, metadata=metadata)
            return

        if view.result is None:
            await _publish_failure(
                updater,
                previous,
                FinalStatus.INTERNAL_ERROR,
                "MISSING_REMEDIATION_HANDOFF",
                a2a_pb.TaskState.TASK_STATE_FAILED,
            )
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
        if task_state not in {
            a2a_pb.TaskState.TASK_STATE_COMPLETED,
            a2a_pb.TaskState.TASK_STATE_REJECTED,
            a2a_pb.TaskState.TASK_STATE_FAILED,
        }:
            await _publish_failure(
                updater,
                previous,
                FinalStatus.INTERNAL_ERROR,
                "INVALID_WORKFLOW_STATUS",
                a2a_pb.TaskState.TASK_STATE_FAILED,
            )
            return
        await updater.update_status(cast(a2a_pb.TaskState, task_state), message, metadata=metadata)

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
        if self._release_provenance is not None:
            provenance = await self._release_provenance.resolve()
            if provenance.status not in {ReleaseProvenanceStatus.LOCAL, ReleaseProvenanceStatus.VERIFIED}:
                raise RuntimeError("release provenance is unavailable")
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

    async def _artifact_preview(
        self,
        context: RequestContext,
        task_id: str,
        context_id: str,
        payload: dict[str, object],
    ) -> a2a_pb.Message:
        request = ArtifactPreviewRequestV1.model_validate(payload)
        if self._artifact_reader is None or self._task_store is None:
            raise ArtifactReadError("ARTIFACT_PREVIEW_UNSUPPORTED")
        source_task = await self._task_store.get(request.run_id, context.call_context)
        if source_task is None or source_task.context_id != context_id:
            raise ArtifactReadError("ARTIFACT_NOT_FOUND")
        handoff = _remediation_handoff(source_task)
        manifest = handoff.artifact_manifest
        if manifest is None or manifest.run_id != request.run_id:
            raise ArtifactReadError("ARTIFACT_NOT_FOUND")
        artifact = next(
            (
                item
                for item in manifest.artifacts
                if item.name == request.artifact_name and item.digest == request.digest
            ),
            None,
        )
        if artifact is None:
            raise ArtifactReadError("ARTIFACT_NOT_FOUND")
        preview = await self._artifact_reader.read(
            ArtifactReadRequest(
                run_id=request.run_id,
                artifact=artifact,
                max_object_bytes=_MAX_ARTIFACT_OBJECT_BYTES,
                max_preview_bytes=_MAX_ARTIFACT_PREVIEW_BYTES,
            )
        )
        result = ArtifactPreviewResultV1(
            run_id=request.run_id,
            **preview.model_dump(mode="python"),
        )
        return a2a_pb.Message(
            role=a2a_pb.Role.ROLE_AGENT,
            task_id=task_id,
            context_id=context_id,
            message_id=f"artifact-preview-{task_id}",
            parts=[_data_part(result.model_dump(mode="json"), ARTIFACT_PREVIEW_RESULT_MEDIA_TYPE)],
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


def _remediation_handoff(task: a2a_pb.Task) -> RemediationHandoffV1:
    if task.status.state != a2a_pb.TaskState.TASK_STATE_COMPLETED:
        raise ArtifactReadError("ARTIFACT_NOT_FOUND")
    for artifact in task.artifacts:
        for part in artifact.parts:
            if part.media_type != REMEDIATION_HANDOFF_MEDIA_TYPE or part.WhichOneof("content") != "data":
                continue
            payload = json_format.MessageToDict(part.data, preserving_proto_field_name=True)
            try:
                return RemediationHandoffV1.model_validate(payload)
            except ValidationError as exc:
                raise ArtifactReadError("ARTIFACT_INTEGRITY_FAILED") from exc
    raise ArtifactReadError("ARTIFACT_NOT_FOUND")


def _data_part(payload: dict[str, object], media_type: str) -> a2a_pb.Part:
    part = a2a_pb.Part(media_type=media_type)
    json_format.ParseDict(payload, part.data)
    return part


def _status_message(updater: TaskUpdater, code: str) -> a2a_pb.Message:
    return updater.new_agent_message([a2a_pb.Part(text=code, media_type="text/plain")])


async def _publish_failure(
    updater: TaskUpdater,
    previous: RemediationRunSummaryV1,
    status: FinalStatus,
    code: str,
    task_state: int,
) -> None:
    summary = _replace_run_summary(previous, status=status, updated_at=max(datetime.now(UTC), previous.updated_at))
    await updater.update_status(
        cast(a2a_pb.TaskState, task_state),
        _status_message(updater, code),
        metadata={RUN_SUMMARY_METADATA_KEY: summary.model_dump(mode="json")},
    )


def _new_run_summary(
    context: RequestContext,
    task_id: str,
    handoff: DiagnosisHandoffV1,
) -> RemediationRunSummaryV1:
    now = datetime.now(UTC)
    session_id = context.call_context.state.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise RuntimeError("A2A_RUNTIME_SESSION_REQUIRED")
    path = urlsplit(handoff.repository.url).path.strip("/")
    repository = path.removesuffix(".git") or None
    return RemediationRunSummaryV1(
        task_id=task_id,
        session_id=session_id,
        case_id=handoff.case_id,
        jira_ticket_id=handoff.jira_ticket_id,
        repository=repository,
        status=FinalStatus.PENDING,
        created_at=now,
        updated_at=now,
    )


def _resumed_run_summary(context: RequestContext, task_id: str) -> RemediationRunSummaryV1:
    task = context.current_task
    if task is not None:
        raw = json_format.MessageToDict(task.metadata, preserving_proto_field_name=True).get(RUN_SUMMARY_METADATA_KEY)
        try:
            previous = RemediationRunSummaryV1.model_validate(raw)
            return _replace_run_summary(
                previous,
                status=FinalStatus.PENDING,
                updated_at=max(datetime.now(UTC), previous.updated_at),
            )
        except ValidationError:
            pass
    now = datetime.now(UTC)
    session_id = context.call_context.state.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise RuntimeError("A2A_RUNTIME_SESSION_REQUIRED")
    return RemediationRunSummaryV1(
        task_id=task_id,
        session_id=session_id,
        status=FinalStatus.PENDING,
        created_at=now,
        updated_at=now,
    )


def _updated_run_summary(
    previous: RemediationRunSummaryV1,
    view: RemediationRunView,
) -> RemediationRunSummaryV1:
    result = view.result
    repository = previous.repository
    draft_pr_url = previous.draft_pr_url
    artifact_count = previous.artifact_count
    case_id = previous.case_id
    if result is not None:
        case_id = result.case_id
        path = urlsplit(result.repository.url).path.strip("/")
        repository = path.removesuffix(".git") or repository
        if result.draft_pr is not None:
            draft_pr_url = result.draft_pr.url
        if result.artifact_manifest is not None:
            artifact_count = len(result.artifact_manifest.artifacts)
    elif view.approval_request is not None:
        case_id = view.approval_request.case_id
    return _replace_run_summary(
        previous,
        case_id=case_id,
        repository=repository,
        status=view.status,
        updated_at=max(datetime.now(UTC), previous.updated_at),
        draft_pr_url=draft_pr_url,
        artifact_count=artifact_count,
    )


def _replace_run_summary(previous: RemediationRunSummaryV1, **updates: object) -> RemediationRunSummaryV1:
    return RemediationRunSummaryV1.model_validate({**previous.model_dump(), **updates})


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
