"""Advisory long-term incident memory adapters."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol, cast

from bedrock_agentcore.memory import MemoryClient
from pydantic import Field

from remediation_agent.adapters.evidence import SecretRedactor
from remediation_agent.domain.enums import MemoryRetrievalStatus, MemoryWriteStatus
from remediation_agent.domain.models import (
    IncidentMemoryMatchV1,
    IncidentMemoryRecordV1,
    IncidentMemoryRetrievalV1,
    IncidentMemoryWriteReceiptV1,
    StrictModel,
)
from remediation_agent.ports.models import IncidentMemoryRetrievalRequest, IncidentMemoryStoreRequest

_MIN_SCORE = 0.70
_MAX_AGE_DAYS = 30.0
_MAX_MATCHES = 3
_MAX_CONTEXT_BYTES = 8_192
_TIMEOUT_SECONDS = 5.0
_NAMESPACE = re.compile(r"^/[A-Za-z0-9._/-]+/$")


class _DataPlane(Protocol):
    def retrieve_memory_records(self, **kwargs: object) -> Mapping[str, object]: ...

    def batch_create_memory_records(self, **kwargs: object) -> Mapping[str, object]: ...


class _MemoryContent(StrictModel):
    text: str = Field(min_length=1, max_length=65_536)


class _RetrievedRecord(StrictModel):
    memoryRecordId: str = Field(min_length=1, max_length=200)
    content: _MemoryContent
    memoryStrategyId: str = Field(min_length=1, max_length=200)
    namespaces: list[str] = Field(min_length=1, max_length=10)
    createdAt: datetime
    score: float = Field(ge=0.0, le=1.0)
    metadata: dict[str, object] = Field(default_factory=dict)


class _RetrieveResponse(StrictModel):
    memoryRecordSummaries: list[_RetrievedRecord] = Field(default_factory=list)
    nextToken: str | None = None
    ResponseMetadata: dict[str, object] | None = None  # noqa: N815 - AWS response field


class _CreatedRecord(StrictModel):
    memoryRecordId: str | None = None
    status: str = Field(min_length=1, max_length=100)
    requestIdentifier: str | None = Field(default=None, max_length=200)
    errorCode: int | None = None
    errorMessage: str | None = Field(default=None, max_length=1_000)


class _BatchCreateResponse(StrictModel):
    successfulRecords: list[_CreatedRecord] = Field(default_factory=list)
    failedRecords: list[_CreatedRecord] = Field(default_factory=list)
    ResponseMetadata: dict[str, object] | None = None  # noqa: N815 - AWS response field


class DisabledIncidentMemory:
    """Null adapter used by the safe default configuration."""

    async def retrieve(self, request: IncidentMemoryRetrievalRequest) -> IncidentMemoryRetrievalV1:
        return IncidentMemoryRetrievalV1(
            status=MemoryRetrievalStatus.DISABLED,
            query_digest=_query_digest(request),
            duration_ms=0,
        )

    async def store(self, request: IncidentMemoryStoreRequest) -> IncidentMemoryWriteReceiptV1:
        return IncidentMemoryWriteReceiptV1(
            status=MemoryWriteStatus.NOT_ELIGIBLE,
            incident_id=request.record.incident_id,
            duration_ms=0,
        )


class AgentCoreIncidentMemory:
    """AgentCore semantic memory with host-owned scope and strict admission filtering."""

    def __init__(
        self,
        *,
        memory_id: str,
        strategy_id: str,
        namespace: str,
        region_name: str,
        timeout_seconds: float = _TIMEOUT_SECONDS,
        data_plane: _DataPlane | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.memory_id = _identifier(memory_id, "memory ID")
        self.strategy_id = _identifier(strategy_id, "strategy ID")
        self.namespace = _safe_namespace(namespace)
        self.timeout_seconds = timeout_seconds
        self.redactor = redactor or SecretRedactor()
        if data_plane is None:
            sdk = MemoryClient(region_name=region_name, integration_source="aios-remediation")
            data_plane = cast(_DataPlane, sdk.gmdp_client)
        self._data_plane = data_plane

    async def retrieve(self, request: IncidentMemoryRetrievalRequest) -> IncidentMemoryRetrievalV1:
        started = time.monotonic()
        digest = _query_digest(request)
        namespace = self.namespace_for(request.repository)
        query = self.redactor.redact(
            f"repository={request.repository}\nremediation_type={request.remediation_type}\n"
            f"issue={request.issue_summary}\ndiagnosis={request.diagnosis_summary}"
        )[:8_192]
        try:
            raw = await asyncio.wait_for(
                asyncio.to_thread(
                    self._data_plane.retrieve_memory_records,
                    memoryId=self.memory_id,
                    namespace=namespace,
                    searchCriteria={
                        "searchQuery": query,
                        "memoryStrategyId": self.strategy_id,
                        "topK": _MAX_MATCHES,
                    },
                    maxResults=_MAX_MATCHES,
                ),
                timeout=self.timeout_seconds,
            )
            response = _RetrieveResponse.model_validate(raw)
            matches = self._accepted_matches(response, request, namespace)
            return IncidentMemoryRetrievalV1(
                status=MemoryRetrievalStatus.RETRIEVED if matches else MemoryRetrievalStatus.NO_MATCH,
                query_digest=digest,
                matches=matches,
                duration_ms=_elapsed_ms(started),
            )
        except TimeoutError:
            code = "MEMORY_RETRIEVAL_TIMEOUT"
        except Exception as exc:  # noqa: BLE001 - provider failures are normalized and fail open
            code = f"MEMORY_RETRIEVAL_{type(exc).__name__.upper()}"[:200]
        return IncidentMemoryRetrievalV1(
            status=MemoryRetrievalStatus.ERROR,
            query_digest=digest,
            duration_ms=_elapsed_ms(started),
            error_code=code,
        )

    async def store(self, request: IncidentMemoryStoreRequest) -> IncidentMemoryWriteReceiptV1:
        started = time.monotonic()
        record = request.record
        namespace = self.namespace_for(record.repository)
        body = record.model_dump_json()
        if self.redactor.redact(body) != body:
            return IncidentMemoryWriteReceiptV1(
                status=MemoryWriteStatus.ERROR,
                incident_id=record.incident_id,
                duration_ms=_elapsed_ms(started),
                error_code="MEMORY_SECRET_CONTENT_REJECTED",
            )
        try:
            raw = await asyncio.wait_for(
                asyncio.to_thread(
                    self._data_plane.batch_create_memory_records,
                    memoryId=self.memory_id,
                    clientToken=request.idempotency_token,
                    records=[
                        {
                            "requestIdentifier": record.incident_id,
                            "namespaces": [namespace],
                            "content": {"text": body},
                            "timestamp": record.created_at,
                            "memoryStrategyId": self.strategy_id,
                            "metadata": {
                                "repository": {"stringValue": record.repository},
                                "admissionType": {"stringValue": record.admission_type.value},
                                "schemaVersion": {"stringValue": record.schema_version},
                            },
                        }
                    ],
                ),
                timeout=self.timeout_seconds,
            )
            response = _BatchCreateResponse.model_validate(raw)
            if response.successfulRecords:
                status_text = response.successfulRecords[0].status.upper()
                status = (
                    MemoryWriteStatus.ALREADY_EXISTS
                    if "EXIST" in status_text or "DUPLICATE" in status_text
                    else MemoryWriteStatus.STORED
                )
                return IncidentMemoryWriteReceiptV1(
                    status=status,
                    incident_id=record.incident_id,
                    duration_ms=_elapsed_ms(started),
                )
            code = (
                str(response.failedRecords[0].errorCode)
                if response.failedRecords and response.failedRecords[0].errorCode is not None
                else "MEMORY_WRITE_FAILED"
            )
        except TimeoutError:
            code = "MEMORY_WRITE_TIMEOUT"
        except Exception as exc:  # noqa: BLE001 - storage failure is observable but non-gating
            code = f"MEMORY_WRITE_{type(exc).__name__.upper()}"[:200]
        return IncidentMemoryWriteReceiptV1(
            status=MemoryWriteStatus.ERROR,
            incident_id=record.incident_id,
            duration_ms=_elapsed_ms(started),
            error_code=code,
        )

    def namespace_for(self, repository: str) -> str:
        slug = repository.lower().replace("/", "-")
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,199}", slug) is None:
            raise ValueError("repository slug is unsafe for incident-memory namespace")
        return f"{self.namespace}{slug}/"

    def _accepted_matches(
        self,
        response: _RetrieveResponse,
        request: IncidentMemoryRetrievalRequest,
        namespace: str,
    ) -> list[IncidentMemoryMatchV1]:
        now = request.requested_at.astimezone(UTC)
        accepted: list[IncidentMemoryMatchV1] = []
        context_bytes = 0
        for item in sorted(response.memoryRecordSummaries, key=lambda candidate: candidate.score, reverse=True):
            created_at = item.createdAt.astimezone(UTC)
            age_days = max(0.0, (now - created_at).total_seconds() / 86_400)
            text = item.content.text
            if (
                item.memoryStrategyId != self.strategy_id
                or namespace not in item.namespaces
                or item.score < _MIN_SCORE
                or age_days > _MAX_AGE_DAYS
                or self.redactor.redact(text) != text
            ):
                continue
            size = len(text.encode("utf-8"))
            if size + context_bytes > _MAX_CONTEXT_BYTES:
                continue
            try:
                record = IncidentMemoryRecordV1.model_validate_json(text)
            except ValueError:
                continue
            if record.repository != request.repository:
                continue
            context_bytes += size
            accepted.append(
                IncidentMemoryMatchV1(
                    incident_id=record.incident_id,
                    admission_type=record.admission_type,
                    score=item.score,
                    age_days=round(age_days, 3),
                    repository=record.repository,
                    incident_signature=record.incident_signature,
                    root_cause=record.root_cause,
                    remediation_summary=record.remediation_summary,
                    changed_paths=record.changed_paths,
                    validation=record.validation,
                    rollback_summary=record.rollback_summary,
                    residual_risks=record.residual_risks,
                )
            )
            if len(accepted) == _MAX_MATCHES:
                break
        return accepted


def _safe_namespace(value: str) -> str:
    value = value.strip()
    if _NAMESPACE.fullmatch(value) is None or ".." in value or "//" in value:
        raise ValueError("incident-memory namespace must be a safe absolute namespace ending in /")
    return value


def _identifier(value: str, name: str) -> str:
    value = value.strip()
    if not value or len(value) > 200 or re.fullmatch(r"[A-Za-z0-9._:-]+", value) is None:
        raise ValueError(f"{name} is invalid")
    return value


def _query_digest(request: IncidentMemoryRetrievalRequest) -> str:
    canonical = json.dumps(request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1_000))
