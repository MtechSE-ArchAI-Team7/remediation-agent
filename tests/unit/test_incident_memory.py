from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from remediation_agent.adapters.incident_memory import AgentCoreIncidentMemory, DisabledIncidentMemory
from remediation_agent.domain.enums import (
    MemoryAdmissionType,
    MemoryRetrievalStatus,
    MemoryWriteStatus,
    ValidationOutcome,
)
from remediation_agent.domain.models import IncidentMemoryRecordV1, IncidentValidationSummary
from remediation_agent.ports.models import IncidentMemoryRetrievalRequest, IncidentMemoryStoreRequest


class FakeDataPlane:
    def __init__(self, retrieve: dict[str, object] | None = None, create: dict[str, object] | None = None) -> None:
        self.retrieve_response = retrieve or {"memoryRecordSummaries": []}
        self.create_response = create or {
            "successfulRecords": [{"memoryRecordId": "record-1", "status": "CREATED", "requestIdentifier": "x"}],
            "failedRecords": [],
        }
        self.retrieve_calls: list[dict[str, object]] = []
        self.create_calls: list[dict[str, object]] = []

    def retrieve_memory_records(self, **kwargs: object) -> dict[str, object]:
        self.retrieve_calls.append(kwargs)
        return self.retrieve_response

    def batch_create_memory_records(self, **kwargs: object) -> dict[str, object]:
        self.create_calls.append(kwargs)
        return self.create_response


def request(now: datetime) -> IncidentMemoryRetrievalRequest:
    return IncidentMemoryRetrievalRequest(
        repository="MtechSE-ArchAI-Team7/buggy-ecommerce-demo",
        remediation_type="CODE",
        issue_summary="Average calculation fails.",
        diagnosis_summary="A zero divisor is possible.",
        requested_at=now,
    )


def record(now: datetime, *, signature: str = "Average calculation fails.") -> IncidentMemoryRecordV1:
    return IncidentMemoryRecordV1(
        incident_id="incident-1",
        repository="MtechSE-ArchAI-Team7/buggy-ecommerce-demo",
        source_commit="a" * 40,
        incident_signature=signature,
        root_cause="A zero divisor is possible.",
        remediation_summary="Guard the empty collection.",
        changed_paths=["server.js"],
        validation=[IncidentValidationSummary(task_name="average_regression", outcome=ValidationOutcome.PASSED)],
        rollback_summary="Revert the patch.",
        policy_version="1",
        prompt_version="1",
        model_provider="fake",
        model_name="scripted",
        evidence_ids=["evidence-1"],
        evidence_digests=["sha256:evidence"],
        admission_type=MemoryAdmissionType.EVALUATION_SEED,
        created_at=now,
    )


def adapter(data_plane: FakeDataPlane) -> AgentCoreIncidentMemory:
    return AgentCoreIncidentMemory(
        memory_id="memory-1",
        strategy_id="strategy-1",
        namespace="/aios/incidents/",
        region_name="ap-southeast-1",
        data_plane=data_plane,
    )


@pytest.mark.asyncio
async def test_retrieval_filters_score_age_namespace_strategy_and_context() -> None:
    now = datetime.now(UTC)
    safe = record(now - timedelta(days=2))
    summaries = [
        {
            "memoryRecordId": "accepted",
            "content": {"text": safe.model_dump_json()},
            "memoryStrategyId": "strategy-1",
            "namespaces": ["/aios/incidents/mtechse-archai-team7-buggy-ecommerce-demo/"],
            "createdAt": safe.created_at,
            "score": 0.91,
        },
        {
            "memoryRecordId": "low-score",
            "content": {"text": safe.model_dump_json()},
            "memoryStrategyId": "strategy-1",
            "namespaces": ["/aios/incidents/mtechse-archai-team7-buggy-ecommerce-demo/"],
            "createdAt": safe.created_at,
            "score": 0.69,
        },
        {
            "memoryRecordId": "stale",
            "content": {"text": record(now - timedelta(days=31)).model_dump_json()},
            "memoryStrategyId": "strategy-1",
            "namespaces": ["/aios/incidents/mtechse-archai-team7-buggy-ecommerce-demo/"],
            "createdAt": now - timedelta(days=31),
            "score": 0.99,
        },
    ]
    result = await adapter(FakeDataPlane({"memoryRecordSummaries": summaries})).retrieve(request(now))

    assert result.status is MemoryRetrievalStatus.RETRIEVED
    assert [item.incident_id for item in result.matches] == ["incident-1"]
    assert result.matches[0].age_days == pytest.approx(2.0)


@pytest.mark.asyncio
async def test_secret_bearing_retrieval_is_rejected_and_empty_is_no_match() -> None:
    now = datetime.now(UTC)
    unsafe = record(now, signature="api_key=super-secret-value")
    result = await adapter(
        FakeDataPlane(
            {
                "memoryRecordSummaries": [
                    {
                        "memoryRecordId": "unsafe",
                        "content": {"text": unsafe.model_dump_json()},
                        "memoryStrategyId": "strategy-1",
                        "namespaces": ["/aios/incidents/mtechse-archai-team7-buggy-ecommerce-demo/"],
                        "createdAt": now,
                        "score": 0.99,
                    }
                ]
            }
        )
    ).retrieve(request(now))

    assert result.status is MemoryRetrievalStatus.NO_MATCH
    assert result.matches == []


@pytest.mark.asyncio
async def test_store_uses_host_scope_and_idempotency_token() -> None:
    now = datetime.now(UTC)
    provider = FakeDataPlane()
    result = await adapter(provider).store(IncidentMemoryStoreRequest(record=record(now), idempotency_token="a" * 64))

    assert result.status is MemoryWriteStatus.STORED
    assert provider.create_calls[0]["memoryId"] == "memory-1"
    assert provider.create_calls[0]["clientToken"] == "a" * 64
    records = provider.create_calls[0]["records"]
    assert isinstance(records, list)
    assert records[0]["namespaces"] == ["/aios/incidents/mtechse-archai-team7-buggy-ecommerce-demo/"]


@pytest.mark.asyncio
async def test_disabled_memory_is_explicit() -> None:
    now = datetime.now(UTC)
    disabled = DisabledIncidentMemory()
    retrieval = await disabled.retrieve(request(now))
    write = await disabled.store(IncidentMemoryStoreRequest(record=record(now), idempotency_token="b" * 64))

    assert retrieval.status is MemoryRetrievalStatus.DISABLED
    assert write.status is MemoryWriteStatus.NOT_ELIGIBLE


@pytest.mark.parametrize("namespace", ["relative/", "/unsafe/../scope/", "/unsafe//scope/"])
def test_unsafe_namespace_is_rejected(namespace: str) -> None:
    with pytest.raises(ValueError, match="namespace"):
        AgentCoreIncidentMemory(
            memory_id="memory-1",
            strategy_id="strategy-1",
            namespace=namespace,
            region_name="ap-southeast-1",
            data_plane=FakeDataPlane(),
        )
