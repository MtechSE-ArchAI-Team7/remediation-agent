"""Service-level tests for shared REST/A2A downstream delivery coordination."""

from __future__ import annotations

from datetime import UTC, datetime

from remediation_agent.domain.models import DownstreamDeliveryReceiptV1
from remediation_agent.ports.models import HandoffDeliveryRequest
from tests.conftest import build_test_service, diagnosis_handoff, scripted_responses


class _Delivery:
    def __init__(self, *, succeeds: bool = True) -> None:
        self.succeeds = succeeds
        self.requests: list[HandoffDeliveryRequest] = []

    async def deliver(self, request: HandoffDeliveryRequest) -> DownstreamDeliveryReceiptV1:
        self.requests.append(request)
        return DownstreamDeliveryReceiptV1(
            delivery_id=request.delivery_id,
            message_id=request.message_id,
            attempted=True,
            succeeded=self.succeeds,
            attempted_at=datetime.now(UTC),
            request_digest=request.request_digest,
            error_code=None if self.succeeds else "DOWNSTREAM_TIMEOUT",
        )


async def test_successful_outcome_delivers_once_and_persists_receipt() -> None:
    delivery = _Delivery()
    service, *_ = build_test_service(
        scripted_responses(),
        handoff_delivery=delivery,
        github_writes_enabled=True,
        github_repository="MtechSE-ArchAI-Team7/example-service",
    )

    _[3].create = True
    view = await service.start(diagnosis_handoff())
    fetched = await service.get(view.run_id)

    assert view.downstream_delivery is not None
    assert view.downstream_delivery.succeeded is True
    assert fetched.downstream_delivery == view.downstream_delivery
    assert len(delivery.requests) == 1
    assert delivery.requests[0].handoff == view.result


async def test_delivery_failure_is_separate_from_remediation_status() -> None:
    delivery = _Delivery(succeeds=False)
    service, *_ = build_test_service(
        scripted_responses(),
        handoff_delivery=delivery,
        github_writes_enabled=True,
        github_repository="MtechSE-ArchAI-Team7/example-service",
    )

    _[3].create = True
    view = await service.start(diagnosis_handoff())

    assert view.result is not None
    assert view.status == view.result.final_status
    assert view.downstream_delivery is not None
    assert view.downstream_delivery.succeeded is False
    assert view.downstream_delivery.error_code == "DOWNSTREAM_TIMEOUT"
