"""Strict A2A Protocol 1.0 media types and bounded transport contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from remediation_agent.domain.models import NonEmptyStr, StrictModel

DIAGNOSIS_HANDOFF_MEDIA_TYPE = "application/vnd.aios.diagnosis-handoff.v1+json"
APPROVAL_DECISION_MEDIA_TYPE = "application/vnd.aios.approval-decision.v1+json"
APPROVAL_REQUEST_MEDIA_TYPE = "application/vnd.aios.approval-request.v1+json"
REMEDIATION_HANDOFF_MEDIA_TYPE = "application/vnd.aios.remediation-handoff.v1+json"
EXPLAINABILITY_TRACE_MEDIA_TYPE = "application/vnd.aios.explainability-trace.v1+json"
DELIVERY_RECEIPT_MEDIA_TYPE = "application/vnd.aios.delivery-receipt.v1+json"
PROVIDER_PROBE_REQUEST_MEDIA_TYPE = "application/vnd.aios.provider-probe-request.v1+json"
PROVIDER_PROBE_RESULT_MEDIA_TYPE = "application/vnd.aios.provider-probe-result.v1+json"


class ProviderProbeRequestV1(StrictModel):
    """Fixed provider readiness request used by the release smoke check."""

    schema_version: Literal["1.0"] = "1.0"
    probe: Literal["bedrock", "openai"]


class ProviderProbeModelResult(StrictModel):
    status: Literal["ok"]


class ProviderProbeResultV1(StrictModel):
    """Bounded provider response without prompt or credential material."""

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["ok"]
    provider: NonEmptyStr
    model: NonEmptyStr
    duration_ms: int = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    response_digest: NonEmptyStr


SUPPORTED_INPUT_MEDIA_TYPES = frozenset(
    {
        DIAGNOSIS_HANDOFF_MEDIA_TYPE,
        APPROVAL_DECISION_MEDIA_TYPE,
        PROVIDER_PROBE_REQUEST_MEDIA_TYPE,
    }
)
