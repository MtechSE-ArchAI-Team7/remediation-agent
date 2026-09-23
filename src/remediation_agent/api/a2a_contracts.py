"""Strict A2A Protocol 1.0 media types and bounded transport contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from remediation_agent.domain.enums import FinalStatus
from remediation_agent.domain.models import NonEmptyStr, StrictModel

DIAGNOSIS_HANDOFF_MEDIA_TYPE = "application/vnd.aios.diagnosis-handoff.v1+json"
APPROVAL_DECISION_MEDIA_TYPE = "application/vnd.aios.approval-decision.v1+json"
APPROVAL_REQUEST_MEDIA_TYPE = "application/vnd.aios.approval-request.v1+json"
REMEDIATION_HANDOFF_MEDIA_TYPE = "application/vnd.aios.remediation-handoff.v1+json"
EXPLAINABILITY_TRACE_MEDIA_TYPE = "application/vnd.aios.explainability-trace.v1+json"
DELIVERY_RECEIPT_MEDIA_TYPE = "application/vnd.aios.delivery-receipt.v1+json"
PROVIDER_PROBE_REQUEST_MEDIA_TYPE = "application/vnd.aios.provider-probe-request.v1+json"
PROVIDER_PROBE_RESULT_MEDIA_TYPE = "application/vnd.aios.provider-probe-result.v1+json"
ARTIFACT_PREVIEW_REQUEST_MEDIA_TYPE = "application/vnd.aios.artifact-preview-request.v1+json"
ARTIFACT_PREVIEW_RESULT_MEDIA_TYPE = "application/vnd.aios.artifact-preview-result.v1+json"
RUN_SUMMARY_METADATA_KEY = "aios_run"
_CANONICAL_UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


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


class ArtifactPreviewRequestV1(StrictModel):
    """Select one artifact by run-bound manifest identity, never by object path."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: NonEmptyStr
    artifact_name: str = Field(min_length=1, max_length=255)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ArtifactPreviewResultV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: NonEmptyStr
    name: NonEmptyStr
    media_type: NonEmptyStr
    digest: NonEmptyStr
    content: str
    size_bytes: int = Field(ge=0)
    truncated: bool
    digest_verified: Literal[True] = True


class RemediationRunSummaryV1(StrictModel):
    """Public-demo run locator and bounded presentation summary."""

    schema_version: Literal["1.0"] = "1.0"
    task_id: str = Field(pattern=_CANONICAL_UUID)
    session_id: str = Field(pattern=_CANONICAL_UUID)
    case_id: str | None = Field(default=None, max_length=200)
    jira_ticket_id: str | None = Field(default=None, max_length=64)
    repository: str | None = Field(default=None, max_length=500)
    status: FinalStatus
    created_at: datetime
    updated_at: datetime
    draft_pr_url: str | None = Field(default=None, max_length=2_048)
    artifact_count: int = Field(default=0, ge=0)
    stale: Literal[False] = False

    @model_validator(mode="after")
    def update_cannot_predate_creation(self) -> RemediationRunSummaryV1:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot predate created_at")
        return self


SUPPORTED_INPUT_MEDIA_TYPES = frozenset(
    {
        DIAGNOSIS_HANDOFF_MEDIA_TYPE,
        APPROVAL_DECISION_MEDIA_TYPE,
        PROVIDER_PROBE_REQUEST_MEDIA_TYPE,
        ARTIFACT_PREVIEW_REQUEST_MEDIA_TYPE,
    }
)
