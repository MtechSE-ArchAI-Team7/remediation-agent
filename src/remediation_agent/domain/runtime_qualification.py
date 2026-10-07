"""Fixed-fixture hosted filesystem qualification; no remediation approval authority."""

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from remediation_agent.domain.models import (
    ArtifactManifest,
    BehavioralEvidence,
    ReleaseProvenanceV1,
    StrictModel,
    ValidationDiagnostic,
    ValidationStorageEvidence,
)

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class RuntimeQualificationRequestV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    operation: Literal["prepare", "resume"]
    fixture: Literal["ah54", "ah56"]
    qualification_id: str = Field(pattern=_UUID)
    receipt_digest: str | None = Field(default=None, pattern=_DIGEST)

    @model_validator(mode="after")
    def require_receipt_on_resume(self) -> "RuntimeQualificationRequestV1":
        if (self.operation == "resume") != (self.receipt_digest is not None):
            raise ValueError("Only resume requires a prepared receipt digest")
        return self


class RuntimeQualificationResultV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    qualification_id: str = Field(pattern=_UUID)
    fixture: Literal["ah54", "ah56"]
    status: Literal["PREPARED", "PASSED", "FAILED"]
    release: ReleaseProvenanceV1
    policy_digest: str = Field(pattern=_DIGEST)
    asset_digest: str = Field(pattern=_DIGEST)
    fixture_digest: str = Field(pattern=_DIGEST)
    candidate_digest: str = Field(pattern=_DIGEST)
    receipt_digest: str = Field(pattern=_DIGEST)
    process_restarted: bool = False
    git_integrity_verified: bool = False
    cleanup_verified: bool = False
    managed_filesystem: bool
    completed_at: datetime
    evidence: BehavioralEvidence | None = None
    storage: ValidationStorageEvidence | None = None
    failures: list[ValidationDiagnostic] = Field(default_factory=list, max_length=20)
    artifact_manifest: ArtifactManifest | None = None
