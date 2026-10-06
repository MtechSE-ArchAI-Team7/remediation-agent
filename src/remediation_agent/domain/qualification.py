"""Bounded release evidence from isolated full-workflow trials, never native deliveries."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from remediation_agent.domain.models import IdentifierStr, StrictModel


class QualificationTrialV1(StrictModel):
    run_id: IdentifierStr
    status: str
    locally_verified: bool
    evidence_persisted: bool
    cleanup_verified: bool
    publication_verified: bool
    candidate_digest: str
    commit_sha: str
    assertions_digests: list[str] = Field(min_length=1, max_length=50)


class ReleaseQualificationV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    case: Literal["ah54", "ah56"]
    backend: Literal["docker", "code-interpreter"]
    remote_writes: Literal["simulated"] = "simulated"
    approvals: Literal["isolated-test-only"] = "isolated-test-only"
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    runtime_configuration_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str
    assets_digest: str
    model_configuration_digest: str
    prompt_version: str
    snapshot_digest: str
    qualified_at: datetime
    trials: list[QualificationTrialV1] = Field(min_length=1, max_length=3)


def require_release_qualification(
    report: ReleaseQualificationV1, *, source: str, image: str, runtime_configuration: str
) -> None:
    if (
        report.source_revision != source
        or report.image_digest != image
        or report.runtime_configuration_digest != runtime_configuration
        or report.backend != "code-interpreter"
        or len(report.trials) != 3
        or len({trial.run_id for trial in report.trials}) != 3
        or len({tuple(trial.assertions_digests) for trial in report.trials}) != 1
        or any(
            trial.status != "DRAFT_PR_CREATED"
            or not all(
                (trial.locally_verified, trial.evidence_persisted, trial.cleanup_verified, trial.publication_verified)
            )
            or not trial.candidate_digest.startswith("sha256:")
            or len(trial.commit_sha) != 40
            for trial in report.trials
        )
    ):
        raise ValueError("RELEASE_QUALIFICATION_MISMATCH")
