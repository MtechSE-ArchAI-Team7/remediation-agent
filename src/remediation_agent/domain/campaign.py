"""Operator-owned evaluation contracts, separate from runtime handoff authority."""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, model_validator

from remediation_agent.domain.models import DiagnosisHandoffV1, StrictModel

CampaignId = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Money = Annotated[Decimal, Field(ge=0, allow_inf_nan=False)]


class CampaignPriceV1(StrictModel):
    provider: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=200)
    observed_at: AwareDatetime
    source: str = Field(min_length=1, max_length=500)
    input_per_million_usd: Money
    output_per_million_usd: Money

    def cost(self, input_tokens: int, output_tokens: int) -> Decimal:
        if min(input_tokens, output_tokens) < 0:
            raise ValueError("NEGATIVE_TOKEN_COUNT")
        return (self.input_per_million_usd * input_tokens + self.output_per_million_usd * output_tokens) / Decimal(
            1_000_000
        )


class CampaignCaseV1(StrictModel):
    case_id: CampaignId
    category: Literal["code", "configuration", "unsafe", "unsupported", "approval", "attack"]
    language: Literal["javascript", "python", "json", "none"]
    repetitions: int = Field(ge=1, le=10)
    handoff: DiagnosisHandoffV1
    expected_statuses: list[str] = Field(min_length=1, max_length=5)
    fixture_digest: Digest
    require_draft: bool = False
    attack_family: Literal["goal_hijack", "leakage", "extraction", "malformed_output", "execution"] | None = None
    attack_surface: Literal["diagnosis", "repository", "tool", "memory"] | None = None

    @model_validator(mode="after")
    def attack_is_explicit(self) -> CampaignCaseV1:
        if (self.category == "attack") != (self.attack_family is not None and self.attack_surface is not None):
            raise ValueError("ATTACK_CLASSIFICATION_REQUIRED")
        if self.category != "attack" and (self.attack_family is not None or self.attack_surface is not None):
            raise ValueError("UNEXPECTED_ATTACK_CLASSIFICATION")
        if self.category in {"unsafe", "unsupported", "approval", "attack"} and self.require_draft:
            raise ValueError("NEGATIVE_CASE_CANNOT_REQUIRE_PUBLICATION")
        return self


class CampaignManifestV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    campaign_id: CampaignId
    execution_mode: Literal["live_model_isolated", "simulated"] = "live_model_isolated"
    publication_mode: Literal["disabled", "real_draft"] = "disabled"
    created_at: AwareDatetime
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    runtime_version: str = Field(pattern=r"^[1-9][0-9]{0,4}$")
    image_digest: Digest
    implementation_digest: Digest | None = None
    policy_digest: Digest
    prompt_version: str = Field(min_length=1, max_length=200)
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    price: CampaignPriceV1
    model_budget_usd: Money = Decimal("50")
    # Total upper bounds, including all correction/revision calls and transport retries.
    max_input_tokens_per_trial: int = Field(gt=0, le=10_000_000)
    max_output_tokens_per_trial: int = Field(gt=0, le=1_000_000)
    trial_timeout_seconds: int = Field(default=840, ge=1, le=3600)
    cases: list[CampaignCaseV1] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def sources_are_bound(self) -> CampaignManifestV1:
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("DUPLICATE_CASE_ID")
        if self.repository.split("/")[-1] == "aios-remediation-demo" or (
            self.publication_mode == "real_draft" and self.repository.split("/")[-1] == "buggy-ecommerce-demo"
        ):
            raise ValueError("READ_ONLY_REFERENCE_IS_NOT_CAMPAIGN_TARGET")
        expected = f"https://github.com/{self.repository}"
        for case in self.cases:
            if case.require_draft and self.publication_mode != "real_draft":
                raise ValueError("PUBLICATION_DISABLED")
            if case.handoff.repository.url.removesuffix(".git") != expected:
                raise ValueError("CAMPAIGN_REPOSITORY_MISMATCH")
            if not case.handoff.repository.commit_sha or len(case.handoff.repository.commit_sha) != 40:
                raise ValueError("FULL_IMMUTABLE_COMMIT_REQUIRED")
        if self.model_budget_usd <= 0 or self.reservation_usd <= 0:
            raise ValueError("POSITIVE_BUDGET_AND_PRICE_REQUIRED")
        return self

    @property
    def reservation_usd(self) -> Decimal:
        return self.price.cost(self.max_input_tokens_per_trial, self.max_output_tokens_per_trial)


class CampaignObservationV1(StrictModel):
    """Measured outcome. Unknown usage and unevaluated controls remain unknown."""

    status: str = Field(min_length=1, max_length=100)
    failure_code: str | None = Field(default=None, pattern=r"^[A-Z0-9_]{1,100}$")
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    usage_complete: bool = False
    model_latency_ms: int | None = Field(default=None, ge=0)
    remediation_latency_ms: int = Field(ge=0)
    cleanup_verified: bool = False
    publication_verified: bool = False
    controls_verified: bool = False
    canary_leaked: bool | None = None
    evidence_digests: list[Digest] = Field(default_factory=list, max_length=200)


class CampaignTrialV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    campaign_id: CampaignId
    manifest_digest: Digest
    case_id: CampaignId
    trial_number: int = Field(ge=1, le=10)
    run_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    state: Literal["STARTED", "FINISHED", "BUDGET_STOPPED"]
    reserved_usd: Money
    charged_usd: Money
    estimated_cost_usd: Money | None = None
    observation: CampaignObservationV1 | None = None

    @model_validator(mode="after")
    def terminal_shape(self) -> CampaignTrialV1:
        if (self.state == "FINISHED") != (self.observation is not None):
            raise ValueError("TRIAL_OBSERVATION_MISMATCH")
        if (self.state == "STARTED") != (self.finished_at is None):
            raise ValueError("TRIAL_FINISH_TIME_MISMATCH")
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("TRIAL_CLOCK_REVERSED")
        return self


class CampaignCaseResultV1(StrictModel):
    case_id: CampaignId
    planned: int = Field(ge=0)
    attempted: int = Field(ge=0)
    completed: int = Field(ge=0)
    successful: int = Field(ge=0)
    uncertain: int = Field(ge=0)
    budget_stopped: int = Field(ge=0)
    failures: dict[str, int]
    success_interval_95: tuple[float, float] | None = None
    median_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


class CampaignResultV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    campaign_id: CampaignId
    manifest_digest: Digest
    cases: list[CampaignCaseResultV1]
    charged_usd: Money
    estimated_cost_usd: Money | None
    complete: bool
    cloud_costs: Literal["NOT_MEASURED"] = "NOT_MEASURED"
