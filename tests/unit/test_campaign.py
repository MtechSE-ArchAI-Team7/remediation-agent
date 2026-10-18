"""Campaign restart, budget, denominator and storage-fault contracts."""

import asyncio
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from remediation_agent.adapters.campaign import LocalCampaignStore
from remediation_agent.campaign import run_campaign, summarize_campaign
from remediation_agent.domain.campaign import (
    CampaignCaseV1,
    CampaignManifestV1,
    CampaignObservationV1,
    CampaignPriceV1,
    CampaignTrialV1,
)
from tests.conftest import diagnosis_handoff

NOW = datetime(2026, 10, 18, tzinfo=UTC)


def manifest(*, budget: str = "50", repetitions: int = 5) -> CampaignManifestV1:
    handoff = diagnosis_handoff()
    handoff = handoff.model_copy(
        update={
            "repository": handoff.repository.model_copy(
                update={
                    "url": "https://github.com/operator/controlled.git",
                    "commit_sha": "a" * 40,
                }
            )
        }
    )
    return CampaignManifestV1(
        campaign_id="closure-v1",
        publication_mode="real_draft",
        created_at=NOW,
        source_revision="b" * 40,
        runtime_version="63",
        image_digest="sha256:" + "c" * 64,
        policy_digest="sha256:" + "d" * 64,
        prompt_version="fixture",
        repository="operator/controlled",
        price=CampaignPriceV1(
            provider="fixture",
            model="fixture",
            observed_at=NOW,
            source="fixture price table",
            input_per_million_usd=Decimal("1"),
            output_per_million_usd=Decimal("2"),
        ),
        model_budget_usd=Decimal(budget),
        max_input_tokens_per_trial=1_000_000,
        max_output_tokens_per_trial=100_000,
        cases=[
            CampaignCaseV1(
                case_id="code",
                category="code",
                language="python",
                repetitions=repetitions,
                handoff=handoff,
                expected_statuses=["DRAFT_PR_CREATED"],
                fixture_digest="sha256:" + "e" * 64,
                require_draft=True,
            )
        ],
    )


class Executor:
    def __init__(self, fault: str | None = None) -> None:
        self.calls: list[str] = []
        self.fault = fault

    async def execute(self, case: CampaignCaseV1, run_id: str) -> CampaignObservationV1:
        self.calls.append(run_id)
        if self.fault == "cancel":
            raise asyncio.CancelledError
        if self.fault == "timeout":
            raise TimeoutError("provider-secret-must-not-be-recorded")
        if self.fault == "error":
            raise RuntimeError("provider-secret-must-not-be-recorded")
        return CampaignObservationV1(
            status="DRAFT_PR_CREATED",
            cleanup_verified=True,
            publication_verified=True,
            controls_verified=self.fault != "control",
            canary_leaked=False,
            remediation_latency_ms=100,
            input_tokens=None if self.fault == "usage" else 100,
            output_tokens=None if self.fault == "usage" else 50,
            usage_complete=self.fault != "usage",
        )


async def test_all_denominators_and_durable_resume(tmp_path: Path) -> None:
    cfg, executor = manifest(), Executor()
    with LocalCampaignStore(tmp_path, cfg) as store:
        result = await run_campaign(cfg, store, executor, clock=lambda: NOW)
        assert result.complete
        row = result.cases[0]
        assert (row.planned, row.attempted, row.completed, row.successful) == (5, 5, 5, 5)
        assert row.input_tokens == 500 and row.p95_latency_ms == 100
        assert row.success_interval_95 and row.success_interval_95[0] > 0.5
        assert result.estimated_cost_usd == Decimal("0.001")
        assert result.charged_usd == Decimal("0.001")
    with LocalCampaignStore(tmp_path, cfg) as store:
        assert await run_campaign(cfg, store, executor, clock=lambda: NOW) == result
    assert len(executor.calls) == len(set(executor.calls)) == 5
    assert len(list(tmp_path.glob("*.started.json"))) == 5
    assert len(list(tmp_path.glob("*.finished.json"))) == 5


async def test_budget_reserves_before_any_side_effect_and_retains_unstarted(tmp_path: Path) -> None:
    cfg, executor = manifest(budget="2"), Executor("usage")
    with LocalCampaignStore(tmp_path, cfg) as store:
        result = await run_campaign(cfg, store, executor, clock=lambda: NOW)
    assert len(executor.calls) == 1
    row = result.cases[0]
    assert (row.planned, row.attempted, row.completed, row.budget_stopped) == (5, 1, 1, 4)
    assert not result.complete and result.charged_usd <= 2


async def test_cancellation_retains_reservation_and_never_reexecutes_unknown_run(tmp_path: Path) -> None:
    cfg = manifest(budget="2")
    executor = Executor("cancel")
    with LocalCampaignStore(tmp_path, cfg) as store:
        with pytest.raises(asyncio.CancelledError):
            await run_campaign(cfg, store, executor, clock=lambda: NOW)
    resumed = Executor()
    with LocalCampaignStore(tmp_path, cfg) as store:
        result = await run_campaign(cfg, store, resumed, clock=lambda: NOW)
    assert not resumed.calls
    assert result.cases[0].uncertain == 1 and result.cases[0].budget_stopped == 4
    assert result.estimated_cost_usd is None


@pytest.mark.parametrize("fault,code", [("error", "TRIAL_EXECUTION_ERROR"), ("timeout", "TRIAL_TIMEOUT")])
async def test_failures_are_retained_without_provider_content(tmp_path: Path, fault: str, code: str) -> None:
    cfg = manifest()
    with LocalCampaignStore(tmp_path, cfg) as store:
        result = await run_campaign(cfg, store, Executor(fault), clock=lambda: NOW)
    row = result.cases[0]
    assert row.completed == 5 and row.successful == 0 and row.failures == {code: 5}
    assert row.input_tokens is None and result.estimated_cost_usd is None
    assert "provider-secret" not in "".join(p.read_text() for p in tmp_path.glob("*.json"))


async def test_unknown_usage_is_not_zero(tmp_path: Path) -> None:
    cfg = manifest()
    with LocalCampaignStore(tmp_path, cfg) as store:
        result = await run_campaign(cfg, store, Executor("usage"), clock=lambda: NOW)
    assert result.cases[0].input_tokens is None
    assert result.estimated_cost_usd is None and result.charged_usd == Decimal("6")


async def test_failed_controls_cannot_be_reported_as_success(tmp_path: Path) -> None:
    cfg = manifest()
    with LocalCampaignStore(tmp_path, cfg) as store:
        result = await run_campaign(cfg, store, Executor("control"), clock=lambda: NOW)
    assert result.cases[0].successful == 0


async def test_storage_failure_prevents_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, executor = manifest(), Executor()
    with LocalCampaignStore(tmp_path, cfg) as store:

        def fail(trial: CampaignTrialV1) -> None:
            raise OSError(28, "storage full")

        monkeypatch.setattr(store, "append", fail)
        with pytest.raises(OSError):
            await run_campaign(cfg, store, executor, clock=lambda: NOW)
    assert not executor.calls


def test_manifest_and_journal_are_exclusive_and_bound(tmp_path: Path) -> None:
    cfg = manifest()
    with LocalCampaignStore(tmp_path, cfg):
        with pytest.raises(BlockingIOError), LocalCampaignStore(tmp_path, cfg):
            pass
    changed = cfg.model_copy(update={"prompt_version": "changed"})
    with pytest.raises(ValueError, match="MANIFEST_CHANGED"), LocalCampaignStore(tmp_path, changed):
        pass
    with LocalCampaignStore(tmp_path, cfg) as store:
        with pytest.raises(ValueError, match="NOT_AUTHORIZED"):
            store.read("../escape", 1)
        (tmp_path / "code-1.finished.json").write_text("torn write")
        with pytest.raises(ValidationError):
            store.read("code", 1)


@pytest.mark.parametrize(
    "change",
    [
        {"repository": "operator/buggy-ecommerce-demo"},
        {"repository": "operator/aios-remediation-demo"},
        {"repository": "operator/different"},
        {"model_budget_usd": "0"},
        {"unknown": True},
    ],
)
def test_manifest_rejects_unsafe_targets_and_missing_budget(change: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        CampaignManifestV1.model_validate({**manifest().model_dump(), **change})


def test_manifest_rejects_duplicate_cases_unpinned_sources_and_invalid_attack() -> None:
    data = manifest().model_dump()
    data["cases"] *= 2
    with pytest.raises(ValidationError, match="DUPLICATE"):
        CampaignManifestV1.model_validate(data)
    cfg = manifest()
    broken_handoff = cfg.cases[0].handoff.model_copy(
        update={"repository": cfg.cases[0].handoff.repository.model_copy(update={"commit_sha": None})}
    )
    cfg = cfg.model_copy(update={"cases": [cfg.cases[0].model_copy(update={"handoff": broken_handoff})]})
    with pytest.raises(ValidationError, match="IMMUTABLE"):
        CampaignManifestV1.model_validate(cfg.model_dump())
    case = manifest().cases[0].model_dump()
    with pytest.raises(ValidationError, match="CLASSIFICATION"):
        CampaignCaseV1.model_validate({**case, "category": "attack"})
    with pytest.raises(ValidationError, match="CLASSIFICATION"):
        CampaignCaseV1.model_validate({**case, "attack_surface": "memory"})
    with pytest.raises(ValidationError, match="PUBLICATION"):
        CampaignCaseV1.model_validate({**case, "category": "unsafe"})
    with pytest.raises(ValueError, match="NEGATIVE"):
        manifest().price.cost(-1, 0)


async def test_journal_rejects_duplicates_tampering_and_symlink_records(tmp_path: Path) -> None:
    cfg = manifest(repetitions=1)
    with LocalCampaignStore(tmp_path, cfg) as store:
        await run_campaign(cfg, store, Executor(), clock=lambda: NOW)
        record = store.read("code", 1)
        assert record
        with pytest.raises(ValueError, match="INVALID_TRANSITION"):
            store.append(record)
        with pytest.raises(ValueError, match="BINDING"):
            summarize_campaign(cfg, [record, record])
        path = tmp_path / "code-1.finished.json"
        path.write_text(record.model_copy(update={"case_id": "wrong"}).model_dump_json())
        with pytest.raises(ValueError, match="BINDING"):
            store.read("code", 1)
        path.unlink()
        path.symlink_to(tmp_path / "manifest.json")
        with pytest.raises(ValueError, match="SYMLINK"):
            store.read("code", 1)


def test_empty_campaign_report_does_not_invent_measurements() -> None:
    report = summarize_campaign(manifest(), [])
    assert not report.complete and report.cases[0].attempted == 0
    assert report.cases[0].median_latency_ms is None and report.estimated_cost_usd is None
