"""Offline driver checks preserve approval, publication and evidence boundaries."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from remediation_agent.adapters.models import ProviderStructuredModel
from remediation_agent.adversarial import FAMILIES, canary_for
from remediation_agent.config import Settings
from remediation_agent.domain.campaign import CampaignCaseV1
from remediation_agent.domain.enums import ApprovalStatus, FinalStatus
from scripts import run_gap_campaign as driver
from scripts.gap_fixtures import digest_files, fixtures, handoff, initialize
from tests.unit.test_campaign import manifest
from tests.unit.test_model_adapter import _ChatModel


@pytest.mark.parametrize("category", ["code", "unsafe", "attack"])
async def test_trial_driver_approval_and_evidence_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, category: str
) -> None:
    fixture = next(f for f in fixtures() if f.key == "py-average")
    family = FAMILIES[0] if category == "attack" else None
    surface = "memory" if family else None
    files = driver.files_for(fixture, family, surface)
    commit = initialize(tmp_path / "source", files)
    case = CampaignCaseV1.model_validate(
        {
            "case_id": fixture.key,
            "category": category,
            "language": "python",
            "repetitions": 1,
            "handoff": handoff(fixture, commit),
            "fixture_digest": digest_files(files),
            "expected_statuses": ["HUMAN_ACTION_REQUIRED"],
            "attack_family": family,
            "attack_surface": surface,
        }
    )
    provider = ProviderStructuredModel(_ChatModel([]), provider="fake", model="fixture", timeout_seconds=1, retries=0)
    close = AsyncMock()
    monkeypatch.setattr(provider, "aclose", close)
    monkeypatch.setattr(driver, "build_structured_model", lambda *_args: provider)
    request = SimpleNamespace(approval_id="approval", scope_digest="sha256:" + "a" * 64)
    pending = SimpleNamespace(status=FinalStatus.AWAITING_APPROVAL, approval_request=request)
    done = SimpleNamespace(status=FinalStatus.HUMAN_ACTION_REQUIRED, explainability=None, result=None)
    state = {"cleanup_result": SimpleNamespace(succeeded=True), "current_diff": "unexpected change"}
    service = SimpleNamespace(
        start=AsyncMock(return_value=pending),
        approve=AsyncMock(return_value=done),
        graph=SimpleNamespace(aget_state=AsyncMock(return_value=SimpleNamespace(values=state))),
        _config=lambda run_id: {"run_id": run_id},
    )
    monkeypatch.setattr(driver, "RemediationService", lambda *_args, **_kwargs: service)
    output = tmp_path / "evidence"
    observation = await driver.LiveFixtureExecutor(
        Settings.model_construct(policy_file=Path("config/policies/reference.json"), llm_provider="fake"),
        manifest(),
        output,
    ).execute(case, "trial")
    decision = service.approve.call_args.args[1]
    assert decision.status == (ApprovalStatus.APPROVED if category == "code" else ApprovalStatus.REJECTED)
    assert observation.controls_verified == (category != "unsafe")
    assert observation.cleanup_verified
    assert not observation.publication_verified
    assert observation.failure_code == ("ATTACK_NOT_EXPOSED" if category == "attack" else None)
    assert observation.evidence_digests
    evidence = (output / "trial/trial-evidence.json").read_text()
    assert canary_for("trial") not in evidence
    assert '"remote_writes": false' in evidence
    close.assert_awaited_once()


async def test_trial_rejects_changed_fixture_before_provider_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = next(f for f in fixtures() if f.key == "py-average")
    case = manifest().cases[0].model_copy(update={"case_id": fixture.key})
    factory = AsyncMock()
    monkeypatch.setattr(driver, "build_structured_model", factory)
    with pytest.raises(ValueError, match="CAMPAIGN_FIXTURE_CHANGED"):
        await driver.LiveFixtureExecutor(
            Settings.model_construct(policy_file=Path("config/policies/reference.json"), llm_provider="fake"),
            manifest(),
            tmp_path,
        ).execute(case, "trial")
    factory.assert_not_called()
