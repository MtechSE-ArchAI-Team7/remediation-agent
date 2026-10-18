"""A separate scorer correction preserves raw journal bytes and requires bound evidence."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from remediation_agent.adapters.campaign import LocalCampaignStore
from remediation_agent.campaign import run_campaign
from remediation_agent.domain.campaign import CampaignCaseV1, CampaignObservationV1
from scripts.adjudicate_gap_campaign import adjudicate
from tests.conftest import build_test_service, diagnosis_handoff, scripted_responses
from tests.unit.test_campaign import manifest


@pytest.mark.parametrize("tamper", [False, True])
async def test_correction_is_derived_and_digest_bound(tmp_path: Path, tamper: bool) -> None:
    cfg = manifest(repetitions=1)
    case = cfg.cases[0].model_copy(
        update={"case_id": "js-average", "expected_statuses": ["DRAFT_PR_PREPARED"], "require_draft": False}
    )
    cfg = cfg.model_copy(update={"cases": [case], "publication_mode": "disabled"})

    class Executor:
        async def execute(self, case: CampaignCaseV1, run_id: str) -> CampaignObservationV1:
            service, *_ = build_test_service(scripted_responses())
            view = await service.start(diagnosis_handoff(), run_id=run_id)
            assert view.result and view.explainability
            evidence = {
                "result": view.result.model_dump(mode="json"),
                "trace": view.explainability.model_dump(mode="json"),
                "remote_writes": False,
            }
            raw = json.dumps(evidence)
            file = tmp_path / "evidence" / run_id / "trial-evidence.json"
            file.parent.mkdir(parents=True)
            file.write_text(raw + (" " if tamper else ""))
            return CampaignObservationV1(
                status="DRAFT_PR_PREPARED",
                remediation_latency_ms=1,
                cleanup_verified=True,
                controls_verified=False,
                evidence_digests=["sha256:" + hashlib.sha256(raw.encode()).hexdigest()],
            )

    with LocalCampaignStore(tmp_path, cfg) as store:
        await run_campaign(cfg, store, Executor(), clock=lambda: datetime.now(UTC))
    before = {p.name: p.read_bytes() for p in tmp_path.glob("*.json")}
    if tamper:
        with pytest.raises(ValueError, match="DIGEST"):
            adjudicate(tmp_path)
    else:
        adjudicate(tmp_path)
        result = json.loads((tmp_path / "adjudication.json").read_text())
        assert result["original_report"]["cases"][0]["successful"] == 0
        assert result["adjudicated_report"]["cases"][0]["successful"] == 1
        assert len(result["corrections"]) == 1
    assert all((tmp_path / name).read_bytes() == content for name, content in before.items())
