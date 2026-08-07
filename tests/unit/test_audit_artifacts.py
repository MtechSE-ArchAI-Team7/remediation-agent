"""Tamper-evident audit and artifact path tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from remediation_agent.adapters.evidence import AuditTrail, LocalArtifactStore
from remediation_agent.ports.models import ArtifactWriteRequest


def test_audit_events_are_redacted_and_hash_chained() -> None:
    trail = AuditTrail("policy-v1", "prompt-v1")
    first = trail.event([], case_id="case", run_id="run", event_type="START", result_code="OK", detail="token=secret")
    second = trail.event(
        [first],
        case_id="case",
        run_id="run",
        event_type="END",
        result_code="OK",
        detail="complete",
    )
    assert "secret" not in first.detail
    assert second.previous_hash == first.event_hash
    assert first.event_hash != second.event_hash


async def test_artifact_store_rejects_traversal(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    with pytest.raises(ValueError, match="unsafe artifact name"):
        await store.write_bundle(ArtifactWriteRequest(run_id="run", files={"../escape": "no"}))
