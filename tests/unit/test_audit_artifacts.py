"""Tamper-evident audit and artifact path tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from remediation_agent.adapters.evidence import AuditTrail, LocalArtifactReader, LocalArtifactStore
from remediation_agent.domain.models import ArtifactRef
from remediation_agent.ports.models import ArtifactReadError, ArtifactReadRequest, ArtifactWriteRequest


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


async def test_local_artifact_reader_uses_manifest_path_and_rejects_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = LocalArtifactStore(root)
    manifest = await store.write_bundle(ArtifactWriteRequest(run_id="run", files={"result.json": '{"ok":true}'}))
    reader = LocalArtifactReader(root)

    result = await reader.read(
        ArtifactReadRequest(
            run_id="run",
            artifact=manifest.artifacts[0],
            max_object_bytes=1024,
            max_preview_bytes=1024,
        )
    )

    assert json.loads(result.content) == {"ok": True}
    (root / "run" / "result.json").unlink()
    outside = tmp_path / "outside.json"
    outside.write_text('{"secret":true}', encoding="utf-8")
    (root / "run" / "result.json").symlink_to(outside)
    with pytest.raises(ArtifactReadError, match="ARTIFACT_ACCESS_DENIED"):
        await reader.read(
            ArtifactReadRequest(
                run_id="run",
                artifact=ArtifactRef(
                    name="result.json",
                    path="run/result.json",
                    digest=manifest.artifacts[0].digest,
                    media_type="application/json",
                ),
                max_object_bytes=1024,
                max_preview_bytes=1024,
            )
        )
