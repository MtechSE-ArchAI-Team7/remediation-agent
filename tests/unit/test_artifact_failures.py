"""Evidence read/write containment, immutable briefs and digest-bound previews."""

import hashlib
from pathlib import Path

import pytest

from remediation_agent.adapters.evidence import (
    JsonlAuditSink,
    LocalArtifactReader,
    LocalArtifactStore,
    SecretRedactor,
    build_artifact_preview,
)
from remediation_agent.domain.models import ArtifactRef
from remediation_agent.ports.models import (
    ArtifactReadError,
    ArtifactReadRequest,
    ArtifactWriteRequest,
    AuditWriteRequest,
)


@pytest.mark.parametrize("fault", ["run", "name", "symlink", "type", "path", "missing", "directory"])
async def test_artifact_reads_fail_closed(tmp_path: Path, fault: str) -> None:
    root = tmp_path / "artifacts"
    store = LocalArtifactStore(root)
    manifest = await store.write_bundle(ArtifactWriteRequest(run_id="run", files={"value.json": "{}"}))
    ref = manifest.artifacts[0]
    run = "run"
    if fault == "run":
        run = ".."
    elif fault == "name":
        ref = ref.model_copy(update={"name": "../value.json"})
    elif fault == "symlink":
        (root / "run/value.json").unlink()
        (root / "run/value.json").symlink_to(tmp_path / "outside")
    elif fault == "type":
        ref = ref.model_copy(update={"media_type": "application/octet-stream"})
    elif fault == "path":
        ref = ref.model_copy(update={"path": "other/value.json"})
    elif fault == "missing":
        (root / "run/value.json").unlink()
    else:
        (root / "run/value.json").unlink()
        (root / "run/value.json").mkdir()
    with pytest.raises(ArtifactReadError):
        await LocalArtifactReader(root).read(
            ArtifactReadRequest(run_id=run, artifact=ref, max_object_bytes=1024, max_preview_bytes=100)
        )


async def test_write_immutability_and_audit_symlinks(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    for run, name in [("..", "value.json"), ("run", "../escape")]:
        with pytest.raises(ValueError):
            await store.write_bundle(ArtifactWriteRequest(run_id=run, files={name: "{}"}))
    request = ArtifactWriteRequest(run_id="run", files={"verification-brief.json": "{}"})
    assert await store.write_bundle(request) == await store.write_bundle(request)
    with pytest.raises(ValueError, match="immutable"):
        await store.write_bundle(
            ArtifactWriteRequest(run_id="run", files={"verification-brief.json": '{"different":true}'})
        )
    (tmp_path / "run/link").symlink_to(tmp_path)
    with pytest.raises(ValueError, match="symlink"):
        await store.write_bundle(ArtifactWriteRequest(run_id="run", files={"link/file": "value"}))
    sink = JsonlAuditSink(tmp_path)
    with pytest.raises(ValueError):
        await sink.write(AuditWriteRequest(run_id="..", jsonl="{}"))
    (tmp_path / "other").symlink_to(tmp_path / "run")
    with pytest.raises(ValueError):
        await sink.write(AuditWriteRequest(run_id="other", jsonl="{}"))
    (tmp_path / "run/audit.jsonl").symlink_to(tmp_path / "outside")
    with pytest.raises(ValueError):
        await sink.write(AuditWriteRequest(run_id="run", jsonl="{}"))
    (tmp_path / "run/audit.jsonl").unlink()
    await sink.write(AuditWriteRequest(run_id="run", jsonl="token=fixture-sensitive"))
    assert "fixture-sensitive" not in (tmp_path / "run/audit.jsonl").read_text()
    refs = await store.write_bundle(
        ArtifactWriteRequest(run_id="run", files={"a.diff": "diff", "b.txt": "text", "c.jsonl": "{}"})
    )
    assert {r.media_type for r in refs.artifacts} == {"text/x-diff", "text/plain", "application/x-ndjson"}


@pytest.mark.parametrize("body,preview", [(b"", 1), ("é".encode(), 1), ("é".encode(), 2), (b"\xff", 1)])
def test_preview_utf8_boundary_and_empty_output(body: bytes, preview: int) -> None:
    ref = ArtifactRef(
        name="value.txt",
        path="run/value.txt",
        digest="sha256:" + hashlib.sha256(body).hexdigest(),
        media_type="text/plain",
    )
    request = ArtifactReadRequest(run_id="run", artifact=ref, max_object_bytes=10, max_preview_bytes=preview)
    if body == b"\xff":
        with pytest.raises(ArtifactReadError):
            build_artifact_preview(request, body, SecretRedactor())
    else:
        result = build_artifact_preview(request, body, SecretRedactor())
        assert result.digest_verified
        assert result.content == ("é" if preview == 2 else "")
