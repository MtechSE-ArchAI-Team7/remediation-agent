"""Trusted reporter and offline asset controls, without Docker or cloud credentials."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from remediation_agent.adapters.behavioral import _copy, _extract
from remediation_agent.adapters.validation_assets.runner import verify_bundle
from remediation_agent.domain.models import BehavioralReport

_ASSETS = Path(__file__).parents[2] / "src/remediation_agent/adapters/validation_assets"


def test_native_bundle_platform_and_digest_are_required(tmp_path: Path) -> None:
    (tmp_path / "node").write_bytes(b"trusted-build")
    manifest = {
        "system": platform.system(),
        "machine": platform.machine(),
        "files": {"node": hashlib.sha256(b"trusted-build").hexdigest()},
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    assert verify_bundle(tmp_path) == str(tmp_path / "node")
    (tmp_path / "node").write_bytes(b"modified")
    with pytest.raises(RuntimeError, match="digest mismatch"):
        verify_bundle(tmp_path)
    manifest["machine"] = "unsupported-architecture"
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(RuntimeError, match="incompatible"):
        verify_bundle(tmp_path)


def test_snapshot_copy_excludes_credentials_and_rejects_symlinks(tmp_path: Path) -> None:
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    (source / ".env").write_text("PRIVATE_VALUE=fixture")
    (source / "server.js").write_text("source")
    _copy(source, target)
    assert (target / "server.js").read_text() == "source" and not (target / ".env").exists()
    (source / "escape").symlink_to(tmp_path)
    with pytest.raises(ValueError, match="symlink"):
        _copy(source, target)


def test_base_archive_cannot_escape(tmp_path: Path) -> None:
    import io
    import tarfile

    path = tmp_path / "base.tar"
    with tarfile.open(path, "w") as archive:
        entry = tarfile.TarInfo("../escape")
        entry.size = 1
        archive.addfile(entry, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="Unsafe"):
        _extract(path, tmp_path / "base")


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("test('regression',()=>assert.equal(1,2));", "ASSERTION_FAILED"),
        ("test('regression',()=>assert.equal(1,1));", "PASSED"),
        ("test.skip('regression',()=>assert.equal(1,1));", "SKIPPED"),
        ("test('regression',()=>require('./absent'));", "SETUP_ERROR"),
    ],
)
def test_node_reporter_distinguishes_assertions_from_setup(tmp_path: Path, body: str, expected: str) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for reporter contract test")
    test_file = tmp_path / "case.test.js"
    test_file.write_text("const test=require('node:test');const assert=require('node:assert/strict');" + body)
    result = subprocess.run(  # noqa: S603 - fixed node:test runner on disposable fixture
        [node, "--test", f"--test-reporter={_ASSETS / 'node_reporter.cjs'}", str(test_file)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    report = BehavioralReport.model_validate_json(result.stdout)
    assert len(report.cases) == 1 and report.cases[0].outcome == expected


def test_unsupported_dependencies_or_conflicting_lockfile_cannot_pass(tmp_path: Path) -> None:
    from remediation_agent.adapters.validation_assets.runner import verify_dependencies

    bundle, app = tmp_path / "bundle", tmp_path / "app"
    bundle.mkdir()
    app.mkdir()
    (bundle / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/express": {"version": "4.18.2"}}}))
    (app / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.18.2"}}))
    verify_dependencies(bundle, app)
    (app / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/express": {"version": "5.0.0"}}}))
    with pytest.raises(RuntimeError, match="lockfile differs"):
        verify_dependencies(bundle, app)
    (app / "package.json").write_text(json.dumps({"dependencies": {"express": "^5.0.0"}}))
    with pytest.raises(RuntimeError, match="does not support"):
        verify_dependencies(bundle, app)
