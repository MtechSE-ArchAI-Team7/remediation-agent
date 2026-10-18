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


def test_node_reporter_preserves_nested_setup_diagnostic(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for reporter contract test")
    test_file = tmp_path / "case.test.js"
    test_file.write_text("require('./dependency-that-does-not-exist');")
    result = subprocess.run(  # noqa: S603 - fixed node:test runner on disposable fixture
        [node, "--test", f"--test-reporter={_ASSETS / 'node_reporter.cjs'}", str(test_file)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    report = BehavioralReport.model_validate_json(result.stdout)
    assert len(report.cases) == 1
    assert report.cases[0].outcome == "SETUP_ERROR"
    assert "dependency-that-does-not-exist" in report.cases[0].detail
    assert len(report.cases[0].detail) <= 1_000


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


def test_staged_assets_are_readable_without_becoming_writable_to_sandbox(tmp_path: Path) -> None:
    from remediation_agent.adapters.behavioral import _prepare_docker_assets

    root = tmp_path / "staged"
    root.mkdir(mode=0o700)
    manifest = root / "manifest.json"
    manifest.write_text("{}")
    manifest.chmod(0o600)
    node = root / "node"
    node.write_bytes(b"executable fixture")
    node.chmod(0o700)
    _prepare_docker_assets(root)
    assert root.stat().st_mode & 0o777 == 0o755
    assert manifest.stat().st_mode & 0o777 == 0o644
    assert node.stat().st_mode & 0o777 == 0o755
    assert manifest.read_text() == "{}"
    outside = tmp_path / "outside"
    outside.write_text("private")
    outside.chmod(0o600)
    (root / "escape").symlink_to(outside)
    with pytest.raises(ValueError, match="Unsafe verification"):
        _prepare_docker_assets(root)
    assert outside.stat().st_mode & 0o777 == 0o600
