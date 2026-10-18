"""Trusted runner errors cannot be mistaken for reproduced or repaired defects."""

import hashlib
import importlib.metadata
import io
import json
import platform
import shutil
import sys
import tarfile
from pathlib import Path

import pytest

from remediation_agent.adapters.validation_assets import runner


@pytest.mark.parametrize(
    "spec,version,accepted",
    [
        ("1.2.3", "1.2.3", True),
        ("^1.2.3", "1.4.0", True),
        ("^1.2.3", "2.0.0", False),
        ("^0.2.3", "0.2.4", True),
        ("^0.2.3", "0.3.0", False),
        ("^0.0.3", "0.0.3", True),
        ("^0.0.3", "0.0.4", False),
        (">=1", "1.2.3", False),
    ],
)
def test_offline_dependency_contract(spec: str, version: str, accepted: bool) -> None:
    assert runner._version_satisfies(spec, version) is accepted


def test_bundle_missing_unexpected_and_symlink_files_fail(tmp_path: Path) -> None:
    expected = {"system": platform.system(), "machine": platform.machine(), "files": {"node": "wrong"}}
    (tmp_path / "manifest.json").write_text(json.dumps(expected))
    with pytest.raises(RuntimeError, match="missing or unexpected"):
        runner.verify_bundle(tmp_path)
    (tmp_path / "node").symlink_to(tmp_path / "manifest.json")
    with pytest.raises(RuntimeError, match="Unsafe"):
        runner.verify_bundle(tmp_path)


@pytest.mark.parametrize("kind", ["empty", "lock_format", "missing_version"])
def test_missing_dependency_contract_fails(tmp_path: Path, kind: str) -> None:
    bundle, app = tmp_path / "bundle", tmp_path / "app"
    bundle.mkdir()
    app.mkdir()
    (bundle / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/a": {"version": "1.0.0"}}}))
    (app / "package.json").write_text(json.dumps({"dependencies": {} if kind == "empty" else {"a": "1.0.0"}}))
    if kind == "lock_format":
        (app / "package-lock.json").write_text('{"packages": []}')
    if kind == "missing_version":
        (bundle / "package-lock.json").write_text('{"packages": {}}')
    with pytest.raises(RuntimeError):
        runner.verify_dependencies(bundle, app)


def test_browser_escape_digest_and_executable_checks(tmp_path: Path) -> None:
    path = tmp_path / "browser-manifest.json"
    (tmp_path / "browser").write_bytes(b"trusted")
    manifest = {"files": {"browser": hashlib.sha256(b"trusted").hexdigest()}, "executable": "browser"}
    path.write_text(json.dumps(manifest))
    assert runner.verify_browser(tmp_path)[0] == str(tmp_path / "browser")
    manifest["executable"] = "../escape"
    path.write_text(json.dumps(manifest))
    with pytest.raises(RuntimeError, match="executable"):
        runner.verify_browser(tmp_path)
    manifest["files"] = {"browser": "wrong"}
    path.write_text(json.dumps(manifest))
    with pytest.raises(RuntimeError, match="digest"):
        runner.verify_browser(tmp_path)
    with tarfile.open(tmp_path / "browser.tar.xz", "w:xz") as archive:
        item = tarfile.TarInfo("../escape")
        item.size = 1
        archive.addfile(item, io.BytesIO(b"x"))
    with pytest.raises(RuntimeError, match="Unsafe browser asset"):
        runner.unpack_browser(tmp_path, tmp_path / "unpacked")


def test_child_output_timeout_and_cleanup() -> None:
    code, output = runner.execute([sys.executable, "-c", "print('ok')"], {}, 2, 100)
    assert code == 0 and output.strip() == "ok"
    with pytest.raises(RuntimeError, match="output limit"):
        runner.execute([sys.executable, "-c", "print('x'*100)"], {}, 2, 10)
    with pytest.raises(RuntimeError, match="timeout"):
        runner.execute([sys.executable, "-c", "import time; time.sleep(3)"], {}, 0, 100)


@pytest.mark.parametrize("profile", ["pytest", "node_test", "ecommerce_checkout", "ecommerce_purchase"])
@pytest.mark.parametrize("fault", ["pass", "assertion", "malformed", "empty", "setup", "tamper"])
def test_profile_runner_classifies_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, fault: str
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    temporary = tmp_path / "scratch"
    temporary.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setattr(runner, "__file__", str(assets / "runner.py"))
    monkeypatch.setattr(runner, "verify_bundle", lambda _: sys.executable)
    monkeypatch.setattr(runner, "verify_dependencies", lambda *_: None)
    monkeypatch.setattr(runner, "verify_browser", lambda _: ("browser", "lib"))
    monkeypatch.setattr(shutil, "which", lambda _: sys.executable)
    monkeypatch.setattr(importlib.metadata, "distributions", lambda: [])
    (assets / "task.json").write_text(
        json.dumps(
            {
                "profile": profile,
                "test_paths": ["tests"],
                "timeout": 10,
                "output_limit": 1000,
            }
        )
    )

    def execute(argv: list[str], env: dict[str, str], timeout: int, limit: int) -> tuple[int, str]:
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert timeout == 5 and limit == 1000
        if fault == "tamper":
            (work / "modified").write_text("changed")
        report = {
            "cases": []
            if fault == "empty"
            else [
                {
                    "test_id": "contract",
                    "outcome": "ASSERTION_FAILED" if fault == "assertion" else "PASSED",
                }
            ]
        }
        body = "not-json" if fault == "malformed" else json.dumps(report)
        if profile == "pytest":
            Path(env["AIOS_REPORT_PATH"]).write_text(body)
        return (2 if fault == "setup" else 1 if fault == "assertion" else 0), body

    monkeypatch.setattr(runner, "execute", execute)
    if fault in {"pass", "assertion"}:
        assert runner.run(temporary) == (1 if fault == "assertion" else 0)
    else:
        with pytest.raises(RuntimeError):
            runner.run(temporary)
    assert not (temporary / "result.json").exists()


def test_unknown_profile_missing_runtime_and_symlink_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runner, "__file__", str(tmp_path / "runner.py"))
    config = tmp_path / "task.json"
    config.write_text('{"profile": "unknown"}')
    with pytest.raises(RuntimeError, match="Unknown"):
        runner.run(tmp_path)
    config.write_text('{"profile": "node_test", "test_paths": ["tests"]}')
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="executable is absent"):
        runner.run(tmp_path)
    (tmp_path / "link").symlink_to(config)
    with pytest.raises(RuntimeError, match="symlink"):
        runner.snapshot_digest(tmp_path)
