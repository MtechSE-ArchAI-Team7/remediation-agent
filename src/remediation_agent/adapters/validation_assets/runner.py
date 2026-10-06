"""Trusted sandbox bootstrap. No repository-provided command strings are evaluated."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import selectors
import shutil
import signal

# Fixed argv inside the restricted execution boundary.
import subprocess  # nosec B404
import sys
import tempfile
import time
from pathlib import Path


def execute(argv: list[str], env: dict[str, str], timeout: int, limit: int) -> tuple[int, str]:
    # Only the host-owned profile constructs argv.
    process = subprocess.Popen(  # noqa: S603  # nosec B603
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        start_new_session=True,
    )
    output = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    if process.stdout is None:
        raise RuntimeError("Behavioral child stdout is absent")
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise RuntimeError("Behavioral child timeout")
            for key, _ in selector.select(0.1):
                data = os.read(key.fd, 8192)
                if not data:
                    selector.unregister(key.fd)
                output.extend(data)
                if len(output) > limit:
                    raise RuntimeError("Behavioral child output limit")
        return process.wait(timeout=1), output.decode("utf-8", errors="replace")
    finally:
        selector.close()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        process.stdout.close()


def verify_bundle(bundle: Path) -> str:
    manifest = json.loads((bundle / "manifest.json").read_text())
    if manifest["system"] != platform.system() or manifest["machine"] != platform.machine():
        raise RuntimeError("Offline dependency bundle is incompatible with the sandbox platform")
    files = manifest["files"]
    actual = {path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()}
    if actual != {*files, "manifest.json"}:
        raise RuntimeError("Offline dependency bundle contains missing or unexpected files")
    for name, digest in files.items():
        path = bundle / name
        if not path.resolve().is_relative_to(bundle.resolve()) or path.is_symlink():
            raise RuntimeError("Unsafe dependency bundle path")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError("Offline dependency bundle digest mismatch")
    return str(bundle.resolve() / "node")


def verify_dependencies(bundle: Path, root: Path) -> None:
    """The offline version set must satisfy the reviewed application's declared contract."""
    locked = json.loads((bundle / "package-lock.json").read_text())["packages"]
    declared = json.loads((root / "package.json").read_text())
    dependencies = {**declared.get("dependencies", {}), **declared.get("optionalDependencies", {})}
    if not dependencies:
        raise RuntimeError("Application dependency contract is absent")
    for name, spec in dependencies.items():
        supplied = locked.get(f"node_modules/{name}", {}).get("version")
        if not supplied or spec not in {supplied, f"^{supplied}"}:
            raise RuntimeError(f"Offline bundle does not support application dependency {name}")
    app_lock = root / "package-lock.json"
    if app_lock.exists():
        packages = json.loads(app_lock.read_text()).get("packages")
        if not isinstance(packages, dict):
            raise RuntimeError("Unsupported application lockfile format")
        for name, entry in packages.items():
            if name and not entry.get("dev", False) and entry.get("version") != locked.get(name, {}).get("version"):
                raise RuntimeError(f"Application lockfile differs from offline dependency {name}")


def main() -> int:
    assets = Path(__file__).resolve().parent
    cfg = json.loads((assets / "task.json").read_text())
    before = snapshot_digest(Path.cwd())
    report_path = Path(tempfile.mkdtemp(prefix="aios-report-")) / "result.json"
    # Clear PYTHONPATH, cloud variables and caller credentials before executing repository code.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1"}
    profile = cfg["profile"]
    if profile == "pytest":
        env["PYTHONPATH"] = os.pathsep.join([str(assets), os.environ.get("PYTHONPATH", "")])
        argv = [sys.executable, "-m", "pytest", "-p", "pytest_reporter", "-p", "no:cacheprovider", *cfg["test_paths"]]
        env["AIOS_REPORT_PATH"] = str(report_path)
    elif profile == "node_test":
        argv = ["node", "--test", f"--test-reporter={assets / 'node_reporter.cjs'}", *cfg["test_paths"]]
    elif profile == "ecommerce_checkout":
        node = verify_bundle(assets / "bundle")
        verify_dependencies(assets / "bundle", Path.cwd())
        env["NODE_PATH"] = str(assets / "bundle" / "node_modules")
        argv = [node, str(assets / "checkout.cjs")]
    elif profile == "ecommerce_purchase":
        node = verify_bundle(assets / "bundle")
        verify_dependencies(assets / "bundle", Path.cwd())
        env["NODE_PATH"] = str(assets / "bundle" / "node_modules")
        argv = [node, str(assets / "purchase.cjs")]
    else:
        raise RuntimeError("Unknown trusted behavioral profile")
    executable = shutil.which(argv[0])
    if executable is None:
        raise RuntimeError("Behavioral runtime executable is absent")
    runtime = {
        "python": sys.version,
        "system": platform.system(),
        "machine": platform.machine(),
        "executable_digest": hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
        "python_dependencies": sorted(
            (package.metadata.get("Name", ""), package.version) for package in importlib.metadata.distributions()
        ),
    }
    try:
        code, output = execute(argv, env, max(1, int(cfg["timeout"]) - 5), int(cfg["output_limit"]))
        if snapshot_digest(Path.cwd()) != before:
            raise RuntimeError("Behavioral execution changed source, assertions or trusted assets")
        try:
            report = json.loads(report_path.read_text() if profile == "pytest" else output)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Malformed behavioral report (exit={code}): {output[:800]}") from exc
    finally:
        report_path.unlink(missing_ok=True)
        report_path.parent.rmdir()
    if not report.get("cases") or code not in (0, 1):
        raise RuntimeError("No executable behavioral assertions or test runner setup failed")
    report["runtime_digest"] = "sha256:" + hashlib.sha256(json.dumps(runtime, sort_keys=True).encode()).hexdigest()
    print(json.dumps(report))
    return 0 if all(case["outcome"] == "PASSED" for case in report["cases"]) else 1


def snapshot_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("Behavioral snapshot contains a symlink")
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
    return digest.hexdigest()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - bounded failure record, never a passing test
        print(json.dumps({"cases": [{"test_id": "setup", "outcome": "SETUP_ERROR", "detail": str(exc)[:1000]}]}))
        sys.exit(1)
