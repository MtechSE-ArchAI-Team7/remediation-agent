"""Seal build-time dependencies; runtime verification never downloads packages."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sys
from pathlib import Path


def seal(source: Path, destination: Path, node: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    modules = source / "node_modules"
    for path in modules.rglob("*"):
        if path.is_symlink() and not path.resolve().is_relative_to(modules.resolve()):
            raise ValueError("dependency symlink escapes build tree")
    shutil.copytree(modules, destination / "node_modules", symlinks=False)
    for path in (destination / "node_modules").rglob("*"):
        if path.is_file() and (path.suffix in {".key", ".pem"} or path.name.startswith((".env", "credentials"))):
            path.unlink()
    shutil.copyfile(source / "package-lock.json", destination / "package-lock.json")
    shutil.copy2(node, destination / "node")
    manifest = {
        "system": platform.system(),
        "machine": platform.machine(),
        "files": {
            path.relative_to(destination).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(destination.rglob("*"))
            if path.is_file()
        },
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    seal(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
