"""Package the locked headless browser and its shared libraries at image-build time."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess  # nosec B404 - fixed build-time dependency inspection
import sys
import tarfile
import tempfile
from pathlib import Path


def seal(cache: Path, output: Path) -> None:
    candidates = list(cache.glob("chromium_headless_shell-*/*/headless_shell"))
    candidates += list(cache.glob("chromium_headless_shell-*/*/chrome-headless-shell"))
    if len(candidates) != 1:
        raise ValueError("Expected exactly one locked headless browser")
    with tempfile.TemporaryDirectory(prefix="browser-build-") as temporary:
        root = Path(temporary)
        shutil.copytree(candidates[0].parent, root / "browser", symlinks=False)
        binary = root / "browser" / candidates[0].name
        libraries = root / "lib"
        libraries.mkdir()
        pending = [binary]
        copied: set[Path] = set()
        while pending:
            target = pending.pop()
            result = subprocess.run(  # noqa: S603 # nosec B603
                ["/usr/bin/ldd", str(target)],
                capture_output=True,
                text=True,
                check=True,
            )
            if "not found" in result.stdout:
                raise ValueError("Browser shared library is unavailable")
            for match in re.finditer(r"(/[^\s()]+)", result.stdout):
                library = Path(match.group(1)).resolve()
                if library in copied:
                    continue
                copied.add(library)
                shutil.copy2(library, libraries / Path(match.group(1)).name)
                pending.append(library)
        loaders = list(libraries.glob("ld-linux-*.so.*"))
        if len(loaders) != 1:
            raise ValueError("Expected one matching browser ELF loader")
        # Chromium resolves resource files relative to /proc/self/exe. When invoked
        # through the sealed loader, that loader must live beside icudtl.dat.
        shutil.copy2(loaders[0], binary.parent / loaders[0].name)
        (root / "browser-manifest.json").write_text(
            json.dumps(
                {
                    "executable": binary.relative_to(root).as_posix(),
                    "files": {
                        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted(root.rglob("*"))
                        if p.is_file()
                    },
                },
                sort_keys=True,
            )
        )
        with tarfile.open(output, "w:xz", preset=6) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    archive.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)


if __name__ == "__main__":
    seal(Path(sys.argv[1]), Path(sys.argv[2]))
