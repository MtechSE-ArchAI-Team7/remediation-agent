#!/usr/bin/env python3
"""Launch sealed Chromium with its matching sealed ELF loader and shared libraries."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parent / "browser-runtime"
manifest = json.loads((root / "browser-manifest.json").read_text())
executable = (root / manifest["executable"]).resolve()
loaders = list(executable.parent.glob("ld-linux-*.so.*"))
if not executable.is_relative_to(root) or len(loaders) != 1 or loaders[0].is_symlink():
    raise RuntimeError("Unsupported sealed browser loader")
# The verified browser needs a matching glibc loader, not the managed host's loader.
# No executable name or argument is supplied by a remediation model.
# Direct child launch avoids zygote's /proc/self/exe re-execution of the loader.
# Playwright's existing outer-sandbox isolation policy is unchanged.
os.execv(  # noqa: S606 # nosec B606 - operator-owned sealed loader, never a model command
    str(loaders[0]),
    [
        str(loaders[0]),
        "--library-path",
        str(root / "lib"),
        str(executable),
        f"--browser-subprocess-path={Path(__file__).resolve()}",
        "--no-zygote",
        *sys.argv[1:],
    ],
)
