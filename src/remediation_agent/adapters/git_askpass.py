"""Minimal Git askpass process; values are provided only through its environment."""

from __future__ import annotations

import os
import sys


def main() -> int:
    prompt = sys.argv[1] if len(sys.argv) > 1 else ""
    if "username" in prompt.lower():
        value = os.environ.get("AIOS_GIT_ASKPASS_USERNAME")
    elif "password" in prompt.lower():
        value = os.environ.get("AIOS_GIT_ASKPASS_PASSWORD")
    else:
        value = None
    if not value:
        return 1
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
