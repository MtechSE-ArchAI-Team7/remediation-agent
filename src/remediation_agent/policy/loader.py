"""Load and validate operator policy JSON."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from pydantic import ValidationError

from remediation_agent.policy.models import PolicyConfig


class PolicyLoadError(ValueError):
    """Raised when policy cannot be loaded safely."""


def load_policy(path: Path) -> PolicyConfig:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise PolicyLoadError("policy file must be a regular non-symlink file")
        if metadata.st_size > 1_048_576:
            raise PolicyLoadError("policy file exceeds the 1 MiB parser limit")
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyLoadError(f"cannot read policy file {path.name}: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyLoadError(f"invalid policy JSON in {path.name}: {exc}") from exc
    try:
        return PolicyConfig.model_validate(value)
    except ValidationError as exc:
        raise PolicyLoadError(f"invalid policy in {path.name}: {exc}") from exc
