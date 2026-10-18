"""Exclusive, durable campaign journal. Started trials are never silently retried."""

from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

from remediation_agent.domain.campaign import CampaignManifestV1, CampaignTrialV1


def manifest_digest(manifest: CampaignManifestV1) -> str:
    return "sha256:" + hashlib.sha256(manifest.model_dump_json().encode()).hexdigest()


class LocalCampaignStore:
    """Hold one process lock throughout a campaign, including model calls."""

    def __init__(self, root: Path, manifest: CampaignManifestV1) -> None:
        self.root = root
        self.manifest = manifest
        self.digest = manifest_digest(manifest)
        self._lock: BinaryIO | None = None

    def __enter__(self) -> LocalCampaignStore:
        if self.root.is_symlink():
            raise ValueError("CAMPAIGN_ROOT_SYMLINK")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.root / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self._lock = os.fdopen(fd, "r+b")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            target = self.root / "manifest.json"
            if target.exists():
                if target.is_symlink() or target.read_bytes() != self.manifest.model_dump_json(indent=2).encode():
                    raise ValueError("CAMPAIGN_MANIFEST_CHANGED")
            else:
                self._write(target, self.manifest.model_dump_json(indent=2).encode())
        except BaseException:
            self._lock.close()
            self._lock = None
            raise
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def _name(self, case_id: str, trial_number: int) -> str:
        case = next((c for c in self.manifest.cases if c.case_id == case_id), None)
        if self._lock is None or case is None or not 1 <= trial_number <= case.repetitions:
            raise ValueError("CAMPAIGN_TRIAL_NOT_AUTHORIZED")
        return f"{case_id}-{trial_number}"

    def read(self, case_id: str, trial_number: int) -> CampaignTrialV1 | None:
        name = self._name(case_id, trial_number)
        for suffix in ("finished", "started", "budget_stopped"):
            path = self.root / f"{name}.{suffix}.json"
            if path.is_symlink():
                raise ValueError("CAMPAIGN_RECORD_SYMLINK")
            if path.exists():
                if path.stat().st_size > 262_144:
                    raise ValueError("CAMPAIGN_RECORD_OVERSIZED")
                trial = CampaignTrialV1.model_validate_json(path.read_bytes())
                if (
                    trial.manifest_digest != self.digest
                    or trial.campaign_id != self.manifest.campaign_id
                    or trial.case_id != case_id
                    or trial.trial_number != trial_number
                    or trial.state.lower() != suffix
                ):
                    raise ValueError("CAMPAIGN_RECORD_BINDING_MISMATCH")
                return trial
        return None

    def append(self, trial: CampaignTrialV1) -> None:
        name = self._name(trial.case_id, trial.trial_number)
        if trial.manifest_digest != self.digest or trial.campaign_id != self.manifest.campaign_id:
            raise ValueError("CAMPAIGN_RECORD_BINDING_MISMATCH")
        previous = self.read(trial.case_id, trial.trial_number)
        if trial.state == "FINISHED":
            if (
                previous is None
                or previous.state != "STARTED"
                or previous.run_id != trial.run_id
                or previous.started_at != trial.started_at
                or previous.reserved_usd != trial.reserved_usd
            ):
                raise ValueError("CAMPAIGN_INVALID_TRANSITION")
        elif previous is not None:
            raise ValueError("CAMPAIGN_TRIAL_ALREADY_RECORDED")
        self._write(self.root / f"{name}.{trial.state.lower()}.json", trial.model_dump_json(indent=2).encode())

    def _write(self, path: Path, data: bytes) -> None:
        # The retained STARTED reservation survives a torn terminal write. Corruption stops resume.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
