"""Owned disposable validation storage, separate from the reviewed Git workspace."""

from __future__ import annotations

import asyncio
import errno
import os
import shutil
import tempfile
from pathlib import Path
from uuid import uuid4

from remediation_agent.domain.enums import ValidationCleanupStatus
from remediation_agent.domain.models import ValidationCleanupReceipt, ValidationDiagnostic, ValidationSnapshotRef

MANAGED_CEILING = 768 * 1024 * 1024
_RESERVE = 128 * 1024 * 1024
_TRANSIENT = {errno.EIO, errno.EBUSY, errno.ENOTEMPTY, errno.ETIMEDOUT, errno.ESTALE, 121}


class ValidationStorageError(RuntimeError):
    def __init__(self, diagnostic: ValidationDiagnostic):
        super().__init__(diagnostic.code + ": " + diagnostic.detail)
        self.diagnostic = diagnostic


def diagnostic(exc: Exception, operation: str, resource: str) -> ValidationDiagnostic:
    from remediation_agent.adapters.evidence import SecretRedactor

    number = exc.errno if isinstance(exc, OSError) else None
    code = (
        "VALIDATION_STORAGE_EXHAUSTED" if number in {errno.ENOSPC, errno.EDQUOT} else "VALIDATION_INFRASTRUCTURE_ERROR"
    )
    if number in {errno.EIO, errno.ESTALE, 121}:
        code = "WORKSPACE_STORAGE_IO_ERROR"
    return ValidationDiagnostic.model_validate(
        {
            "code": code,
            "operation": operation,
            "resource": resource,
            "errno": number,
            "detail": SecretRedactor().redact(str(exc))[:2000],
        }
    )


def footprint(root: Path, *, max_files: int = 100_000) -> tuple[int, int]:
    size = count = 0
    if root.is_symlink():
        raise ValueError("Storage root cannot be a symlink")
    for directory, directories, files in os.walk(root, followlinks=False, onerror=_raise_io):
        for name in (*directories, *files):
            path = Path(directory) / name
            stat = path.lstat()
            if path.is_symlink():
                raise ValueError("Validation storage contains a symlink")
            count += 1
            if count > max_files:
                raise ValueError("Validation storage file count exceeds the operator limit")
            if name in files:
                size += stat.st_size
    return size, count


def _raise_io(error: OSError) -> None:
    raise error


class ValidationScratch:
    def __init__(self, root: Path, workspace_root: Path):
        if root.is_symlink():
            raise ValueError("Validation scratch root cannot be a symlink")
        self.root = root.resolve()
        self.workspace_root = workspace_root.resolve()
        # Managed storage is a whole mount, not just the configured runs directory.
        managed = (
            Path("/mnt/workspace") if self.workspace_root.is_relative_to("/mnt/workspace") else self.workspace_root
        )
        self.managed_root = managed
        if self.root.is_relative_to(managed) or managed.is_relative_to(self.root):
            raise ValueError("Validation scratch and managed workspace roots must be disjoint")
        self._leases: dict[str, Path] = {}
        self._snapshots: dict[str, ValidationSnapshotRef] = {}

    def preflight(self, projected: int, files: int) -> tuple[int, int]:
        managed, _ = footprint(self.managed_root)
        if managed > MANAGED_CEILING or files > 50_000:
            raise ValidationStorageError(
                ValidationDiagnostic(
                    code="VALIDATION_STORAGE_EXHAUSTED",
                    operation="preflight",
                    resource="WORKSPACE",
                    detail="Managed storage exceeds 768 MiB or projected file count exceeds 50,000.",
                )
            )
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        status = self.root.stat()
        if self.root.is_symlink() or status.st_uid != os.geteuid() or status.st_mode & 0o022:
            raise ValueError("Validation scratch must be operator-owned and not group/world writable")
        free = shutil.disk_usage(self.root).free
        if projected + _RESERVE > free:
            raise ValidationStorageError(
                ValidationDiagnostic(
                    code="VALIDATION_STORAGE_EXHAUSTED",
                    operation="preflight",
                    resource="SCRATCH",
                    detail="Projected validation staging plus 128 MiB reserve exceeds available scratch space.",
                )
            )
        return managed, free

    def create(self) -> tuple[str, Path]:
        lease = uuid4().hex
        path = Path(tempfile.mkdtemp(prefix="pair-", dir=self.root))
        self._leases[lease] = path
        return lease, path

    def register(self, lease: str, label: str, owner: str, base: str) -> ValidationSnapshotRef:
        if label not in {"base", "candidate"} or lease not in self._leases:
            raise ValueError("Unknown validation snapshot lease")
        snapshot = ValidationSnapshotRef(
            workspace_id=f"verify-{label}-{lease}",
            path=str(self._leases[lease] / label),
            base_commit=base,
            lease_id=lease,
            owner_workspace_id=owner,
        )
        self._snapshots[snapshot.workspace_id] = snapshot
        return snapshot

    def resolve(self, snapshot: ValidationSnapshotRef, *, require_exists: bool = True) -> Path:
        if self._snapshots.get(snapshot.workspace_id) != snapshot:
            raise ValueError("Unowned validation snapshot")
        parent = self._leases.get(snapshot.lease_id)
        if parent is None:
            raise ValueError("Unknown validation lease")
        path = Path(snapshot.path)
        if path.parent != parent or path.name not in {"base", "candidate"}:
            raise ValueError("Validation snapshot escapes its lease")
        self._safe(path, parent)
        if require_exists and not path.is_dir():
            raise ValueError("Validation snapshot is absent")
        return path

    def _safe(self, path: Path, parent: Path) -> None:
        if self.root.is_symlink() or parent.is_symlink() or path.is_symlink():
            raise ValueError("Validation cleanup refuses a symlink")
        if parent.parent != self.root or not path.resolve().is_relative_to(parent.resolve()):
            raise ValueError("Validation cleanup escaped its owned lease")

    async def cleanup_snapshot(self, snapshot: ValidationSnapshotRef) -> ValidationCleanupReceipt:
        try:
            path = self.resolve(snapshot, require_exists=False)
        except (OSError, ValueError) as exc:
            return ValidationCleanupReceipt(
                resource="SNAPSHOT",
                resource_id=snapshot.workspace_id,
                status=ValidationCleanupStatus.FAILED,
                diagnostic=diagnostic(exc, "snapshot_cleanup", "SNAPSHOT"),
            )
        return await self._remove(path, snapshot.workspace_id, "SNAPSHOT")

    async def cleanup_lease(self, lease: str) -> ValidationCleanupReceipt:
        path = self._leases.get(lease)
        if path is None:
            raise ValueError("Unknown validation lease")
        return await self._remove(path, lease, "SCRATCH")

    async def _remove(self, path: Path, identity: str, resource: str) -> ValidationCleanupReceipt:
        problem: ValidationDiagnostic | None = None
        attempt = 0
        for attempt in range(1, 4):
            try:
                parent = path if resource == "SCRATCH" else path.parent
                self._safe(path, parent)
                if path.exists():
                    await asyncio.to_thread(shutil.rmtree, path)
                if path.exists():
                    raise OSError(errno.EBUSY, "Owned validation resource remains after cleanup")
                return ValidationCleanupReceipt.model_validate(
                    {"resource": resource, "resource_id": identity, "status": "SUCCEEDED", "attempts": attempt}
                )
            except (OSError, ValueError) as exc:
                problem = diagnostic(exc, "snapshot_cleanup", resource)
                if not isinstance(exc, OSError) or exc.errno not in _TRANSIENT or attempt == 3:
                    break
                await asyncio.sleep(0.1 * attempt)
        return ValidationCleanupReceipt.model_validate(
            {
                "resource": resource,
                "resource_id": identity,
                "status": "FAILED",
                "attempts": attempt,
                "diagnostic": problem,
            }
        )
