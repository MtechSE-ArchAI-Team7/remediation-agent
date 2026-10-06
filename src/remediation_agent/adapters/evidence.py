"""Redacted audit and local artifact implementations."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from uuid import uuid4

from remediation_agent.domain.models import ArtifactManifest, ArtifactRef, AuditEvent
from remediation_agent.ports.models import (
    ArtifactReadError,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactWriteRequest,
    AuditWriteRequest,
)

_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|secret|password|credential)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?<![A-Za-z0-9])/(?:Users|home)/[^/\s]+"),
)


class SecretRedactor:
    def redact(self, value: str) -> str:
        result = value
        for pattern in _SECRET_PATTERNS:
            result = pattern.sub("[REDACTED]", result)
        return result

    def redact_artifact(self, name: str, content: str) -> str:
        if name == "patch.diff":
            from remediation_agent.source import source_artifact

            return source_artifact(name, content).content
        if name.endswith(".json"):
            try:
                parsed = json.loads(content)
            except ValueError:
                return self.redact(content)
            return json.dumps(self.redact_data(parsed), indent=2, ensure_ascii=False)
        return self.redact(content)

    def redact_data(self, value: object) -> object:
        """Redact values before JSON encoding so replacement never corrupts structure."""
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            return {key: self.redact_data(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact_data(item) for item in value]
        return value


class AuditTrail:
    """Create a hash-chained in-state audit trail."""

    def __init__(self, policy_version: str, prompt_version: str, redactor: SecretRedactor | None = None) -> None:
        self.policy_version = policy_version
        self.prompt_version = prompt_version
        self.redactor = redactor or SecretRedactor()

    def event(
        self,
        existing: list[AuditEvent],
        *,
        case_id: str,
        run_id: str,
        event_type: str,
        result_code: str,
        detail: str,
        input_value: str = "",
        output_value: str = "",
        actor: str = "resolution-remediation-agent",
    ) -> AuditEvent:
        previous_hash = existing[-1].event_hash if existing else "sha256:" + "0" * 64
        event_id = str(uuid4())
        timestamp = datetime.now(UTC)
        redacted_detail = self.redactor.redact(detail)
        input_digest = _digest(self.redactor.redact(input_value))
        output_digest = _digest(self.redactor.redact(output_value))
        canonical = json.dumps(
            {
                "event_id": event_id,
                "timestamp": timestamp.isoformat(),
                "actor": actor,
                "case_id": case_id,
                "run_id": run_id,
                "event_type": event_type,
                "result_code": result_code,
                "detail": redacted_detail,
                "policy_version": self.policy_version,
                "prompt_version": self.prompt_version,
                "input_digest": input_digest,
                "output_digest": output_digest,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            actor=actor,
            case_id=case_id,
            run_id=run_id,
            event_type=event_type,
            result_code=result_code,
            detail=redacted_detail,
            policy_version=self.policy_version,
            prompt_version=self.prompt_version,
            input_digest=input_digest,
            output_digest=output_digest,
            previous_hash=previous_hash,
            event_hash=_digest(canonical),
        )

    @staticmethod
    def to_jsonl(events: list[AuditEvent]) -> str:
        return "".join(event.model_dump_json() + "\n" for event in events)


class LocalArtifactStore:
    def __init__(self, root: Path, redactor: SecretRedactor | None = None) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.redactor = redactor or SecretRedactor()

    async def write_bundle(self, request: ArtifactWriteRequest) -> ArtifactManifest:
        run_directory = (self.root / request.run_id).resolve()
        if not run_directory.is_relative_to(self.root) or run_directory == self.root:
            raise ValueError("artifact run ID escapes artifact root")
        run_directory.mkdir(parents=True, exist_ok=True)
        run_directory.chmod(0o700)
        refs: list[ArtifactRef] = []
        for name, content in sorted(request.files.items()):
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                raise ValueError(f"unsafe artifact name: {name}")
            unresolved_target = run_directory / relative
            path_cursor = unresolved_target
            while path_cursor != run_directory:
                if path_cursor.is_symlink():
                    raise ValueError(f"artifact path contains a symlink: {name}")
                path_cursor = path_cursor.parent
            target = unresolved_target.resolve()
            if not target.is_relative_to(run_directory):
                raise ValueError(f"artifact path escapes run directory: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            redacted = self.redactor.redact_artifact(name, content)
            if name == "verification-brief.json":
                try:
                    with target.open("x", encoding="utf-8") as output:
                        output.write(redacted)
                except FileExistsError:
                    if target.read_text(encoding="utf-8") != redacted:
                        raise ValueError("verification brief is immutable within a run") from None
            else:
                target.write_text(redacted, encoding="utf-8")
            target.chmod(0o600)
            refs.append(
                ArtifactRef(
                    name=name,
                    path=f"{request.run_id}/{relative.as_posix()}",
                    digest=_digest(redacted),
                    media_type=_media_type(name),
                )
            )
        return ArtifactManifest(run_id=request.run_id, artifacts=refs)


class LocalArtifactReader:
    """Read a manifest-selected local artifact without accepting an arbitrary path."""

    def __init__(self, root: Path, redactor: SecretRedactor | None = None) -> None:
        self.root = root.resolve()
        self.redactor = redactor or SecretRedactor()

    async def read(self, request: ArtifactReadRequest) -> ArtifactReadResult:
        if request.artifact.media_type not in _PREVIEW_MEDIA_TYPES:
            raise ArtifactReadError("ARTIFACT_PREVIEW_UNSUPPORTED")
        relative = PurePosixPath(request.artifact.name)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ArtifactReadError("ARTIFACT_ACCESS_DENIED")
        run_directory = (self.root / request.run_id).resolve()
        if not run_directory.is_relative_to(self.root) or run_directory == self.root:
            raise ArtifactReadError("ARTIFACT_ACCESS_DENIED")
        unresolved_target = run_directory / relative
        path_cursor = unresolved_target
        while path_cursor != run_directory:
            if path_cursor.is_symlink():
                raise ArtifactReadError("ARTIFACT_ACCESS_DENIED")
            path_cursor = path_cursor.parent
        target = unresolved_target.resolve()
        if not target.is_relative_to(run_directory):
            raise ArtifactReadError("ARTIFACT_ACCESS_DENIED")
        if request.artifact.path != f"{request.run_id}/{relative.as_posix()}":
            raise ArtifactReadError("ARTIFACT_ACCESS_DENIED")
        try:
            body = target.read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactReadError("ARTIFACT_NOT_FOUND") from exc
        except OSError as exc:
            raise ArtifactReadError("ARTIFACT_ACCESS_DENIED") from exc
        return build_artifact_preview(request, body, self.redactor)


class JsonlAuditSink:
    def __init__(self, artifact_root: Path, redactor: SecretRedactor | None = None) -> None:
        self.artifact_root = artifact_root.resolve()
        self.redactor = redactor or SecretRedactor()

    async def write(self, request: AuditWriteRequest) -> None:
        unresolved_directory = self.artifact_root / request.run_id
        if unresolved_directory.is_symlink():
            raise ValueError("audit run directory cannot be a symlink")
        run_directory = unresolved_directory.resolve()
        if not run_directory.is_relative_to(self.artifact_root) or run_directory == self.artifact_root:
            raise ValueError("audit run ID escapes artifact root")
        run_directory.mkdir(parents=True, exist_ok=True)
        run_directory.chmod(0o700)
        target = run_directory / "audit.jsonl"
        if target.is_symlink():
            raise ValueError("audit target cannot be a symlink")
        target.write_text(self.redactor.redact(request.jsonl), encoding="utf-8")
        target.chmod(0o600)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _media_type(name: str) -> str:
    if name.endswith(".json"):
        return "application/json"
    if name.endswith(".jsonl"):
        return "application/x-ndjson"
    if name.endswith(".diff"):
        return "text/x-diff"
    return "text/plain"


_PREVIEW_MEDIA_TYPES = frozenset({"application/json", "application/x-ndjson", "text/x-diff", "text/plain"})


def build_artifact_preview(
    request: ArtifactReadRequest,
    body: bytes,
    redactor: SecretRedactor,
) -> ArtifactReadResult:
    if len(body) > request.max_object_bytes:
        raise ArtifactReadError("ARTIFACT_TOO_LARGE")
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    if digest != request.artifact.digest:
        raise ArtifactReadError("ARTIFACT_INTEGRITY_FAILED")
    try:
        content = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactReadError("ARTIFACT_PREVIEW_UNSUPPORTED") from exc
    redacted = redactor.redact(content)
    preview = redacted.encode("utf-8")[: request.max_preview_bytes]
    while preview:
        try:
            rendered = preview.decode("utf-8")
            break
        except UnicodeDecodeError:
            preview = preview[:-1]
    else:
        rendered = ""
    return ArtifactReadResult(
        name=request.artifact.name,
        media_type=request.artifact.media_type,
        digest=request.artifact.digest,
        content=rendered,
        size_bytes=len(body),
        truncated=len(redacted.encode("utf-8")) > len(preview),
        digest_verified=True,
    )
