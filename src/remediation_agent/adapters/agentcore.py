"""AWS-managed persistence, secrets, and workspace recovery for AgentCore."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Protocol, cast

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from pydantic import SecretStr, field_validator

from remediation_agent.adapters.evidence import SecretRedactor, build_artifact_preview
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.domain.models import (
    ArtifactManifest,
    ArtifactRef,
    RepositoryRef,
    StrictModel,
    WorkspaceRef,
)
from remediation_agent.ports.models import (
    ArtifactReadError,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactWriteRequest,
    AuditWriteRequest,
)


class AgentCoreRuntimeSecret(StrictModel):
    """The complete and deliberately small runtime secret document."""

    github_token: SecretStr
    checkpoint_encryption_key: SecretStr

    @field_validator("checkpoint_encryption_key")
    @classmethod
    def checkpoint_key_has_supported_length(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode("utf-8")) != 32:
            raise ValueError("checkpoint_encryption_key must encode to exactly 32 bytes")
        return value


class AgentCoreOpenAISecret(StrictModel):
    """The exact OpenAI credential document accepted by the hosted runtime."""

    OPENAI_APIKEY: SecretStr

    @field_validator("OPENAI_APIKEY")
    @classmethod
    def openai_key_is_not_blank(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("OPENAI_APIKEY must not be blank")
        return value


class _SecretsManagerClient(Protocol):
    def get_secret_value(self, **kwargs: object) -> Mapping[str, object]: ...


class _S3Client(Protocol):
    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...


class _ReadableBody(Protocol):
    def read(self, amount: int | None = None) -> bytes: ...


class SecretsManagerRuntimeSecretProvider:
    """Fetch and validate one exact Secrets Manager JSON document."""

    def __init__(
        self,
        secret_arn: str,
        *,
        region_name: str,
        client: _SecretsManagerClient | None = None,
    ) -> None:
        self.secret_arn = secret_arn
        self._client = client or cast(
            _SecretsManagerClient,
            boto3.client("secretsmanager", region_name=region_name),
        )

    async def load(self) -> AgentCoreRuntimeSecret:
        response = await asyncio.to_thread(self._client.get_secret_value, SecretId=self.secret_arn)
        raw = response.get("SecretString")
        if not isinstance(raw, str):
            raise ValueError("runtime secret must be stored as a JSON SecretString")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("runtime secret is not valid JSON") from exc
        return AgentCoreRuntimeSecret.model_validate(payload)


class SecretsManagerOpenAISecretProvider:
    """Fetch and strictly validate the separately managed OpenAI credential."""

    def __init__(
        self,
        secret_arn: str,
        *,
        region_name: str,
        client: _SecretsManagerClient | None = None,
    ) -> None:
        self.secret_arn = secret_arn
        self._client = client or cast(
            _SecretsManagerClient,
            boto3.client("secretsmanager", region_name=region_name),
        )

    async def load(self) -> AgentCoreOpenAISecret:
        response = await asyncio.to_thread(self._client.get_secret_value, SecretId=self.secret_arn)
        raw = response.get("SecretString")
        if not isinstance(raw, str):
            raise ValueError("OpenAI secret must be stored as a JSON SecretString")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("OpenAI secret is not valid JSON") from exc
        return AgentCoreOpenAISecret.model_validate(payload)


class S3ArtifactStore:
    """Write redacted, digest-addressed artifact objects beneath one run prefix."""

    def __init__(
        self,
        bucket: str,
        *,
        region_name: str,
        client: _S3Client | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.bucket = bucket
        self._client = client or cast(_S3Client, boto3.client("s3", region_name=region_name))
        self._redactor = redactor or SecretRedactor()

    async def write_bundle(self, request: ArtifactWriteRequest) -> ArtifactManifest:
        run_id = _safe_segment(request.run_id, "run ID")
        refs: list[ArtifactRef] = []
        for name, content in sorted(request.files.items()):
            relative = _safe_relative(name)
            redacted = self._redactor.redact_artifact(name, content)
            digest = _digest(redacted)
            key = f"runs/{run_id}/artifacts/{digest.removeprefix('sha256:')}/{relative.as_posix()}"
            await self._put_immutable(key, redacted.encode("utf-8"), _media_type(name))
            refs.append(
                ArtifactRef(
                    name=name,
                    path=f"s3://{self.bucket}/{key}",
                    digest=digest,
                    media_type=_media_type(name),
                )
            )
        return ArtifactManifest(run_id=run_id, artifacts=refs)

    async def _put_immutable(self, key: str, body: bytes, content_type: str) -> None:
        try:
            await asyncio.to_thread(
                self._client.put_object,
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType=content_type,
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status != 412:
                raise


class S3ArtifactReader:
    """Read one manifest-selected, digest-addressed artifact from the configured bucket."""

    def __init__(
        self,
        bucket: str,
        *,
        region_name: str,
        client: _S3Client | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.bucket = bucket
        self._client = client or cast(_S3Client, boto3.client("s3", region_name=region_name))
        self._redactor = redactor or SecretRedactor()

    async def read(self, request: ArtifactReadRequest) -> ArtifactReadResult:
        try:
            run_id = _safe_segment(request.run_id, "run ID")
            relative = _safe_relative(request.artifact.name)
        except ValueError as exc:
            raise ArtifactReadError("ARTIFACT_ACCESS_DENIED") from exc
        if request.artifact.media_type not in {
            "application/json",
            "application/x-ndjson",
            "text/x-diff",
            "text/plain",
        }:
            raise ArtifactReadError("ARTIFACT_PREVIEW_UNSUPPORTED")
        digest_value = request.artifact.digest.removeprefix("sha256:")
        if len(digest_value) != 64 or any(character not in "0123456789abcdef" for character in digest_value):
            raise ArtifactReadError("ARTIFACT_INTEGRITY_FAILED")
        key = f"runs/{run_id}/artifacts/{digest_value}/{relative.as_posix()}"
        if request.artifact.path != f"s3://{self.bucket}/{key}":
            raise ArtifactReadError("ARTIFACT_ACCESS_DENIED")
        try:
            response = await asyncio.to_thread(self._client.get_object, Bucket=self.bucket, Key=key)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {"NoSuchKey", "404", "NotFound"}:
                raise ArtifactReadError("ARTIFACT_NOT_FOUND") from exc
            raise ArtifactReadError("ARTIFACT_ACCESS_DENIED") from exc
        body = response.get("Body")
        if not hasattr(body, "read"):
            raise ArtifactReadError("ARTIFACT_PREVIEW_UNSUPPORTED")
        content = await asyncio.to_thread(
            cast(_ReadableBody, body).read,
            request.max_object_bytes + 1,
        )
        return build_artifact_preview(request, content, self._redactor)


class S3AuditSink:
    """Persist immutable audit events and a digest-addressed final manifest."""

    def __init__(
        self,
        bucket: str,
        *,
        region_name: str,
        client: _S3Client | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.bucket = bucket
        self._client = client or cast(_S3Client, boto3.client("s3", region_name=region_name))
        self._redactor = redactor or SecretRedactor()

    async def write(self, request: AuditWriteRequest) -> None:
        run_id = _safe_segment(request.run_id, "run ID")
        redacted = self._redactor.redact(request.jsonl)
        event_keys: list[str] = []
        for sequence, line in enumerate(redacted.splitlines(), start=1):
            if not line.strip():
                continue
            parsed = json.loads(line)
            canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
            digest = _digest(canonical).removeprefix("sha256:")
            key = f"runs/{run_id}/audit/{sequence:06d}-{digest}.json"
            await self._put_immutable(key, (canonical + "\n").encode("utf-8"), "application/json")
            event_keys.append(key)
        manifest = json.dumps({"run_id": run_id, "events": event_keys}, sort_keys=True, separators=(",", ":"))
        manifest_digest = _digest(manifest).removeprefix("sha256:")
        await self._put_immutable(
            f"runs/{run_id}/audit/manifests/{manifest_digest}.json",
            manifest.encode("utf-8"),
            "application/json",
        )

    async def _put_immutable(self, key: str, body: bytes, content_type: str) -> None:
        try:
            await asyncio.to_thread(
                self._client.put_object,
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType=content_type,
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status != 412:
                raise


class AgentCoreWorkspaceRecovery:
    """Re-clone an interrupted run only when the workflow proves recovery is pre-application."""

    def __init__(self, repository: LocalGitRepository) -> None:
        self._repository = repository

    async def ensure(
        self,
        repository: RepositoryRef,
        workspace: WorkspaceRef,
        *,
        recovery_is_safe: bool,
    ) -> WorkspaceRef:
        path = Path(workspace.path)
        if path.is_dir() and not path.is_symlink():
            return workspace
        if not recovery_is_safe:
            raise RuntimeError("WORKSPACE_RECOVERY_UNSAFE")
        immutable_ref = repository.model_copy(update={"commit_sha": workspace.base_commit})
        recovered = await self._repository.create_workspace(immutable_ref)
        if recovered.base_commit.lower() != workspace.base_commit.lower():
            await self._repository.remove_workspace(recovered)
            raise RuntimeError("WORKSPACE_RECOVERY_UNSAFE")
        return recovered


def _safe_segment(value: str, label: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError(f"unsafe {label}")
    return value


def _safe_relative(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts or "\x00" in value:
        raise ValueError(f"unsafe artifact name: {value}")
    return relative


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
