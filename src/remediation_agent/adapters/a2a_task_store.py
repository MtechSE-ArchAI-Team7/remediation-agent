"""Redacted, session-scoped S3 persistence for hosted A2A task projections."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from typing import Protocol, cast

import boto3  # type: ignore[import-untyped]
from a2a.server.context import ServerCallContext
from a2a.server.tasks import TaskStore
from a2a.types import a2a_pb2 as a2a_pb
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from google.protobuf import json_format  # type: ignore[import-untyped]

from remediation_agent.adapters.evidence import SecretRedactor


class _ReadableBody(Protocol):
    def read(self, amount: int | None = None) -> bytes: ...


class _S3TaskClient(Protocol):
    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def list_objects_v2(self, **kwargs: object) -> Mapping[str, object]: ...

    def delete_object(self, **kwargs: object) -> Mapping[str, object]: ...


class S3A2ATaskStore(TaskStore):
    """Persist only bounded task state, excluding raw inbound A2A history."""

    def __init__(
        self,
        bucket: str,
        *,
        region_name: str,
        prefix: str = "a2a/tasks",
        max_projection_bytes: int = 524_288,
        client: _S3TaskClient | None = None,
        redactor: SecretRedactor | None = None,
        require_session: bool = True,
    ) -> None:
        if max_projection_bytes < 1:
            raise ValueError("A2A task projection size must be positive")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        if not self.prefix or ".." in self.prefix.split("/"):
            raise ValueError("A2A task-store prefix is unsafe")
        self.max_projection_bytes = max_projection_bytes
        self._client = client or cast(_S3TaskClient, boto3.client("s3", region_name=region_name))
        self._redactor = redactor or SecretRedactor()
        self._require_session = require_session

    async def save(self, task: a2a_pb.Task, context: ServerCallContext) -> None:
        projection = a2a_pb.Task()
        projection.CopyFrom(task)
        projection.ClearField("history")
        raw = json_format.MessageToDict(
            projection,
            preserving_proto_field_name=True,
            always_print_fields_with_no_presence=True,
        )
        redacted = self._redact(raw)
        body = json.dumps(redacted, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(body) > self.max_projection_bytes:
            raise RuntimeError("A2A_TASK_PROJECTION_TOO_LARGE")
        await asyncio.to_thread(
            self._client.put_object,
            Bucket=self.bucket,
            Key=self._task_key(task.id, context),
            Body=body,
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )

    async def get(self, task_id: str, context: ServerCallContext) -> a2a_pb.Task | None:
        try:
            response = await asyncio.to_thread(
                self._client.get_object,
                Bucket=self.bucket,
                Key=self._task_key(task_id, context),
            )
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {"NoSuchKey", "404", "NotFound"}:
                return None
            raise RuntimeError("A2A_TASK_STORE_READ_FAILED") from exc
        body = response.get("Body")
        if not hasattr(body, "read"):
            raise RuntimeError("A2A_TASK_STORE_INVALID_BODY")
        content = await asyncio.to_thread(cast(_ReadableBody, body).read, self.max_projection_bytes + 1)
        if len(content) > self.max_projection_bytes:
            raise RuntimeError("A2A_TASK_PROJECTION_TOO_LARGE")
        try:
            payload = json.loads(content)
            task = cast(
                a2a_pb.Task,
                json_format.ParseDict(payload, a2a_pb.Task(), ignore_unknown_fields=False),
            )
        except (json.JSONDecodeError, json_format.ParseError, TypeError, ValueError) as exc:
            raise RuntimeError("A2A_TASK_STORE_MALFORMED") from exc
        if task.id != task_id:
            raise RuntimeError("A2A_TASK_STORE_ID_MISMATCH")
        return task

    async def list(
        self,
        params: a2a_pb.ListTasksRequest,
        context: ServerCallContext,
    ) -> a2a_pb.ListTasksResponse:
        page_size = params.page_size if params.HasField("page_size") else 50
        request: dict[str, object] = {
            "Bucket": self.bucket,
            "Prefix": self._owner_prefix(context),
            "MaxKeys": min(page_size, 100),
        }
        if params.page_token:
            request["ContinuationToken"] = params.page_token
        try:
            response = await asyncio.to_thread(self._client.list_objects_v2, **request)
        except ClientError as exc:
            raise RuntimeError("A2A_TASK_STORE_LIST_FAILED") from exc
        tasks: list[a2a_pb.Task] = []
        contents = response.get("Contents", [])
        if not isinstance(contents, list):
            raise RuntimeError("A2A_TASK_STORE_MALFORMED_LIST")
        for item in contents:
            if not isinstance(item, Mapping):
                continue
            key = item.get("Key")
            if not isinstance(key, str) or not key.endswith(".json"):
                continue
            task_id = key.rsplit("/", 1)[-1].removesuffix(".json")
            task = await self.get(task_id, context)
            if task is None:
                continue
            if params.context_id and task.context_id != params.context_id:
                continue
            if params.status and task.status.state != params.status:
                continue
            tasks.append(task)
        token = response.get("NextContinuationToken", "")
        return a2a_pb.ListTasksResponse(
            tasks=tasks,
            next_page_token=token if isinstance(token, str) else "",
            page_size=len(tasks),
            total_size=len(tasks),
        )

    async def delete(self, task_id: str, context: ServerCallContext) -> None:
        try:
            await asyncio.to_thread(
                self._client.delete_object,
                Bucket=self.bucket,
                Key=self._task_key(task_id, context),
            )
        except ClientError as exc:
            raise RuntimeError("A2A_TASK_STORE_DELETE_FAILED") from exc

    def _task_key(self, task_id: str, context: ServerCallContext) -> str:
        if not task_id or any(value in task_id for value in ("/", "\\", "\x00")) or task_id in {".", ".."}:
            raise ValueError("unsafe A2A task ID")
        return f"{self._owner_prefix(context)}{task_id}.json"

    def _owner_prefix(self, context: ServerCallContext) -> str:
        raw_session = context.state.get("session_id")
        if self._require_session and (not isinstance(raw_session, str) or not raw_session):
            raise RuntimeError("A2A_RUNTIME_SESSION_REQUIRED")
        session = raw_session if isinstance(raw_session, str) and raw_session else "isolated-test"
        caller = context.user.user_name
        material = f"{context.tenant}\x00{caller}\x00{session}".encode()
        owner = hashlib.sha256(material).hexdigest()
        return f"{self.prefix}/{owner}/"

    def _redact(self, value: object) -> object:
        if isinstance(value, str):
            return self._redactor.redact(value)
        if isinstance(value, dict):
            return {key: self._redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        return value
