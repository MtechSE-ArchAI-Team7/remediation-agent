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
from a2a.utils.task import decode_page_token, encode_page_token
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from google.protobuf import json_format  # type: ignore[import-untyped]
from pydantic import ValidationError

from remediation_agent.adapters.evidence import SecretRedactor
from remediation_agent.api.a2a_contracts import RUN_SUMMARY_METADATA_KEY, RemediationRunSummaryV1


class _ReadableBody(Protocol):
    def read(self, amount: int | None = None) -> bytes: ...


class _S3TaskClient(Protocol):
    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def list_objects_v2(self, **kwargs: object) -> Mapping[str, object]: ...

    def delete_object(self, **kwargs: object) -> Mapping[str, object]: ...


class S3A2ATaskStore(TaskStore):
    """Persist session-scoped tasks plus a bounded public-demo run index."""

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
        try:
            await asyncio.to_thread(
                self._client.put_object,
                Bucket=self.bucket,
                Key=self._task_key(task.id, context),
                Body=body,
                ContentType="application/json",
                ServerSideEncryption="AES256",
            )
        except ClientError as exc:
            raise RuntimeError("A2A_TASK_STORE_WRITE_FAILED") from exc
        summary = self._run_summary(projection)
        if summary is not None:
            index_projection = a2a_pb.Task(
                id=projection.id,
                context_id=projection.context_id,
                status=projection.status,
                metadata={RUN_SUMMARY_METADATA_KEY: summary.model_dump(mode="json")},
            )
            index_raw = json_format.MessageToDict(
                index_projection,
                preserving_proto_field_name=True,
                always_print_fields_with_no_presence=True,
            )
            index_body = json.dumps(self._redact(index_raw), sort_keys=True, separators=(",", ":")).encode("utf-8")
            if len(index_body) > self.max_projection_bytes:
                raise RuntimeError("A2A_TASK_INDEX_TOO_LARGE")
            try:
                await asyncio.to_thread(
                    self._client.put_object,
                    Bucket=self.bucket,
                    Key=self._index_key(task.id),
                    Body=index_body,
                    ContentType="application/json",
                    ServerSideEncryption="AES256",
                )
            except ClientError as exc:
                raise RuntimeError("A2A_TASK_INDEX_WRITE_FAILED") from exc

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
        del context
        page_size = params.page_size if params.HasField("page_size") else 50
        request: dict[str, object] = {
            "Bucket": self.bucket,
            "Prefix": self._index_prefix(),
            "MaxKeys": 1000,
        }
        try:
            response = await asyncio.to_thread(self._client.list_objects_v2, **request)
        except ClientError as exc:
            raise RuntimeError("A2A_TASK_STORE_LIST_FAILED") from exc
        if response.get("IsTruncated") is True:
            raise RuntimeError("A2A_TASK_INDEX_LIMIT_EXCEEDED")
        indexed: list[tuple[a2a_pb.Task, RemediationRunSummaryV1]] = []
        contents = response.get("Contents", [])
        if not isinstance(contents, list):
            raise RuntimeError("A2A_TASK_STORE_MALFORMED_LIST")
        for item in contents:
            if not isinstance(item, Mapping):
                continue
            key = item.get("Key")
            if not isinstance(key, str) or not key.endswith(".json"):
                continue
            task = await self._read_task_key(key, error_code="A2A_TASK_INDEX_MALFORMED")
            summary = self._run_summary(task)
            if summary is None:
                raise RuntimeError("A2A_TASK_INDEX_MALFORMED")
            if params.context_id and task.context_id != params.context_id:
                continue
            if params.status and task.status.state != params.status:
                continue
            if params.HasField("status_timestamp_after"):
                if not task.status.HasField("timestamp") or task.status.timestamp <= params.status_timestamp_after:
                    continue
            indexed.append((task, summary))
        indexed.sort(
            key=lambda item: (
                self._status_priority(item[1].status),
                -item[1].updated_at.timestamp(),
                item[0].id,
            )
        )
        total_size = len(indexed)
        start = 0
        if params.page_token:
            try:
                start_id = decode_page_token(params.page_token)
                start = next(index for index, item in enumerate(indexed) if item[0].id == start_id)
            except (ValueError, StopIteration) as exc:
                raise RuntimeError("A2A_TASK_INDEX_INVALID_PAGE_TOKEN") from exc
        page = indexed[start : start + page_size]
        next_index = start + page_size
        token = encode_page_token(indexed[next_index][0].id) if next_index < total_size else ""
        return a2a_pb.ListTasksResponse(
            tasks=[item[0] for item in page],
            next_page_token=token,
            page_size=len(page),
            total_size=total_size,
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

    def _index_prefix(self) -> str:
        return f"{self.prefix}/index/"

    def _index_key(self, task_id: str) -> str:
        if not task_id or any(value in task_id for value in ("/", "\\", "\x00")) or task_id in {".", ".."}:
            raise ValueError("unsafe A2A task ID")
        return f"{self._index_prefix()}{task_id}.json"

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

    async def _read_task_key(self, key: str, *, error_code: str) -> a2a_pb.Task:
        try:
            response = await asyncio.to_thread(self._client.get_object, Bucket=self.bucket, Key=key)
            body = response.get("Body")
            if not hasattr(body, "read"):
                raise RuntimeError(error_code)
            content = await asyncio.to_thread(cast(_ReadableBody, body).read, self.max_projection_bytes + 1)
            if len(content) > self.max_projection_bytes:
                raise RuntimeError(error_code)
            payload = json.loads(content)
            return cast(a2a_pb.Task, json_format.ParseDict(payload, a2a_pb.Task(), ignore_unknown_fields=False))
        except RuntimeError:
            raise
        except (ClientError, json.JSONDecodeError, json_format.ParseError, TypeError, ValueError) as exc:
            raise RuntimeError(error_code) from exc

    @staticmethod
    def _run_summary(task: a2a_pb.Task) -> RemediationRunSummaryV1 | None:
        raw = json_format.MessageToDict(task.metadata, preserving_proto_field_name=True).get(RUN_SUMMARY_METADATA_KEY)
        if raw is None:
            return None
        try:
            summary = RemediationRunSummaryV1.model_validate(raw)
        except ValidationError as exc:
            raise RuntimeError("A2A_TASK_INDEX_MALFORMED") from exc
        if summary.task_id != task.id:
            raise RuntimeError("A2A_TASK_INDEX_ID_MISMATCH")
        return summary

    @staticmethod
    def _status_priority(status: str) -> int:
        if status == "AWAITING_APPROVAL":
            return 0
        if status == "PENDING":
            return 1
        return 2
