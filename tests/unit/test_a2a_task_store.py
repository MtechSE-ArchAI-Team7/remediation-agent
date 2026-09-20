"""Tests for redacted, scoped A2A task persistence."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest
from a2a.auth.user import User
from a2a.server.context import ServerCallContext
from a2a.types import a2a_pb2 as a2a_pb

from remediation_agent.adapters.a2a_task_store import S3A2ATaskStore


class _User(User):
    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def user_name(self) -> str:
        return self._name


class _S3:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_object(self, **kwargs: Any) -> dict[str, object]:
        self.objects[str(kwargs["Key"])] = bytes(kwargs["Body"])
        return {}

    def get_object(self, **kwargs: Any) -> dict[str, object]:
        key = str(kwargs["Key"])
        if key not in self.objects:
            from botocore.exceptions import ClientError  # type: ignore[import-untyped]

            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[key])}

    def list_objects_v2(self, **kwargs: Any) -> dict[str, object]:
        prefix = str(kwargs["Prefix"])
        return {"Contents": [{"Key": key} for key in sorted(self.objects) if key.startswith(prefix)]}

    def delete_object(self, **kwargs: Any) -> dict[str, object]:
        self.objects.pop(str(kwargs["Key"]), None)
        return {}


def _context(session_id: str, caller: str = "caller-1") -> ServerCallContext:
    return ServerCallContext(state={"session_id": session_id}, user=_User(caller))


def _task(task_id: str = "11111111-1111-4111-8111-111111111111") -> a2a_pb.Task:
    return a2a_pb.Task(
        id=task_id,
        context_id="22222222-2222-4222-8222-222222222222",
        status=a2a_pb.TaskStatus(state=a2a_pb.TaskState.TASK_STATE_WORKING),
        history=[
            a2a_pb.Message(
                message_id="33333333-3333-4333-8333-333333333333",
                role=a2a_pb.Role.ROLE_USER,
                parts=[a2a_pb.Part(text="token=super-secret-value")],
            )
        ],
    )


async def test_s3_store_recovers_projection_without_raw_history() -> None:
    client = _S3()
    store = S3A2ATaskStore("bucket", region_name="ap-southeast-1", client=client)
    context = _context("session-1")

    await store.save(_task(), context)
    recreated = S3A2ATaskStore("bucket", region_name="ap-southeast-1", client=client)
    recovered = await recreated.get(_task().id, context)

    assert recovered is not None
    assert recovered.id == _task().id
    assert recovered.history == []
    persisted = next(iter(client.objects.values())).decode()
    assert "super-secret-value" not in persisted


async def test_s3_store_isolates_sessions_and_callers_and_deletes_safely() -> None:
    client = _S3()
    store = S3A2ATaskStore("bucket", region_name="ap-southeast-1", client=client)
    owner = _context("session-1", "caller-1")
    await store.save(_task(), owner)

    assert await store.get(_task().id, _context("session-2", "caller-1")) is None
    assert await store.get(_task().id, _context("session-1", "caller-2")) is None
    page = await store.list(a2a_pb.ListTasksRequest(), owner)
    assert [task.id for task in page.tasks] == [_task().id]

    await store.delete(_task().id, owner)
    assert await store.get(_task().id, owner) is None


async def test_s3_store_fails_closed_for_size_and_malformed_data() -> None:
    client = _S3()
    small = S3A2ATaskStore(
        "bucket",
        region_name="ap-southeast-1",
        client=client,
        max_projection_bytes=10,
    )
    with pytest.raises(RuntimeError, match="TOO_LARGE"):
        await small.save(_task(), _context("session-1"))

    store = S3A2ATaskStore("bucket", region_name="ap-southeast-1", client=client)
    key = store._task_key(_task().id, _context("session-1"))  # noqa: SLF001 - corruption fixture
    client.objects[key] = json.dumps({"id": 42}).encode()
    with pytest.raises(RuntimeError, match="MALFORMED"):
        await store.get(_task().id, _context("session-1"))


async def test_s3_store_requires_agentcore_session_in_hosted_mode() -> None:
    store = S3A2ATaskStore("bucket", region_name="ap-southeast-1", client=_S3())
    with pytest.raises(RuntimeError, match="SESSION_REQUIRED"):
        await store.save(_task(), ServerCallContext())
