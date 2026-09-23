"""Tests for redacted, scoped A2A task persistence."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from a2a.auth.user import User
from a2a.server.context import ServerCallContext
from a2a.types import a2a_pb2 as a2a_pb

from remediation_agent.adapters.a2a_task_store import S3A2ATaskStore
from remediation_agent.api.a2a_contracts import RUN_SUMMARY_METADATA_KEY, RemediationRunSummaryV1
from remediation_agent.domain.enums import FinalStatus


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
    def __init__(self, *, fail_put_suffix: str | None = None) -> None:
        self.objects: dict[str, bytes] = {}
        self.fail_put_suffix = fail_put_suffix

    def put_object(self, **kwargs: Any) -> dict[str, object]:
        key = str(kwargs["Key"])
        if self.fail_put_suffix is not None and key.endswith(self.fail_put_suffix):
            from botocore.exceptions import ClientError  # type: ignore[import-untyped]

            raise ClientError({"Error": {"Code": "InternalError"}}, "PutObject")
        self.objects[key] = bytes(kwargs["Body"])
        return {}

    def get_object(self, **kwargs: Any) -> dict[str, object]:
        key = str(kwargs["Key"])
        if key not in self.objects:
            from botocore.exceptions import ClientError

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


def _run_task(
    task_id: str = "11111111-1111-4111-8111-111111111111",
    *,
    status: FinalStatus = FinalStatus.AWAITING_APPROVAL,
    updated_at: datetime | None = None,
) -> a2a_pb.Task:
    updated = updated_at or datetime(2026, 9, 23, tzinfo=UTC)
    state = (
        a2a_pb.TaskState.TASK_STATE_INPUT_REQUIRED
        if status is FinalStatus.AWAITING_APPROVAL
        else a2a_pb.TaskState.TASK_STATE_COMPLETED
    )
    summary = RemediationRunSummaryV1(
        task_id=task_id,
        session_id="22222222-2222-4222-8222-222222222222",
        case_id="CASE-123",
        jira_ticket_id="TICKET-123",
        repository="owner/repository",
        status=status,
        created_at=datetime(2026, 9, 20, tzinfo=UTC),
        updated_at=updated,
    )
    task = a2a_pb.Task(
        id=task_id,
        context_id="22222222-2222-4222-8222-222222222222",
        status=a2a_pb.TaskStatus(state=state),
        metadata={RUN_SUMMARY_METADATA_KEY: summary.model_dump(mode="json")},
        history=[a2a_pb.Message(message_id="history", role=a2a_pb.Role.ROLE_USER, parts=[a2a_pb.Part(text="secret")])],
    )
    task.status.timestamp.FromDatetime(updated)
    return task


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
    assert list(page.tasks) == []

    await store.delete(_task().id, owner)
    assert await store.get(_task().id, owner) is None


async def test_public_run_index_lists_across_sessions_and_excludes_other_tasks() -> None:
    client = _S3()
    store = S3A2ATaskStore("bucket", region_name="ap-southeast-1", client=client)
    older = _run_task(updated_at=datetime(2026, 9, 21, tzinfo=UTC), status=FinalStatus.DRAFT_PR_CREATED)
    waiting = _run_task(
        "33333333-3333-4333-8333-333333333333",
        updated_at=datetime(2026, 9, 20, tzinfo=UTC),
    )
    await store.save(older, _context("session-1", "caller-1"))
    await store.save(waiting, _context("session-2", "caller-2"))
    await store.save(_task("44444444-4444-4444-8444-444444444444"), _context("probe-session"))

    page = await store.list(a2a_pb.ListTasksRequest(page_size=20), _context("unrelated-session", "viewer"))

    assert [task.id for task in page.tasks] == [waiting.id, older.id]
    assert page.total_size == 2
    assert all(task.history == [] and task.artifacts == [] for task in page.tasks)
    index_bodies = [body.decode() for key, body in client.objects.items() if "/index/" in key]
    assert len(index_bodies) == 2
    assert all("secret" not in body for body in index_bodies)


async def test_public_run_index_updates_without_duplicates_and_paginates() -> None:
    client = _S3()
    store = S3A2ATaskStore("bucket", region_name="ap-southeast-1", client=client)
    original = _run_task(status=FinalStatus.AWAITING_APPROVAL)
    updated = _run_task(
        status=FinalStatus.DRAFT_PR_CREATED,
        updated_at=datetime(2026, 9, 23, tzinfo=UTC) + timedelta(minutes=1),
    )
    await store.save(original, _context("session-1"))
    await store.save(updated, _context("session-1"))

    page = await store.list(a2a_pb.ListTasksRequest(page_size=1), _context("viewer"))

    assert page.total_size == 1
    assert len(page.tasks) == 1
    persisted = json.loads(next(body for key, body in client.objects.items() if "/index/" in key))
    assert persisted["metadata"][RUN_SUMMARY_METADATA_KEY]["status"] == "DRAFT_PR_CREATED"


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

    client.objects[store._index_key(_task().id)] = b'{"metadata":{"aios_run":{"status":"secret"}}}'  # noqa: SLF001
    with pytest.raises(RuntimeError, match="A2A_TASK_INDEX_MALFORMED"):
        await store.list(a2a_pb.ListTasksRequest(page_size=20), _context("viewer"))


async def test_s3_store_surfaces_projection_and_index_write_failures() -> None:
    projection_client = _S3(fail_put_suffix=f"/{_task().id}.json")
    projection_store = S3A2ATaskStore(
        "bucket",
        region_name="ap-southeast-1",
        client=projection_client,
    )
    with pytest.raises(RuntimeError, match="A2A_TASK_STORE_WRITE_FAILED"):
        await projection_store.save(_task(), _context("session-1"))

    index_client = _S3(fail_put_suffix=f"index/{_task().id}.json")
    index_store = S3A2ATaskStore("bucket", region_name="ap-southeast-1", client=index_client)
    with pytest.raises(RuntimeError, match="A2A_TASK_INDEX_WRITE_FAILED"):
        await index_store.save(_run_task(), _context("session-1"))


async def test_s3_store_requires_agentcore_session_in_hosted_mode() -> None:
    store = S3A2ATaskStore("bucket", region_name="ap-southeast-1", client=_S3())
    with pytest.raises(RuntimeError, match="SESSION_REQUIRED"):
        await store.save(_task(), ServerCallContext())
