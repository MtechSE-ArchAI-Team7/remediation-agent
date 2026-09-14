"""PostgreSQL checkpointer lifecycle helpers."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.checkpoint.serde.encrypted import EncryptedSerializer
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph_checkpoint_aws import AgentCoreMemorySaver  # type: ignore[import-untyped]

from remediation_agent.domain import enums, models


def checkpoint_serializer() -> JsonPlusSerializer:
    """Return a strict serializer with no pickle and only local domain types allowlisted."""

    allowed_types = [
        value
        for module in (enums, models)
        for value in vars(module).values()
        if isinstance(value, type) and value.__module__ == module.__name__
    ]
    return JsonPlusSerializer(pickle_fallback=False, allowed_msgpack_modules=allowed_types)


def in_memory_checkpointer() -> InMemorySaver:
    """Create the external-service-free checkpointer used by automated tests."""

    return InMemorySaver(serde=checkpoint_serializer())


def encrypted_checkpoint_serializer(encryption_key: str) -> EncryptedSerializer:
    """Wrap the strict serializer in authenticated checkpoint encryption."""

    key = encryption_key.encode("utf-8")
    if len(key) not in {16, 24, 32}:
        raise ValueError("checkpoint encryption key must encode to exactly 16, 24, or 32 bytes")
    return EncryptedSerializer.from_pycryptodome_aes(serde=checkpoint_serializer(), key=key)


def agentcore_memory_checkpointer(
    memory_id: str,
    encryption_key: str,
    *,
    region_name: str,
) -> AgentCoreMemorySaver:
    """Create the AgentCore Memory-backed saver used by the hosted runtime."""

    return AgentCoreMemorySaver(
        memory_id,
        serde=encrypted_checkpoint_serializer(encryption_key),
        region_name=region_name,
    )


@asynccontextmanager
async def postgres_checkpointer(
    dsn: str,
    encryption_key: str,
    *,
    setup: bool = False,
) -> AsyncIterator[AsyncPostgresSaver]:
    serializer = encrypted_checkpoint_serializer(encryption_key)
    async with AsyncPostgresSaver.from_conn_string(dsn, serde=serializer) as checkpointer:
        if setup:
            await checkpointer.setup()
        yield checkpointer
