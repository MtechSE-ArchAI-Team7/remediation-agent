"""PostgreSQL checkpointer lifecycle helpers."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.checkpoint.serde.encrypted import EncryptedSerializer
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

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
    """Create the external-service-free checkpointer used by tests and demonstrations."""

    return InMemorySaver(serde=checkpoint_serializer())


@asynccontextmanager
async def postgres_checkpointer(
    dsn: str,
    encryption_key: str,
    *,
    setup: bool = False,
) -> AsyncIterator[AsyncPostgresSaver]:
    key = encryption_key.encode("utf-8")
    if len(key) not in {16, 24, 32}:
        raise ValueError("checkpoint encryption key must encode to exactly 16, 24, or 32 bytes")
    serializer = EncryptedSerializer.from_pycryptodome_aes(serde=checkpoint_serializer(), key=key)
    async with AsyncPostgresSaver.from_conn_string(dsn, serde=serializer) as checkpointer:
        if setup:
            await checkpointer.setup()
        yield checkpointer
