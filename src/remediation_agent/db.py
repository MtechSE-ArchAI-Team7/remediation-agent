"""Explicit PostgreSQL checkpoint schema initialization command."""

from __future__ import annotations

import asyncio

from remediation_agent.adapters.checkpoint import postgres_checkpointer
from remediation_agent.config import CheckpointSettings


async def initialize_database(settings: CheckpointSettings) -> None:
    dsn, key = settings.connection_values()
    async with postgres_checkpointer(dsn, key, setup=True):
        return


def main() -> None:
    asyncio.run(initialize_database(CheckpointSettings()))  # type: ignore[call-arg]


if __name__ == "__main__":
    main()
