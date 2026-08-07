"""Explicit PostgreSQL checkpoint schema initialization command."""

from __future__ import annotations

import asyncio

from remediation_agent.adapters.checkpoint import postgres_checkpointer
from remediation_agent.config import Settings


async def initialize_database(settings: Settings) -> None:
    dsn, key = settings.require_persistent_checkpointing()
    async with postgres_checkpointer(dsn, key, setup=True):
        return


def main() -> None:
    asyncio.run(initialize_database(Settings()))  # type: ignore[call-arg]


if __name__ == "__main__":
    main()
