"""ASGI process entry point."""

from __future__ import annotations

import uvicorn

from remediation_agent.config import Settings


def main() -> None:
    settings = Settings()  # type: ignore[call-arg]
    uvicorn.run(
        "remediation_agent.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )


if __name__ == "__main__":
    main()
