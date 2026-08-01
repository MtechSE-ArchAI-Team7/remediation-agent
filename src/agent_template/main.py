from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(title="Agent Template")

    @app.get("/")
    async def hello() -> dict[str, str]:
        return {"message": "hello world"}

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "healthy"}

    return app


def main() -> None:
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("agent_template.main:create_app", host="0.0.0.0", port=port, factory=True)  # nosec B104


if __name__ == "__main__":
    main()
