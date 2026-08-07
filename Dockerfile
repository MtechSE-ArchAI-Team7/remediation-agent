FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY pyproject.toml uv.lock ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable
COPY config ./config
RUN /app/.venv/bin/python -c "from remediation_agent.api.app import create_app; assert callable(create_app)"

FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app
RUN useradd --system --uid 10001 --create-home remediation
COPY --from=builder --chown=10001:10001 /app /app
USER 10001:10001

EXPOSE 8080
CMD ["uvicorn", "remediation_agent.api.app:app", "--host", "0.0.0.0", "--port", "8080"]
