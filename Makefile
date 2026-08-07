.PHONY: sync lint format format-check typecheck test test-integration security schemas build docker-build sandbox-build db-up db-init db-down

UV_CACHE_DIR ?= /tmp/aios-remediation-uv-cache
export UV_CACHE_DIR

sync:
	uv sync --frozen

lint:
	uv run ruff check .

format:
	uv run ruff format .

format-check:
	uv run ruff format --check .

typecheck:
	uv run mypy src tests scripts

test:
	uv run pytest --cov=src

test-integration:
	uv run pytest -m integration

security:
	uv run bandit -q -r src
	uv run pip-audit --skip-editable

schemas:
	uv run python scripts/export_schemas.py

build:
	uv build --no-build-isolation

docker-build:
	docker build -t aios-remediation-agent:local .

sandbox-build:
	docker build -f docker/sandbox.Dockerfile -t aios-remediation-sandbox:local .

db-up:
	docker compose up -d postgres

db-init:
	uv run remediation-db-init

db-down:
	docker compose down
