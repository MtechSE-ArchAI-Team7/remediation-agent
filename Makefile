.PHONY: sync lint format format-check typecheck test test-mcp test-integration test-sandbox-integration security schemas openapi build docker-build sandbox-build db-up db-init db-down

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

test-mcp:
	uv run pytest tests/mcp tests/graph/test_mcp_inspection.py tests/unit/test_model_adapter.py

test-integration:
	uv run pytest -m integration

test-sandbox-integration: sandbox-build
	uv run pytest -m integration tests/integration/test_docker_sandbox.py

security:
	uv run bandit -q -r src
	uv run pip-audit --skip-editable

schemas:
	uv run python scripts/export_schemas.py

openapi:
	uv run python scripts/export_openapi.py

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
