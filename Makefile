.PHONY: validation-bundle sync lint format format-check typecheck test test-model-live test-mcp test-mcp-live test-tool-gateway-live test-integration test-sandbox-integration test-code-interpreter-live security schemas openapi tool-catalog evaluate evaluate-hosted evaluate-judge evaluate-memory evaluate-memory-hosted evaluate-memory-judge memory-seed assessment-report build docker-build agentcore-docker-build sandbox-build db-up db-init db-down

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

test-model-live:
	AIOS_RUN_AGENTCORE_GATEWAY_LIVE=1 uv run pytest -m live_model tests/integration/test_agentcore_gateway_live.py

test-mcp:
	uv run pytest tests/mcp tests/graph/test_mcp_inspection.py tests/unit/test_model_adapter.py

test-mcp-live:
	uv run pytest -m live_mcp tests/mcp/test_repository_mcp.py

test-tool-gateway-live:
	AIOS_RUN_AGENTCORE_TOOL_GATEWAY_LIVE=1 uv run pytest -m live_mcp tests/integration/test_agentcore_tool_gateway_live.py

test-integration:
	uv run pytest -m integration

test-sandbox-integration: sandbox-build validation-bundle
	uv run pytest -m integration tests/integration/test_docker_sandbox.py tests/integration/test_purchase_behavior.py

test-code-interpreter-live:
	AIOS_RUN_CODE_INTERPRETER_LIVE=1 uv run pytest -m live_code_interpreter tests/integration/test_agentcore_code_interpreter_live.py tests/integration/test_purchase_behavior.py

security:
	uv run bandit -q -r src
	uv run pip-audit --skip-editable

schemas:
	uv run python scripts/export_schemas.py

openapi:
	uv run python scripts/export_openapi.py

tool-catalog:
	uv run python scripts/export_tool_catalog.py

evaluate:
	uv run python scripts/run_evaluation.py deterministic

evaluate-hosted:
	uv run python scripts/run_evaluation.py hosted

evaluate-judge:
	uv run python scripts/run_evaluation.py judge

evaluate-memory:
	uv run python scripts/run_evaluation.py memory-deterministic

evaluate-memory-hosted:
	uv run python scripts/run_evaluation.py memory-hosted

evaluate-memory-judge:
	uv run python scripts/run_evaluation.py memory-judge

memory-seed:
	@test -n "$(AIOS_MEMORY_SEED_ARTIFACT)" || (echo "AIOS_MEMORY_SEED_ARTIFACT must name a completed passed evaluation artifact" && exit 2)
	uv run python scripts/run_evaluation.py memory-seed --artifact "$(AIOS_MEMORY_SEED_ARTIFACT)"

assessment-report:
	uv run python scripts/run_evaluation.py report

build:
	uv build --no-build-isolation

docker-build:
	docker build -t aios-remediation-agent:local .

agentcore-docker-build:
	docker build --platform linux/arm64 -f Dockerfile.agentcore -t aios-remediation-agentcore:local .

sandbox-build:
	docker build -f docker/sandbox.Dockerfile -t aios-remediation-sandbox:local .

db-up:
	docker compose up -d postgres

db-init:
	uv run remediation-db-init

db-down:
	docker compose down

# Export a host-platform bundle for local Docker qualification; hosted image builds its own Linux bundle.
validation-bundle:
	rm -rf .artifacts/validation/ecommerce
	docker buildx build -f docker/validation-bundle.Dockerfile --target validation-export --output type=local,dest=.artifacts/validation/ecommerce .
