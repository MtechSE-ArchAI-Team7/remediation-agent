.PHONY: sync lint format-check typecheck test build docker-build

sync:
	uv sync --frozen

lint:
	uv run ruff check .

format-check:
	uv run ruff format --check .

typecheck:
	uv run mypy

test:
	uv run pytest --cov=src

build:
	uv build --no-build-isolation

docker-build:
	docker build -t agent-template:local .
