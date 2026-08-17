"""Export the FastAPI OpenAPI document as deterministic YAML."""

from __future__ import annotations

from pathlib import Path

import yaml  # type: ignore[import-untyped]

from remediation_agent.api.app import create_app


def render_openapi_yaml() -> str:
    """Render the application-generated OpenAPI contract with stable key order."""

    document = create_app().openapi()
    rendered: str = yaml.safe_dump(
        document,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )
    return rendered


def main() -> None:
    output = Path(__file__).parents[1] / "openapi.yaml"
    output.write_text(render_openapi_yaml(), encoding="utf-8")


if __name__ == "__main__":
    main()
