"""Release-image constraints for trusted behavioral dependencies."""

from pathlib import Path


def test_agentcore_image_packages_qualified_code_interpreter_platform() -> None:
    dockerfile = (Path(__file__).parents[2] / "Dockerfile.agentcore").read_text()

    assert dockerfile.startswith("ARG CODE_INTERPRETER_PLATFORM=linux/arm64\n")
    assert "FROM --platform=${CODE_INTERPRETER_PLATFORM} node:24-bookworm AS validation-build" in dockerfile


def test_runtime_base_upgrades_inherited_vulnerable_packages() -> None:
    dockerfile = (Path(__file__).parents[2] / "Dockerfile.agentcore").read_text()
    runtime_base = dockerfile.split(" AS runtime-base\n", 1)[1].split("FROM runtime-base AS builder", 1)[0]

    assert "apk upgrade --no-cache" in runtime_base
    for requirement in (
        "ca-certificates-bundle>=20260909-r3",
        "libbrotlicommon1>=1.2.0-r7",
        "libbrotlidec1>=1.2.0-r7",
        "libbrotlienc1>=1.2.0-r7",
    ):
        assert f"'{requirement}'" in runtime_base


def test_hosted_validation_vendors_the_qualified_patched_pytest() -> None:
    root = Path(__file__).parents[2]
    dockerfile = (root / "Dockerfile.agentcore").read_text()
    sandbox = (root / "docker/sandbox.Dockerfile").read_text()

    assert 'uv pip install --target /app/validation/pytest_vendor "pytest==9.1.1"' in dockerfile
    assert "pytest==9.1.1" in sandbox
