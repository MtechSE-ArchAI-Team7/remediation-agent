"""Release-image constraints for trusted behavioral dependencies."""

from pathlib import Path


def test_agentcore_image_packages_qualified_code_interpreter_platform() -> None:
    dockerfile = (Path(__file__).parents[2] / "Dockerfile.agentcore").read_text()

    assert dockerfile.startswith("ARG CODE_INTERPRETER_PLATFORM=linux/arm64\n")
    assert "FROM --platform=${CODE_INTERPRETER_PLATFORM} node:20.19.5-bookworm AS validation-build" in dockerfile
