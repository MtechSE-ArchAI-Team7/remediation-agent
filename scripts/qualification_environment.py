"""Export only safe provider settings from the verified existing runtime for image qualification."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ACCOUNT = "734849394833"
REGION = "ap-southeast-1"
RUNTIME = "remediation_agent-2425SXH9D3"
MODEL_KEYS = {
    "AIOS_LLM_PROVIDER",
    "AIOS_LLM_MODEL",
    "AIOS_OPENAI_AUTH_MODE",
    "AIOS_OPENAI_GATEWAY_ARN",
    "AIOS_MODEL_TIMEOUT_SECONDS",
    "AIOS_MODEL_TRANSPORT_RETRIES",
    "AIOS_MODEL_TEMPERATURE",
    "AIOS_PROMPT_VERSION",
    "AIOS_POLICY_FILE",
    "AIOS_CODE_INTERPRETER_IDENTIFIER",
}


def runtime_digest(runtime: dict[str, object]) -> str:
    if runtime.get("agentRuntimeArn") != f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{RUNTIME}":
        raise ValueError("QUALIFICATION_RUNTIME_IDENTITY_MISMATCH")
    environment = runtime.get("environmentVariables")
    if not isinstance(environment, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in environment.items()
    ):
        raise ValueError("QUALIFICATION_RUNTIME_ENVIRONMENT_INVALID")
    stable = {
        k: v
        for k, v in environment.items()
        if k
        not in {"AIOS_RELEASE_ID", "AIOS_RELEASE_SOURCE_SHA", "AIOS_RELEASE_IMAGE_DIGEST", "AIOS_AGENTCORE_RUNTIME_ID"}
    }
    return "sha256:" + hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def export(runtime_path: Path, output: Path) -> None:
    runtime = json.loads(runtime_path.read_text())
    digest = runtime_digest(runtime)
    environment = runtime["environmentVariables"]
    if (
        environment.get("AIOS_OPENAI_AUTH_MODE") != "aws_iam_gateway"
        or environment.get("AIOS_LLM_PROVIDER") != "openai"
    ):
        raise ValueError("Release qualification currently requires the configured IAM model gateway")
    allowed = {key: value for key, value in environment.items() if key in MODEL_KEYS}
    if allowed.get("AIOS_POLICY_FILE") != "/app/config/policies/agentcore-demo.json":
        raise ValueError("Unqualified operator policy location")
    allowed.update(
        {
            "AIOS_AWS_REGION": REGION,
            "AIOS_BEHAVIORAL_BUNDLE": "/app/validation/ecommerce",
            "AIOS_RUN_WORKFLOW_QUALIFICATION": "1",
            "AIOS_QUALIFICATION_RUNTIME_CONFIGURATION_DIGEST": digest,
        }
    )
    if any("\n" in value or "\r" in value for value in allowed.values()):
        raise ValueError("Unsafe qualification environment")
    output.write_text("".join(f"{key}={value}\n" for key, value in sorted(allowed.items())))


if __name__ == "__main__":
    export(Path(sys.argv[1]), Path(sys.argv[2]))
