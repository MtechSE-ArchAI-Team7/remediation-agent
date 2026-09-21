"""Opt-in authenticated AgentCore gateway contract test."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from remediation_agent.adapters.models import build_structured_model
from remediation_agent.config import Settings
from remediation_agent.domain.enums import ModelOperation
from remediation_agent.domain.models import StrictModel
from remediation_agent.ports.models import ModelRequest

_GATEWAY_ARN = "arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:gateway/llm-gateway-with-inbound-auth-u8utldecju"


class _GatewayContractResult(StrictModel):
    status: str


@pytest.mark.live_model
async def test_authenticated_gateway_returns_one_bounded_structured_response() -> None:
    if os.environ.get("AIOS_RUN_AGENTCORE_GATEWAY_LIVE") != "1":
        pytest.skip("set AIOS_RUN_AGENTCORE_GATEWAY_LIVE=1 to call the authenticated gateway")
    settings = Settings.model_validate(
        {
            "policy_file": Path("config/policies/reference.json"),
            "llm_provider": "openai",
            "llm_model": "kei-openai-target/gpt-5.6-terra",
            "aws_region": "ap-southeast-1",
            "openai_auth_mode": "aws_iam_gateway",
            "openai_gateway_arn": _GATEWAY_ARN,
            "OPENAI_API_KEY": None,
            "openai_secret_arn": None,
            "openai_base_url": None,
            "model_transport_retries": 0,
        }
    )
    model = build_structured_model(settings, max_output_tokens=128, max_format_retries=0)
    try:
        generation = await model.generate(
            ModelRequest(
                operation=ModelOperation.AGENTCORE_SMOKE,
                prompt_version="gateway-live-v1",
                system_instruction="Return status exactly 'ok' in the requested schema.",
                payload={"contract": "authenticated AgentCore gateway"},
            ),
            _GatewayContractResult,
        )
    finally:
        await model.aclose()

    assert generation.value.status == "ok"
    assert generation.record.provider == "openai"
    assert generation.record.model == "kei-openai-target/gpt-5.6-terra"
