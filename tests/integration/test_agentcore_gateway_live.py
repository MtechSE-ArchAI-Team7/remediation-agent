"""Opt-in authenticated AgentCore gateway contract test."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from remediation_agent.adapters.models import build_structured_model
from remediation_agent.config import Settings
from remediation_agent.domain.enums import ModelOperation
from remediation_agent.domain.models import EditProposal, RemediationPlan, RiskAssessment, StrictModel
from remediation_agent.ports.models import ModelRequest


class _GatewayContractResult(StrictModel):
    status: str


@pytest.mark.live_model
async def test_authenticated_gateway_returns_one_bounded_structured_response() -> None:
    if os.environ.get("AIOS_RUN_AGENTCORE_GATEWAY_LIVE") != "1":
        pytest.skip("set AIOS_RUN_AGENTCORE_GATEWAY_LIVE=1 to call the authenticated gateway")
    settings = Settings.model_validate(
        {"policy_file": Path("config/policies/reference.json"), "OPENAI_API_KEY": None, "openai_secret_arn": None}
    )
    assert settings.llm_provider == "openai" and settings.openai_auth_mode == "aws_iam_gateway"
    model = build_structured_model(settings, max_output_tokens=2_048, max_format_retries=0)
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
        plan = await model.generate(
            ModelRequest(
                operation=ModelOperation.PLANNING,
                prompt_version="gateway-live-v1",
                system_instruction=(
                    "Return a minimal remediation plan for evidence e1 and src/app.py. Use validation task unit_tests."
                ),
                payload={"evidence_id": "e1", "path": "src/app.py", "validation_task": "unit_tests"},
            ),
            RemediationPlan,
        )
        risk = await model.generate(
            ModelRequest(
                operation=ModelOperation.RISK,
                prompt_version="gateway-live-v1",
                system_instruction="Return a LOW risk ALLOW assessment with a concise rationale.",
                payload={"change": "add an input guard"},
            ),
            RiskAssessment,
        )
        patch = await model.generate(
            ModelRequest(
                operation=ModelOperation.PATCH,
                prompt_version="gateway-live-v1",
                system_instruction=(
                    "Return one exact source edit changing const value = 1; to const value = 2; in src/app.js. "
                    "Use range [1,2), the supplied base digest, and exact expected content including its newline."
                ),
                payload={
                    "path": "src/app.js",
                    "base_content_digest": "sha256:" + "a" * 64,
                    "expected_content": "const value = 1;\n",
                },
            ),
            EditProposal,
        )
        revision = await model.generate(
            ModelRequest(
                operation=ModelOperation.REVISION,
                prompt_version="gateway-live-v1",
                system_instruction="Return the same typed source edit proposal.",
                payload={"proposal": patch.value.model_dump(mode="json")},
            ),
            EditProposal,
        )
    finally:
        await model.aclose()

    assert generation.value.status == "ok"
    assert generation.record.provider == "openai"
    assert generation.record.model == settings.llm_model
    assert plan.value.evidence_ids == ["e1"]
    assert risk.value.rationale
    assert patch.value.edits[0].expected_content == "const value = 1;\n"
    assert revision.value.edits[0].path == "src/app.js"
