"""Bedrock AgentCore Runtime smoke-test HTTP contract."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, status
from pydantic import Field

from remediation_agent.adapters.models import build_structured_model
from remediation_agent.config import Settings
from remediation_agent.domain.enums import ModelOperation
from remediation_agent.domain.models import NonEmptyStr, StrictModel
from remediation_agent.ports.models import ModelRequest
from remediation_agent.ports.protocols import StructuredModel

_LOGGER = logging.getLogger(__name__)
_PROMPT_VERSION = "agentcore-smoke-v1"
_MAX_OUTPUT_TOKENS = 64
_MAX_FORMAT_RETRIES = 1


class AgentCoreProbeInput(StrictModel):
    """Only supported smoke-test invocation input."""

    probe: Literal["bedrock"]


class AgentCoreInvocationRequest(StrictModel):
    """AgentCore HTTP invocation envelope."""

    input: AgentCoreProbeInput


class AgentCoreProbeResult(StrictModel):
    """Constrained structured output requested from Bedrock."""

    status: Literal["ok"]


class AgentCoreInvocationOutput(StrictModel):
    """Safe smoke-test metadata returned to the invoker."""

    status: Literal["ok"]
    provider: NonEmptyStr
    model: NonEmptyStr
    duration_ms: int = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    response_digest: NonEmptyStr


class AgentCoreInvocationResponse(StrictModel):
    """AgentCore HTTP response envelope."""

    output: AgentCoreInvocationOutput


class AgentCorePingResponse(StrictModel):
    """AgentCore Runtime health response."""

    status: Literal["Healthy"] = "Healthy"


def create_agentcore_app(model: StructuredModel | None = None) -> FastAPI:
    """Create the isolated AgentCore hosting and Bedrock-access smoke application."""

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        if model is not None:
            application.state.structured_model = model
            yield
            return

        settings = Settings()  # type: ignore[call-arg]
        if settings.llm_provider != "bedrock":
            raise ValueError("AgentCore smoke deployment requires AIOS_LLM_PROVIDER=bedrock")
        application.state.structured_model = build_structured_model(
            settings,
            max_output_tokens=_MAX_OUTPUT_TOKENS,
            max_format_retries=_MAX_FORMAT_RETRIES,
        )
        yield

    application = FastAPI(
        title="AIOS Remediation AgentCore Smoke Probe",
        description="Smoke-only AgentCore Runtime and Bedrock connectivity probe; it performs no remediation.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @application.get("/ping", response_model=AgentCorePingResponse, operation_id="agentcore_ping")
    async def ping() -> AgentCorePingResponse:
        return AgentCorePingResponse()

    @application.post(
        "/invocations",
        response_model=AgentCoreInvocationResponse,
        operation_id="invoke_agentcore_smoke_probe",
    )
    async def invoke(
        invocation: AgentCoreInvocationRequest,
        request: Request,
    ) -> AgentCoreInvocationResponse:
        structured_model: StructuredModel = request.app.state.structured_model
        try:
            generation = await structured_model.generate(
                ModelRequest(
                    operation=ModelOperation.AGENTCORE_SMOKE,
                    prompt_version=_PROMPT_VERSION,
                    system_instruction=(
                        "This is a bounded infrastructure smoke probe. Return status exactly 'ok' in the requested "
                        "schema. Do not add commentary, call tools, or use external data."
                    ),
                    payload={"probe": invocation.input.probe},
                ),
                AgentCoreProbeResult,
            )
        except Exception as exc:  # noqa: BLE001 - redact the external provider boundary
            _LOGGER.warning("AgentCore Bedrock smoke probe failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="BEDROCK_PROBE_FAILED",
            ) from exc

        record = generation.record
        return AgentCoreInvocationResponse(
            output=AgentCoreInvocationOutput(
                status=generation.value.status,
                provider=record.provider,
                model=record.model,
                duration_ms=record.duration_ms,
                input_tokens=record.input_tokens,
                output_tokens=record.output_tokens,
                response_digest=record.output_digest,
            )
        )

    return application


app = create_agentcore_app()
