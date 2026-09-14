"""Bedrock AgentCore HTTP contract for the full remediation workflow."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import Field

from remediation_agent.adapters.agentcore import (
    AgentCoreWorkspaceRecovery,
    S3ArtifactStore,
    S3AuditSink,
    SecretsManagerRuntimeSecretProvider,
)
from remediation_agent.adapters.agentcore_sandbox import AgentCoreCodeInterpreterSandbox
from remediation_agent.adapters.checkpoint import agentcore_memory_checkpointer
from remediation_agent.adapters.credentials import GitHubAskpassCredentialProvider
from remediation_agent.adapters.mcp import GitHubRemoteMcpInspectionTools
from remediation_agent.adapters.models import build_structured_model
from remediation_agent.adapters.pr import DraftPullRequestProvider
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.config import Settings
from remediation_agent.domain.enums import ModelOperation
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    DiagnosisHandoffV1,
    NonEmptyStr,
    RemediationRunView,
    StrictModel,
)
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from remediation_agent.ports.models import ModelRequest
from remediation_agent.ports.protocols import StructuredModel
from remediation_agent.service import (
    ApprovalConflictError,
    InvocationDeadlineError,
    RemediationService,
    RunNotFoundError,
)
from remediation_agent.workflow.graph import build_graph
from remediation_agent.workflow.nodes import WorkflowNodes

_LOGGER = logging.getLogger(__name__)
_PROMPT_VERSION = "agentcore-smoke-v1"
_ACTOR_ID = "resolution-remediation-agent"
_SESSION_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id"


class AgentCoreProbeInput(StrictModel):
    probe: Literal["bedrock"]


class AgentCoreProbeInvocation(StrictModel):
    action: Literal["probe"]
    input: AgentCoreProbeInput


class AgentCoreStartInvocation(StrictModel):
    action: Literal["start"]
    input: DiagnosisHandoffV1


class AgentCoreGetInvocation(StrictModel):
    action: Literal["get"]
    run_id: NonEmptyStr


class AgentCoreApproveInvocation(StrictModel):
    action: Literal["approve"]
    run_id: NonEmptyStr
    decision: ApprovalDecisionV1


AgentCoreInvocationRequest = Annotated[
    AgentCoreProbeInvocation | AgentCoreStartInvocation | AgentCoreGetInvocation | AgentCoreApproveInvocation,
    Field(discriminator="action"),
]


class AgentCoreProbeResult(StrictModel):
    status: Literal["ok"]


class AgentCoreProbeOutput(StrictModel):
    status: Literal["ok"]
    provider: NonEmptyStr
    model: NonEmptyStr
    duration_ms: int = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    response_digest: NonEmptyStr


class AgentCoreProbeResponse(StrictModel):
    output: AgentCoreProbeOutput


class AgentCoreRunResponse(StrictModel):
    output: RemediationRunView


class AgentCorePingResponse(StrictModel):
    status: Literal["Healthy"] = "Healthy"


def create_agentcore_app(
    model: StructuredModel | None = None,
    service: RemediationService | None = None,
) -> FastAPI:
    """Create the AgentCore application with injectable boundaries for offline tests."""

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        if model is not None:
            application.state.structured_model = model
        if service is not None:
            application.state.remediation_service = service
        if model is not None or service is not None:
            yield
            return

        settings = Settings()  # type: ignore[call-arg]
        if settings.llm_provider != "bedrock" or settings.aws_region is None:
            raise ValueError("AgentCore deployment requires the Bedrock provider and AWS Region")
        memory_id, secret_arn, artifact_bucket = settings.require_agentcore_configuration()
        policy_config = load_policy(settings.policy_file)
        policy = PolicyEngine(policy_config)
        runtime_secret = await SecretsManagerRuntimeSecretProvider(
            secret_arn,
            region_name=settings.aws_region,
        ).load()
        github_token = runtime_secret.github_token.get_secret_value()
        structured_model = build_structured_model(
            settings,
            policy_config.limits.max_model_output_tokens,
            policy_config.limits.max_model_format_retries,
        )
        credential_provider = GitHubAskpassCredentialProvider(github_token)
        repository = LocalGitRepository(
            settings.workspace_root,
            author_name=settings.git_author_name,
            author_email=settings.git_author_email,
            credential_provider=credential_provider,
        )
        nodes = WorkflowNodes(
            policy=policy,
            model=structured_model,
            repository=repository,
            inspection_tools=GitHubRemoteMcpInspectionTools(github_token, policy),
            sandbox=AgentCoreCodeInterpreterSandbox(
                settings.workspace_root,
                region_name=settings.aws_region,
                code_interpreter_identifier=settings.code_interpreter_identifier,
                validation_bundle=settings.code_interpreter_bundle,
            ),
            pr_provider=DraftPullRequestProvider(
                token=github_token,
                writes_enabled=settings.github_writes_enabled and policy_config.github.writes_enabled,
            ),
            artifact_store=S3ArtifactStore(artifact_bucket, region_name=settings.aws_region),
            audit_sink=S3AuditSink(artifact_bucket, region_name=settings.aws_region),
            prompt_version=settings.prompt_version,
            github_writes_enabled=settings.github_writes_enabled,
            github_repository=settings.github_repository,
        )
        checkpointer = agentcore_memory_checkpointer(
            memory_id,
            runtime_secret.checkpoint_encryption_key.get_secret_value(),
            region_name=settings.aws_region,
        )
        application.state.structured_model = structured_model
        application.state.remediation_service = RemediationService(
            build_graph(nodes, checkpointer),
            max_active_runs=policy_config.limits.max_active_runs,
            actor_id=_ACTOR_ID,
            invocation_timeout_seconds=settings.invocation_timeout_seconds,
            workspace_recovery=AgentCoreWorkspaceRecovery(repository),
        )
        yield

    application = FastAPI(
        title="AIOS Resolution/Remediation Agent on AgentCore",
        description="The one-agent LangGraph remediation workflow hosted behind the AgentCore HTTP contract.",
        version="0.2.0",
        lifespan=lifespan,
    )

    @application.get("/ping", response_model=AgentCorePingResponse, operation_id="agentcore_ping")
    async def ping() -> AgentCorePingResponse:
        return AgentCorePingResponse()

    @application.post(
        "/invocations",
        response_model=AgentCoreProbeResponse | AgentCoreRunResponse,
        operation_id="invoke_agentcore_remediation",
    )
    async def invoke(
        invocation: AgentCoreInvocationRequest,
        request: Request,
        session_id: Annotated[str, Header(alias=_SESSION_HEADER)],
    ) -> AgentCoreProbeResponse | AgentCoreRunResponse:
        canonical_session_id = _validate_session_id(session_id)
        if isinstance(invocation, AgentCoreProbeInvocation):
            return await _invoke_probe(invocation, request)

        raw_runtime = getattr(request.app.state, "remediation_service", None)
        if raw_runtime is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="RUNTIME_NOT_CONFIGURED")
        runtime = cast(RemediationService, raw_runtime)
        try:
            if isinstance(invocation, AgentCoreStartInvocation):
                view = await runtime.start(invocation.input, run_id=canonical_session_id)
            elif isinstance(invocation, AgentCoreGetInvocation):
                _require_matching_run(invocation.run_id, canonical_session_id)
                view = await runtime.get(invocation.run_id)
            else:
                _require_matching_run(invocation.run_id, canonical_session_id)
                view = await runtime.approve(invocation.run_id, invocation.decision)
        except RunNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="RUN_NOT_FOUND") from exc
        except ApprovalConflictError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="APPROVAL_CONFLICT") from exc
        except InvocationDeadlineError as exc:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail="INVOCATION_DEADLINE_EXCEEDED"
            ) from exc
        except RuntimeError as exc:
            if str(exc) == "WORKSPACE_RECOVERY_UNSAFE":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="WORKSPACE_RECOVERY_UNSAFE") from exc
            _LOGGER.warning("AgentCore remediation invocation failed: %s", type(exc).__name__)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="RUNTIME_INVOCATION_FAILED"
            ) from exc
        return AgentCoreRunResponse(output=view)

    return application


async def _invoke_probe(invocation: AgentCoreProbeInvocation, request: Request) -> AgentCoreProbeResponse:
    structured_model = getattr(request.app.state, "structured_model", None)
    if structured_model is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="BEDROCK_PROBE_NOT_CONFIGURED")
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
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="BEDROCK_PROBE_FAILED") from exc
    record = generation.record
    return AgentCoreProbeResponse(
        output=AgentCoreProbeOutput(
            status=generation.value.status,
            provider=record.provider,
            model=record.model,
            duration_ms=record.duration_ms,
            input_tokens=record.input_tokens,
            output_tokens=record.output_tokens,
            response_digest=record.output_digest,
        )
    )


def _validate_session_id(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="INVALID_RUNTIME_SESSION_ID") from exc
    canonical = str(parsed)
    if canonical != value.lower():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="INVALID_RUNTIME_SESSION_ID")
    return canonical


def _require_matching_run(run_id: str, session_id: str) -> None:
    if run_id != session_id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="RUN_SESSION_MISMATCH")


app = create_agentcore_app()
