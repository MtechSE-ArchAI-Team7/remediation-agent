"""FastAPI application and production dependency lifecycle."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Body, Depends, FastAPI, HTTPException, Path, Request, status

from remediation_agent.adapters.a2a_delivery import AgentCoreA2ADelivery
from remediation_agent.adapters.checkpoint import postgres_checkpointer
from remediation_agent.adapters.credentials import GitHubAskpassCredentialProvider
from remediation_agent.adapters.evidence import JsonlAuditSink, LocalArtifactStore
from remediation_agent.adapters.mcp import GitHubRemoteMcpInspectionTools
from remediation_agent.adapters.models import build_structured_model
from remediation_agent.adapters.pr import DraftPullRequestProvider
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.adapters.sandbox import DockerSandboxExecutor
from remediation_agent.api.models import (
    ErrorResponse,
    HealthResponse,
    ReadinessResponse,
    ServiceInfoResponse,
    ToolCatalogResponse,
)
from remediation_agent.api.openapi import (
    APPROVAL_DECISION_EXAMPLES,
    ERROR_EXAMPLES,
    OPENAPI_TAGS,
    RUN_RESPONSE_EXAMPLES,
    START_REMEDIATION_EXAMPLES,
)
from remediation_agent.config import Settings
from remediation_agent.domain.models import ApprovalDecisionV1, DiagnosisHandoffV1, RemediationRunView
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from remediation_agent.service import ApprovalConflictError, RemediationService, RunNotFoundError
from remediation_agent.tools.catalog import OPERATIONAL_TOOL_CATALOG, operational_tool_counts
from remediation_agent.workflow.graph import build_graph
from remediation_agent.workflow.nodes import WorkflowNodes


def create_app(service: RemediationService | None = None) -> FastAPI:
    """Create an API with an injected test service or production runtime dependencies."""

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        if service is not None:
            application.state.remediation_service = service
            yield
            return

        settings = Settings()  # type: ignore[call-arg]
        policy_config = load_policy(settings.policy_file)
        policy = PolicyEngine(policy_config)
        dsn, encryption_key = settings.require_persistent_checkpointing()
        model = build_structured_model(
            settings,
            policy_config.limits.max_model_output_tokens,
            policy_config.limits.max_model_format_retries,
        )
        try:
            github_token = settings.require_github_token()
            credential_provider = GitHubAskpassCredentialProvider(github_token)
            repository = LocalGitRepository(
                settings.workspace_root,
                author_name=settings.git_author_name,
                author_email=settings.git_author_email,
                credential_provider=credential_provider,
            )
            inspection_tools = GitHubRemoteMcpInspectionTools(github_token, policy)
            sandbox = DockerSandboxExecutor(settings.workspace_root, settings.sandbox_image)
            pr_provider = DraftPullRequestProvider(
                token=github_token,
                writes_enabled=settings.github_writes_enabled and policy_config.github.writes_enabled,
            )
            artifact_store = LocalArtifactStore(settings.artifact_root)
            audit_sink = JsonlAuditSink(settings.artifact_root)
            async with postgres_checkpointer(dsn, encryption_key) as checkpointer:
                nodes = WorkflowNodes(
                    policy=policy,
                    model=model,
                    repository=repository,
                    inspection_tools=inspection_tools,
                    sandbox=sandbox,
                    pr_provider=pr_provider,
                    artifact_store=artifact_store,
                    audit_sink=audit_sink,
                    prompt_version=settings.prompt_version,
                    github_writes_enabled=settings.github_writes_enabled,
                    github_repository=settings.github_repository,
                )
                application.state.remediation_service = RemediationService(
                    build_graph(nodes, checkpointer),
                    max_active_runs=policy_config.limits.max_active_runs,
                    handoff_delivery=_handoff_delivery(settings),
                    delivery_audit_sink=audit_sink,
                )
                yield
        finally:
            await model.aclose()

    application = FastAPI(
        title="AIOS Resolution/Remediation Agent",
        description=(
            "Policy-bounded repository remediation. The API does not implement caller authentication; "
            "deployment and network controls must restrict access to authorized operators."
        ),
        version="0.1.0",
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
    )

    @application.get(
        "/",
        response_model=ServiceInfoResponse,
        tags=["Service"],
        summary="Get service identity",
        description="Return the service name and its one-agent LangGraph architecture identifier.",
        operation_id="get_service_info",
        response_description="Service identity and architecture.",
    )
    async def root() -> ServiceInfoResponse:
        return ServiceInfoResponse()

    @application.get(
        "/healthz",
        response_model=HealthResponse,
        tags=["Service"],
        summary="Check process liveness",
        description="Return success when the API process can serve requests; dependencies are checked by `/readyz`.",
        operation_id="get_health",
        response_description="The API process is alive.",
    )
    async def health() -> HealthResponse:
        return HealthResponse()

    @application.get(
        "/readyz",
        response_model=ReadinessResponse,
        tags=["Service"],
        summary="Check runtime readiness",
        description="Confirm that runtime dependencies were constructed and checkpoint persistence is reachable.",
        operation_id="get_readiness",
        response_description="The service and checkpoint store are ready.",
        responses={
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "model": ErrorResponse,
                "description": "Runtime construction or checkpoint persistence is unavailable.",
                "content": {"application/json": {"examples": {"not_ready": ERROR_EXAMPLES["not_ready"]}}},
            }
        },
    )
    async def readiness(request: Request) -> ReadinessResponse:
        if not hasattr(request.app.state, "remediation_service"):
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="runtime is not ready")
        runtime: RemediationService = request.app.state.remediation_service
        if not await runtime.ready():
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="checkpoint store is not ready")
        return ReadinessResponse()

    @application.get(
        "/v1/tools",
        response_model=ToolCatalogResponse,
        tags=["Tools"],
        summary="List operational tools",
        description=(
            "Return the versioned catalogue of model-callable inspection controls and deterministic workflow-only "
            "operations. Listing the catalogue invokes no tool and creates no side effect."
        ),
        operation_id="list_operational_tools",
        response_description="The implemented operational tool catalogue and authority boundaries.",
    )
    async def list_tools() -> ToolCatalogResponse:
        model_count, workflow_count = operational_tool_counts()
        return ToolCatalogResponse(
            total_tools=len(OPERATIONAL_TOOL_CATALOG),
            model_callable_tools=model_count,
            workflow_only_tools=workflow_count,
            tools=OPERATIONAL_TOOL_CATALOG,
        )

    @application.post(
        "/v1/remediations",
        response_model=RemediationRunView,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["Remediations"],
        summary="Start a remediation run",
        description=(
            "Validate an Agent 2 diagnosis handoff and execute the single remediation workflow synchronously until "
            "it reaches a terminal state or a human-approval interrupt. Inspect `status` in the accepted response."
        ),
        operation_id="start_remediation",
        response_description="The current run view, which may be terminal or awaiting approval.",
        responses={
            status.HTTP_202_ACCEPTED: {
                "content": {"application/json": {"examples": RUN_RESPONSE_EXAMPLES}},
            }
        },
    )
    async def start_remediation(
        handoff: Annotated[DiagnosisHandoffV1, Body(openapi_examples=START_REMEDIATION_EXAMPLES)],
        runtime: Annotated[RemediationService, Depends(_service)],
    ) -> RemediationRunView:
        return await runtime.start(handoff)

    @application.post(
        "/v1/remediations/{run_id}/approvals",
        response_model=RemediationRunView,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["Remediations"],
        summary="Submit an approval decision",
        description=(
            "Resume a run waiting at an approval interrupt. The approval ID and scope digest must exactly match "
            "the pending request; stale or mismatched approvals are rejected."
        ),
        operation_id="submit_remediation_approval",
        response_description="The resumed run view, which may be terminal or reach another approval interrupt.",
        responses={
            status.HTTP_202_ACCEPTED: {
                "content": {"application/json": {"examples": RUN_RESPONSE_EXAMPLES}},
            },
            status.HTTP_404_NOT_FOUND: {
                "model": ErrorResponse,
                "description": "The run identifier is invalid or no persisted run exists.",
                "content": {"application/json": {"examples": {"not_found": ERROR_EXAMPLES["not_found"]}}},
            },
            status.HTTP_409_CONFLICT: {
                "model": ErrorResponse,
                "description": "The run is not awaiting approval or the decision does not match the pending scope.",
                "content": {
                    "application/json": {"examples": {"approval_conflict": ERROR_EXAMPLES["approval_conflict"]}}
                },
            },
        },
    )
    async def submit_approval(
        run_id: Annotated[str, Path(description="UUID returned when the remediation run was started.")],
        decision: Annotated[ApprovalDecisionV1, Body(openapi_examples=APPROVAL_DECISION_EXAMPLES)],
        runtime: Annotated[RemediationService, Depends(_service)],
    ) -> RemediationRunView:
        try:
            return await runtime.approve(run_id, decision)
        except RunNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except ApprovalConflictError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    @application.get(
        "/v1/remediations/{run_id}",
        response_model=RemediationRunView,
        tags=["Remediations"],
        summary="Get a remediation run",
        description="Return the latest persisted state for an interrupted or completed remediation run.",
        operation_id="get_remediation",
        response_description="The latest persisted run view.",
        responses={
            status.HTTP_200_OK: {
                "content": {"application/json": {"examples": RUN_RESPONSE_EXAMPLES}},
            },
            status.HTTP_404_NOT_FOUND: {
                "model": ErrorResponse,
                "description": "The run identifier is invalid or no persisted run exists.",
                "content": {"application/json": {"examples": {"not_found": ERROR_EXAMPLES["not_found"]}}},
            },
        },
    )
    async def get_remediation(
        run_id: Annotated[str, Path(description="UUID returned when the remediation run was started.")],
        runtime: Annotated[RemediationService, Depends(_service)],
    ) -> RemediationRunView:
        try:
            return await runtime.get(run_id)
        except RunNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return application


def _handoff_delivery(settings: Settings) -> AgentCoreA2ADelivery | None:
    if not settings.agent4_delivery_enabled:
        return None
    if settings.agent4_runtime_arn is None or settings.agent4_region is None:
        raise ValueError("Agent 4 delivery configuration is incomplete")
    return AgentCoreA2ADelivery(
        settings.agent4_runtime_arn,
        region_name=settings.agent4_region,
        qualifier=settings.agent4_qualifier,
        timeout_seconds=settings.agent4_timeout_seconds,
    )


def _service(request: Request) -> RemediationService:
    runtime: RemediationService = request.app.state.remediation_service
    return runtime


app = create_app()
