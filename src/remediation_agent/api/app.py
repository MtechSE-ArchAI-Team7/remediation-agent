"""FastAPI application and production dependency lifecycle."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status

from remediation_agent.adapters.checkpoint import postgres_checkpointer
from remediation_agent.adapters.evidence import JsonlAuditSink, LocalArtifactStore
from remediation_agent.adapters.models import build_structured_model
from remediation_agent.adapters.pr import DraftPullRequestProvider
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.adapters.sandbox import DockerSandboxExecutor
from remediation_agent.config import Settings
from remediation_agent.domain.models import ApprovalDecisionV1, DiagnosisHandoffV1, RemediationRunView
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from remediation_agent.service import ApprovalConflictError, RemediationService, RunNotFoundError
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
        repository = LocalGitRepository(
            settings.workspace_root,
            author_name=settings.git_author_name,
            author_email=settings.git_author_email,
        )
        sandbox = DockerSandboxExecutor(settings.workspace_root, settings.sandbox_image)
        pr_provider = DraftPullRequestProvider(
            token=settings.github_token.get_secret_value() if settings.github_token else None,
            writes_enabled=settings.github_writes_enabled and policy_config.github.writes_enabled,
        )
        artifact_store = LocalArtifactStore(settings.artifact_root)
        audit_sink = JsonlAuditSink(settings.artifact_root)
        async with postgres_checkpointer(dsn, encryption_key) as checkpointer:
            nodes = WorkflowNodes(
                policy=policy,
                model=model,
                repository=repository,
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
            )
            yield

    application = FastAPI(
        title="AIOS Resolution/Remediation Agent",
        version="0.1.0",
        lifespan=lifespan,
    )

    @application.get("/")
    async def root() -> dict[str, str]:
        return {"name": "AIOS Resolution/Remediation Agent", "architecture": "one-agent-langgraph-workflow"}

    @application.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/readyz")
    async def readiness(request: Request) -> dict[str, str]:
        if not hasattr(request.app.state, "remediation_service"):
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="runtime is not ready")
        runtime: RemediationService = request.app.state.remediation_service
        if not await runtime.ready():
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="checkpoint store is not ready")
        return {"status": "ready"}

    @application.post("/v1/remediations", response_model=RemediationRunView, status_code=status.HTTP_202_ACCEPTED)
    async def start_remediation(
        handoff: DiagnosisHandoffV1,
        runtime: Annotated[RemediationService, Depends(_service)],
    ) -> RemediationRunView:
        return await runtime.start(handoff)

    @application.post(
        "/v1/remediations/{run_id}/approvals",
        response_model=RemediationRunView,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def submit_approval(
        run_id: str,
        decision: ApprovalDecisionV1,
        runtime: Annotated[RemediationService, Depends(_service)],
    ) -> RemediationRunView:
        try:
            return await runtime.approve(run_id, decision)
        except RunNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except ApprovalConflictError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    @application.get("/v1/remediations/{run_id}", response_model=RemediationRunView)
    async def get_remediation(
        run_id: str,
        runtime: Annotated[RemediationService, Depends(_service)],
    ) -> RemediationRunView:
        try:
            return await runtime.get(run_id)
        except RunNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return application


def _service(request: Request) -> RemediationService:
    runtime: RemediationService = request.app.state.remediation_service
    return runtime


app = create_app()
