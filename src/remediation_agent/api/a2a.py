"""Hosted AgentCore composition root for A2A Protocol 1.0."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import MethodType
from typing import Any, cast

from a2a.server.context import ServerCallContext
from a2a.server.routes import create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskStore
from a2a.types import a2a_pb2 as a2a_pb
from a2a.utils.constants import PROTOCOL_VERSION_1_0, VERSION_HEADER
from bedrock_agentcore.runtime import build_a2a_app
from bedrock_agentcore.runtime.a2a import BedrockCallContextBuilder
from starlette.applications import Starlette

from remediation_agent.adapters.a2a_task_store import S3A2ATaskStore
from remediation_agent.api.a2a_contracts import (
    APPROVAL_DECISION_MEDIA_TYPE,
    APPROVAL_REQUEST_MEDIA_TYPE,
    DELIVERY_RECEIPT_MEDIA_TYPE,
    DIAGNOSIS_HANDOFF_MEDIA_TYPE,
    PROVIDER_PROBE_REQUEST_MEDIA_TYPE,
    PROVIDER_PROBE_RESULT_MEDIA_TYPE,
    REMEDIATION_HANDOFF_MEDIA_TYPE,
)
from remediation_agent.api.a2a_executor import RemediationA2AExecutor
from remediation_agent.api.agentcore import create_agentcore_app
from remediation_agent.config import Settings
from remediation_agent.ports.protocols import StructuredModel
from remediation_agent.service import RemediationService


def build_agent_card(runtime_url: str = "http://localhost:9000/") -> a2a_pb.AgentCard:
    """Return the public, versioned Agent 3 capability contract."""

    sigv4 = a2a_pb.SecurityScheme(
        api_key_security_scheme=a2a_pb.APIKeySecurityScheme(
            name="Authorization",
            location="header",
            description="AWS Signature Version 4 credentials supplied by AgentCore",
        )
    )
    security = [
        a2a_pb.SecurityRequirement(
            schemes={"aws_sigv4": a2a_pb.StringList(list=[])},
        )
    ]
    return a2a_pb.AgentCard(
        name="AIOS Resolution/Remediation Agent",
        description=(
            "The single policy-bounded Agent 3 LangGraph workflow for repository remediation and readiness probes."
        ),
        version="1.0.0",
        supported_interfaces=[
            a2a_pb.AgentInterface(
                url=runtime_url,
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            )
        ],
        capabilities=a2a_pb.AgentCapabilities(
            streaming=True,
            push_notifications=False,
            extended_agent_card=False,
        ),
        security_schemes={"aws_sigv4": sigv4},
        security_requirements=security,
        default_input_modes=[DIAGNOSIS_HANDOFF_MEDIA_TYPE, APPROVAL_DECISION_MEDIA_TYPE],
        default_output_modes=[
            APPROVAL_REQUEST_MEDIA_TYPE,
            REMEDIATION_HANDOFF_MEDIA_TYPE,
            DELIVERY_RECEIPT_MEDIA_TYPE,
        ],
        skills=[
            a2a_pb.AgentSkill(
                id="remediate_repository",
                name="Remediate repository",
                description=(
                    "Inspect an immutable repository revision, prepare a policy-bounded change, validate it in a "
                    "restricted workspace, and return a versioned remediation handoff."
                ),
                tags=["remediation", "repository", "langgraph"],
                input_modes=[DIAGNOSIS_HANDOFF_MEDIA_TYPE, APPROVAL_DECISION_MEDIA_TYPE],
                output_modes=[
                    APPROVAL_REQUEST_MEDIA_TYPE,
                    REMEDIATION_HANDOFF_MEDIA_TYPE,
                    DELIVERY_RECEIPT_MEDIA_TYPE,
                ],
                security_requirements=security,
            ),
            a2a_pb.AgentSkill(
                id="runtime_readiness_probe",
                name="Runtime readiness probe",
                description="Run the fixed, bounded provider probe used by deployment validation.",
                tags=["readiness", "provider-probe"],
                input_modes=[PROVIDER_PROBE_REQUEST_MEDIA_TYPE],
                output_modes=[PROVIDER_PROBE_RESULT_MEDIA_TYPE],
                security_requirements=security,
            ),
        ],
    )


def create_a2a_app(
    model: StructuredModel | None = None,
    service: RemediationService | None = None,
    *,
    probe_provider: str | None = None,
    task_store: TaskStore | None = None,
    runtime_url: str | None = None,
) -> Starlette:
    """Compose the hosted A2A application with injectable offline boundaries."""

    executor = RemediationA2AExecutor(
        service,
        model=model,
        probe_provider=probe_provider,
    )
    context_builder = _AgentCoreV1CallContextBuilder()
    store = _DeferredTaskStore(task_store or InMemoryTaskStore())
    card = build_agent_card(runtime_url or "http://localhost:9000/")
    application = cast(
        Starlette,
        build_a2a_app(
            executor,
            card,
            runtime_url=runtime_url,
            task_store=store,
            context_builder=cast(Any, context_builder),
        ),
    )
    _replace_compatibility_route(application, context_builder)

    dependencies = create_agentcore_app(
        model,
        service,
        probe_provider=cast(Any, probe_provider),
    )
    dependency_lifespan = dependencies.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application_scope: Starlette) -> AsyncIterator[None]:
        del application_scope
        async with dependency_lifespan(dependencies):
            runtime = cast(RemediationService, dependencies.state.remediation_service)
            configured_model = cast(StructuredModel | None, getattr(dependencies.state, "structured_model", None))
            configured_provider = cast(str | None, getattr(dependencies.state, "probe_provider", None))
            executor.configure(
                runtime,
                model=configured_model,
                probe_provider=configured_provider,
            )
            if task_store is None and service is None:
                settings = Settings()  # type: ignore[call-arg]
                memory_id, secret_arn, artifact_bucket = settings.require_agentcore_configuration()
                del memory_id, secret_arn
                if settings.aws_region is None:
                    raise ValueError("AIOS_AWS_REGION is required for the hosted A2A task store")
                store.configure(
                    S3A2ATaskStore(
                        artifact_bucket,
                        region_name=settings.aws_region,
                        prefix=settings.a2a_task_store_prefix,
                        max_projection_bytes=settings.a2a_task_store_max_bytes,
                    )
                )
            yield

    application.router.lifespan_context = lifespan
    return application


def _replace_compatibility_route(
    application: Starlette,
    context_builder: BedrockCallContextBuilder,
) -> None:
    """Replace AgentCore's compatibility dispatcher with the strict v1 dispatcher."""

    for index, route in enumerate(application.router.routes):
        if getattr(route, "path", None) != "/":
            continue
        endpoint = getattr(route, "endpoint", None)
        dispatcher = getattr(endpoint, "__self__", None)
        request_handler = getattr(dispatcher, "request_handler", None)
        if request_handler is None:
            raise RuntimeError("AgentCore A2A JSON-RPC route shape changed")

        async def reject_cancel(handler: object, params: object, context: object) -> None:
            del handler, params, context
            from a2a.utils.errors import TaskNotCancelableError

            raise TaskNotCancelableError

        request_handler.on_cancel_task = MethodType(reject_cancel, request_handler)
        application.router.routes[index] = create_jsonrpc_routes(
            request_handler=request_handler,
            rpc_url="/",
            context_builder=cast(Any, context_builder),
            enable_v0_3_compat=False,
        )[0]
        return
    raise RuntimeError("AgentCore A2A JSON-RPC route was not created")


class _AgentCoreV1CallContextBuilder(BedrockCallContextBuilder):
    """Supply the fixed A2A v1 contract omitted by AgentCore's invocation proxy."""

    def build(self, request: Any) -> ServerCallContext:
        """Default a hosted invocation to v1 without overriding a client version."""

        context = cast(ServerCallContext, super().build(request))
        headers = context.state.get("headers")
        session_id = context.state.get("session_id")
        if not isinstance(headers, dict) or not isinstance(session_id, str) or not session_id:
            return context

        version_header = VERSION_HEADER.casefold()
        if not any(isinstance(name, str) and name.casefold() == version_header for name in headers):
            headers[VERSION_HEADER] = PROTOCOL_VERSION_1_0
        return context


class _DeferredTaskStore(TaskStore):
    """Keep the SDK request handler stable while hosted dependencies start."""

    def __init__(self, backend: TaskStore) -> None:
        self._backend = backend

    def configure(self, backend: TaskStore) -> None:
        self._backend = backend

    async def save(self, task: a2a_pb.Task, context: ServerCallContext) -> None:
        await self._backend.save(task, context)

    async def get(self, task_id: str, context: ServerCallContext) -> a2a_pb.Task | None:
        return await self._backend.get(task_id, context)

    async def list(
        self,
        params: a2a_pb.ListTasksRequest,
        context: ServerCallContext,
    ) -> a2a_pb.ListTasksResponse:
        return await self._backend.list(params, context)

    async def delete(self, task_id: str, context: ServerCallContext) -> None:
        await self._backend.delete(task_id, context)


app = create_a2a_app()
