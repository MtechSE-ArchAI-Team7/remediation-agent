"""Small response models owned by the HTTP boundary."""

from typing import Literal

from remediation_agent.domain.models import StrictModel


class ServiceInfoResponse(StrictModel):
    """Static service identity returned from the root endpoint."""

    name: Literal["AIOS Resolution/Remediation Agent"] = "AIOS Resolution/Remediation Agent"
    architecture: Literal["one-agent-langgraph-workflow"] = "one-agent-langgraph-workflow"


class HealthResponse(StrictModel):
    """Process-liveness response."""

    status: Literal["ok"] = "ok"


class ReadinessResponse(StrictModel):
    """Dependency-readiness response."""

    status: Literal["ready"] = "ready"


class ErrorResponse(StrictModel):
    """Error envelope used by explicit FastAPI HTTP exceptions."""

    detail: str
