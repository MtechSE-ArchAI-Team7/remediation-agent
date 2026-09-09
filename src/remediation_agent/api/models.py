"""Small response models owned by the HTTP boundary."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from remediation_agent.domain.enums import OperationalToolExecutionMode
from remediation_agent.domain.models import OperationalToolDescriptor, StrictModel


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


class ToolCatalogResponse(StrictModel):
    """Versioned public inventory of implemented operational tools."""

    catalog_version: Literal["1.0"] = "1.0"
    total_tools: int = Field(ge=1)
    model_callable_tools: int = Field(ge=0)
    workflow_only_tools: int = Field(ge=0)
    tools: tuple[OperationalToolDescriptor, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def counts_match_tools(self) -> ToolCatalogResponse:
        identifiers = [item.tool_id for item in self.tools]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("tool identifiers must be unique")
        model_count = sum(
            item.execution_mode is not OperationalToolExecutionMode.DETERMINISTIC_WORKFLOW for item in self.tools
        )
        if self.total_tools != len(self.tools):
            raise ValueError("total_tools does not match the catalogue")
        if self.model_callable_tools != model_count:
            raise ValueError("model_callable_tools does not match the catalogue")
        if self.workflow_only_tools != len(self.tools) - model_count:
            raise ValueError("workflow_only_tools does not match the catalogue")
        return self


class ErrorResponse(StrictModel):
    """Error envelope used by explicit FastAPI HTTP exceptions."""

    detail: str
