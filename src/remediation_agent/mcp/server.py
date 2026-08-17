"""Stdio MCP server for bounded inspection of one assigned workspace."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator

from remediation_agent.adapters.evidence import SecretRedactor
from remediation_agent.adapters.repository import LocalGitRepository
from remediation_agent.domain.enums import InspectionToolStatus, PolicyDecision
from remediation_agent.domain.models import InspectionArtifact, InspectionToolResponse, WorkspaceRef
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from remediation_agent.ports.models import ReadFileRequest, SearchRequest, TreeRequest

_WORKSPACE_ROOT_ENV = "AIOS_MCP_WORKSPACE_ROOT"
_WORKSPACE_ID_ENV = "AIOS_MCP_WORKSPACE_ID"
_BASE_COMMIT_ENV = "AIOS_MCP_BASE_COMMIT"
_POLICY_FILE_ENV = "AIOS_MCP_POLICY_FILE"

RepositoryPath = Annotated[str, Field(min_length=1, max_length=500)]
SearchQuery = Annotated[str, Field(min_length=1, max_length=200)]


class RepositoryMcpSettings(BaseModel):
    """Trusted process configuration supplied by the remediation host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    workspace_root: Path
    workspace_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    base_commit: str = Field(pattern=r"^[0-9a-fA-F]{7,64}$")
    policy_file: Path

    @field_validator("workspace_root", "policy_file")
    @classmethod
    def paths_are_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("MCP host paths must be absolute")
        return value

    @classmethod
    def from_environment(cls) -> RepositoryMcpSettings:
        required = {
            "workspace_root": os.environ.get(_WORKSPACE_ROOT_ENV),
            "workspace_id": os.environ.get(_WORKSPACE_ID_ENV),
            "base_commit": os.environ.get(_BASE_COMMIT_ENV),
            "policy_file": os.environ.get(_POLICY_FILE_ENV),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"missing MCP host configuration: {', '.join(sorted(missing))}")
        return cls.model_validate(required)


def create_server(settings: RepositoryMcpSettings) -> FastMCP:
    """Create the three-tool server scoped to one existing workspace."""

    repository = LocalGitRepository(settings.workspace_root)
    policy = PolicyEngine(load_policy(settings.policy_file))
    redactor = SecretRedactor()
    workspace_path = settings.workspace_root / settings.workspace_id
    workspace = WorkspaceRef(
        workspace_id=settings.workspace_id,
        path=str(workspace_path),
        base_commit=settings.base_commit,
    )
    repository.validate_workspace(workspace)
    server = FastMCP(
        "AIOS repository inspection",
        instructions="Expose only bounded read-only operations for the assigned repository workspace.",
        log_level="ERROR",
    )

    def denied(code: str, detail: str) -> InspectionToolResponse:
        return InspectionToolResponse(
            status=InspectionToolStatus.DENIED,
            error_code=code,
            detail=redactor.redact(detail),
        )

    def failed(detail: str) -> InspectionToolResponse:
        return InspectionToolResponse(
            status=InspectionToolStatus.ERROR,
            error_code="INSPECTION_OPERATION_FAILED",
            detail=redactor.redact(detail),
        )

    def path_is_denied(relative_path: str) -> InspectionToolResponse | None:
        if relative_path == ".":
            return None
        try:
            decision = policy.classify_path(relative_path)
        except ValueError as exc:
            return denied("UNSAFE_PATH", str(exc))
        if decision is PolicyDecision.DENY:
            return denied("PATH_DENIED", "Repository path is forbidden by operator policy.")
        return None

    @server.tool(
        name="list_repository_tree",
        description="List a bounded repository tree beneath a relative directory in the assigned workspace.",
        structured_output=True,
    )
    async def list_repository_tree(relative_path: RepositoryPath = ".") -> InspectionToolResponse:
        if rejection := path_is_denied(relative_path):
            return rejection
        try:
            result = await repository.list_tree(
                TreeRequest(
                    workspace=workspace,
                    relative_path=relative_path,
                    max_entries=policy.config.limits.max_tree_entries,
                    forbidden_path_patterns=policy.config.paths.forbidden,
                )
            )
            content = redactor.redact("\n".join(result.entries))
            return InspectionToolResponse(
                status=InspectionToolStatus.SUCCEEDED,
                artifact=InspectionArtifact(
                    kind="TREE",
                    locator=relative_path,
                    content=content,
                    digest=policy.digest_text(content),
                    truncated=result.truncated,
                ),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return failed(str(exc))

    @server.tool(
        name="read_repository_file",
        description="Read one bounded UTF-8 text file at a repository-relative path in the assigned workspace.",
        structured_output=True,
    )
    async def read_repository_file(relative_path: RepositoryPath) -> InspectionToolResponse:
        if rejection := path_is_denied(relative_path):
            return rejection
        try:
            result = await repository.read_file(
                ReadFileRequest(
                    workspace=workspace,
                    relative_path=relative_path,
                    max_bytes=policy.config.limits.max_file_bytes,
                )
            )
            content = redactor.redact(result.content)
            return InspectionToolResponse(
                status=InspectionToolStatus.SUCCEEDED,
                artifact=InspectionArtifact(
                    kind="FILE",
                    locator=result.relative_path,
                    content=content,
                    digest=policy.digest_text(content),
                    truncated=result.truncated,
                ),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return failed(str(exc))

    @server.tool(
        name="search_repository",
        description=(
            "Run one bounded fixed-string search across allowed UTF-8 repository files in the assigned workspace."
        ),
        structured_output=True,
    )
    async def search_repository(query: SearchQuery) -> InspectionToolResponse:
        try:
            result = await repository.search(
                SearchRequest(
                    workspace=workspace,
                    query=query,
                    max_results=policy.config.limits.max_search_results,
                    max_file_bytes=policy.config.limits.max_file_bytes,
                    forbidden_path_patterns=policy.config.paths.forbidden,
                )
            )
            content = redactor.redact(
                "\n".join(f"{hit.relative_path}:{hit.line_number}:{hit.line}" for hit in result.hits)
            )
            return InspectionToolResponse(
                status=InspectionToolStatus.SUCCEEDED,
                artifact=InspectionArtifact(
                    kind="SEARCH",
                    locator=query,
                    content=content,
                    digest=policy.digest_text(content),
                    truncated=result.truncated,
                ),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return failed(str(exc))

    return server


def main() -> None:
    """Run the repository MCP server over stdio."""

    create_server(RepositoryMcpSettings.from_environment()).run(transport="stdio")


if __name__ == "__main__":
    main()
