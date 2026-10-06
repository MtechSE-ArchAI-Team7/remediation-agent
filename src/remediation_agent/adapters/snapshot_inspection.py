"""Real bounded snapshot inspection used by isolated full-workflow qualification."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from langchain_core.tools import BaseTool, StructuredTool

from remediation_agent.adapters.evidence import SecretRedactor
from remediation_agent.domain.enums import InspectionToolStatus, PolicyDecision
from remediation_agent.domain.models import (
    GetFileContentsArgs,
    GetRepositoryTreeArgs,
    InspectionArtifact,
    InspectionToolResponse,
    RepositoryRef,
    SearchCodeArgs,
    WorkspaceRef,
)
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.ports.models import ReadFileRequest, SearchRequest, TreeRequest
from remediation_agent.ports.protocols import RepositoryInspectionPort
from remediation_agent.source import source_artifact


class SnapshotInspectionTools:
    """Fixed inspection operations over real isolated snapshots for offline qualification only."""

    def __init__(self, repository: RepositoryInspectionPort, policy: PolicyEngine) -> None:
        self.repository = repository
        self.policy = policy
        self.redactor = SecretRedactor()
        self.sessions_started = 0
        self.sessions_closed = 0

    @asynccontextmanager
    async def session(
        self,
        repository: RepositoryRef,
        workspace: WorkspaceRef,
    ) -> AsyncIterator[Sequence[BaseTool]]:
        self.sessions_started += 1
        owner, repo = _github_target(repository)

        async def get_repository_tree(
            owner: str,
            repo: str,
            tree_sha: str | None = None,
            recursive: bool = False,
            path_filter: str | None = None,
        ) -> tuple[str, dict[str, object]]:
            _ = recursive
            rejection = self._target_rejection(owner, repo, repository, workspace, tree_sha)
            relative_path = path_filter or "."
            if rejection is None:
                rejection = self._path_rejection(relative_path)
            if rejection:
                return _tool_response(rejection)
            try:
                result = await self.repository.list_tree(
                    TreeRequest(
                        workspace=workspace,
                        relative_path=relative_path,
                        max_entries=self.policy.config.limits.max_tree_entries,
                        forbidden_path_patterns=self.policy.config.paths.forbidden,
                    )
                )
                content = self.redactor.redact("\n".join(result.entries))
                response = InspectionToolResponse(
                    status=InspectionToolStatus.SUCCEEDED,
                    artifact=InspectionArtifact(
                        kind="TREE",
                        locator=relative_path,
                        content=content,
                        digest=self.policy.digest_text(content),
                        truncated=result.truncated,
                    ),
                )
            except (KeyError, OSError, RuntimeError, ValueError) as exc:
                response = self._failed(str(exc))
            return _tool_response(response)

        async def get_file_contents(
            owner: str,
            repo: str,
            path: str | None = None,
            ref: str | None = None,
            sha: str | None = None,
            fields: list[str] | None = None,
        ) -> tuple[str, dict[str, object]]:
            _ = fields
            rejection = self._target_rejection(owner, repo, repository, workspace, sha)
            if rejection is None and ref is not None:
                rejection = InspectionToolResponse(
                    status=InspectionToolStatus.DENIED,
                    error_code="MUTABLE_REF_DENIED",
                    detail="Mutable Git refs are not permitted for inspection.",
                )
            relative_path = path or "."
            if rejection is None:
                rejection = self._path_rejection(relative_path)
            if rejection:
                return _tool_response(rejection)
            try:
                result = await self.repository.read_file(
                    ReadFileRequest(
                        workspace=workspace,
                        relative_path=relative_path,
                        max_bytes=self.policy.config.limits.max_file_bytes,
                    )
                )
                content = result.content
                response = InspectionToolResponse(
                    status=InspectionToolStatus.SUCCEEDED,
                    artifact=source_artifact(result.relative_path, content, truncated=result.truncated),
                )
            except (KeyError, OSError, RuntimeError, ValueError) as exc:
                response = self._failed(str(exc))
            return _tool_response(response)

        async def search_code(
            query: str,
            sort: str | None = None,
            order: str | None = None,
            fields: list[str] | None = None,
            page: int = 1,
            perPage: int = 30,
        ) -> tuple[str, dict[str, object]]:
            _ = (sort, order, fields, page, perPage)
            qualifier = f"repo:{owner}/{repo}"
            if query.count(qualifier) != 1 or "org:" in query or "user:" in query:
                return _tool_response(
                    InspectionToolResponse(
                        status=InspectionToolStatus.DENIED,
                        error_code="SEARCH_SCOPE_DENIED",
                        detail="Code search must contain exactly the assigned repo qualifier.",
                    )
                )
            local_query = query.replace(qualifier, "").strip()
            try:
                result = await self.repository.search(
                    SearchRequest(
                        workspace=workspace,
                        query=local_query,
                        max_results=self.policy.config.limits.max_search_results,
                        max_file_bytes=self.policy.config.limits.max_file_bytes,
                        forbidden_path_patterns=self.policy.config.paths.forbidden,
                    )
                )
                content = self.redactor.redact("\n".join(dict.fromkeys(hit.relative_path for hit in result.hits)))
                response = InspectionToolResponse(
                    status=InspectionToolStatus.SUCCEEDED,
                    artifact=InspectionArtifact(
                        kind="SEARCH",
                        locator=query,
                        content=content,
                        digest=self.policy.digest_text(content),
                        truncated=result.truncated,
                    ),
                )
            except (OSError, RuntimeError, ValueError) as exc:
                response = self._failed(str(exc))
            return _tool_response(response)

        tools = [
            StructuredTool.from_function(
                coroutine=get_repository_tree,
                name="get_repository_tree",
                description="List a bounded repository tree.",
                args_schema=GetRepositoryTreeArgs,
                response_format="content_and_artifact",
            ),
            StructuredTool.from_function(
                coroutine=get_file_contents,
                name="get_file_contents",
                description="Read one bounded repository file.",
                args_schema=GetFileContentsArgs,
                response_format="content_and_artifact",
            ),
            StructuredTool.from_function(
                coroutine=search_code,
                name="search_code",
                description="Search bounded repository text.",
                args_schema=SearchCodeArgs,
                response_format="content_and_artifact",
            ),
        ]
        try:
            yield tools
        finally:
            self.sessions_closed += 1

    def _path_rejection(self, relative_path: str) -> InspectionToolResponse | None:
        if relative_path == ".":
            return None
        try:
            decision = self.policy.classify_path(relative_path)
        except ValueError as exc:
            return InspectionToolResponse(
                status=InspectionToolStatus.DENIED,
                error_code="UNSAFE_PATH",
                detail=self.redactor.redact(str(exc)),
            )
        if decision is PolicyDecision.DENY:
            return InspectionToolResponse(
                status=InspectionToolStatus.DENIED,
                error_code="PATH_DENIED",
                detail="Repository path is forbidden by operator policy.",
            )
        return None

    def _failed(self, detail: str) -> InspectionToolResponse:
        return InspectionToolResponse(
            status=InspectionToolStatus.ERROR,
            error_code="INSPECTION_OPERATION_FAILED",
            detail=self.redactor.redact(detail),
        )

    @staticmethod
    def _target_rejection(
        owner: str,
        repo: str,
        repository: RepositoryRef,
        workspace: WorkspaceRef,
        commit_sha: str | None,
    ) -> InspectionToolResponse | None:
        expected_owner, expected_repo = _github_target(repository)
        if owner != expected_owner or repo != expected_repo:
            return InspectionToolResponse(
                status=InspectionToolStatus.DENIED,
                error_code="REPOSITORY_SCOPE_DENIED",
                detail="Inspection is restricted to the assigned repository.",
            )
        if commit_sha != workspace.base_commit:
            return InspectionToolResponse(
                status=InspectionToolStatus.DENIED,
                error_code="IMMUTABLE_REF_REQUIRED",
                detail="Inspection must use the assigned commit SHA.",
            )
        return None


def _tool_response(response: InspectionToolResponse) -> tuple[str, dict[str, object]]:
    return response.model_dump_json(), {"structured_content": response.model_dump(mode="json")}


def _github_target(repository: RepositoryRef) -> tuple[str, str]:
    parts = [part for part in urlsplit(repository.url).path.split("/") if part]
    if len(parts) != 2:
        raise ValueError("fake inspection requires a GitHub owner/repository URL")
    return parts[0], parts[1].removesuffix(".git")
