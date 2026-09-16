"""Run-scoped client for GitHub's hosted repository-inspection MCP tools."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import httpx
from langchain_core.tools import BaseTool, StructuredTool
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import (
    BlobResourceContents,
    CallToolResult,
    EmbeddedResource,
    ResourceLink,
    TextContent,
    TextResourceContents,
)
from pydantic import Field

from remediation_agent.adapters.evidence import SecretRedactor
from remediation_agent.domain.enums import InspectionToolStatus, PolicyDecision, RepositoryProvider
from remediation_agent.domain.models import (
    GetFileContentsArgs,
    GetRepositoryTreeArgs,
    InspectionArtifact,
    InspectionToolResponse,
    RepositoryRef,
    SearchCodeArgs,
    StrictModel,
    WorkspaceRef,
)
from remediation_agent.policy.engine import PolicyEngine

GITHUB_MCP_ENDPOINT = "https://api.githubcopilot.com/mcp/"
INSPECTION_MCP_TOOL_NAMES = frozenset({"get_repository_tree", "get_file_contents", "search_code"})
COMMIT_PINNED_MCP_TOOL_NAMES = frozenset({"get_repository_tree", "get_file_contents"})
_GITHUB_MCP_TOOL_HEADER = "get_repository_tree,get_file_contents,search_code"

_EXPECTED_ARGUMENTS = {
    "get_repository_tree": {"owner", "repo", "tree_sha", "recursive", "path_filter"},
    "get_file_contents": {"owner", "repo", "path", "ref", "sha", "fields"},
    "search_code": {"query", "sort", "order", "fields", "page", "perPage"},
}
_SEARCH_SCOPE = re.compile(r"(?<![A-Za-z0-9_])(repo|org|user):([^\s]+)", re.IGNORECASE)
_SAFE_DIRECTORY_FIELDS = ["name", "path", "sha", "size", "type"]
_SAFE_SEARCH_FIELDS = ["name", "path", "sha", "repository"]


@dataclass(frozen=True)
class _GitHubTarget:
    owner: str
    repo: str
    commit_sha: str


class _TreeEntry(StrictModel):
    path: str = Field(min_length=1, max_length=2_048)
    type: str = Field(min_length=1, max_length=50)
    size: int | None = Field(default=None, ge=0)
    mode: str = Field(min_length=1, max_length=20)
    sha: str = Field(min_length=7, max_length=64)
    url: str = Field(min_length=1, max_length=4_096)


class _TreeResponse(StrictModel):
    sha: str = Field(min_length=7, max_length=64)
    truncated: bool
    tree: list[_TreeEntry]
    tree_sha: str = Field(min_length=7, max_length=300)
    owner: str = Field(min_length=1, max_length=100)
    repo: str = Field(min_length=1, max_length=100)
    recursive: bool
    count: int = Field(ge=0)


class _DirectoryEntry(StrictModel):
    name: str = Field(min_length=1, max_length=2_048)
    path: str = Field(min_length=1, max_length=2_048)
    sha: str = Field(min_length=7, max_length=64)
    size: int = Field(ge=0)
    type: str = Field(min_length=1, max_length=50)


class _SearchItem(StrictModel):
    name: str = Field(min_length=1, max_length=2_048)
    path: str = Field(min_length=1, max_length=2_048)
    sha: str = Field(min_length=7, max_length=64)
    repository: str = Field(min_length=1, max_length=201)


class _SearchResponse(StrictModel):
    total_count: int = Field(ge=0)
    incomplete_results: bool
    items: list[_SearchItem]


class GitHubRemoteMcpInspectionTools:
    """Expose a policy-bounded view of GitHub's three native read tools."""

    def __init__(self, token: str, policy: PolicyEngine) -> None:
        if not token:
            raise ValueError("GitHub MCP token must not be empty")
        self._token = token
        self.policy = policy
        self.redactor = SecretRedactor()
        self.startup_timeout_seconds = policy.config.limits.max_mcp_tool_timeout_seconds

    @asynccontextmanager
    async def session(
        self,
        repository: RepositoryRef,
        workspace: WorkspaceRef,
    ) -> AsyncIterator[Sequence[BaseTool]]:
        target = self._target(repository, workspace)
        try:
            async with httpx.AsyncClient(
                headers=self._headers(),
                timeout=float(self.startup_timeout_seconds),
                verify=True,
                follow_redirects=False,
                trust_env=False,
            ) as http_client:
                async with streamable_http_client(GITHUB_MCP_ENDPOINT, http_client=http_client) as (read, write, _):
                    async with ClientSession(read, write) as client:
                        async with asyncio.timeout(self.startup_timeout_seconds):
                            await client.initialize()
                            discovered = await load_mcp_tools(client, handle_tool_errors=False)
                        self._validate_tools(discovered)
                        yield self._bounded_tools(client, target, workspace)
        except Exception as exc:  # noqa: BLE001 - normalize the external MCP transport boundary
            raise RuntimeError(f"GitHub MCP session failed: {_mcp_failure_code(exc)}") from exc

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "X-MCP-Tools": _GITHUB_MCP_TOOL_HEADER,
            "X-MCP-Readonly": "true",
            "X-MCP-Lockdown": "true",
        }

    @staticmethod
    def _validate_tools(tools: Sequence[BaseTool]) -> None:
        by_name = {tool.name: tool for tool in tools}
        if len(tools) != len(INSPECTION_MCP_TOOL_NAMES) or set(by_name) != INSPECTION_MCP_TOOL_NAMES:
            raise RuntimeError("GitHub MCP server exposed an unexpected tool set")
        for name, expected in _EXPECTED_ARGUMENTS.items():
            if set(by_name[name].args) != expected:
                raise RuntimeError(f"GitHub MCP tool has an unexpected argument schema: {name}")

    @staticmethod
    def _target(repository: RepositoryRef, workspace: WorkspaceRef) -> _GitHubTarget:
        if repository.provider is not RepositoryProvider.GITHUB:
            raise ValueError("GitHub MCP inspection requires a GitHub repository handoff")
        parsed = urlsplit(repository.url)
        parts = [part for part in parsed.path.split("/") if part]
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or len(parts) != 2
            or not parts[1].endswith(".git")
            or not parts[0]
            or not parts[1][:-4]
            or repository.url != f"https://github.com/{parts[0]}/{parts[1][:-4]}.git"
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", parts[0]) is None
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", parts[1][:-4]) is None
        ):
            raise ValueError(
                "GitHub MCP repository must use exact credential-free https://github.com/owner/repo.git form"
            )
        if re.fullmatch(r"[0-9a-f]{40}", workspace.base_commit) is None:
            raise ValueError("GitHub MCP workspace must resolve to a full immutable commit SHA")
        return _GitHubTarget(owner=parts[0], repo=parts[1][:-4], commit_sha=workspace.base_commit)

    def _bounded_tools(
        self,
        client: ClientSession,
        target: _GitHubTarget,
        workspace: WorkspaceRef,
    ) -> list[BaseTool]:
        async def get_repository_tree(
            owner: str,
            repo: str,
            tree_sha: str | None = None,
            recursive: bool = False,
            path_filter: str | None = None,
        ) -> tuple[str, dict[str, object]]:
            rejection = self._target_rejection(owner, repo, target)
            if rejection is None and tree_sha != target.commit_sha:
                rejection = self._denied("IMMUTABLE_REF_REQUIRED", "Tree inspection must use the assigned commit SHA.")
            requested_path = path_filter or "."
            if rejection is None:
                rejection = self._path_rejection(requested_path)
            if rejection is not None:
                return _tool_response(rejection)
            arguments: dict[str, object] = {
                "owner": target.owner,
                "repo": target.repo,
                "tree_sha": target.commit_sha,
                "recursive": recursive,
            }
            if path_filter is not None:
                arguments["path_filter"] = path_filter
            try:
                result = await client.call_tool("get_repository_tree", arguments)
                response = self._normalize_tree(result, target, requested_path)
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                response = self._failed("GITHUB_MCP_TOOL_FAILED", type(exc).__name__)
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
            rejection = self._target_rejection(owner, repo, target)
            if rejection is None and ref is not None:
                rejection = self._denied("MUTABLE_REF_DENIED", "Mutable Git refs are not permitted for inspection.")
            if rejection is None and sha != target.commit_sha:
                rejection = self._denied("IMMUTABLE_REF_REQUIRED", "File inspection must use the assigned commit SHA.")
            requested_path = path or "."
            if rejection is None:
                rejection = self._path_rejection(requested_path)
            if rejection is None:
                rejection = self._workspace_path_rejection(workspace, requested_path)
            if rejection is not None:
                return _tool_response(rejection)
            arguments: dict[str, object] = {
                "owner": target.owner,
                "repo": target.repo,
                "path": "" if path is None else path,
                "sha": target.commit_sha,
                "fields": _SAFE_DIRECTORY_FIELDS,
            }
            try:
                result = await client.call_tool("get_file_contents", arguments)
                response = self._normalize_file_or_directory(result, requested_path)
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                response = self._failed("GITHUB_MCP_TOOL_FAILED", type(exc).__name__)
            return _tool_response(response)

        async def search_code(
            query: str,
            sort: str | None = None,
            order: str | None = None,
            fields: list[str] | None = None,
            page: int = 1,
            perPage: int = 30,
        ) -> tuple[str, dict[str, object]]:
            _ = fields
            rejection = self._search_rejection(query, target)
            if rejection is not None:
                return _tool_response(rejection)
            arguments: dict[str, object] = {
                "query": query,
                "fields": _SAFE_SEARCH_FIELDS,
                "page": page,
                "perPage": min(perPage, self.policy.config.limits.max_search_results),
            }
            if sort is not None:
                arguments["sort"] = sort
            if order is not None:
                arguments["order"] = order
            try:
                result = await client.call_tool("search_code", arguments)
                response = self._normalize_search(result, target, workspace, query)
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                response = self._failed("GITHUB_MCP_TOOL_FAILED", type(exc).__name__)
            return _tool_response(response)

        return [
            StructuredTool.from_function(
                coroutine=get_repository_tree,
                name="get_repository_tree",
                description="Get a bounded repository tree at the authorized immutable GitHub commit.",
                args_schema=GetRepositoryTreeArgs,
                response_format="content_and_artifact",
            ),
            StructuredTool.from_function(
                coroutine=get_file_contents,
                name="get_file_contents",
                description="Get bounded file or directory contents at the authorized immutable GitHub commit.",
                args_schema=GetFileContentsArgs,
                response_format="content_and_artifact",
            ),
            StructuredTool.from_function(
                coroutine=search_code,
                name="search_code",
                description=(
                    "Find candidate paths in the authorized GitHub repository; results are not pinned evidence."
                ),
                args_schema=SearchCodeArgs,
                response_format="content_and_artifact",
            ),
        ]

    def _target_rejection(self, owner: str, repo: str, target: _GitHubTarget) -> InspectionToolResponse | None:
        if owner != target.owner or repo != target.repo:
            return self._denied("REPOSITORY_SCOPE_DENIED", "Inspection is restricted to the assigned repository.")
        return None

    def _path_rejection(self, path: str) -> InspectionToolResponse | None:
        if path in {"", "."}:
            return None
        try:
            decision = self.policy.classify_path(path)
        except ValueError as exc:
            return self._denied("UNSAFE_PATH", str(exc))
        if decision is PolicyDecision.DENY:
            return self._denied("PATH_DENIED", "Repository path is forbidden by operator policy.")
        return None

    def _workspace_path_rejection(self, workspace: WorkspaceRef, path: str) -> InspectionToolResponse | None:
        root = Path(workspace.path)
        if root.is_symlink():
            return self._denied("UNSAFE_WORKSPACE", "Workspace root cannot be a symlink.")
        resolved_root = root.resolve()
        requested = Path(path)
        cursor = resolved_root
        for part in requested.parts:
            if part in {"", "."}:
                continue
            cursor /= part
            if cursor.is_symlink():
                return self._denied("SYMLINK_DENIED", "Repository path contains a symlink.")
        candidate = (resolved_root / requested).resolve()
        if not candidate.is_relative_to(resolved_root):
            return self._denied("UNSAFE_PATH", "Resolved repository path escapes the workspace.")
        if not candidate.exists():
            return self._denied("PATH_UNAVAILABLE", "Repository path is unavailable at the assigned commit.")
        return None

    def _search_rejection(self, query: str, target: _GitHubTarget) -> InspectionToolResponse | None:
        scopes = [(kind.lower(), value.rstrip("\"'")) for kind, value in _SEARCH_SCOPE.findall(query)]
        repository_scopes = [value for kind, value in scopes if kind == "repo"]
        if any(kind in {"org", "user"} for kind, _ in scopes):
            return self._denied("SEARCH_SCOPE_DENIED", "Organization-wide and user-wide code search is not permitted.")
        expected = f"{target.owner}/{target.repo}"
        if repository_scopes != [expected]:
            return self._denied("SEARCH_SCOPE_DENIED", "Code search must contain exactly the assigned repo qualifier.")
        return None

    def _normalize_tree(
        self,
        result: CallToolResult,
        target: _GitHubTarget,
        locator: str,
    ) -> InspectionToolResponse:
        error = self._remote_error(result)
        if error is not None:
            return error
        payload = _TreeResponse.model_validate(self._json_value(result))
        if payload.owner != target.owner or payload.repo != target.repo or payload.tree_sha != target.commit_sha:
            raise ValueError("GitHub MCP tree response target did not match the authorized commit")
        entries: list[str] = []
        truncated = payload.truncated
        for item in payload.tree:
            if item.mode in {"120000", "160000"} or item.type == "commit":
                continue
            if self._path_rejection(item.path) is not None:
                continue
            suffix = "/" if item.type == "tree" else ""
            entries.append(f"{item.path}{suffix}")
            if len(entries) >= self.policy.config.limits.max_tree_entries:
                truncated = truncated or payload.count > len(entries)
                break
        return self._success("TREE", locator, "\n".join(entries), truncated=truncated)

    def _normalize_file_or_directory(self, result: CallToolResult, locator: str) -> InspectionToolResponse:
        error = self._remote_error(result)
        if error is not None:
            return error
        embedded_text: str | None = None
        for block in result.content:
            if isinstance(block, EmbeddedResource):
                if isinstance(block.resource, BlobResourceContents):
                    return self._denied("BINARY_FILE_DENIED", "Binary repository files are not inspectable.")
                if not isinstance(block.resource, TextResourceContents):
                    raise ValueError("GitHub MCP returned an unsupported embedded resource")
                embedded_text = block.resource.text
            elif isinstance(block, ResourceLink):
                return self._denied("EXTERNAL_RESOURCE_DENIED", "External repository resource links are not followed.")
            elif not isinstance(block, TextContent):
                raise ValueError("GitHub MCP returned unsupported non-text content")
        if embedded_text is not None:
            if result.structuredContent is not None:
                raise ValueError("GitHub MCP file response mixed structured and embedded content")
            bounded, truncated = _truncate_utf8(embedded_text, self.policy.config.limits.max_file_bytes)
            return self._success("FILE", locator, bounded, truncated=truncated)

        parsed = self._json_value(result)
        if isinstance(parsed, list):
            entries = [_DirectoryEntry.model_validate(item) for item in parsed]
            visible: list[str] = []
            truncated = False
            for item in entries:
                if item.type in {"symlink", "submodule"} or self._path_rejection(item.path) is not None:
                    continue
                suffix = "/" if item.type == "dir" else ""
                visible.append(f"{item.path}{suffix}")
                if len(visible) >= self.policy.config.limits.max_tree_entries:
                    truncated = len(entries) > len(visible)
                    break
            return self._success("TREE", locator, "\n".join(visible), truncated=truncated)
        if isinstance(parsed, Mapping) and parsed.get("type") in {"symlink", "submodule"}:
            return self._denied("UNSUPPORTED_PATH_TYPE", "Symlink and submodule contents are not inspectable.")
        raise ValueError("GitHub MCP file response did not contain text or a directory listing")

    def _normalize_search(
        self,
        result: CallToolResult,
        target: _GitHubTarget,
        workspace: WorkspaceRef,
        query: str,
    ) -> InspectionToolResponse:
        error = self._remote_error(result)
        if error is not None:
            return error
        payload = _SearchResponse.model_validate(self._json_value(result))
        paths: list[str] = []
        for item in payload.items:
            if item.repository != f"{target.owner}/{target.repo}":
                raise ValueError("GitHub MCP search result escaped the authorized repository")
            if self._path_rejection(item.path) is not None:
                continue
            if self._workspace_path_rejection(workspace, item.path) is not None:
                continue
            paths.append(item.path)
            if len(paths) >= self.policy.config.limits.max_search_results:
                break
        truncated = payload.incomplete_results or payload.total_count > len(payload.items)
        return self._success("SEARCH", query, "\n".join(paths), truncated=truncated)

    def _remote_error(self, result: CallToolResult) -> InspectionToolResponse | None:
        if not result.isError:
            return None
        detail = self.redactor.redact(self._text_content(result))[:4_000] or "GitHub MCP tool returned an error."
        return InspectionToolResponse(
            status=InspectionToolStatus.ERROR,
            error_code="GITHUB_MCP_TOOL_ERROR",
            detail=detail,
        )

    @staticmethod
    def _single_text(result: CallToolResult) -> str:
        pieces = [block.text for block in result.content if isinstance(block, TextContent)]
        if len(pieces) != 1:
            raise ValueError("GitHub MCP result must contain exactly one JSON text block")
        return pieces[0]

    def _json_value(self, result: CallToolResult) -> object:
        if result.structuredContent is not None:
            if any(not isinstance(block, TextContent) for block in result.content):
                raise ValueError("GitHub MCP structured result included unsupported content")
            value: object = result.structuredContent
            encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
        else:
            raw = self._single_text(result)
            encoded = raw.encode("utf-8")
            value = json.loads(raw)
        if len(encoded) > self.policy.config.limits.max_context_bytes:
            raise ValueError("GitHub MCP JSON response exceeded the configured context limit")
        return value

    @staticmethod
    def _text_content(result: CallToolResult) -> str:
        return "\n".join(block.text for block in result.content if isinstance(block, TextContent))

    def _success(
        self,
        kind: Literal["TREE", "FILE", "SEARCH"],
        locator: str,
        content: str,
        *,
        truncated: bool,
    ) -> InspectionToolResponse:
        redacted = self.redactor.redact(content)
        bounded, context_truncated = _truncate_utf8(redacted, self.policy.config.limits.max_context_bytes)
        return InspectionToolResponse(
            status=InspectionToolStatus.SUCCEEDED,
            artifact=InspectionArtifact(
                kind=kind,
                locator=locator,
                content=bounded,
                digest=self.policy.digest_text(bounded),
                truncated=truncated or context_truncated,
            ),
        )

    def _denied(self, code: str, detail: str) -> InspectionToolResponse:
        return InspectionToolResponse(
            status=InspectionToolStatus.DENIED,
            error_code=code,
            detail=self.redactor.redact(detail),
        )

    def _failed(self, code: str, detail: str) -> InspectionToolResponse:
        return InspectionToolResponse(
            status=InspectionToolStatus.ERROR,
            error_code=code,
            detail=self.redactor.redact(detail),
        )


def _truncate_utf8(value: str, max_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True


def _tool_response(response: InspectionToolResponse) -> tuple[str, dict[str, object]]:
    return response.model_dump_json(), {"structured_content": response.model_dump(mode="json")}


def _mcp_failure_code(error: BaseException) -> str:
    """Return a bounded diagnostic category without exposing provider error text."""

    pending = [error]
    visited: set[int] = set()
    fallback = "SESSION_ERROR"
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, httpx.HTTPStatusError):
            return f"HTTP_{current.response.status_code}"
        if isinstance(current, (TimeoutError, httpx.TimeoutException)):
            fallback = "TIMEOUT"
        elif isinstance(current, httpx.ConnectError):
            fallback = "CONNECT_ERROR"
        elif isinstance(current, httpx.RemoteProtocolError):
            fallback = "REMOTE_PROTOCOL_ERROR"
        elif isinstance(current, httpx.TransportError) and fallback == "SESSION_ERROR":
            fallback = "TRANSPORT_ERROR"
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return fallback
