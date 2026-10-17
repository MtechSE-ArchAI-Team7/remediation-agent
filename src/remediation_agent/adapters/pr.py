"""Host-controlled, exact draft publication through GitHub's hosted MCP endpoint."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Literal, cast

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, Tool
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from remediation_agent.adapters.mcp import GITHUB_MCP_ENDPOINT
from remediation_agent.domain.enums import RepositoryProvider
from remediation_agent.domain.models import DraftPrMetadata, RepositoryRef
from remediation_agent.ports.models import (
    CreatedDraftPr,
    DraftPrRequest,
    PreparedDraftPr,
    PublicationCallRecord,
    PublicationError,
    PublicationReadiness,
)

PUBLICATION_MCP_TOOLS = frozenset({"list_pull_requests", "create_pull_request", "pull_request_read"})
_MAX_RESPONSE_BYTES = 1024 * 1024
_ARGUMENT_TYPES = {
    "create_pull_request": {
        "owner": "string",
        "repo": "string",
        "title": "string",
        "body": "string",
        "head": "string",
        "base": "string",
        "draft": "boolean",
        "maintainer_can_modify": "boolean",
        "reviewers": "array",
    },
    "list_pull_requests": {
        "owner": "string",
        "repo": "string",
        "state": "string",
        "head": "string",
        "base": "string",
        "sort": "string",
        "direction": "string",
        "fields": "array",
        "page": "number",
        "perPage": "number",
    },
    "pull_request_read": {
        "owner": "string",
        "repo": "string",
        "pullNumber": "number",
        "method": "string",
        "page": "number",
        "perPage": "number",
        "after": "string",
    },
}
_REQUIRED = {
    "create_pull_request": {"owner", "repo", "title", "head", "base"},
    "list_pull_requests": {"owner", "repo"},
    "pull_request_read": {"owner", "repo", "pullNumber", "method"},
}
Operation = Literal["discovery", "list_pull_requests", "create_pull_request", "pull_request_read"]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class _Repository(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    full_name: str


class _Ref(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    ref: str
    sha: str
    repo: _Repository


class _PrNumber(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    number: int = Field(gt=0)


class _GitHubPr(_PrNumber):
    html_url: str
    state: str
    draft: bool
    merged: bool
    head: _Ref
    base: _Ref
    merged_at: str | None = None


class _CreatedReference(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    id: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=2048)


class _LimitedStream(httpx.AsyncByteStream):
    """Cap each HTTP response before the MCP parser buffers JSON or SSE data."""

    def __init__(self, stream: httpx.AsyncByteStream) -> None:
        self.stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        size = 0
        async for chunk in self.stream:
            size += len(chunk)
            if size > _MAX_RESPONSE_BYTES:
                raise PublicationError("PUBLICATION_RESPONSE_OVERSIZED")
            yield chunk

    async def aclose(self) -> None:
        await self.stream.aclose()


async def _bound_response(response: httpx.Response) -> None:
    response.stream = _LimitedStream(cast(httpx.AsyncByteStream, response.stream))


def _failure(exc: BaseException) -> PublicationError:
    if isinstance(exc, PublicationError):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        failures = [_failure(child) for child in exc.exceptions]
        return next((f for f in failures if f.code != "GITHUB_MCP_SESSION_FAILED"), failures[0])
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return PublicationError(
            f"GITHUB_HTTP_{status}",
            retryable=status in {408, 409, 422, 429}
            or status >= 500
            or (
                status == 403
                and (exc.response.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in exc.response.headers)
            ),
        )
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
        return PublicationError("GITHUB_MCP_TIMEOUT", retryable=True)
    if isinstance(exc, httpx.TransportError):
        return PublicationError("GITHUB_TRANSPORT_FAILURE", retryable=True)
    if isinstance(exc, ValueError):
        return PublicationError("GITHUB_RESPONSE_INVALID")
    return PublicationError("GITHUB_MCP_SESSION_FAILED")


class DraftPullRequestProvider:
    """No model tools, direct REST fallback, session state, or unbounded retries."""

    def __init__(
        self,
        *,
        token: str | None = None,
        writes_enabled: bool = False,
        timeout_seconds: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("publication timeout must be positive")
        self.token = token
        self.writes_enabled = writes_enabled
        self.timeout_seconds = timeout_seconds
        self.transport = transport
        self.clock = clock

    def _target(self, repository: RepositoryRef, slug: str | None) -> tuple[str, str]:
        if not self.writes_enabled or not self.token or not slug:
            raise PublicationError("PUBLICATION_NOT_CONFIGURED")
        if (
            repository.provider is not RepositoryProvider.GITHUB
            or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", slug) is None
            or any(part in {".", ".."} for part in slug.split("/"))
            or repository.url.removesuffix(".git") != f"https://github.com/{slug}"
        ):
            raise PublicationError("PUBLICATION_REPOSITORY_MISMATCH")
        owner, repo = slug.split("/")
        return owner, repo

    @staticmethod
    def _validate_tools(tools: Sequence[Tool], next_cursor: str | None) -> None:
        if next_cursor or len(tools) != 3 or {tool.name for tool in tools} != PUBLICATION_MCP_TOOLS:
            raise PublicationError("GITHUB_MCP_TOOLSET_DRIFT")
        for tool in tools:
            schema = tool.inputSchema
            properties = schema.get("properties")
            if (
                schema.get("type") != "object"
                or not isinstance(properties, dict)
                or set(properties) != set(_ARGUMENT_TYPES[tool.name])
                or set(schema.get("required", [])) != _REQUIRED[tool.name]
            ):
                raise PublicationError("GITHUB_MCP_SCHEMA_DRIFT")
            for key, expected in _ARGUMENT_TYPES[tool.name].items():
                prop = properties[key]
                if not isinstance(prop, dict) or prop.get("type") != expected:
                    raise PublicationError("GITHUB_MCP_SCHEMA_DRIFT")
            if tool.name == "pull_request_read" and "get" not in properties["method"].get("enum", []):
                raise PublicationError("GITHUB_MCP_SCHEMA_DRIFT")
            if tool.name == "list_pull_requests" and "all" not in properties["state"].get("enum", []):
                raise PublicationError("GITHUB_MCP_SCHEMA_DRIFT")

    def _record(
        self,
        records: list[PublicationCallRecord],
        operation: Operation,
        started: datetime,
        arguments: object,
        result: object,
        code: str,
    ) -> None:
        records.append(
            PublicationCallRecord(
                operation=operation,
                started_at=started,
                completed_at=self.clock(),
                result_code=code,
                input_digest=_digest(arguments),
                output_digest=_digest(result),
            )
        )

    @asynccontextmanager
    async def _session(self, records: list[PublicationCallRecord]) -> AsyncIterator[ClientSession]:
        started = self.clock()
        discovered = False
        try:
            async with httpx.AsyncClient(
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "X-MCP-Tools": ",".join(sorted(PUBLICATION_MCP_TOOLS)),
                    "X-MCP-Lockdown": "true",
                },
                transport=self.transport,
                timeout=self.timeout_seconds,
                verify=True,
                follow_redirects=False,
                trust_env=False,
                event_hooks={"response": [_bound_response]},
            ) as http:
                async with streamable_http_client(GITHUB_MCP_ENDPOINT, http_client=http) as (read, write, _):
                    async with ClientSession(read, write) as client:
                        async with asyncio.timeout(self.timeout_seconds):
                            await client.initialize()
                            listing = await client.list_tools()
                            self._validate_tools(listing.tools, listing.nextCursor)
                        self._record(
                            records,
                            "discovery",
                            started,
                            sorted(PUBLICATION_MCP_TOOLS),
                            listing.model_dump(mode="json"),
                            "OK",
                        )
                        discovered = True
                        yield client
        except Exception as exc:  # noqa: BLE001 - sanitize all external MCP/HTTP and exception-group failures
            failure = _failure(exc)
            if not discovered:
                self._record(records, "discovery", started, sorted(PUBLICATION_MCP_TOOLS), None, failure.code)
            raise PublicationError(failure.code, retryable=failure.retryable, records=records) from None

    @staticmethod
    def _response(result: CallToolResult) -> object:
        if len(result.model_dump_json().encode()) > _MAX_RESPONSE_BYTES:
            raise PublicationError("PUBLICATION_RESPONSE_OVERSIZED")
        if result.isError:
            # Provider prose is untrusted: extract only a bounded numeric status, never echo its text.
            text = " ".join(item.text for item in result.content if item.type == "text")
            match = re.search(r"\b(?:HTTP(?: status)?|status(?: code)?)\s*[:=]?\s*([45]\d{2})\b", text, re.I)
            if match is None:
                # Hosted GitHub MCP wraps go-github errors as "METHOD URL: STATUS ...".
                match = re.search(r"\b(?:GET|POST) https://api\.github\.com/[^\s]+: ([45]\d{2})\b", text)
            if match:
                status = int(match[1])
                raise PublicationError(
                    f"GITHUB_HTTP_{status}",
                    retryable=status in {408, 409, 422, 429}
                    or status >= 500
                    or (
                        status == 403
                        and re.search(r"\b(?:API rate limit exceeded|secondary rate limit)\b", text, re.I) is not None
                    ),
                )
            raise PublicationError("GITHUB_MCP_TOOL_ERROR")
        if any(item.type != "text" for item in result.content) or len(result.content) > 1:
            raise PublicationError("GITHUB_RESPONSE_INVALID")
        text_payload: object = None
        if result.content:
            text_payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
        structured: object = result.structuredContent
        if isinstance(structured, dict) and set(structured) == {"pull_request"}:
            structured = structured["pull_request"]
        if structured is not None:
            if result.content and structured != text_payload:
                raise PublicationError("GITHUB_RESPONSE_CONFLICT")
            return structured
        if not result.content:
            raise PublicationError("GITHUB_RESPONSE_INVALID")
        return text_payload

    async def _call(
        self,
        client: ClientSession,
        records: list[PublicationCallRecord],
        name: Operation,
        args: dict[str, object],
    ) -> object:
        if name not in PUBLICATION_MCP_TOOLS:
            raise PublicationError("GITHUB_MCP_TOOL_DENIED")
        started = self.clock()
        result: CallToolResult | None = None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                result = await client.call_tool(name, args)
                value = self._response(result)
        except asyncio.CancelledError:
            # A failed HTTP task can cancel the awaiting call before the session reports
            # its transport error. Retain the attempted side effect for reconciliation.
            self._record(records, name, started, args, None, "GITHUB_MCP_CALL_INTERRUPTED")
            raise
        except Exception as exc:  # noqa: BLE001 - transport/tool errors may contain credentials
            failure = _failure(exc)
            self._record(records, name, started, args, result.model_dump(mode="json") if result else None, failure.code)
            raise failure from None
        self._record(records, name, started, args, result.model_dump(mode="json"), "OK")
        return value

    async def check_readiness(self, repository: RepositoryRef, slug: str | None) -> PublicationReadiness:
        owner, repo = self._target(repository, slug)
        records: list[PublicationCallRecord] = []
        async with self._session(records) as client:
            value = await self._call(
                client,
                records,
                "list_pull_requests",
                {
                    "owner": owner,
                    "repo": repo,
                    "state": "all",
                    "perPage": 1,
                    "page": 1,
                    "fields": ["number"],
                },
            )
            TypeAdapter(list[_PrNumber]).validate_python(value)
        return PublicationReadiness(records=records)

    async def prepare(self, request: DraftPrRequest) -> PreparedDraftPr:
        return PreparedDraftPr(metadata=DraftPrMetadata(payload=request.payload))

    async def verify_draft(self, request: DraftPrRequest) -> CreatedDraftPr:
        return await self._reconcile(request, create=False)

    async def create_draft(self, request: DraftPrRequest) -> CreatedDraftPr:
        return await self._reconcile(request, create=True)

    async def _reconcile(self, request: DraftPrRequest, *, create: bool) -> CreatedDraftPr:
        owner, repo = self._target(request.repository, request.repository_slug)
        if any(
            re.fullmatch(r"[0-9a-f]{40}", sha or "") is None
            for sha in (request.expected_commit, request.expected_base_commit)
        ):
            raise PublicationError("PUBLICATION_EVIDENCE_MISSING")
        records: list[PublicationCallRecord] = []
        async with self._session(records) as client:
            value = await self._call(
                client,
                records,
                "list_pull_requests",
                {
                    "owner": owner,
                    "repo": repo,
                    "state": "all",
                    "head": f"{owner}:{request.payload.head_branch}",
                    "perPage": 2,
                    "page": 1,
                    "fields": ["number"],
                },
            )
            existing = TypeAdapter(list[_PrNumber]).validate_python(value)
            if len(existing) > 1:
                raise PublicationError("AMBIGUOUS_EXISTING_PR")
            if existing:
                number = existing[0].number
            elif create:
                value = await self._call(
                    client,
                    records,
                    "create_pull_request",
                    {
                        "owner": owner,
                        "repo": repo,
                        "title": request.payload.title,
                        "body": request.payload.body,
                        "head": request.payload.head_branch,
                        "base": request.payload.base_branch,
                        "draft": True,
                        "maintainer_can_modify": False,
                    },
                )
                reference = _CreatedReference.model_validate(value)
                match = re.fullmatch(
                    rf"https://github\.com/{re.escape(owner)}/{re.escape(repo)}/pull/([1-9]\d*)", reference.url
                )
                if match is None:
                    raise PublicationError("GITHUB_RESPONSE_INVALID")
                number = int(match[1])  # GitHub's returned database ID is NOT the PR number.
            else:
                raise PublicationError("DRAFT_NOT_FOUND", retryable=True)
            value = await self._call(
                client,
                records,
                "pull_request_read",
                {
                    "owner": owner,
                    "repo": repo,
                    "pullNumber": number,
                    "method": "get",
                },
            )
            result = _GitHubPr.model_validate(value)
            if (
                result.number != number
                or result.state != "open"
                or not result.draft
                or result.merged
                or result.merged_at is not None
                or result.head.ref != request.payload.head_branch
                or result.base.ref != request.payload.base_branch
                or result.head.repo.full_name != request.repository_slug
                or result.base.repo.full_name != request.repository_slug
                or result.head.sha != request.expected_commit
                or result.base.sha != request.expected_base_commit
                or result.html_url != f"https://github.com/{request.repository_slug}/pull/{number}"
            ):
                raise PublicationError("UNRELATED_OR_CHANGED_DRAFT")
        return CreatedDraftPr(
            metadata=DraftPrMetadata(
                payload=request.payload,
                created=True,
                provider_id=str(number),
                url=result.html_url,
            ),
            records=records,
        )
