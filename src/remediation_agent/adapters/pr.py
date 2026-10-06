"""Exact, idempotent GitHub draft publication; an existing unrelated PR is never accepted."""

from __future__ import annotations

import httpx
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, TypeAdapter

from remediation_agent.domain.models import DraftPrMetadata, RepositoryRef
from remediation_agent.ports.models import CreatedDraftPr, DraftPrRequest, PreparedDraftPr, PublicationError


class _Repository(BaseModel):
    model_config = ConfigDict(extra="ignore")
    full_name: str


class _Ref(BaseModel):
    model_config = ConfigDict(extra="ignore")
    ref: str
    sha: str
    repo: _Repository


class _GitHubPr(BaseModel):
    model_config = ConfigDict(extra="ignore")
    number: int = Field(gt=0)
    html_url: HttpUrl
    state: str
    draft: bool
    head: _Ref
    base: _Ref
    merged_at: str | None = None


class DraftPullRequestProvider:
    def __init__(
        self,
        *,
        token: str | None = None,
        writes_enabled: bool = False,
        timeout_seconds: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.token = token
        self.writes_enabled = writes_enabled
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    async def check_readiness(self, repository: RepositoryRef, slug: str | None) -> None:
        if not self.writes_enabled or not self.token or not slug:
            raise PublicationError("PUBLICATION_NOT_CONFIGURED")
        if repository.url.removesuffix(".git") != f"https://github.com/{slug}":
            raise PublicationError("PUBLICATION_REPOSITORY_MISMATCH")
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds, transport=self.transport, follow_redirects=False
            ) as client:
                response = await client.get(
                    f"https://api.github.com/repos/{slug}",
                    headers={"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json"},
                )
                response.raise_for_status()
                metadata = response.json()
                if metadata.get("full_name") != slug or metadata.get("permissions", {}).get("push") is not True:
                    raise PublicationError("PUBLICATION_PERMISSION_UNAVAILABLE")
        except (httpx.HTTPError, ValueError, AttributeError):
            raise PublicationError("PUBLICATION_READINESS_FAILED") from None

    async def prepare(self, request: DraftPrRequest) -> PreparedDraftPr:
        return PreparedDraftPr(metadata=DraftPrMetadata(payload=request.payload))

    async def verify_draft(self, request: DraftPrRequest) -> CreatedDraftPr:
        return await self._reconcile(request, create=False)

    async def create_draft(self, request: DraftPrRequest) -> CreatedDraftPr:
        return await self._reconcile(request, create=True)

    async def _reconcile(self, request: DraftPrRequest, *, create: bool) -> CreatedDraftPr:
        if not self.writes_enabled or not self.token or not request.repository_slug:
            raise PublicationError("PUBLICATION_NOT_CONFIGURED")
        if not request.expected_commit or not request.expected_base_commit:
            raise PublicationError("PUBLICATION_EVIDENCE_MISSING")
        if request.repository.url.removesuffix(".git") != f"https://github.com/{request.repository_slug}":
            raise PublicationError("PUBLICATION_REPOSITORY_MISMATCH")
        url = f"https://api.github.com/repos/{request.repository_slug}/pulls"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds, transport=self.transport, follow_redirects=False
            ) as client:
                owner = request.repository_slug.split("/", maxsplit=1)[0]
                response = await client.get(
                    url,
                    headers=headers,
                    params={"state": "all", "head": f"{owner}:{request.payload.head_branch}", "per_page": 100},
                )
                response.raise_for_status()
                if len(response.content) > 1024 * 1024:
                    raise PublicationError("PUBLICATION_RESPONSE_OVERSIZED")
                existing = TypeAdapter(list[_GitHubPr]).validate_python(response.json())
                if len(existing) > 1:
                    raise PublicationError("AMBIGUOUS_EXISTING_PR")
                if existing:
                    result = existing[0]
                elif create:
                    response = await client.post(
                        url,
                        headers=headers,
                        json={
                            "title": request.payload.title,
                            "body": request.payload.body,
                            "head": request.payload.head_branch,
                            "base": request.payload.base_branch,
                            "draft": True,
                        },
                    )
                    response.raise_for_status()
                    if len(response.content) > 1024 * 1024:
                        raise PublicationError("PUBLICATION_RESPONSE_OVERSIZED")
                    result = _GitHubPr.model_validate(response.json())
                else:
                    raise PublicationError("DRAFT_NOT_FOUND", retryable=True)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            raise PublicationError(
                f"GITHUB_HTTP_{status}",
                retryable=status in {408, 409, 422, 429}
                or status >= 500
                or (
                    status == 403
                    and (
                        exc.response.headers.get("x-ratelimit-remaining") == "0"
                        or "retry-after" in exc.response.headers
                    )
                ),
            ) from None
        except httpx.TransportError:
            raise PublicationError("GITHUB_TRANSPORT_FAILURE", retryable=True) from None
        except ValueError:
            raise PublicationError("GITHUB_RESPONSE_INVALID") from None
        if (
            result.state != "open"
            or not result.draft
            or result.merged_at is not None
            or result.head.ref != request.payload.head_branch
            or result.base.ref != request.payload.base_branch
            or result.head.repo.full_name != request.repository_slug
            or result.base.repo.full_name != request.repository_slug
            or result.head.sha != request.expected_commit
            or result.base.sha != request.expected_base_commit
            or str(result.html_url) != f"https://github.com/{request.repository_slug}/pull/{result.number}"
        ):
            raise PublicationError("UNRELATED_OR_CHANGED_DRAFT")
        return CreatedDraftPr(
            metadata=DraftPrMetadata(
                payload=request.payload, created=True, provider_id=str(result.number), url=str(result.html_url)
            )
        )
