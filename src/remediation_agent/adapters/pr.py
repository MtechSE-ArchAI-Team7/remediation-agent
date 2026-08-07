"""Deterministic and optional GitHub draft-PR providers."""

from __future__ import annotations

import httpx
from pydantic import BaseModel, ConfigDict, HttpUrl, TypeAdapter

from remediation_agent.domain.models import DraftPrMetadata
from remediation_agent.ports.models import CreatedDraftPr, DraftPrRequest, PreparedDraftPr


class _GitHubPr(BaseModel):
    model_config = ConfigDict(extra="ignore")

    number: int
    html_url: HttpUrl


class DraftPullRequestProvider:
    """Always prepare a payload and optionally create it through GitHub."""

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

    async def prepare(self, request: DraftPrRequest) -> PreparedDraftPr:
        return PreparedDraftPr(metadata=DraftPrMetadata(payload=request.payload))

    async def create_draft(self, request: DraftPrRequest) -> CreatedDraftPr:
        if not self.writes_enabled:
            raise RuntimeError("GitHub writes are disabled by trusted configuration")
        if not self.token:
            raise RuntimeError("GitHub token is not configured")
        if not request.repository_slug:
            raise RuntimeError("GitHub repository slug is not configured")
        url = f"https://api.github.com/repos/{request.repository_slug}/pulls"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Idempotency-Key": request.idempotency_key,
        }
        payload = {
            "title": request.payload.title,
            "body": request.payload.body,
            "head": request.payload.head_branch,
            "base": request.payload.base_branch,
            "draft": True,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, transport=self.transport) as client:
                owner = request.repository_slug.split("/", maxsplit=1)[0]
                existing_response = await client.get(
                    url,
                    headers=headers,
                    params={"state": "open", "head": f"{owner}:{request.payload.head_branch}"},
                )
                existing_response.raise_for_status()
                existing = TypeAdapter(list[_GitHubPr]).validate_python(existing_response.json())
                if existing:
                    return CreatedDraftPr(
                        metadata=DraftPrMetadata(
                            payload=request.payload,
                            created=True,
                            provider_id=str(existing[0].number),
                            url=str(existing[0].html_url),
                        )
                    )
                response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            result = _GitHubPr.model_validate(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError("GitHub draft pull-request operation failed") from exc
        return CreatedDraftPr(
            metadata=DraftPrMetadata(
                payload=request.payload,
                created=True,
                provider_id=str(result.number),
                url=str(result.html_url),
            )
        )
