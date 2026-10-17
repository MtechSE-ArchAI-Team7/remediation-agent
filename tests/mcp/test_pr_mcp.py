"""Real SDK/server transport coverage plus an explicitly read-only hosted contract."""

from __future__ import annotations

import json
import os

import httpx
import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import TextContent, Tool
from pydantic import TypeAdapter

from remediation_agent.adapters.pr import DraftPullRequestProvider, _GitHubPr, _PrNumber
from remediation_agent.domain.enums import RepositoryProvider
from remediation_agent.domain.models import RepositoryRef
from remediation_agent.ports.models import PublicationCallRecord
from tests.unit.test_pr_provider import CONTRACT, _draft, _request

pytestmark = pytest.mark.mcp


async def test_real_streamable_http_server_creates_and_verifies() -> None:
    server = FastMCP(
        "github-pr-fixture",
        streamable_http_path="/mcp/",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(allowed_hosts=["api.githubcopilot.com"]),
    )
    published = False
    calls: list[str] = []

    @server._mcp_server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]  # noqa: SLF001
    async def list_tools() -> list[Tool]:
        document = json.loads(CONTRACT.read_text())
        return [Tool.model_validate(value) for value in document["tools"]]

    @server._mcp_server.call_tool()  # type: ignore[untyped-decorator]  # noqa: SLF001
    async def call_tool(name: str, arguments: dict[str, object]) -> list[TextContent]:
        nonlocal published
        calls.append(name)
        assert arguments["owner"] == "example" and arguments["repo"] == "project"
        value: object
        if name == "list_pull_requests":
            value = [{"number": 42}] if published else []
        elif name == "create_pull_request":
            assert arguments["draft"] is True
            published = True
            value = {"id": "999001", "url": "https://github.com/example/project/pull/42"}
        else:
            assert name == "pull_request_read" and arguments["method"] == "get"
            value = _draft()
        return [TextContent(type="text", text=json.dumps(value))]

    app = server.streamable_http_app()
    provider = DraftPullRequestProvider(
        token="fixture-only",  # noqa: S106 - in-process fixture
        writes_enabled=True,
        transport=httpx.ASGITransport(app=app),
    )
    async with app.router.lifespan_context(app):
        result = await provider.create_draft(_request())
        assert result.metadata.provider_id == "42"
        assert (await provider.verify_draft(_request())).metadata == result.metadata
    assert calls == [
        "list_pull_requests",
        "create_pull_request",
        "pull_request_read",
        "list_pull_requests",
        "pull_request_read",
    ]


@pytest.mark.live_mcp
async def test_live_publication_contract_is_read_only() -> None:
    token = os.environ.get("AIOS_GITHUB_TOKEN")
    url = os.environ.get("AIOS_LIVE_GITHUB_MCP_REPOSITORY_URL")
    if not token or not url:
        pytest.skip("live GitHub MCP contract variables are not configured")
    repository = RepositoryRef(provider=RepositoryProvider.GITHUB, url=url, base_branch="main")
    slug = url.removeprefix("https://github.com/").removesuffix(".git")
    provider = DraftPullRequestProvider(token=token, writes_enabled=True)
    readiness = await provider.check_readiness(repository, slug)
    assert [r.operation for r in readiness.records] == ["discovery", "list_pull_requests"]
    owner, repo = slug.split("/")
    records: list[PublicationCallRecord] = []
    async with provider._session(records) as client:  # noqa: SLF001 - contract test never calls a write tool
        value = await provider._call(
            client,
            records,
            "list_pull_requests",
            {  # noqa: SLF001
                "owner": owner,
                "repo": repo,
                "state": "all",
                "perPage": 1,
                "page": 1,
                "fields": ["number"],
            },
        )
        items = TypeAdapter(list[_PrNumber]).validate_python(value)
        if items:
            value = await provider._call(
                client,
                records,
                "pull_request_read",
                {  # noqa: SLF001
                    "owner": owner,
                    "repo": repo,
                    "pullNumber": items[0].number,
                    "method": "get",
                },
            )
            _GitHubPr.model_validate(value)
    assert not any(record.operation == "create_pull_request" for record in records)
