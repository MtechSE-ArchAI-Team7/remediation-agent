"""In-process GitHub-shaped MCP transport for isolated tests and release qualification.

This fixture has no network client. Production construction never imports it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import httpx
from pydantic import TypeAdapter


class SimulatedGitHubPrMcp:
    def __init__(self, contract: Path, create: Callable[[dict[str, object]], dict[str, object]]) -> None:
        document = json.loads(contract.read_text())
        self.tools = TypeAdapter(list[dict[str, object]]).validate_python(document["tools"])
        self.create = create
        self.published: list[dict[str, object]] = []
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.requests: list[httpx.Request] = []
        self.initialized = 0
        self.closed = 0
        self.lose_create_response = False
        self.result_override: Callable[[str, dict[str, object]], dict[str, object] | None] | None = None

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.respond)

    def respond(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if str(request.url) != "https://api.githubcopilot.com/mcp/":
            raise AssertionError("fixture refuses REST or an alternate MCP endpoint")
        if request.method == "DELETE":
            self.closed += 1
            return httpx.Response(200)
        if request.method == "GET":
            return httpx.Response(405)
        message = json.loads(request.content)
        method = message["method"]
        if "id" not in message:
            return httpx.Response(202)
        result: dict[str, object]
        if method == "initialize":
            self.initialized += 1
            result = {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "github-publication-fixture", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": self.tools}
        elif method == "tools/call":
            params = message["params"]
            name = str(params["name"])
            args = TypeAdapter(dict[str, object]).validate_python(params.get("arguments", {}))
            self.calls.append((name, args))
            override = self.result_override(name, args) if self.result_override else None
            if override is not None:
                result = override
            else:
                value: object
                if name == "list_pull_requests":
                    head = args.get("head")
                    found = (
                        self.published
                        if head is None
                        else [
                            pr
                            for pr in self.published
                            if f"{args['owner']}:{cast(dict[str, object], pr['head'])['ref']}" == head
                        ]
                    )
                    value = [{"number": pr["number"]} for pr in found[: int(str(args["perPage"]))]]
                elif name == "create_pull_request":
                    pr = self.create(args)
                    self.published.append(pr)
                    if self.lose_create_response:
                        self.lose_create_response = False
                        raise httpx.ReadTimeout("simulated lost response", request=request)
                    value = {"id": "9000001", "url": pr["html_url"]}
                elif name == "pull_request_read":
                    value = next(pr for pr in self.published if pr["number"] == args["pullNumber"])
                else:
                    raise AssertionError("fixture refuses unregistered tools")
                result = {"content": [{"type": "text", "text": json.dumps(value)}], "isError": False}
        else:
            raise AssertionError("unexpected MCP method")
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": message["id"], "result": result},
            headers={"mcp-session-id": "fixture-session"},
        )
