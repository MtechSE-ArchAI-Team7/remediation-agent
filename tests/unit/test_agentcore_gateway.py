"""SigV4 transport tests for the bounded AgentCore gateway boundary."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
from botocore.credentials import Credentials  # type: ignore[import-untyped]

from remediation_agent.adapters.agentcore_gateway import AgentCoreGatewaySigV4Auth, AgentCoreMcpGatewaySigV4Auth

_BASE_URL = (
    "https://llm-gateway-with-inbound-auth-u8utldecju.gateway.bedrock-agentcore."
    "ap-southeast-1.amazonaws.com/inference/v1"
)
_RESPONSES_URL = _BASE_URL + "/responses"
_MCP_BASE_URL = (
    "https://aios-remediation-tool-gateway-abcdefghij.gateway.bedrock-agentcore.ap-southeast-1.amazonaws.com/mcp"
)


class _CredentialsProvider:
    def __init__(self, credentials: Iterator[Credentials]) -> None:
        self._credentials = credentials
        self.calls = 0

    def get_credentials(self) -> Credentials:
        self.calls += 1
        return next(self._credentials)


def _signed(auth: AgentCoreGatewaySigV4Auth, *, body: bytes = b'{"model":"target/model"}') -> httpx.Request:
    request = httpx.Request(
        "POST",
        _RESPONSES_URL,
        content=body,
        headers={"Authorization": "Bearer placeholder", "Content-Type": "application/json"},
    )
    return list(auth.auth_flow(request))[0]


def test_sigv4_replaces_bearer_header_and_signs_temporary_credentials() -> None:
    provider = _CredentialsProvider(iter([Credentials("AKID", "secret", "session-token")]))
    auth = AgentCoreGatewaySigV4Auth(
        base_url=_BASE_URL,
        region_name="ap-southeast-1",
        credential_provider=provider,
    )

    request = _signed(auth)

    authorization = request.headers["Authorization"]
    assert authorization.startswith("AWS4-HMAC-SHA256 Credential=AKID/")
    assert "/ap-southeast-1/bedrock-agentcore/aws4_request" in authorization
    assert request.headers["X-Amz-Security-Token"] == "session-token"
    assert request.headers["X-Amz-Date"]
    assert "Bearer" not in authorization
    assert provider.calls == 1


def test_sigv4_refreshes_credentials_for_every_request() -> None:
    provider = _CredentialsProvider(iter([Credentials("FIRST", "secret-1"), Credentials("SECOND", "secret-2")]))
    auth = AgentCoreGatewaySigV4Auth(
        base_url=_BASE_URL,
        region_name="ap-southeast-1",
        credential_provider=provider,
    )

    first = _signed(auth)
    second = _signed(auth)

    assert "Credential=FIRST/" in first.headers["Authorization"]
    assert "Credential=SECOND/" in second.headers["Authorization"]
    assert provider.calls == 2


def test_sigv4_signature_covers_the_request_body(monkeypatch: pytest.MonkeyPatch) -> None:
    import botocore.auth  # type: ignore[import-untyped]

    monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda: datetime(2026, 9, 21, tzinfo=UTC))
    provider = _CredentialsProvider(iter([Credentials("AKID", "secret"), Credentials("AKID", "secret")]))
    auth = AgentCoreGatewaySigV4Auth(
        base_url=_BASE_URL,
        region_name="ap-southeast-1",
        credential_provider=provider,
    )

    first = _signed(auth, body=b'{"input":"one"}')
    second = _signed(auth, body=b'{"input":"two"}')

    assert first.headers["Authorization"] != second.headers["Authorization"]


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("GET", _RESPONSES_URL),
        ("POST", _BASE_URL + "/models"),
        ("POST", _RESPONSES_URL + "?redirect=true"),
        ("POST", "https://example.test/inference/v1/responses"),
        ("POST", _RESPONSES_URL + "/redirected"),
    ],
)
def test_sigv4_rejects_alternate_methods_hosts_paths_queries_and_redirect_targets(method: str, url: str) -> None:
    provider = _CredentialsProvider(iter([Credentials("AKID", "secret")]))
    auth = AgentCoreGatewaySigV4Auth(
        base_url=_BASE_URL,
        region_name="ap-southeast-1",
        credential_provider=provider,
    )
    request = httpx.Request(method, url, content=b"{}")

    with pytest.raises(ValueError, match="not permitted") as exc_info:
        list(auth.auth_flow(request))

    assert "llm-gateway" not in str(exc_info.value)
    assert provider.calls == 0


def test_sigv4_rejects_missing_credentials_without_leaking_request_details() -> None:
    class _MissingProvider:
        def get_credentials(self) -> None:
            return None

    auth = AgentCoreGatewaySigV4Auth(
        base_url=_BASE_URL,
        region_name="ap-southeast-1",
        credential_provider=_MissingProvider(),
    )

    with pytest.raises(RuntimeError, match="AWS credentials are required") as exc_info:
        _signed(auth)

    assert "llm-gateway" not in str(exc_info.value)


def test_sigv4_rejects_a_spoofed_host_header() -> None:
    provider = _CredentialsProvider(iter([Credentials("AKID", "secret")]))
    auth = AgentCoreGatewaySigV4Auth(
        base_url=_BASE_URL,
        region_name="ap-southeast-1",
        credential_provider=provider,
    )
    request = httpx.Request("POST", _RESPONSES_URL, content=b"{}", headers={"Host": "example.test"})

    with pytest.raises(ValueError, match="target is not permitted"):
        list(auth.auth_flow(request))

    assert provider.calls == 0


def test_mcp_sigv4_signs_only_the_exact_gateway_mcp_path() -> None:
    provider = _CredentialsProvider(iter([Credentials("AKID", "secret", "session-token")]))
    auth = AgentCoreMcpGatewaySigV4Auth(
        base_url=_MCP_BASE_URL,
        region_name="ap-southeast-1",
        credential_provider=provider,
    )
    request = httpx.Request("POST", _MCP_BASE_URL, content=b'{"jsonrpc":"2.0"}')

    signed = list(auth.auth_flow(request))[0]

    assert signed.headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKID/")
    assert signed.headers["X-Amz-Security-Token"] == "session-token"


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("GET", _MCP_BASE_URL),
        ("POST", _MCP_BASE_URL + "/"),
        ("POST", _MCP_BASE_URL + "?redirect=true"),
        ("POST", "https://example.test/mcp"),
    ],
)
def test_mcp_sigv4_rejects_alternate_methods_hosts_paths_and_queries(method: str, url: str) -> None:
    provider = _CredentialsProvider(iter([Credentials("AKID", "secret")]))
    auth = AgentCoreMcpGatewaySigV4Auth(
        base_url=_MCP_BASE_URL,
        region_name="ap-southeast-1",
        credential_provider=provider,
    )

    with pytest.raises(ValueError, match="not permitted"):
        list(auth.auth_flow(httpx.Request(method, url, content=b"{}")))

    assert provider.calls == 0
