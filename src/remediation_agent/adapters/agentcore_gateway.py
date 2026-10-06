"""Restricted SigV4 transport for the AgentCore OpenAI-compatible gateway."""

from __future__ import annotations

from collections.abc import Generator
from typing import Protocol
from urllib.parse import urlsplit

import boto3  # type: ignore[import-untyped]
import httpx
from botocore.auth import SigV4Auth  # type: ignore[import-untyped]
from botocore.awsrequest import AWSRequest  # type: ignore[import-untyped]

_SERVICE = "bedrock-agentcore"
_RESPONSES_PATH = "/inference/v1/responses"
_MCP_PATH = "/mcp"


class _FrozenCredentials(Protocol):
    access_key: str
    secret_key: str
    token: str | None


class _RefreshableCredentials(Protocol):
    def get_frozen_credentials(self) -> _FrozenCredentials: ...


class _CredentialProvider(Protocol):
    def get_credentials(self) -> _RefreshableCredentials | None: ...


class _Boto3CredentialProvider:
    def __init__(self, region_name: str) -> None:
        self._session = boto3.Session(region_name=region_name)

    def get_credentials(self) -> _RefreshableCredentials | None:
        credentials = self._session.get_credentials()
        return credentials  # type: ignore[no-any-return]


class _AgentCoreGatewaySigV4Auth(httpx.Auth):
    """Sign one exact AgentCore Gateway endpoint with fresh AWS credentials."""

    requires_request_body = True

    def __init__(
        self,
        *,
        base_url: str,
        region_name: str,
        expected_base_path: str,
        expected_request_path: str,
        credential_provider: _CredentialProvider | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.port is not None:
            raise ValueError("AgentCore gateway base URL must use an unqualified HTTPS origin")
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError("AgentCore gateway base URL contains forbidden URL components")
        if parsed.path.rstrip("/") != expected_base_path:
            raise ValueError(f"AgentCore gateway base URL must end in {expected_base_path}")
        expected_suffix = f".gateway.bedrock-agentcore.{region_name}.amazonaws.com"
        if not parsed.hostname.endswith(expected_suffix):
            raise ValueError("AgentCore gateway host does not match the configured AWS Region")
        self._origin = f"https://{parsed.hostname}"
        self._region_name = region_name
        self._expected_request_path = expected_request_path
        self._credential_provider = credential_provider or _Boto3CredentialProvider(region_name)

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        self._validate_request(request)
        credentials = self._credential_provider.get_credentials()
        if credentials is None:
            raise RuntimeError("AWS credentials are required for AgentCore gateway authentication")
        frozen = credentials.get_frozen_credentials()

        request.headers.pop("authorization", None)
        request.headers.pop("x-amz-date", None)
        request.headers.pop("x-amz-security-token", None)
        aws_request = AWSRequest(
            method=request.method,
            url=str(request.url),
            data=request.content,
            headers=dict(request.headers),
        )
        SigV4Auth(frozen, _SERVICE, self._region_name).add_auth(aws_request)
        for name, value in aws_request.headers.items():
            request.headers[name] = value
        yield request

    def _validate_request(self, request: httpx.Request) -> None:
        parsed = urlsplit(str(request.url))
        origin = f"{parsed.scheme}://{parsed.hostname}"
        expected_host = self._origin.removeprefix("https://")
        if (
            request.method != "POST"
            or origin != self._origin
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
            or request.headers.get("host") != expected_host
        ):
            raise ValueError("AgentCore gateway request target is not permitted")
        if parsed.path != self._expected_request_path or parsed.query or parsed.fragment:
            raise ValueError("AgentCore gateway request path is not permitted")


class AgentCoreGatewaySigV4Auth(_AgentCoreGatewaySigV4Auth):
    """Sign only the configured OpenAI-compatible Responses endpoint."""

    def __init__(
        self,
        *,
        base_url: str,
        region_name: str,
        credential_provider: _CredentialProvider | None = None,
    ) -> None:
        super().__init__(
            base_url=base_url,
            region_name=region_name,
            expected_base_path="/inference/v1",
            expected_request_path=_RESPONSES_PATH,
            credential_provider=credential_provider,
        )


class AgentCoreMcpGatewaySigV4Auth(_AgentCoreGatewaySigV4Auth):
    """Sign only the configured MCP endpoint."""

    def __init__(
        self,
        *,
        base_url: str,
        region_name: str,
        credential_provider: _CredentialProvider | None = None,
    ) -> None:
        super().__init__(
            base_url=base_url,
            region_name=region_name,
            expected_base_path=_MCP_PATH,
            expected_request_path=_MCP_PATH,
            credential_provider=credential_provider,
        )
