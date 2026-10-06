"""Operator-owned release provenance adapters."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Protocol, cast

import boto3  # type: ignore[import-untyped]

from remediation_agent.domain.enums import ReleaseProvenanceStatus
from remediation_agent.domain.models import ReleaseProvenanceV1


class _AgentCoreControlClient(Protocol):
    def list_agent_runtime_versions(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_agent_runtime(self, **kwargs: object) -> Mapping[str, object]: ...


class LocalReleaseProvenance:
    """Identify explicitly non-hosted runs without calling cloud control planes."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))

    async def resolve(self) -> ReleaseProvenanceV1:
        return ReleaseProvenanceV1(
            status=ReleaseProvenanceStatus.LOCAL,
            verified_at=self._clock(),
            verification_method="LOCAL",
        )


class AgentCoreReleaseProvenance:
    """Resolve the exact immutable AgentCore version matching the executing release."""

    def __init__(
        self,
        *,
        runtime_id: str,
        release_id: str,
        source_revision: str,
        image_digest: str,
        region_name: str,
        expected_account_id: str,
        max_versions: int = 100,
        client: _AgentCoreControlClient | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.runtime_id = runtime_id
        self.release_id = release_id
        self.source_revision = source_revision.lower()
        self.image_digest = image_digest.lower()
        self.region_name = region_name
        self.expected_account_id = expected_account_id
        self.max_versions = max_versions
        self._client = client or cast(
            _AgentCoreControlClient,
            boto3.client("bedrock-agentcore-control", region_name=region_name),
        )
        self._clock = clock or (lambda: datetime.now(UTC))

    async def resolve(self) -> ReleaseProvenanceV1:
        try:
            versions = await self._list_versions()
            matches: list[ReleaseProvenanceV1] = []
            for version in versions:
                response = await asyncio.to_thread(
                    self._client.get_agent_runtime,
                    agentRuntimeId=self.runtime_id,
                    agentRuntimeVersion=version,
                )
                candidate = self._matching_candidate(response)
                if candidate is not None:
                    matches.append(candidate)
            if len(matches) == 1:
                return matches[0]
            status = ReleaseProvenanceStatus.AMBIGUOUS if len(matches) > 1 else ReleaseProvenanceStatus.UNAVAILABLE
            code = "RELEASE_PROVENANCE_AMBIGUOUS" if matches else "RELEASE_PROVENANCE_NOT_FOUND"
            return self._failure(status, code)
        except Exception as exc:  # noqa: BLE001 - normalize the AWS control-plane boundary
            return self._failure(
                ReleaseProvenanceStatus.UNAVAILABLE,
                f"RELEASE_PROVENANCE_{type(exc).__name__.upper()}"[:200],
            )

    async def _list_versions(self) -> list[str]:
        versions: list[str] = []
        next_token: str | None = None
        while len(versions) < self.max_versions:
            request: dict[str, object] = {
                "agentRuntimeId": self.runtime_id,
                "maxResults": min(100, self.max_versions - len(versions)),
            }
            if next_token is not None:
                request["nextToken"] = next_token
            response = await asyncio.to_thread(self._client.list_agent_runtime_versions, **request)
            raw_versions = response.get("agentRuntimes")
            if not isinstance(raw_versions, list):
                raise ValueError("AgentCore version list is malformed")
            if len(raw_versions) > self.max_versions - len(versions):
                raise ValueError("AgentCore version list exceeded the configured bound")
            for raw in raw_versions:
                if not isinstance(raw, Mapping):
                    raise ValueError("AgentCore version entry is malformed")
                version = raw.get("agentRuntimeVersion")
                if not isinstance(version, str) or not version.isdigit():
                    raise ValueError("AgentCore runtime version is malformed")
                versions.append(version)
                if len(versions) >= self.max_versions:
                    break
            raw_token = response.get("nextToken")
            if raw_token is None:
                return versions
            if not isinstance(raw_token, str) or not raw_token:
                raise ValueError("AgentCore pagination token is malformed")
            next_token = raw_token
        if next_token is not None:
            raise ValueError("AgentCore version scan exceeded the configured bound")
        return versions

    def _matching_candidate(self, response: Mapping[str, object]) -> ReleaseProvenanceV1 | None:
        environment = response.get("environmentVariables")
        artifact = response.get("agentRuntimeArtifact")
        if not isinstance(environment, Mapping) or not isinstance(artifact, Mapping):
            return None
        container = artifact.get("containerConfiguration")
        if not isinstance(container, Mapping):
            return None
        container_uri = container.get("containerUri")
        runtime_arn = response.get("agentRuntimeArn")
        runtime_id = response.get("agentRuntimeId")
        runtime_version = response.get("agentRuntimeVersion")
        if (
            not isinstance(container_uri, str)
            or not isinstance(runtime_arn, str)
            or not isinstance(runtime_id, str)
            or not isinstance(runtime_version, str)
        ):
            return None
        expected_arn_prefix = (
            f"arn:aws:bedrock-agentcore:{self.region_name}:{self.expected_account_id}:runtime/{self.runtime_id}"
        )
        expected_image_prefix = f"{self.expected_account_id}.dkr.ecr.{self.region_name}.amazonaws.com/"
        if (
            environment.get("AIOS_RELEASE_ID") != self.release_id
            or environment.get("AIOS_RELEASE_SOURCE_SHA") != self.source_revision
            or environment.get("AIOS_RELEASE_IMAGE_DIGEST") != self.image_digest
            or runtime_id != self.runtime_id
            or runtime_arn != expected_arn_prefix
            or not container_uri.startswith(expected_image_prefix)
            or not container_uri.endswith("@" + self.image_digest)
        ):
            return None
        return ReleaseProvenanceV1(
            status=ReleaseProvenanceStatus.VERIFIED,
            release_id=self.release_id,
            source_revision=self.source_revision,
            image_digest=self.image_digest,
            runtime_arn=runtime_arn,
            runtime_id=runtime_id,
            runtime_version=runtime_version,
            region=self.region_name,
            verified_at=self._clock(),
            verification_method="AGENTCORE_CONTROL_PLANE",
        )

    def _failure(self, status: ReleaseProvenanceStatus, code: str) -> ReleaseProvenanceV1:
        return ReleaseProvenanceV1(
            status=status,
            release_id=self.release_id,
            source_revision=self.source_revision,
            image_digest=self.image_digest,
            runtime_id=self.runtime_id,
            region=self.region_name,
            verified_at=self._clock(),
            verification_method="AGENTCORE_CONTROL_PLANE",
            error_code=code,
        )
