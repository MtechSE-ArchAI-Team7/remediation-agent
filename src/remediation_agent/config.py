"""Environment-backed application settings."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_AGENTCORE_GATEWAY_ARN = re.compile(
    r"^arn:aws:bedrock-agentcore:(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):gateway/"
    r"(?P<gateway_id>[a-z0-9-]+)$"
)


class CheckpointSettings(BaseSettings):
    """Persistence-only settings used by database lifecycle commands."""

    model_config = SettingsConfigDict(
        env_prefix="AIOS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    postgres_dsn: SecretStr
    checkpoint_encryption_key: SecretStr

    def connection_values(self) -> tuple[str, str]:
        return self.postgres_dsn.get_secret_value(), self.checkpoint_encryption_key.get_secret_value()


class Settings(BaseSettings):
    """Runtime settings; operator safety policy is loaded from a separate JSON file."""

    model_config = SettingsConfigDict(
        env_prefix="AIOS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    policy_file: Path
    llm_provider: Literal["fake", "bedrock", "openai", "deepseek"]
    llm_model: str | None = None
    aws_region: str | None = None
    openai_auth_mode: Literal["api_key", "aws_iam_gateway"] = "api_key"
    openai_api_key: SecretStr | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    openai_secret_arn: str | None = None
    openai_gateway_arn: str | None = None
    deepseek_api_key: SecretStr | None = Field(default=None, validation_alias="DEEPSEEK_API_KEY")
    openai_base_url: str | None = None
    deepseek_base_url: str | None = None
    model_timeout_seconds: float = Field(default=60.0, gt=0)
    model_transport_retries: int = Field(default=2, ge=0)
    model_temperature: float = Field(default=0.0, ge=0.0, le=2.0)

    postgres_dsn: SecretStr | None = None
    checkpoint_encryption_key: SecretStr | None = None
    artifact_root: Path = Path(".artifacts")
    workspace_root: Path = Path(".workspaces")
    behavioral_bundle: Path = Path(".artifacts/validation/ecommerce")
    sandbox_image: str = "aios-remediation-sandbox:local"

    github_token: SecretStr | None = None
    github_repository: str | None = None
    github_writes_enabled: bool = False
    inspection_mcp_mode: Literal["github_direct", "agentcore_gateway"] = "github_direct"
    inspection_gateway_arn: str | None = None
    git_author_name: str = Field(default="AIOS Remediation Agent", min_length=1, max_length=200)
    git_author_email: str = Field(
        default="aios-remediation@users.noreply.github.com",
        min_length=3,
        max_length=320,
        pattern=r"^[^\s@]+@[^\s@]+$",
    )

    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8080, ge=1, le=65535)
    prompt_version: str = "remediation-v3"

    agentcore_memory_id: str | None = None
    incident_memory_enabled: bool = False
    incident_memory_writes_enabled: bool = False
    incident_memory_id: str | None = None
    incident_memory_strategy_id: str | None = None
    incident_memory_namespace: str | None = None
    runtime_secret_arn: str | None = None
    artifact_bucket: str | None = None
    a2a_task_store_prefix: str = "a2a/tasks"
    a2a_task_store_max_bytes: int = Field(default=524_288, ge=1, le=2_000_000)
    code_interpreter_identifier: str = "aws.codeinterpreter.v1"
    code_interpreter_bundle: Path = Path("/app/validation/pytest_vendor.tar.gz")
    invocation_timeout_seconds: float = Field(default=840.0, gt=0, le=840.0)
    agent4_delivery_enabled: bool = False
    agent4_runtime_arn: str | None = None
    agent4_region: str | None = None
    agent4_qualifier: str = "DEFAULT"
    agent4_timeout_seconds: float = Field(default=30.0, gt=0, le=120.0)
    release_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    release_source_sha: str | None = None
    release_image_digest: str | None = None
    agentcore_runtime_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    release_expected_account_id: str = Field(default="734849394833", pattern=r"^[0-9]{12}$")
    release_max_runtime_versions: int = Field(default=100, ge=1, le=500)

    @field_validator(
        "llm_model",
        "aws_region",
        "openai_base_url",
        "deepseek_base_url",
        "openai_api_key",
        "openai_secret_arn",
        "openai_gateway_arn",
        "deepseek_api_key",
        "postgres_dsn",
        "checkpoint_encryption_key",
        "github_token",
        "github_repository",
        "inspection_gateway_arn",
        "agentcore_memory_id",
        "incident_memory_id",
        "incident_memory_strategy_id",
        "incident_memory_namespace",
        "runtime_secret_arn",
        "artifact_bucket",
        "agent4_runtime_arn",
        "agent4_region",
        "release_id",
        "release_source_sha",
        "release_image_digest",
        "agentcore_runtime_id",
        mode="before",
    )
    @classmethod
    def blank_optional_values_are_unset(cls, value: Any) -> Any:
        """Treat blank values in the distributable .env example as absent."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("sandbox_image")
    @classmethod
    def sandbox_image_is_a_single_reference(cls, value: str) -> str:
        if not value or value.startswith("-") or any(character.isspace() for character in value):
            raise ValueError("AIOS_SANDBOX_IMAGE must be one container image reference")
        return value

    @field_validator("release_source_sha")
    @classmethod
    def release_source_sha_is_canonical(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError("AIOS_RELEASE_SOURCE_SHA must be a lowercase 40-character Git SHA")
        return value

    @field_validator("release_image_digest")
    @classmethod
    def release_image_digest_is_canonical(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("AIOS_RELEASE_IMAGE_DIGEST must be a canonical sha256 digest")
        return value

    @field_validator("github_repository")
    @classmethod
    def github_repository_is_owner_and_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parts = value.split("/")
        if len(parts) != 2 or any(not part or part.startswith("-") for part in parts):
            raise ValueError("AIOS_GITHUB_REPOSITORY must use owner/repository form")
        return value

    @model_validator(mode="after")
    def provider_configuration_is_complete(self) -> Settings:
        if self.llm_provider != "fake" and not self.llm_model:
            raise ValueError("AIOS_LLM_MODEL is required for live model providers")
        if self.llm_provider == "bedrock" and not self.aws_region:
            raise ValueError("AIOS_AWS_REGION is required for Bedrock")
        if self.llm_provider == "openai":
            if self.openai_auth_mode == "api_key":
                if self.openai_api_key is None and self.openai_secret_arn is None:
                    raise ValueError("OPENAI_API_KEY or AIOS_OPENAI_SECRET_ARN is required for OpenAI API-key mode")
                if self.openai_gateway_arn is not None:
                    raise ValueError("AIOS_OPENAI_GATEWAY_ARN is only valid in AWS IAM gateway mode")
            else:
                if self.aws_region is None:
                    raise ValueError("AIOS_AWS_REGION is required for OpenAI AWS IAM gateway mode")
                if self.openai_gateway_arn is None:
                    raise ValueError("AIOS_OPENAI_GATEWAY_ARN is required for OpenAI AWS IAM gateway mode")
                if self.openai_api_key is not None or self.openai_secret_arn is not None:
                    raise ValueError("OpenAI API keys and AIOS_OPENAI_SECRET_ARN are forbidden in AWS IAM gateway mode")
                if self.openai_base_url is not None:
                    raise ValueError("AIOS_OPENAI_BASE_URL is forbidden in AWS IAM gateway mode")
                self._validated_openai_gateway_parts()
        elif self.openai_gateway_arn is not None:
            raise ValueError("AIOS_OPENAI_GATEWAY_ARN requires AIOS_LLM_PROVIDER=openai")
        if self.llm_provider == "deepseek" and self.deepseek_api_key is None:
            raise ValueError("DEEPSEEK_API_KEY is required for DeepSeek")
        release_values = (
            self.release_id,
            self.release_source_sha,
            self.release_image_digest,
            self.agentcore_runtime_id,
        )
        if any(value is not None for value in release_values) and any(value is None for value in release_values):
            raise ValueError("all AgentCore release provenance settings must be configured together")
        if self.github_writes_enabled and self.github_token is None and self.runtime_secret_arn is None:
            raise ValueError("AIOS_GITHUB_TOKEN is required when GitHub writes are enabled")
        if self.github_writes_enabled and self.github_repository is None:
            raise ValueError("AIOS_GITHUB_REPOSITORY is required when GitHub writes are enabled")
        if self.inspection_mcp_mode == "agentcore_gateway":
            if self.aws_region is None:
                raise ValueError("AIOS_AWS_REGION is required for AgentCore inspection gateway mode")
            if self.inspection_gateway_arn is None:
                raise ValueError("AIOS_INSPECTION_GATEWAY_ARN is required in AgentCore inspection gateway mode")
            self._validated_inspection_gateway_parts()
        elif self.inspection_gateway_arn is not None:
            raise ValueError("AIOS_INSPECTION_GATEWAY_ARN requires AIOS_INSPECTION_MCP_MODE=agentcore_gateway")
        if self.agent4_delivery_enabled and (self.agent4_runtime_arn is None or self.agent4_region is None):
            raise ValueError(
                "AIOS_AGENT4_RUNTIME_ARN and AIOS_AGENT4_REGION are required when Agent 4 delivery is enabled"
            )
        if self.incident_memory_writes_enabled and not self.incident_memory_enabled:
            raise ValueError("AIOS_INCIDENT_MEMORY_WRITES_ENABLED requires AIOS_INCIDENT_MEMORY_ENABLED")
        if self.incident_memory_enabled:
            missing = [
                name
                for name, value in (
                    ("AIOS_AWS_REGION", self.aws_region),
                    ("AIOS_INCIDENT_MEMORY_ID", self.incident_memory_id),
                    ("AIOS_INCIDENT_MEMORY_STRATEGY_ID", self.incident_memory_strategy_id),
                    ("AIOS_INCIDENT_MEMORY_NAMESPACE", self.incident_memory_namespace),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"Incident-memory configuration is incomplete: {', '.join(missing)}")
            namespace = cast(str, self.incident_memory_namespace)
            if re.fullmatch(r"/[A-Za-z0-9._/-]+/", namespace) is None or ".." in namespace or "//" in namespace:
                raise ValueError("AIOS_INCIDENT_MEMORY_NAMESPACE must be a safe absolute namespace ending in /")
        return self

    def require_incident_memory_configuration(self) -> tuple[str, str, str, str]:
        if not self.incident_memory_enabled:
            raise ValueError("incident memory is disabled")
        return (
            cast(str, self.incident_memory_id),
            cast(str, self.incident_memory_strategy_id),
            cast(str, self.incident_memory_namespace),
            cast(str, self.aws_region),
        )

    def openai_gateway_base_url(self) -> str:
        """Derive the sole OpenAI-compatible base URL permitted for the configured gateway."""

        region, gateway_id = self._validated_openai_gateway_parts()
        return f"https://{gateway_id}.gateway.bedrock-agentcore.{region}.amazonaws.com/inference/v1"

    def _validated_openai_gateway_parts(self) -> tuple[str, str]:
        if self.openai_gateway_arn is None:
            raise ValueError("AIOS_OPENAI_GATEWAY_ARN is required for OpenAI AWS IAM gateway mode")
        match = _AGENTCORE_GATEWAY_ARN.fullmatch(self.openai_gateway_arn)
        if match is None:
            raise ValueError("AIOS_OPENAI_GATEWAY_ARN must be a valid AWS AgentCore gateway ARN")
        region = match.group("region")
        if region != self.aws_region:
            raise ValueError("AIOS_OPENAI_GATEWAY_ARN Region must match AIOS_AWS_REGION")
        return region, match.group("gateway_id")

    def inspection_gateway_endpoint(self) -> str:
        """Derive the sole MCP endpoint permitted for repository inspection."""

        region, gateway_id = self._validated_inspection_gateway_parts()
        return f"https://{gateway_id}.gateway.bedrock-agentcore.{region}.amazonaws.com/mcp"

    def _validated_inspection_gateway_parts(self) -> tuple[str, str]:
        if self.inspection_gateway_arn is None:
            raise ValueError("AIOS_INSPECTION_GATEWAY_ARN is required in AgentCore inspection gateway mode")
        match = _AGENTCORE_GATEWAY_ARN.fullmatch(self.inspection_gateway_arn)
        if match is None:
            raise ValueError("AIOS_INSPECTION_GATEWAY_ARN must be a valid AWS AgentCore gateway ARN")
        region = match.group("region")
        if region != self.aws_region:
            raise ValueError("AIOS_INSPECTION_GATEWAY_ARN Region must match AIOS_AWS_REGION")
        return region, match.group("gateway_id")

    def require_persistent_checkpointing(self) -> tuple[str, str]:
        if self.postgres_dsn is None:
            raise ValueError("AIOS_POSTGRES_DSN is required for the service runtime")
        if self.checkpoint_encryption_key is None:
            raise ValueError("AIOS_CHECKPOINT_ENCRYPTION_KEY is required for persisted checkpoints")
        return self.postgres_dsn.get_secret_value(), self.checkpoint_encryption_key.get_secret_value()

    def require_github_token(self) -> str:
        if self.github_token is None:
            raise ValueError("AIOS_GITHUB_TOKEN is required for hosted GitHub MCP inspection")
        return self.github_token.get_secret_value()

    def require_agentcore_configuration(self) -> tuple[str, str, str]:
        """Return the identifiers required by the hosted AgentCore composition root."""

        missing = [
            name
            for name, value in (
                ("AIOS_AGENTCORE_MEMORY_ID", self.agentcore_memory_id),
                ("AIOS_RUNTIME_SECRET_ARN", self.runtime_secret_arn),
                ("AIOS_ARTIFACT_BUCKET", self.artifact_bucket),
            )
            if value is None
        ]
        if missing:
            raise ValueError(f"AgentCore runtime configuration is incomplete: {', '.join(missing)}")
        return (
            cast(str, self.agentcore_memory_id),
            cast(str, self.runtime_secret_arn),
            cast(str, self.artifact_bucket),
        )

    def require_agentcore_release_configuration(self) -> tuple[str, str, str, str, str]:
        """Return immutable release identity required by hosted provenance checks."""

        values = (
            ("AIOS_RELEASE_ID", self.release_id),
            ("AIOS_RELEASE_SOURCE_SHA", self.release_source_sha),
            ("AIOS_RELEASE_IMAGE_DIGEST", self.release_image_digest),
            ("AIOS_AGENTCORE_RUNTIME_ID", self.agentcore_runtime_id),
            ("AIOS_AWS_REGION", self.aws_region),
        )
        missing = [name for name, value in values if value is None]
        if missing:
            raise ValueError(f"AgentCore release provenance is incomplete: {', '.join(missing)}")
        return cast(tuple[str, str, str, str, str], tuple(value for _, value in values))
