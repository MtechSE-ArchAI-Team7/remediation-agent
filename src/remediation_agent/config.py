"""Environment-backed application settings."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    openai_base_url: str | None = None
    deepseek_base_url: str | None = None
    model_timeout_seconds: float = Field(default=60.0, gt=0)
    model_transport_retries: int = Field(default=2, ge=0)
    model_temperature: float = Field(default=0.0, ge=0.0, le=2.0)

    postgres_dsn: SecretStr | None = None
    checkpoint_encryption_key: SecretStr | None = None
    artifact_root: Path = Path(".artifacts")
    workspace_root: Path = Path(".workspaces")
    sandbox_image: str = "aios-remediation-sandbox:local"

    github_token: SecretStr | None = None
    github_repository: str | None = None
    github_writes_enabled: bool = False
    git_author_name: str = Field(default="AIOS Remediation Agent", min_length=1, max_length=200)
    git_author_email: str = Field(
        default="aios-remediation@users.noreply.github.com",
        min_length=3,
        max_length=320,
        pattern=r"^[^\s@]+@[^\s@]+$",
    )

    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8080, ge=1, le=65535)
    prompt_version: str = "remediation-v1"

    @field_validator("sandbox_image")
    @classmethod
    def sandbox_image_is_a_single_reference(cls, value: str) -> str:
        if not value or value.startswith("-") or any(character.isspace() for character in value):
            raise ValueError("AIOS_SANDBOX_IMAGE must be one container image reference")
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
        return self

    def require_persistent_checkpointing(self) -> tuple[str, str]:
        if self.postgres_dsn is None:
            raise ValueError("AIOS_POSTGRES_DSN is required for the service runtime")
        if self.checkpoint_encryption_key is None:
            raise ValueError("AIOS_CHECKPOINT_ENCRYPTION_KEY is required for persisted checkpoints")
        return self.postgres_dsn.get_secret_value(), self.checkpoint_encryption_key.get_secret_value()
