"""Strict operator policy schema."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from remediation_agent.domain.models import NonEmptyStr, RequestContract, StrictModel


class PathRules(StrictModel):
    autonomous: list[NonEmptyStr] = Field(min_length=1)
    approval_required: list[NonEmptyStr] = Field(min_length=1)
    forbidden: list[NonEmptyStr] = Field(min_length=1)


class RepositoryRules(StrictModel):
    allowed_providers: list[NonEmptyStr] = Field(min_length=1)
    allowed_url_patterns: list[NonEmptyStr] = Field(min_length=1)


class Limits(StrictModel):
    autonomous_max_changed_files: int = Field(gt=0)
    absolute_max_changed_files: int = Field(gt=0)
    autonomous_max_diff_lines: int = Field(gt=0)
    absolute_max_diff_lines: int = Field(gt=0)
    max_validation_attempts: int = Field(gt=0)
    max_model_format_retries: int = Field(ge=0)
    max_tree_entries: int = Field(gt=0)
    max_file_bytes: int = Field(gt=0)
    max_search_results: int = Field(gt=0)
    max_context_bytes: int = Field(gt=0)
    max_inspection_rounds: int = Field(gt=0)
    max_inspection_tool_calls: int = Field(gt=0)
    max_mcp_tool_timeout_seconds: int = Field(gt=0)
    max_task_timeout_seconds: int = Field(gt=0)
    max_task_output_bytes: int = Field(gt=0)
    max_validation_tasks_per_attempt: int = Field(gt=0)
    max_model_output_tokens: int = Field(gt=0)
    max_active_runs: int = Field(gt=0)

    @model_validator(mode="after")
    def absolute_limits_cover_autonomous_limits(self) -> Limits:
        if self.absolute_max_changed_files < self.autonomous_max_changed_files:
            raise ValueError("absolute file limit must be >= autonomous file limit")
        if self.absolute_max_diff_lines < self.autonomous_max_diff_lines:
            raise ValueError("absolute diff limit must be >= autonomous diff limit")
        return self


class ValidationTaskConfig(StrictModel):
    kind: Literal["STATIC", "BEHAVIORAL"] = "STATIC"
    profile: Literal["pytest", "node_test", "ecommerce_purchase"] | None = None
    test_paths: list[NonEmptyStr] = Field(default_factory=list, max_length=20)
    required_test_ids: list[NonEmptyStr] = Field(default_factory=list, max_length=40)
    required_evidence_paths: list[NonEmptyStr] = Field(default_factory=list, max_length=20)
    request_contract: RequestContract | None = None

    @model_validator(mode="after")
    def behavioral_configuration(self) -> ValidationTaskConfig:
        if self.kind == "BEHAVIORAL" and self.profile is None:
            raise ValueError("behavioral tasks require a trusted profile")
        if self.kind == "STATIC" and self.profile is not None:
            raise ValueError("static tasks cannot declare behavioral profiles")
        if self.profile in {"pytest", "node_test"} and not self.test_paths:
            raise ValueError("behavioral test paths must be explicit")
        for name in self.test_paths:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or not path.parts or "\x00" in name or "\\" in name:
                raise ValueError("unsafe behavioral test path")
            if path.parts[0] not in {"tests", "test"}:
                raise ValueError("behavioral overlays must remain in test directories")
        return self

    argv: list[NonEmptyStr] = Field(min_length=1, max_length=50)
    cwd: NonEmptyStr = "."
    environment: dict[str, str] = Field(default_factory=dict, max_length=50)
    timeout_seconds: int = Field(gt=0)
    output_limit_bytes: int = Field(gt=0)
    retryable: bool = False

    @field_validator("argv")
    @classmethod
    def argv_has_no_nul(cls, value: list[str]) -> list[str]:
        if any("\x00" in argument for argument in value):
            raise ValueError("validation argv cannot contain NUL")
        if any(len(argument.encode("utf-8")) > 4_096 for argument in value):
            raise ValueError("validation argv argument exceeds 4096 bytes")
        return value

    @field_validator("cwd")
    @classmethod
    def cwd_is_relative(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("validation cwd must stay inside the workspace")
        return value

    @field_validator("environment")
    @classmethod
    def environment_is_safe(cls, value: dict[str, str]) -> dict[str, str]:
        sensitive = re.compile(r"(TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY)", re.IGNORECASE)
        for key, item in value.items():
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
                raise ValueError(f"invalid environment key: {key}")
            if sensitive.search(key):
                raise ValueError(f"validation environment cannot contain secret-like key: {key}")
            if "\x00" in item:
                raise ValueError(f"validation environment value contains NUL: {key}")
            if len(item.encode("utf-8")) > 4_096:
                raise ValueError(f"validation environment value is too large: {key}")
        return value


class MandatoryTaskRule(StrictModel):
    path_patterns: list[NonEmptyStr] = Field(min_length=1)
    task_names: list[NonEmptyStr] = Field(min_length=1)


class ArtifactPolicy(StrictModel):
    retention_days: int = Field(gt=0)
    write_audit_jsonl: bool
    include_full_diff: bool


class GitHubPolicy(StrictModel):
    writes_enabled: bool = False


class IncidentMemoryPolicy(StrictModel):
    writes_enabled: bool = False


class PolicyConfig(StrictModel):
    policy_id: NonEmptyStr
    version: NonEmptyStr
    repositories: RepositoryRules
    paths: PathRules
    limits: Limits
    default_validation_tasks: list[NonEmptyStr] = Field(min_length=1)
    validation_tasks: dict[str, ValidationTaskConfig] = Field(min_length=1, max_length=50)
    mandatory_tasks: list[MandatoryTaskRule] = Field(default_factory=list)
    artifacts: ArtifactPolicy
    github: GitHubPolicy
    incident_memory: IncidentMemoryPolicy = Field(default_factory=IncidentMemoryPolicy)

    @model_validator(mode="after")
    def references_known_tasks_and_bounded_limits(self) -> PolicyConfig:
        known = set(self.validation_tasks)
        referenced = set(self.default_validation_tasks)
        for rule in self.mandatory_tasks:
            referenced.update(rule.task_names)
        missing = referenced - known
        if missing:
            raise ValueError(f"policy references unknown validation tasks: {sorted(missing)}")
        if len(self.validation_tasks) > self.limits.max_validation_tasks_per_attempt:
            raise ValueError("defined validation tasks exceed the per-attempt task limit")
        for name, task in self.validation_tasks.items():
            if task.timeout_seconds > self.limits.max_task_timeout_seconds:
                raise ValueError(f"task {name} exceeds maximum timeout")
            if task.output_limit_bytes > self.limits.max_task_output_bytes:
                raise ValueError(f"task {name} exceeds maximum output size")
        return self
