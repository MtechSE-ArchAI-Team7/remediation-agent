"""Operator-owned capability definitions shared by planning and sealed assertions."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files

from pydantic import Field, TypeAdapter

from remediation_agent.domain.models import RequestContract, StrictModel
from remediation_agent.policy.models import PolicyConfig


class CapabilityProfileV1(StrictModel):
    version: str
    runtime: str
    dependencies: str
    startup: str
    required_evidence_paths: list[str] = Field(max_length=20)
    request_contract: RequestContract
    limitations: list[str] = Field(max_length=20)
    assertions: dict[str, str] = Field(min_length=1, max_length=40)
    regression_test_ids: list[str] = Field(default_factory=list, max_length=40)


@lru_cache(maxsize=1)
def capability_registry() -> dict[str, CapabilityProfileV1]:
    resource = files("remediation_agent.adapters").joinpath("validation_assets/profiles.json")
    return TypeAdapter(dict[str, CapabilityProfileV1]).validate_json(resource.read_text())


def verify_registry_policy(policy: PolicyConfig) -> None:
    for name, task in policy.validation_tasks.items():
        profile = capability_registry().get(task.profile or "")
        if profile is None:
            continue
        if (
            task.required_test_ids != list(profile.assertions)
            or task.regression_test_ids != profile.regression_test_ids
            or task.assertions != profile.assertions
            or task.required_evidence_paths != profile.required_evidence_paths
            or task.request_contract != profile.request_contract
            or task.limitations != profile.limitations
        ):
            raise ValueError(f"Operator capability {name} differs from its versioned executable definition")
