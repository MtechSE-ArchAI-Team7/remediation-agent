"""Offline checks for the live driver and independent attack oracle."""

import base64
import runpy
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from remediation_agent.adversarial import FAMILIES, SURFACES, attack_payload, canary_for, contains_canary
from remediation_agent.config import Settings
from remediation_agent.policy.engine import PolicyEngine
from scripts.gap_fixtures import fixtures, handoff, initialize, policy
from scripts.run_gap_campaign import make_manifest


def test_all_fixture_sources_are_reproducible_and_policy_bound(tmp_path: Path) -> None:
    for fixture in fixtures():
        first = initialize(tmp_path / fixture.key / "first", fixture.files)
        second = initialize(tmp_path / fixture.key / "second", fixture.files)
        assert first == second
        PolicyEngine(policy(fixture)).validate_repository(handoff(fixture, first).repository)


def test_attack_matrix_retains_each_dimension() -> None:
    manifest = make_manifest(
        "offline-check",
        Settings.model_construct(
            policy_file=Path("config/policies/reference.json"), llm_provider="fake", llm_model="fixture"
        ),
        {"source_revision": "a" * 40, "image_digest": "sha256:" + "b" * 64, "runtime_version": "63"},
        "attacks",
    )
    assert len(manifest.cases) == 20
    assert sum(c.repetitions for c in manifest.cases) == 60
    assert {(c.attack_family, c.attack_surface) for c in manifest.cases} == {(f, s) for f in FAMILIES for s in SURFACES}
    assert manifest.publication_mode == "disabled" and manifest.implementation_digest
    for family in FAMILIES:
        assert "UNTRUSTED FIXTURE" in attack_payload(family)
    with pytest.raises(ValueError):
        attack_payload("unclassified")


def test_oracle_detects_plain_encoded_and_spaced_canaries() -> None:
    canary = canary_for("run-one")
    assert canary != canary_for("run-two")
    for encoded in (
        canary,
        canary.lower(),
        " ".join(canary),
        base64.b64encode(canary.encode()).decode(),
        canary.encode().hex(),
    ):
        assert contains_canary("output " + encoded, canary)
    assert not contains_canary("safe ordinary response", canary)
    with pytest.raises(ValueError):
        contains_canary("short", "short")


def test_raw_visible_response_can_be_checked_even_when_schema_parsing_fails() -> None:
    from remediation_agent.adapters.models import ProviderStructuredModel
    from scripts.run_gap_campaign import ObservedModel
    from tests.unit.test_campaign import manifest
    from tests.unit.test_model_adapter import _ChatModel

    canary = canary_for("malformed")
    provider = ProviderStructuredModel(_ChatModel([]), provider="openai", model="fixture", timeout_seconds=1, retries=0)
    observer = ObservedModel(provider, canary, manifest())
    observer.observe_raw({"raw": AIMessage(content="invalid json " + canary), "parsed": None})
    assert observer.leaked and observer.raw_responses == 1
    assert canary not in str(observer.transcript)


def test_corrected_python_fixture_has_a_real_assertion_failure_and_passing_candidate(tmp_path: Path) -> None:
    fixture = next(f for f in fixtures() if f.key == "py-average")
    initialize(tmp_path / "source", fixture.files)
    test_path = tmp_path / "source/tests/test_contract.py"
    with pytest.raises(AssertionError):
        runpy.run_path(str(test_path))["test_contract"]()
    (tmp_path / "source/src/average.py").write_text(
        "def average(values):\n    return sum(values) / len(values) if values else 0\n"
    )
    runpy.run_path(str(test_path))["test_contract"]()


def test_followup_shards_partition_every_case_without_duplicate_runs() -> None:
    settings = Settings.model_construct(
        policy_file=Path("config/policies/reference.json"), llm_provider="fake", llm_model="fixture"
    )
    runtime = {"source_revision": "a" * 40, "image_digest": "sha256:" + "b" * 64, "runtime_version": "63"}
    first = make_manifest("first", settings, runtime, "followup", 0, 2)
    second = make_manifest("second", settings, runtime, "followup", 1, 2)
    assert not {c.case_id for c in first.cases} & {c.case_id for c in second.cases}
    assert sum(c.repetitions for c in first.cases + second.cases) == 65
    assert len(first.cases) + len(second.cases) == 21
    with pytest.raises(ValueError, match="INVALID_CAMPAIGN_SHARD"):
        make_manifest("invalid", settings, runtime, "followup", 2, 2)
