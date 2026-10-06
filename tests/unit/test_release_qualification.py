"""Release evidence must bind complete hosted trials to exact executing inputs."""

from datetime import UTC, datetime

import pytest

from remediation_agent.domain.qualification import (
    QualificationTrialV1,
    ReleaseQualificationV1,
    require_release_qualification,
)
from scripts.qualification_environment import runtime_digest


def report() -> ReleaseQualificationV1:
    return ReleaseQualificationV1(
        case="ah56",
        backend="code-interpreter",
        source_revision="a" * 40,
        image_digest="sha256:" + "b" * 64,
        runtime_configuration_digest="sha256:" + "c" * 64,
        policy_digest="sha256:policy",
        assets_digest="sha256:assets",
        model_configuration_digest="sha256:model",
        prompt_version="v3",
        snapshot_digest="sha256:snapshot",
        qualified_at=datetime.now(UTC),
        trials=[
            QualificationTrialV1(
                run_id=f"run-{i}",
                status="DRAFT_PR_CREATED",
                locally_verified=True,
                evidence_persisted=True,
                cleanup_verified=True,
                publication_verified=True,
                candidate_digest="sha256:candidate",
                commit_sha="d" * 40,
                assertions_digests=["sha256:assertions"],
            )
            for i in range(3)
        ],
    )


def check(value: ReleaseQualificationV1) -> None:
    require_release_qualification(
        value, source="a" * 40, image="sha256:" + "b" * 64, runtime_configuration="sha256:" + "c" * 64
    )


def test_three_complete_hosted_trials_qualify() -> None:
    check(report())


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_revision", "e" * 40),
        ("image_digest", "sha256:" + "e" * 64),
        ("runtime_configuration_digest", "sha256:" + "e" * 64),
        ("backend", "docker"),
    ],
)
def test_changed_release_inputs_do_not_qualify(field: str, value: str) -> None:
    with pytest.raises(ValueError, match="MISMATCH"):
        check(report().model_copy(update={field: value}))


@pytest.mark.parametrize(
    "field,value",
    [
        ("locally_verified", False),
        ("cleanup_verified", False),
        ("evidence_persisted", False),
        ("publication_verified", False),
        ("status", "DRAFT_PR_PREPARED"),
        ("run_id", "run-1"),
        ("assertions_digests", ["sha256:changed"]),
    ],
)
def test_partial_or_duplicated_trials_do_not_qualify(field: str, value: object) -> None:
    original = report()
    altered = original.model_copy(
        update={"trials": [original.trials[0].model_copy(update={field: value}), *original.trials[1:]]}
    )
    with pytest.raises(ValueError, match="MISMATCH"):
        check(altered)


def test_runtime_configuration_changes_invalidate_qualification() -> None:
    runtime: dict[str, object] = {
        "agentRuntimeArn": "arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:runtime/remediation_agent-2425SXH9D3",
        "environmentVariables": {"AIOS_LLM_MODEL": "model-one", "AIOS_RELEASE_ID": "old"},
    }
    digest = runtime_digest(runtime)
    runtime["environmentVariables"] = {"AIOS_LLM_MODEL": "model-one", "AIOS_RELEASE_ID": "new"}
    assert runtime_digest(runtime) == digest
    runtime["environmentVariables"] = {"AIOS_LLM_MODEL": "model-two"}
    assert runtime_digest(runtime) != digest
    runtime["agentRuntimeArn"] = "arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/other"
    with pytest.raises(ValueError, match="IDENTITY"):
        runtime_digest(runtime)
