"""Static safety checks for GitHub release workflows."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_DIR = _ROOT / ".github" / "workflows"


def _load_workflow(name: str) -> dict[str, object]:
    raw = yaml.safe_load((_WORKFLOW_DIR / name).read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return cast(dict[str, object], raw)


def _trigger(workflow: dict[str, object]) -> dict[str, object]:
    raw = workflow.get("on")
    if raw is None:
        raw = cast(dict[object, object], workflow).get(True)
    assert isinstance(raw, dict)
    return cast(dict[str, object], raw)


def _jobs(workflow: dict[str, object]) -> dict[str, dict[str, object]]:
    raw = workflow["jobs"]
    assert isinstance(raw, dict)
    return cast(dict[str, dict[str, object]], raw)


def _assert_local_agentcore_deploy(job: dict[str, object]) -> None:
    assert job["uses"] == "./.github/workflows/deploy-agentcore-runtime.yaml"


def _contains_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


def test_main_release_runs_ci_then_image_then_agentcore_deploy() -> None:
    workflow = _load_workflow("ci.yaml")
    jobs = _jobs(workflow)

    assert jobs["image"]["needs"] == "ci"
    assert cast(dict[str, object], jobs["image"]["with"])["publish"] == (
        "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
    )
    assert jobs["qualify"]["needs"] == "image"
    assert jobs["qualify"]["uses"] == "./.github/workflows/qualify-agentcore-runtime.yaml"
    assert jobs["deploy"]["needs"] == ["image", "qualify"]
    assert jobs["deploy"]["if"] == "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"

    assert jobs["ci"]["uses"] == "./.github/workflows/checks.yaml"
    assert jobs["image"]["uses"] == "./.github/workflows/build-scan-image.yaml"
    _assert_local_agentcore_deploy(jobs["deploy"])

    deploy_with = cast(dict[str, object], jobs["deploy"]["with"])
    deploy_secrets = cast(dict[str, object], jobs["deploy"]["secrets"])
    assert deploy_with["agent-runtime-id"] == "${{ vars.AGENTCORE_RUNTIME_ID }}"
    assert deploy_with["github-repository"] == "MtechSE-ArchAI-Team7/buggy-ecommerce-demo"
    assert deploy_with["image-uri"] == "${{ needs.image.outputs.image-uri }}"
    assert deploy_with["image-digest"] == "${{ needs.image.outputs.image-digest }}"
    assert deploy_with["source-revision"] == "${{ github.sha }}"
    assert deploy_with["release-id"] == "${{ github.run_id }}-${{ github.run_attempt }}"
    assert deploy_with["server-protocol"] == "A2A"
    smoke = json.loads(cast(str, deploy_with["smoke-test-json"]))
    assert smoke["method"] == "SendMessage"
    probe_part = smoke["params"]["message"]["parts"][0]
    assert probe_part["mediaType"] == "application/vnd.aios.provider-probe-request.v1+json"
    assert probe_part["data"] == {"schema_version": "1.0", "probe": "openai"}
    assert deploy_secrets["AWS_ROLE_ARN"] == "${{ secrets.AWS_AGENTCORE_DEPLOY_ROLE_ARN }}"
    assert not _contains_key(workflow, "environment")


def test_pull_requests_run_ci_without_release_jobs() -> None:
    workflow = _load_workflow("ci.yaml")
    triggers = _trigger(workflow)
    jobs = _jobs(workflow)

    assert "pull_request" in triggers
    assert "pull_request" not in str(cast(dict[str, object], jobs["image"]["with"])["publish"])
    assert "pull_request" not in str(jobs["deploy"]["if"])


def test_qualification_transfers_private_container_evidence_before_upload() -> None:
    job = _jobs(_load_workflow("qualify-agentcore-runtime.yaml"))["qualify"]
    steps = cast(list[dict[str, object]], job["steps"])
    transfer_index = next(
        i for i, step in enumerate(steps) if step.get("name") == "Transfer private evidence to the artifact uploader"
    )
    upload_index = next(
        i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    )
    transfer = steps[transfer_index]
    assert transfer_index < upload_index
    assert transfer["if"] == "${{ always() }}"
    script = cast(str, transfer["run"])
    assert 'evidence="$RUNNER_TEMP/qualification-output"' in script
    assert 'chown --recursive --no-dereference "$(id -u):$(id -g)" "$evidence"' in script
    assert "chmod" not in script  # Private evidence stays private; only the owning CI identity changes.


def test_standalone_image_workflow_keeps_release_triggers_and_manual_deploys() -> None:
    workflow = _load_workflow("image.yaml")
    triggers = _trigger(workflow)
    push = cast(dict[str, object], triggers["push"])
    jobs = _jobs(workflow)

    assert "workflow_dispatch" in triggers
    assert push == {"tags": ["v*"]}
    assert jobs["qualify"]["needs"] == "image"
    assert jobs["deploy"]["needs"] == ["image", "qualify"]
    assert jobs["deploy"]["if"] == (
        "${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' }}"
    )
    assert jobs["image"]["needs"] == "ci"
    assert jobs["image"]["uses"] == "./.github/workflows/build-scan-image.yaml"
    _assert_local_agentcore_deploy(jobs["deploy"])
    deploy_with = cast(dict[str, object], jobs["deploy"]["with"])
    assert deploy_with["server-protocol"] == "A2A"
    assert deploy_with["github-repository"] == "MtechSE-ArchAI-Team7/buggy-ecommerce-demo"
    assert deploy_with["source-revision"] == "${{ github.sha }}"
    assert deploy_with["release-id"] == "${{ github.run_id }}-${{ github.run_attempt }}"
    assert json.loads(cast(str, deploy_with["smoke-test-json"]))["method"] == "SendMessage"
    assert not _contains_key(workflow, "environment")


def test_local_agentcore_deploy_preserves_required_runtime_configuration() -> None:
    workflow = _load_workflow("deploy-agentcore-runtime.yaml")
    deploy = _jobs(workflow)["deploy"]
    steps = cast(list[dict[str, object]], deploy["steps"])
    workflow_call = cast(dict[str, object], _trigger(workflow)["workflow_call"])
    inputs = cast(dict[str, object], workflow_call["inputs"])
    script = "\n".join(value for step in steps if isinstance((value := step.get("run")), str))

    assert "server-protocol" in inputs
    assert cast(dict[str, object], inputs["source-revision"])["required"] is True
    assert cast(dict[str, object], inputs["release-id"])["required"] is True
    assert cast(dict[str, object], inputs["github-repository"])["required"] is True
    assert "AGENTCORE_CURRENT_CONFIGURATION_FILE" in script
    assert ".metadataConfiguration.requireMMDSV2 == true" in script
    for field in ("environmentVariables", "lifecycleConfiguration", "metadataConfiguration", "networkConfiguration"):
        assert script.count(field) >= 3
    assert '--slurpfile current "$AGENTCORE_CURRENT_CONFIGURATION_FILE"' in script
    assert "update-agent-runtime" in script
    assert "invoke-agent-runtime" in script
    assert "AGENTCORE_PREVIOUS_PROTOCOL" in script
    assert "AIOS_GITHUB_REPOSITORY: $repository" in script
    for variable in (
        "AIOS_RELEASE_ID",
        "AIOS_RELEASE_SOURCE_SHA",
        "AIOS_RELEASE_IMAGE_DIGEST",
        "AIOS_AGENTCORE_RUNTIME_ID",
    ):
        assert variable in script
    assert 'endswith("@" + $image_digest)' in script
    assert 'current_repository="$(jq -r' in script
    assert '"$current_repository" == "$TARGET_GITHUB_REPOSITORY"' in script
    assert '"$account_id" != "$EXPECTED_AWS_ACCOUNT_ID"' in script
    assert "Refusing AgentCore deployment in unexpected AWS account" in script
    assert 'has("filesystemConfigurations")' in script
    assert "The AWS CLI is too old to preserve AgentCore filesystem configurations." in script
    assert "Verify deployed runtime invariants" in {cast(str, step.get("name")) for step in steps}
    assert script.count('filesystemConfigurations == [{"sessionStorage":{"mountPath":"/mnt/workspace"}}]') >= 3
    assert script.count('.environmentVariables.AIOS_WORKSPACE_ROOT == "/mnt/workspace/runs"') >= 3
    assert "The AgentCore rollback version failed its release or workspace invariant check." in script
    assert "The bounded rollback provider probe failed after three attempts." in script
    assert "rollback-${RELEASE_ID}" in script
    assert script.count("--arg repository") == 1
    target_bindings = 0
    account_bindings = 0
    for step in steps:
        environment = step.get("env")
        if not isinstance(environment, dict):
            continue
        assert "GITHUB_REPOSITORY" not in environment
        if environment.get("EXPECTED_AWS_ACCOUNT_ID") == "734849394833":
            account_bindings += 1
        if environment.get("TARGET_GITHUB_REPOSITORY") == "${{ inputs.github-repository }}":
            target_bindings += 1
    assert account_bindings == 3
    assert target_bindings == 2
    assert "create-agent-runtime" not in script
    assert "delete-agent-runtime" not in script


def test_every_external_action_is_immutable_and_checkouts_drop_credentials() -> None:
    for path in _WORKFLOW_DIR.glob("*.yaml"):
        workflow = _load_workflow(path.name)
        assert cast(dict[str, object], workflow.get("permissions", {})).get("contents", "read") == "read"
        for job in _jobs(workflow).values():
            if "steps" not in job:
                assert str(job["uses"]).startswith("./.github/workflows/")
                continue
            assert isinstance(job["timeout-minutes"], int)
            for step in cast(list[dict[str, object]], job["steps"]):
                if "uses" in step:
                    assert re.fullmatch(r"[A-Za-z0-9_./-]+@[0-9a-f]{40}", str(step["uses"]))
                    if str(step["uses"]).startswith("actions/checkout@"):
                        assert cast(dict[str, object], step["with"])["persist-credentials"] is False
                assert step.get("continue-on-error") is not True


def test_security_and_coverage_gate_cannot_be_bypassed_by_release_entrypoints() -> None:
    for name in ("ci.yaml", "image.yaml"):
        jobs = _jobs(_load_workflow(name))
        assert jobs["image"]["needs"] == "ci"
        assert jobs["ci"]["uses"] == "./.github/workflows/checks.yaml"
        assert jobs["summary"]["if"] == "${{ always() }}"
    checks = _jobs(_load_workflow("checks.yaml"))
    required = {
        "quality",
        "unit",
        "integration",
        "functional",
        "bandit",
        "audit",
        "coverage",
        "sonar",
        "snyk-code",
        "snyk-python",
        "snyk-node",
    }
    assert set(cast(list[str], checks["gate"]["needs"])) == required
    script = str(checks["gate"]["steps"])
    assert all(name in script for name in required)
    assert "--fail-under=90" in str(checks["coverage"])
    assert checks["coverage"]["needs"] == ["unit", "integration"]
    assert "ci_reports.py junit" in str(checks["integration"])
    assert "sonar.qualitygate.wait=true" in str(checks["sonar"])
    assert "not integration and not live_model" in (_ROOT / "pyproject.toml").read_text()


def test_scanned_archive_is_the_only_publication_source() -> None:
    jobs = _jobs(_load_workflow("build-scan-image.yaml"))
    assert jobs["scan"]["needs"] == ["build"]
    assert jobs["publish"]["needs"] == ["build", "scan"]
    assert jobs["publish"]["if"] == "${{ inputs.publish }}"
    for name in ("scan", "publish"):
        assert "sha256sum --check" in str(jobs[name])
        assert "needs.build.outputs.archive-sha256" in str(jobs[name])
    assert "docker load" in str(jobs["publish"])
    assert "docker build" not in str(jobs["publish"])
    assert "org.opencontainers.image.revision" in str(jobs["publish"])
    assert "ci_reports.py scan trivy" in str(jobs["scan"])
    for step in cast(list[dict[str, object]], jobs["scan"]["steps"]):
        if str(step.get("uses", "")).startswith("aquasecurity/trivy-action@"):
            assert cast(dict[str, object], step["with"])["ignore-unfixed"] is False
    assert "aws-access-key-id" not in str(jobs)


def test_manual_image_validation_cannot_publish_or_deploy() -> None:
    workflow = _load_workflow("validate-image.yaml")
    assert workflow["permissions"] == {"contents": "read"}
    jobs = cast(dict[str, dict[str, object]], workflow["jobs"])
    assert set(jobs) == {"image"}
    assert jobs["image"]["with"] == {"publish": False}
    assert "secrets" not in jobs["image"]
