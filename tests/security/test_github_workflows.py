"""Static safety checks for GitHub release workflows."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_DIR = _ROOT / ".github" / "workflows"
_SHARED_WORKFLOW = re.compile(r"^MtechSE-ArchAI-Team7/github-actions-shared/\.github/workflows/[^@]+@[0-9a-f]{40}$")


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


def _assert_sha_pinned(job: dict[str, object]) -> str:
    uses = job["uses"]
    assert isinstance(uses, str)
    assert _SHARED_WORKFLOW.fullmatch(uses)
    return uses.rsplit("@", maxsplit=1)[1]


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
    assert jobs["image"]["if"] == "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
    assert jobs["deploy"]["needs"] == "image"
    assert jobs["deploy"]["if"] == "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"

    refs = {_assert_sha_pinned(jobs[name]) for name in ("ci", "image", "deploy")}
    assert len(refs) == 1

    deploy_with = cast(dict[str, object], jobs["deploy"]["with"])
    deploy_secrets = cast(dict[str, object], jobs["deploy"]["secrets"])
    assert deploy_with["agent-runtime-id"] == "${{ vars.AGENTCORE_RUNTIME_ID }}"
    assert deploy_with["image-uri"] == "${{ needs.image.outputs.image-uri }}"
    assert deploy_with["image-digest"] == "${{ needs.image.outputs.image-digest }}"
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
    assert "pull_request" not in str(jobs["image"]["if"])
    assert "pull_request" not in str(jobs["deploy"]["if"])


def test_standalone_image_workflow_keeps_release_triggers_and_manual_deploys() -> None:
    workflow = _load_workflow("image.yaml")
    triggers = _trigger(workflow)
    push = cast(dict[str, object], triggers["push"])
    jobs = _jobs(workflow)

    assert "workflow_dispatch" in triggers
    assert push == {"branches": ["main"], "tags": ["v*"]}
    assert jobs["deploy"]["needs"] == "image"
    assert jobs["deploy"]["if"] == "${{ github.event_name == 'workflow_dispatch' }}"
    refs = {_assert_sha_pinned(jobs[name]) for name in ("image", "deploy")}
    assert len(refs) == 1
    deploy_with = cast(dict[str, object], jobs["deploy"]["with"])
    assert deploy_with["server-protocol"] == "A2A"
    assert json.loads(cast(str, deploy_with["smoke-test-json"]))["method"] == "SendMessage"
    assert not _contains_key(workflow, "environment")
