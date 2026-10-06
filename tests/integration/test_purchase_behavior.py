"""Real offline Express/SQLite proof; no evaluation checkout or live target is used."""

from __future__ import annotations

import os
import tarfile
from pathlib import Path

import pytest

from remediation_agent.adapters.agentcore_sandbox import AgentCoreCodeInterpreterSandbox
from remediation_agent.adapters.sandbox import DockerSandboxExecutor
from remediation_agent.domain.models import WorkspaceRef
from remediation_agent.policy.loader import load_policy
from remediation_agent.ports.models import BehavioralTaskRequest
from tests.integration.test_docker_sandbox import _git, docker_executable  # noqa: F401


def snapshot_workspace(tmp_path: Path, case: str) -> WorkspaceRef:
    """Real immutable frontend/server/schema/init, with a reviewed known-good patch."""
    from scripts.qualify_workflow import initialize_snapshot

    _, base, _ = initialize_snapshot(tmp_path, case)
    root = tmp_path / "source"
    _git(root, "apply", str(Path(__file__).parents[1] / "fixtures/qualification" / (case + ".diff")))
    return WorkspaceRef(workspace_id=case + "-proof", path=str(root), base_commit=base)


def purchase_workspace(tmp_path: Path) -> WorkspaceRef:
    return snapshot_workspace(tmp_path, "ah54")


def checkout_workspace(tmp_path: Path) -> WorkspaceRef:
    return snapshot_workspace(tmp_path, "ah56")


async def qualify(sandbox: DockerSandboxExecutor, workspace: WorkspaceRef) -> None:
    await qualify_profile(sandbox, workspace, "purchase_regression", "purchase_below_stock")


async def qualify_checkout(sandbox: DockerSandboxExecutor, workspace: WorkspaceRef) -> None:
    await qualify_profile(sandbox, workspace, "checkout_regression", "checkout_persists_before_success")


async def qualify_profile(
    sandbox: DockerSandboxExecutor, workspace: WorkspaceRef, task_name: str, reproduction: str
) -> None:
    task = load_policy(Path(__file__).parents[2] / "config/policies/demo.json").validation_tasks[task_name]
    root = Path(workspace.path)
    before = _git(root, "diff", "HEAD")
    result = await sandbox.run_behavior(
        BehavioralTaskRequest(
            workspace=workspace, task_name=task_name, task=task, attempt=1, patch_digest="sha256:fixture"
        )
    )
    base = {case.test_id: case.outcome for case in result.evidence.base.cases}
    candidate = {case.test_id: case.outcome for case in result.evidence.candidate.cases}
    assert base[reproduction] == "ASSERTION_FAILED", result.evidence.model_dump_json()
    assert set(base) == set(candidate) == set(task.required_test_ids)
    assert all(outcome == "PASSED" for outcome in candidate.values()), result.evidence.model_dump_json()
    assert result.evidence.assertions_digest.startswith("sha256:")
    assert result.evidence.dependency_digest.startswith("sha256:")
    assert result.evidence.base.runtime_digest == result.evidence.candidate.runtime_digest
    assert result.evidence.cleanup_succeeded and len(result.executions) == 2
    assert _git(root, "diff", "HEAD") == before
    assert not list(sandbox.workspace_root.glob("verification-*"))
    assert not list(root.glob("*.db"))


@pytest.mark.integration
@pytest.mark.usefixtures("docker_executable")
async def test_purchase_real_express_sqlite_before_after(tmp_path: Path) -> None:
    bundle = Path(
        os.environ.get("AIOS_BEHAVIORAL_BUNDLE", str(Path(__file__).parents[2] / ".artifacts/validation/ecommerce"))
    )
    if not bundle.is_dir():
        pytest.skip("Build offline native assets with make validation-bundle first")
    sandbox = DockerSandboxExecutor(tmp_path, "aios-remediation-sandbox:local", behavioral_bundle=bundle)
    await qualify(sandbox, purchase_workspace(tmp_path))


@pytest.mark.integration
@pytest.mark.usefixtures("docker_executable")
async def test_checkout_real_express_sqlite_before_after(tmp_path: Path) -> None:
    bundle = Path(
        os.environ.get("AIOS_BEHAVIORAL_BUNDLE", str(Path(__file__).parents[2] / ".artifacts/validation/ecommerce"))
    )
    if not bundle.is_dir():
        pytest.skip("Build offline native assets with make validation-bundle first")
    sandbox = DockerSandboxExecutor(tmp_path, "aios-remediation-sandbox:local", behavioral_bundle=bundle)
    await qualify_checkout(sandbox, checkout_workspace(tmp_path))


@pytest.mark.integration
@pytest.mark.usefixtures("docker_executable")
async def test_browser_omitting_checkout_request_is_bounded_assertion_failure(tmp_path: Path) -> None:
    bundle = Path(os.environ.get("AIOS_BEHAVIORAL_BUNDLE", ".artifacts/validation/ecommerce"))
    if not bundle.is_dir():
        pytest.skip("Build offline native assets with make validation-bundle first")
    workspace = checkout_workspace(tmp_path)
    app = Path(workspace.path) / "public/app.js"
    app.write_text(app.read_text() + "\nfunction checkout() {}\n")
    sandbox = DockerSandboxExecutor(tmp_path, "aios-remediation-sandbox:local", behavioral_bundle=bundle)
    task = load_policy(Path("config/policies/demo.json")).validation_tasks["checkout_regression"]
    result = await sandbox.run_behavior(
        BehavioralTaskRequest(
            workspace=workspace,
            task_name="checkout_regression",
            task=task,
            attempt=1,
            patch_digest="sha256:missing-browser-request",
        )
    )
    cases = {case.test_id: case.outcome for case in result.evidence.candidate.cases}
    assert cases["checkout_persists_before_success"] == "PASSED"
    assert all(cases[name] == "ASSERTION_FAILED" for name in task.required_test_ids if "browser" in name)
    assert result.evidence.cleanup_succeeded


@pytest.mark.live_code_interpreter
@pytest.mark.skipif(os.environ.get("AIOS_RUN_CODE_INTERPRETER_LIVE") != "1", reason="explicit live opt-in required")
async def test_purchase_code_interpreter_qualification(tmp_path: Path) -> None:
    region = os.environ.get("AIOS_AWS_REGION")
    bundle = os.environ.get("AIOS_BEHAVIORAL_BUNDLE")
    if not region or not bundle:
        pytest.skip("AIOS_AWS_REGION and a compatible AIOS_BEHAVIORAL_BUNDLE are required")
    vendor = tmp_path / "empty.tar.gz"
    with tarfile.open(vendor, "w:gz"):
        pass
    sandbox = AgentCoreCodeInterpreterSandbox(
        tmp_path,
        region_name=region,
        behavioral_bundle=Path(bundle),
        validation_bundle=vendor,
        code_interpreter_identifier=os.environ.get("AIOS_CODE_INTERPRETER_IDENTIFIER", "aws.codeinterpreter.v1"),
    )
    await qualify(sandbox, purchase_workspace(tmp_path))


@pytest.mark.live_code_interpreter
@pytest.mark.skipif(os.environ.get("AIOS_RUN_CODE_INTERPRETER_LIVE") != "1", reason="explicit live opt-in required")
async def test_checkout_code_interpreter_qualification(tmp_path: Path) -> None:
    region = os.environ.get("AIOS_AWS_REGION")
    bundle = os.environ.get("AIOS_BEHAVIORAL_BUNDLE")
    if not region or not bundle:
        pytest.skip("AIOS_AWS_REGION and a compatible AIOS_BEHAVIORAL_BUNDLE are required")
    vendor = tmp_path / "empty.tar.gz"
    with tarfile.open(vendor, "w:gz"):
        pass
    sandbox = AgentCoreCodeInterpreterSandbox(
        tmp_path,
        region_name=region,
        behavioral_bundle=Path(bundle),
        validation_bundle=vendor,
        code_interpreter_identifier=os.environ.get("AIOS_CODE_INTERPRETER_IDENTIFIER", "aws.codeinterpreter.v1"),
    )
    await qualify_checkout(sandbox, checkout_workspace(tmp_path))
