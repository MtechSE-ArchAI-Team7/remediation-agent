"""Real Git and persisted receipts across adapter restart; cloud execution is controlled here."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from remediation_agent.adapters.fakes import FakeSandboxExecutor, MemoryArtifactStore
from remediation_agent.adapters.runtime_qualification import RuntimeQualification
from remediation_agent.adapters.sandbox import DockerSandboxExecutor
from remediation_agent.domain.models import ValidationStorageEvidence
from remediation_agent.domain.runtime_qualification import RuntimeQualificationRequestV1
from remediation_agent.policy.loader import load_policy
from remediation_agent.ports.models import BehavioralTaskExecution, BehavioralTaskRequest
from scripts.qualify_runtime import ARN
from tests.unit.test_provenance import _adapter, _ControlClient, _detail

ROOT = Path(__file__).parents[2]


class ControlledSandbox(DockerSandboxExecutor):
    calls = 0

    async def run_behavior(self, request: BehavioralTaskRequest) -> BehavioralTaskExecution:
        self.calls += 1
        result = await FakeSandboxExecutor().run_behavior(request)
        return result.model_copy(update={"storage": ValidationStorageEvidence(task_name=request.task_name, attempt=1)})


def adapter(tmp_path: Path) -> RuntimeQualification:
    bundle = tmp_path / "assets"
    bundle.mkdir(exist_ok=True)
    (bundle / "manifest.json").write_text("trusted immutable asset")
    root = tmp_path / "managed" / "runs"
    root.mkdir(parents=True, exist_ok=True)
    sandbox = ControlledSandbox(root, "unused", behavioral_bundle=bundle, scratch_root=tmp_path / "scratch")
    return RuntimeQualification(
        workspace_root=root,
        fixtures=ROOT / "config/evaluation/snapshots",
        sandbox=sandbox,
        policy=load_policy(ROOT / "config/policies/demo.json"),
        provenance=_adapter(_ControlClient([{"agentRuntimeVersion": "57"}], {"57": _detail("57")})),
        artifacts=MemoryArtifactStore(),
    )


async def test_prepare_restart_resume_is_bound_and_idempotent(tmp_path: Path) -> None:
    first = adapter(tmp_path)
    session = str(uuid4())
    request = RuntimeQualificationRequestV1(operation="prepare", fixture="ah56", qualification_id=str(uuid4()))
    prepared = await first.execute(request, session)
    assert prepared.status == "PREPARED"
    assert await first.execute(request, session) == prepared
    resumed = adapter(tmp_path)
    resume = request.model_copy(update={"operation": "resume", "receipt_digest": prepared.receipt_digest})
    result = await resumed.execute(resume, session)
    assert result.status == "PASSED", result.model_dump_json()
    assert result.process_restarted and result.git_integrity_verified and result.cleanup_verified
    assert not list(first.root.glob("*/repository"))
    assert await adapter(tmp_path).execute(resume, session) == result
    with pytest.raises(ValueError, match="BINDING_MISMATCH"):
        await adapter(tmp_path).execute(resume, str(uuid4()))
    with pytest.raises(ValueError, match="RECEIPT_REQUIRED"):
        await adapter(tmp_path).execute(resume.model_copy(update={"receipt_digest": "sha256:" + "0" * 64}), session)


@pytest.mark.parametrize("fault", ["missing_git", "changed_source", "same_process"])
async def test_cold_resume_requires_intact_git_and_workspace(tmp_path: Path, fault: str) -> None:
    first = adapter(tmp_path)
    session = str(uuid4())
    request = RuntimeQualificationRequestV1(operation="prepare", fixture="ah54", qualification_id=str(uuid4()))
    prepared = await first.execute(request, session)
    repository = first.root / ("qualification-" + request.qualification_id) / "repository"
    if fault == "missing_git":
        (repository / ".git").rename(repository / "lost-git")
    elif fault == "changed_source":
        (repository / "server.js").write_text("tampered")
    runner = first if fault == "same_process" else adapter(tmp_path)
    result = await runner.execute(
        request.model_copy(update={"operation": "resume", "receipt_digest": prepared.receipt_digest}), session
    )
    assert result.status == "FAILED" and result.failures and result.cleanup_verified
    assert isinstance(runner.sandbox, ControlledSandbox) and not runner.sandbox.calls


def test_qualification_transport_cannot_select_commands_paths_or_approvals() -> None:
    valid = {"operation": "prepare", "fixture": "ah56", "qualification_id": str(uuid4())}
    for extra in ({"command": "echo unsafe"}, {"path": "/mnt/workspace/runs"}, {"approve": True}, {"fixture": "other"}):
        with pytest.raises(ValidationError):
            RuntimeQualificationRequestV1.model_validate({**valid, **extra})


def test_stop_permission_targets_only_the_runtime_and_endpoint_used_by_qualification() -> None:
    policy = json.loads((ROOT / "config/operator/release-qualification-policy.json").read_text())
    grants = [s for s in policy["Statement"] if s["Action"] == "bedrock-agentcore:StopRuntimeSession"]
    # Hosted AWS checks both resources. No wildcard can cover other runtimes or endpoints.
    assert grants == [
        {
            "Sid": "StopOnlyQualificationRuntimeSessions",
            "Effect": "Allow",
            "Action": "bedrock-agentcore:StopRuntimeSession",
            "Resource": [ARN, ARN + "/runtime-endpoint/DEFAULT"],
        }
    ]
