"""AgentCore adapter tests keep cloud boundaries deterministic and credential-free."""

from __future__ import annotations

import base64
import json
import tarfile
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from remediation_agent.adapters.agentcore import (
    AgentCoreRuntimeSecret,
    S3ArtifactStore,
    S3AuditSink,
    SecretsManagerRuntimeSecretProvider,
)
from remediation_agent.adapters.agentcore_sandbox import AgentCoreCodeInterpreterSandbox
from remediation_agent.adapters.sandbox import SandboxError
from remediation_agent.domain.enums import ValidationOutcome
from remediation_agent.domain.models import WorkspaceRef
from remediation_agent.policy.models import ValidationTaskConfig
from remediation_agent.ports.models import ArtifactWriteRequest, AuditWriteRequest, ValidationTaskRequest


class _FakeSecrets:
    def __init__(self, secret: str) -> None:
        self.secret = secret
        self.requests: list[dict[str, object]] = []

    def get_secret_value(self, **kwargs: object) -> Mapping[str, object]:
        self.requests.append(kwargs)
        return {"SecretString": self.secret}


class _FakeS3:
    def __init__(self) -> None:
        self.puts: list[dict[str, object]] = []

    def put_object(self, **kwargs: object) -> Mapping[str, object]:
        self.puts.append(kwargs)
        return {}


class _FakeCodeInterpreter:
    def __init__(self) -> None:
        self.invocations: list[dict[str, object]] = []
        self.stopped: list[str] = []

    def start_code_interpreter_session(self, **kwargs: object) -> Mapping[str, object]:
        return {"sessionId": "ci-session"}

    def invoke_code_interpreter(self, **kwargs: object) -> Mapping[str, object]:
        self.invocations.append(kwargs)
        if kwargs["name"] == "writeFiles":
            return {"stream": [{"result": {"content": [], "isError": False}}]}
        encoded = base64.b64encode(b"one passed\n").decode()
        result = {
            "stdout": encoded,
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
        }
        marker = "__AIOS_VALIDATION_RESULT__" + json.dumps(result)
        return {"stream": [{"result": {"structuredContent": {"stdout": marker}}}]}

    def stop_code_interpreter_session(self, **kwargs: object) -> Mapping[str, object]:
        self.stopped.append(cast(str, kwargs["sessionId"]))
        return {}


async def test_runtime_secret_is_strict_and_requires_a_32_byte_key() -> None:
    fake = _FakeSecrets(json.dumps({"github_token": "github_pat_secret", "checkpoint_encryption_key": "k" * 32}))
    provider = SecretsManagerRuntimeSecretProvider(
        "arn:aws:secretsmanager:ap-southeast-1:734849394833:secret:runtime",
        region_name="ap-southeast-1",
        client=fake,
    )

    secret = await provider.load()

    assert isinstance(secret, AgentCoreRuntimeSecret)
    assert secret.github_token.get_secret_value() == "github_pat_secret"
    assert fake.requests == [{"SecretId": "arn:aws:secretsmanager:ap-southeast-1:734849394833:secret:runtime"}]
    with pytest.raises(ValueError):
        AgentCoreRuntimeSecret.model_validate({"github_token": "token", "checkpoint_encryption_key": "short"})


async def test_s3_artifacts_are_redacted_digest_addressed_and_immutable() -> None:
    fake = _FakeS3()
    store = S3ArtifactStore("artifact-bucket", region_name="ap-southeast-1", client=fake)

    manifest = await store.write_bundle(
        ArtifactWriteRequest(run_id="run-1", files={"result.json": "token=github_pat_abcdefghijklmnopqrstuvwxyz"})
    )

    assert len(fake.puts) == 1
    put = fake.puts[0]
    assert put["IfNoneMatch"] == "*"
    assert put["ServerSideEncryption"] == "AES256"
    assert b"github_pat_" not in cast(bytes, put["Body"])
    assert manifest.artifacts[0].path.startswith("s3://artifact-bucket/runs/run-1/artifacts/")


async def test_s3_audit_sink_writes_sequenced_events_and_digest_manifest() -> None:
    fake = _FakeS3()
    sink = S3AuditSink("artifact-bucket", region_name="ap-southeast-1", client=fake)

    await sink.write(AuditWriteRequest(run_id="run-1", jsonl='{"event":"one"}\n{"event":"two"}\n'))

    keys = [cast(str, item["Key"]) for item in fake.puts]
    assert "/audit/000001-" in keys[0]
    assert "/audit/000002-" in keys[1]
    assert "/audit/manifests/" in keys[2]


async def test_code_interpreter_runs_fixed_python_runner_and_always_stops(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / "run-1"
    workspace.mkdir(parents=True)
    (workspace / "test_example.py").write_text("def test_ok(): assert True\n", encoding="utf-8")
    bundle = tmp_path / "vendor.tar.gz"
    with tarfile.open(bundle, "w:gz"):
        pass
    fake = _FakeCodeInterpreter()
    sandbox = AgentCoreCodeInterpreterSandbox(
        workspace_root,
        region_name="ap-southeast-1",
        validation_bundle=bundle,
        client=fake,
    )
    task = ValidationTaskConfig(
        argv=["python", "-m", "pytest", "-q"],
        cwd=".",
        environment={},
        timeout_seconds=30,
        output_limit_bytes=4096,
        retryable=False,
    )

    result = await sandbox.run_task(
        ValidationTaskRequest(
            workspace=WorkspaceRef(workspace_id="run-1", path=str(workspace), base_commit="a" * 40),
            task_name="unit_tests",
            task=task,
        )
    )

    assert result.outcome is ValidationOutcome.PASSED
    assert result.stdout == "one passed\n"
    assert [item["name"] for item in fake.invocations] == ["writeFiles", "executeCode"]
    execute_arguments = cast(dict[str, object], fake.invocations[1]["arguments"])
    runner = cast(str, execute_arguments["code"])
    assert "shell=False" in runner
    assert fake.stopped == ["ci-session"]


async def test_code_interpreter_rejects_workspace_symlinks_before_cloud_call(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / "run-1"
    workspace.mkdir(parents=True)
    target = tmp_path / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    (workspace / "linked.txt").symlink_to(target)
    bundle = tmp_path / "vendor.tar.gz"
    with tarfile.open(bundle, "w:gz"):
        pass
    fake = _FakeCodeInterpreter()
    sandbox = AgentCoreCodeInterpreterSandbox(
        workspace_root,
        region_name="ap-southeast-1",
        validation_bundle=bundle,
        client=fake,
    )
    task = ValidationTaskConfig(
        argv=["python", "-m", "pytest", "-q"],
        cwd=".",
        environment={},
        timeout_seconds=30,
        output_limit_bytes=4096,
        retryable=False,
    )

    with pytest.raises(SandboxError, match="symlink"):
        await sandbox.run_task(
            ValidationTaskRequest(
                workspace=WorkspaceRef(workspace_id="run-1", path=str(workspace), base_commit="a" * 40),
                task_name="unit_tests",
                task=task,
            )
        )

    assert fake.invocations == []
