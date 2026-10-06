"""AgentCore adapter tests keep cloud boundaries deterministic and credential-free."""

from __future__ import annotations

import base64
import hashlib
import json
import tarfile
from collections.abc import Mapping
from io import BytesIO
from pathlib import Path
from typing import cast

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from remediation_agent.adapters.agentcore import (
    AgentCoreOpenAISecret,
    AgentCoreRuntimeSecret,
    S3ArtifactReader,
    S3ArtifactStore,
    S3AuditSink,
    SecretsManagerOpenAISecretProvider,
    SecretsManagerRuntimeSecretProvider,
)
from remediation_agent.adapters.agentcore_sandbox import AgentCoreCodeInterpreterSandbox
from remediation_agent.adapters.sandbox import SandboxError
from remediation_agent.domain.enums import ValidationOutcome
from remediation_agent.domain.models import ArtifactRef, WorkspaceRef
from remediation_agent.policy.models import ValidationTaskConfig
from remediation_agent.ports.models import (
    ArtifactReadError,
    ArtifactReadRequest,
    ArtifactWriteRequest,
    AuditWriteRequest,
    ValidationTaskRequest,
)


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
        self.objects: dict[str, bytes] = {}

    def put_object(self, **kwargs: object) -> Mapping[str, object]:
        self.puts.append(kwargs)
        self.objects[cast(str, kwargs["Key"])] = cast(bytes, kwargs["Body"])
        return {}

    def get_object(self, **kwargs: object) -> Mapping[str, object]:
        key = cast(str, kwargs["Key"])
        if key not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": BytesIO(self.objects[key])}


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


async def test_openai_secret_is_strict_and_loaded_without_exposure() -> None:
    fake = _FakeSecrets(json.dumps({"OPENAI_APIKEY": "sk-secret-value"}))
    provider = SecretsManagerOpenAISecretProvider(
        "arn:aws:secretsmanager:ap-southeast-1:734849394833:secret:openai",
        region_name="ap-southeast-1",
        client=fake,
    )

    secret = await provider.load()

    assert isinstance(secret, AgentCoreOpenAISecret)
    assert secret.OPENAI_APIKEY.get_secret_value() == "sk-secret-value"
    assert "sk-secret-value" not in repr(secret)
    assert fake.requests == [{"SecretId": "arn:aws:secretsmanager:ap-southeast-1:734849394833:secret:openai"}]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"OPENAI_APIKEY": ""},
        {"OPENAI_APIKEY": "   "},
        {"OPENAI_APIKEY": "sk-secret", "unexpected": "value"},
        {"OPENAI_API_KEY": "sk-wrong-name"},
    ],
)
def test_openai_secret_rejects_missing_blank_or_unknown_fields(payload: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        AgentCoreOpenAISecret.model_validate(payload)


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


async def test_s3_artifact_reader_verifies_manifest_path_digest_redaction_and_truncation() -> None:
    fake = _FakeS3()
    body = b'password=visible-before-redaction\n{"result":"ok"}'
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    name = "result.json"
    key = f"runs/run-1/artifacts/{digest.removeprefix('sha256:')}/{name}"
    fake.objects[key] = body
    reader = S3ArtifactReader("artifact-bucket", region_name="ap-southeast-1", client=fake)
    artifact = ArtifactRef(
        name=name,
        path=f"s3://artifact-bucket/{key}",
        digest=digest,
        media_type="application/json",
    )

    result = await reader.read(
        ArtifactReadRequest(run_id="run-1", artifact=artifact, max_object_bytes=1024, max_preview_bytes=16)
    )

    assert result.digest_verified
    assert result.truncated
    assert "visible-before-redaction" not in result.content
    assert "[REDACTED]" in result.content
    assert result.size_bytes == len(body)


async def test_s3_artifact_reader_rejects_untrusted_path_and_digest_mismatch() -> None:
    fake = _FakeS3()
    reader = S3ArtifactReader("artifact-bucket", region_name="ap-southeast-1", client=fake)
    artifact = ArtifactRef(
        name="result.json",
        path="s3://other-bucket/runs/run-1/artifacts/value/result.json",
        digest="sha256:" + "a" * 64,
        media_type="application/json",
    )

    with pytest.raises(ArtifactReadError, match="ARTIFACT_ACCESS_DENIED"):
        await reader.read(
            ArtifactReadRequest(run_id="run-1", artifact=artifact, max_object_bytes=1024, max_preview_bytes=1024)
        )


async def test_s3_artifact_reader_maps_missing_object_to_bounded_error() -> None:
    digest = "sha256:" + "a" * 64
    artifact = ArtifactRef(
        name="missing.json",
        path=f"s3://artifact-bucket/runs/run-1/artifacts/{'a' * 64}/missing.json",
        digest=digest,
        media_type="application/json",
    )
    reader = S3ArtifactReader("artifact-bucket", region_name="ap-southeast-1", client=_FakeS3())

    with pytest.raises(ArtifactReadError, match="ARTIFACT_NOT_FOUND"):
        await reader.read(
            ArtifactReadRequest(run_id="run-1", artifact=artifact, max_object_bytes=1024, max_preview_bytes=1024)
        )


@pytest.mark.parametrize(
    ("name", "media_type"),
    [
        ("result.json", "application/json"),
        ("audit.jsonl", "application/x-ndjson"),
        ("patch.diff", "text/x-diff"),
        ("notes.txt", "text/plain"),
    ],
)
async def test_s3_artifact_reader_supports_every_text_evidence_type(name: str, media_type: str) -> None:
    fake = _FakeS3()
    body = b"redacted evidence"
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    key = f"runs/run-1/artifacts/{digest.removeprefix('sha256:')}/{name}"
    fake.objects[key] = body
    artifact = ArtifactRef(
        name=name,
        path=f"s3://artifact-bucket/{key}",
        digest=digest,
        media_type=media_type,
    )

    result = await S3ArtifactReader("artifact-bucket", region_name="ap-southeast-1", client=fake).read(
        ArtifactReadRequest(run_id="run-1", artifact=artifact, max_object_bytes=1024, max_preview_bytes=1024)
    )

    assert result.content == "redacted evidence"
    assert result.media_type == media_type


@pytest.mark.parametrize(
    ("body", "recorded_body", "media_type", "max_object_bytes", "expected"),
    [
        (b"expected", b"tampered", "text/plain", 1024, "ARTIFACT_INTEGRITY_FAILED"),
        (b"large", b"large", "text/plain", 2, "ARTIFACT_TOO_LARGE"),
        (b"\xff", b"\xff", "text/plain", 1024, "ARTIFACT_PREVIEW_UNSUPPORTED"),
        (b"value", b"value", "application/octet-stream", 1024, "ARTIFACT_PREVIEW_UNSUPPORTED"),
    ],
)
async def test_s3_artifact_reader_fails_closed_for_unsafe_content(
    body: bytes,
    recorded_body: bytes,
    media_type: str,
    max_object_bytes: int,
    expected: str,
) -> None:
    fake = _FakeS3()
    digest = "sha256:" + hashlib.sha256(recorded_body).hexdigest()
    key = f"runs/run-1/artifacts/{digest.removeprefix('sha256:')}/evidence.txt"
    fake.objects[key] = body
    reader = S3ArtifactReader("artifact-bucket", region_name="ap-southeast-1", client=fake)
    artifact = ArtifactRef(
        name="evidence.txt",
        path=f"s3://artifact-bucket/{key}",
        digest=digest,
        media_type=media_type,
    )

    with pytest.raises(ArtifactReadError, match=expected):
        await reader.read(
            ArtifactReadRequest(
                run_id="run-1",
                artifact=artifact,
                max_object_bytes=max_object_bytes,
                max_preview_bytes=1024,
            )
        )


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

    execution = await sandbox.run_task(
        ValidationTaskRequest(
            workspace=WorkspaceRef(workspace_id="run-1", path=str(workspace), base_commit="a" * 40),
            task_name="unit_tests",
            task=task,
        )
    )

    assert execution.result.outcome is ValidationOutcome.PASSED
    assert execution.result.stdout == "one passed\n"
    assert execution.execution.backend == "AGENTCORE_CODE_INTERPRETER"
    assert execution.execution.cleanup_status == "SUCCEEDED"
    assert execution.execution.session_digest is not None
    assert "ci-session" not in execution.execution.model_dump_json()
    assert [item["name"] for item in fake.invocations] == ["writeFiles", "executeCode"]
    upload_arguments = cast(dict[str, object], fake.invocations[0]["arguments"])
    upload_content = cast(list[dict[str, object]], upload_arguments["content"])
    assert all(not Path(cast(str, item["path"])).is_absolute() for item in upload_content)
    execute_arguments = cast(dict[str, object], fake.invocations[1]["arguments"])
    runner = cast(str, execute_arguments["code"])
    assert "shell=False" in runner
    assert "pathlib.Path('aios-workspace').resolve()" in runner
    assert fake.stopped == ["ci-session"]


async def test_code_interpreter_redacts_unexpected_cloud_failure_and_stops(tmp_path: Path) -> None:
    class UnexpectedCloudFailure(Exception):
        pass

    class FailingCodeInterpreter(_FakeCodeInterpreter):
        def invoke_code_interpreter(self, **kwargs: object) -> Mapping[str, object]:
            raise UnexpectedCloudFailure("credential=do-not-expose")

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / "run-1"
    workspace.mkdir(parents=True)
    (workspace / "test_example.py").write_text("def test_ok(): assert True\n", encoding="utf-8")
    bundle = tmp_path / "vendor.tar.gz"
    with tarfile.open(bundle, "w:gz"):
        pass
    fake = FailingCodeInterpreter()
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

    execution = await sandbox.run_task(
        ValidationTaskRequest(
            workspace=WorkspaceRef(workspace_id="run-1", path=str(workspace), base_commit="a" * 40),
            task_name="unit_tests",
            task=task,
        )
    )

    assert execution.result.outcome is ValidationOutcome.ERROR
    assert execution.execution.cleanup_status == "SUCCEEDED"
    assert "UnexpectedCloudFailure" in execution.result.stderr
    assert "do-not-expose" not in execution.model_dump_json()
    assert fake.stopped == ["ci-session"]


async def test_code_interpreter_records_startup_failure_without_a_session_digest(tmp_path: Path) -> None:
    class StartupFailingCodeInterpreter(_FakeCodeInterpreter):
        def start_code_interpreter_session(self, **kwargs: object) -> Mapping[str, object]:
            raise RuntimeError("credential=do-not-expose")

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / "run-1"
    workspace.mkdir(parents=True)
    (workspace / "server.js").write_text("const value = 1;\n", encoding="utf-8")
    bundle = tmp_path / "vendor.tar.gz"
    with tarfile.open(bundle, "w:gz"):
        pass
    sandbox = AgentCoreCodeInterpreterSandbox(
        workspace_root,
        region_name="ap-southeast-1",
        validation_bundle=bundle,
        client=StartupFailingCodeInterpreter(),
    )

    execution = await sandbox.run_task(
        ValidationTaskRequest(
            workspace=WorkspaceRef(workspace_id="run-1", path=str(workspace), base_commit="a" * 40),
            task_name="javascript_syntax",
            task=ValidationTaskConfig(
                argv=["node", "--check", "server.js"],
                cwd=".",
                environment={},
                timeout_seconds=30,
                output_limit_bytes=4096,
                retryable=False,
            ),
        )
    )

    assert execution.result.outcome is ValidationOutcome.ERROR
    assert execution.execution.cleanup_status == "NOT_APPLICABLE"
    assert execution.execution.session_digest is None
    assert "do-not-expose" not in execution.model_dump_json()


async def test_code_interpreter_records_cleanup_failure_without_exposing_session(tmp_path: Path) -> None:
    class CleanupFailingCodeInterpreter(_FakeCodeInterpreter):
        def stop_code_interpreter_session(self, **kwargs: object) -> Mapping[str, object]:
            raise RuntimeError("raw-session-ci-session")

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / "run-1"
    workspace.mkdir(parents=True)
    (workspace / "server.js").write_text("const value = 1;\n", encoding="utf-8")
    bundle = tmp_path / "vendor.tar.gz"
    with tarfile.open(bundle, "w:gz"):
        pass
    sandbox = AgentCoreCodeInterpreterSandbox(
        workspace_root,
        region_name="ap-southeast-1",
        validation_bundle=bundle,
        client=CleanupFailingCodeInterpreter(),
    )

    execution = await sandbox.run_task(
        ValidationTaskRequest(
            workspace=WorkspaceRef(workspace_id="run-1", path=str(workspace), base_commit="a" * 40),
            task_name="javascript_syntax",
            task=ValidationTaskConfig(
                argv=["node", "--check", "server.js"],
                cwd=".",
                environment={},
                timeout_seconds=30,
                output_limit_bytes=4096,
                retryable=False,
            ),
        )
    )

    assert execution.result.outcome is ValidationOutcome.ERROR
    assert execution.execution.cleanup_status == "FAILED"
    assert "ci-session" not in execution.execution.model_dump_json()


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


async def test_behavioral_validation_refuses_unqualified_custom_interpreter(tmp_path: Path) -> None:
    from remediation_agent.ports.models import BehavioralTaskRequest

    fake = _FakeCodeInterpreter()
    sandbox = AgentCoreCodeInterpreterSandbox(
        tmp_path,
        region_name="ap-southeast-1",
        client=fake,
        code_interpreter_identifier="custom-public-interpreter",
    )
    with pytest.raises(SandboxError, match="custom interpreter isolation is unqualified"):
        await sandbox.run_behavior(
            BehavioralTaskRequest(
                workspace=WorkspaceRef(workspace_id="proof", path=str(tmp_path / "snapshot"), base_commit="a" * 40),
                task_name="purchase_regression",
                patch_digest="sha256:fixture",
                task=ValidationTaskConfig(
                    argv=["node"],
                    kind="BEHAVIORAL",
                    profile="ecommerce_purchase",
                    timeout_seconds=60,
                    output_limit_bytes=4096,
                ),
            )
        )
    assert not fake.invocations
