"""AgentCore Code Interpreter validation adapter."""

from __future__ import annotations

import asyncio
import base64
import fnmatch
import hashlib
import io
import json
import os
import tarfile
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

import boto3  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]

from remediation_agent.adapters.sandbox import DockerSandboxExecutor, SandboxError
from remediation_agent.domain.enums import (
    ValidationBackend,
    ValidationCleanupStatus,
    ValidationOutcome,
)
from remediation_agent.domain.models import ValidationExecutionRecord, ValidationTaskResult
from remediation_agent.ports.models import (
    BehavioralTaskExecution,
    BehavioralTaskRequest,
    SandboxExecutionProfile,
    SandboxTaskExecution,
    ValidationTaskRequest,
)

_MAX_UPLOAD_BYTES = 80 * 1024 * 1024
_MAX_ARCHIVE_FILES = 50_000
_REMOTE_ARCHIVE = "aios-workspace.tar.gz"
_REMOTE_VENDOR = "aios-pytest-vendor.tar.gz"
_RESULT_MARKER = "__AIOS_VALIDATION_RESULT__"
_FORBIDDEN_ARCHIVE_PATTERNS = (
    "**/.git",
    "**/.git/**",
    ".aws",
    ".aws/**",
    "**/.aws/**",
    ".ssh",
    ".ssh/**",
    "**/.ssh/**",
    ".npmrc",
    "**/.npmrc",
    ".pypirc",
    "**/.pypirc",
    "id_rsa",
    "**/id_rsa",
    ".git",
    ".git/**",
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "*.pem",
    "**/*.pem",
    "*.key",
    "**/*.key",
    "credentials*",
    "**/credentials*",
    "secrets/**",
    "**/secrets/**",
)


class _CodeInterpreterClient(Protocol):
    def start_code_interpreter_session(self, **kwargs: object) -> Mapping[str, object]: ...

    def invoke_code_interpreter(self, **kwargs: object) -> Mapping[str, object]: ...

    def stop_code_interpreter_session(self, **kwargs: object) -> Mapping[str, object]: ...


class AgentCoreCodeInterpreterSandbox(DockerSandboxExecutor):
    """Reuse local patch controls but validate only inside an isolated managed session."""

    def __init__(
        self,
        workspace_root: Path,
        *,
        region_name: str,
        code_interpreter_identifier: str = "aws.codeinterpreter.v1",
        behavioral_bundle: Path = Path("/app/validation/ecommerce"),
        validation_bundle: Path = Path("/app/validation/pytest_vendor.tar.gz"),
        client: _CodeInterpreterClient | None = None,
    ) -> None:
        super().__init__(workspace_root, image="agentcore-code-interpreter", behavioral_bundle=behavioral_bundle)
        self.code_interpreter_identifier = code_interpreter_identifier
        self.validation_bundle = validation_bundle
        self._client = client or cast(
            _CodeInterpreterClient,
            boto3.client(
                "bedrock-agentcore",
                region_name=region_name,
                config=Config(connect_timeout=10, read_timeout=180, retries={"max_attempts": 3, "mode": "standard"}),
            ),
        )

    def execution_profile(self) -> SandboxExecutionProfile:
        return SandboxExecutionProfile(
            backend=ValidationBackend.AGENTCORE_CODE_INTERPRETER,
            executor_id=self.code_interpreter_identifier,
            enforced_controls=[
                "OPERATOR_DEFINED_TASK",
                "FIXED_ARGV_NO_SHELL",
                "FRESH_MANAGED_SESSION",
                "SECRET_FREE_ARCHIVE",
                "TIMEOUT_AND_OUTPUT_CAP",
                "SESSION_CLEANUP",
            ],
        )

    async def run_behavior(self, request: BehavioralTaskRequest) -> BehavioralTaskExecution:
        # Custom interpreters may expose public/VPC networks or production IAM roles.
        # Their isolation must be implemented and qualified before this boundary accepts them.
        if self.code_interpreter_identifier != "aws.codeinterpreter.v1":
            raise SandboxError("UNSUPPORTED_VALIDATION_ENVIRONMENT: custom interpreter isolation is unqualified")
        return await super().run_behavior(request)

    async def run_task(self, request: ValidationTaskRequest) -> SandboxTaskExecution:
        root = self._workspace(request.workspace)
        self._validate_workdir(root, request.task.cwd)
        self._validate_environment(request.task.environment)
        archive = await asyncio.to_thread(self._archive_workspace, root)
        bundle = await asyncio.to_thread(self._read_bundle)
        if len(archive) + len(bundle) > _MAX_UPLOAD_BYTES:
            raise SandboxError("UNSUPPORTED_VALIDATION_ENVIRONMENT: upload exceeds 80 MB")

        started = time.monotonic()
        session_id: str | None = None
        raw_result: dict[str, str | int | bool] | None = None
        task_result: ValidationTaskResult | None = None
        failure: Exception | None = None
        try:
            session_id = await asyncio.to_thread(self._start_session, request.workspace.workspace_id)
            await asyncio.to_thread(self._upload, session_id, archive, bundle)
            raw_result = await asyncio.wait_for(
                asyncio.to_thread(self._execute, session_id, request),
                timeout=float(request.task.timeout_seconds) + 30.0,
            )
        except TimeoutError:
            task_result = ValidationTaskResult(
                task_name=request.task_name,
                outcome=ValidationOutcome.TIMED_OUT,
                duration_ms=int((time.monotonic() - started) * 1_000),
                stderr="Validation task exceeded its configured timeout.",
            )
        except Exception as exc:  # noqa: BLE001 - normalize cloud SDK failures at the adapter boundary
            failure = exc

        cleanup_status = ValidationCleanupStatus.NOT_APPLICABLE
        if session_id is not None:
            stopped = await asyncio.to_thread(self._stop_session, session_id)
            cleanup_status = ValidationCleanupStatus.SUCCEEDED if stopped else ValidationCleanupStatus.FAILED

        if failure is not None:
            suffix = " and session cleanup failed" if cleanup_status is ValidationCleanupStatus.FAILED else ""
            task_result = ValidationTaskResult(
                task_name=request.task_name,
                outcome=ValidationOutcome.ERROR,
                duration_ms=int((time.monotonic() - started) * 1_000),
                stderr=f"AgentCore validation failed: {type(failure).__name__}{suffix}",
            )

        if task_result is None:
            if raw_result is None:
                raise SandboxError("Code Interpreter returned no validation result")
            raw_exit_code = raw_result["exit_code"]
            raw_truncated = raw_result["truncated"]
            if (
                not isinstance(raw_exit_code, int)
                or isinstance(raw_exit_code, bool)
                or not isinstance(raw_truncated, bool)
            ):
                raise SandboxError("trusted validation runner returned invalid result types")
            stdout, stdout_truncated = _cap(raw_result["stdout"], request.task.output_limit_bytes)
            remaining = max(0, request.task.output_limit_bytes - len(stdout.encode("utf-8")))
            stderr, stderr_truncated = _cap(raw_result["stderr"], remaining)
            task_result = ValidationTaskResult(
                task_name=request.task_name,
                outcome=ValidationOutcome.PASSED if raw_exit_code == 0 else ValidationOutcome.FAILED,
                exit_code=raw_exit_code,
                duration_ms=int((time.monotonic() - started) * 1_000),
                stdout=stdout,
                stderr=stderr,
                output_truncated=stdout_truncated or stderr_truncated or raw_truncated,
            )
        if cleanup_status is ValidationCleanupStatus.FAILED:
            task_result = task_result.model_copy(
                update={
                    "outcome": ValidationOutcome.ERROR,
                    "stderr": "Code Interpreter session cleanup failed.",
                }
            )
        profile = self.execution_profile()
        return SandboxTaskExecution(
            result=task_result,
            execution=ValidationExecutionRecord(
                attempt=request.attempt,
                task_name=request.task_name,
                backend=profile.backend,
                executor_id=profile.executor_id,
                input_digest=archive_digest(archive),
                session_digest=archive_digest(session_id.encode("utf-8")) if session_id else None,
                enforced_controls=profile.enforced_controls,
                cleanup_status=cleanup_status,
                outcome=task_result.outcome,
                duration_ms=task_result.duration_ms,
            ),
        )

    def _start_session(self, workspace_id: str) -> str:
        response = self._client.start_code_interpreter_session(
            codeInterpreterIdentifier=self.code_interpreter_identifier,
            name=f"aios-{workspace_id[:40]}-{uuid4().hex[:8]}",
            sessionTimeoutSeconds=900,
            clientToken=str(uuid4()),
        )
        session_id = response.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise RuntimeError("Code Interpreter omitted its session identifier")
        return session_id

    def _upload(self, session_id: str, archive: bytes, bundle: bytes) -> None:
        result = self._invoke(
            session_id,
            "writeFiles",
            {
                "content": [
                    {"path": _REMOTE_ARCHIVE, "blob": archive},
                    {"path": _REMOTE_VENDOR, "blob": bundle},
                ]
            },
        )
        if result.get("isError") is True:
            raise RuntimeError("Code Interpreter rejected validation inputs")

    def _execute(self, session_id: str, request: ValidationTaskRequest) -> dict[str, str | int | bool]:
        runner = _runner_code(
            list(request.task.argv),
            request.task.cwd,
            dict(request.task.environment),
            request.task.timeout_seconds,
            request.task.output_limit_bytes,
        )
        result = self._invoke(
            session_id,
            "executeCode",
            {"language": "python", "code": runner, "clearContext": True},
        )
        structured = result.get("structuredContent")
        if not isinstance(structured, Mapping):
            raise RuntimeError("Code Interpreter omitted structured execution output")
        raw_stdout = structured.get("stdout")
        if not isinstance(raw_stdout, str):
            raise RuntimeError("Code Interpreter omitted validation stdout")
        marker_line = next(
            (line for line in reversed(raw_stdout.splitlines()) if line.startswith(_RESULT_MARKER)), None
        )
        if marker_line is None:
            raise RuntimeError("trusted validation runner did not return a result")
        parsed = json.loads(marker_line.removeprefix(_RESULT_MARKER))
        if not isinstance(parsed, dict):
            raise RuntimeError("trusted validation runner returned an invalid result")
        try:
            stdout = base64.b64decode(str(parsed["stdout"]), validate=True).decode("utf-8", errors="replace")
            stderr = base64.b64decode(str(parsed["stderr"]), validate=True).decode("utf-8", errors="replace")
            exit_code = int(parsed["exit_code"])
            truncated = bool(parsed["truncated"])
        except (KeyError, ValueError) as exc:
            raise RuntimeError("trusted validation runner returned an invalid result") from exc
        return {"stdout": stdout, "stderr": stderr, "exit_code": exit_code, "truncated": truncated}

    def _invoke(self, session_id: str, name: str, arguments: dict[str, object]) -> Mapping[str, object]:
        response = self._client.invoke_code_interpreter(
            codeInterpreterIdentifier=self.code_interpreter_identifier,
            sessionId=session_id,
            name=name,
            arguments=arguments,
        )
        stream = response.get("stream")
        if not isinstance(stream, Iterable):
            raise RuntimeError("Code Interpreter returned no event stream")
        for event in cast(Iterable[Mapping[str, object]], stream):
            result = event.get("result")
            if isinstance(result, Mapping):
                return result
            if any(key.endswith("Exception") for key in event):
                raise RuntimeError("Code Interpreter operation failed")
        raise RuntimeError("Code Interpreter stream ended without a result")

    def _stop_session(self, session_id: str) -> bool:
        try:
            self._client.stop_code_interpreter_session(
                codeInterpreterIdentifier=self.code_interpreter_identifier,
                sessionId=session_id,
                clientToken=str(uuid4()),
            )
        except Exception:  # noqa: BLE001 - cleanup must be attempted and normalized
            return False
        return True

    def _archive_workspace(self, root: Path) -> bytes:
        buffer = io.BytesIO()
        count = 0
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for current_root, directories, files in os.walk(root, followlinks=False):
                current = Path(current_root)
                for name in directories:
                    candidate = current / name
                    if candidate.is_symlink():
                        raise SandboxError(f"validation archive contains a symlink: {candidate.relative_to(root)}")
                directories[:] = sorted(
                    name
                    for name in directories
                    if name != ".git" and not _forbidden((current / name).relative_to(root).as_posix())
                )
                for name in sorted(files):
                    path = current / name
                    relative = path.relative_to(root).as_posix()
                    if _forbidden(relative):
                        continue
                    if path.is_symlink():
                        raise SandboxError(f"validation archive contains a symlink: {relative}")
                    if not path.is_file():
                        continue
                    count += 1
                    if count > _MAX_ARCHIVE_FILES:
                        raise SandboxError("UNSUPPORTED_VALIDATION_ENVIRONMENT: too many files")
                    archive.add(path, arcname=relative, recursive=False)
                    if buffer.tell() > _MAX_UPLOAD_BYTES:
                        raise SandboxError("UNSUPPORTED_VALIDATION_ENVIRONMENT: workspace exceeds 80 MB")
        return buffer.getvalue()

    def _read_bundle(self) -> bytes:
        if not self.validation_bundle.is_file() or self.validation_bundle.is_symlink():
            raise SandboxError("UNSUPPORTED_VALIDATION_ENVIRONMENT: offline validation bundle is absent")
        return self.validation_bundle.read_bytes()

    @staticmethod
    def _validate_workdir(root: Path, relative_value: str) -> None:
        cursor = root
        for part in Path(relative_value).parts:
            cursor /= part
            if cursor.is_symlink():
                raise SandboxError("validation cwd contains a symlink")
        workdir = (root / relative_value).resolve()
        if not workdir.is_relative_to(root) or not workdir.is_dir():
            raise SandboxError("validation cwd escapes or is absent from workspace")

    @staticmethod
    def _validate_environment(environment: Mapping[str, str]) -> None:
        reserved = {"PATH", "PYTHONPATH", "PYTHONHOME", "HOME"}
        if any(key in reserved or key.startswith(("AWS_", "GITHUB_")) for key in environment):
            raise SandboxError("validation environment attempts to override a reserved key")


def _forbidden(relative: str) -> bool:
    return any(fnmatch.fnmatchcase(relative, pattern) for pattern in _FORBIDDEN_ARCHIVE_PATTERNS)


def _cap(value: str | int | bool, limit: int) -> tuple[str, bool]:
    raw = str(value).encode("utf-8")
    if len(raw) <= limit:
        return str(value), False
    return raw[:limit].decode("utf-8", errors="ignore"), True


def _runner_code(argv: list[str], cwd: str, environment: dict[str, str], timeout: int, output_limit: int) -> str:
    payload = json.dumps(
        {"argv": argv, "cwd": cwd, "environment": environment, "timeout": timeout, "limit": output_limit},
        sort_keys=True,
    )
    return f"""
import base64, io, json, os, pathlib, subprocess, tarfile

cfg = json.loads({payload!r})
root = pathlib.Path('aios-workspace').resolve()
vendor = pathlib.Path('aios-vendor').resolve()
root.mkdir(parents=True, exist_ok=True)
vendor.mkdir(parents=True, exist_ok=True)

def safe_extract(source, destination):
    with tarfile.open(source, 'r:gz') as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination) or member.issym() or member.islnk():
                raise RuntimeError('unsafe validation archive')
        archive.extractall(destination, filter='data')

safe_extract({_REMOTE_ARCHIVE!r}, root)
safe_extract({_REMOTE_VENDOR!r}, vendor)
workdir = (root / cfg['cwd']).resolve()
if not workdir.is_relative_to(root) or not workdir.is_dir():
    raise RuntimeError('unsafe validation cwd')
env = {{'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'PYTHONPATH': str(vendor), 'PYTHONDONTWRITEBYTECODE': '1'}}
env.update(cfg['environment'])
try:
    process = subprocess.run(cfg['argv'], cwd=workdir, env=env, shell=False, capture_output=True,
                             timeout=cfg['timeout'], check=False)
    stdout, stderr, exit_code = process.stdout, process.stderr, process.returncode
except subprocess.TimeoutExpired as exc:
    stdout, stderr, exit_code = exc.stdout or b'', exc.stderr or b'', 124
limit = cfg['limit']
truncated = len(stdout) + len(stderr) > limit
stdout = stdout[:limit]
stderr = stderr[:max(0, limit - len(stdout))]
result = {{'stdout': base64.b64encode(stdout).decode(), 'stderr': base64.b64encode(stderr).decode(),
          'exit_code': exit_code, 'truncated': truncated}}
print({_RESULT_MARKER!r} + json.dumps(result, sort_keys=True, separators=(',', ':')))
"""


def archive_digest(value: bytes) -> str:
    """Return a stable digest used by adapter tests and evidence."""

    return "sha256:" + hashlib.sha256(value).hexdigest()
