"""Restricted Docker validation executor."""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import time
from pathlib import Path
from uuid import uuid4

from unidiff import PatchSet  # type: ignore[attr-defined]

from remediation_agent.domain.enums import (
    ValidationBackend,
    ValidationCleanupStatus,
    ValidationOutcome,
)
from remediation_agent.domain.models import (
    ArtifactManifest,
    CapabilityReportV1,
    CleanupResult,
    ValidationExecutionRecord,
    ValidationTaskResult,
    WorkspaceRef,
)
from remediation_agent.ports.models import (
    BehavioralTaskExecution,
    BehavioralTaskRequest,
    PatchApplicabilityError,
    PatchApplyRequest,
    PatchApplyResult,
    SandboxExecutionProfile,
    SandboxTaskExecution,
    ValidationTaskRequest,
)

_CONTAINER_TMPFS = "/tmp:rw,noexec,nosuid,size=64m"  # noqa: S108  # nosec B108


class SandboxError(RuntimeError):
    """Raised when a restricted workspace operation fails."""


class DockerSandboxExecutor:
    """Apply patches with Git and run only configured argv inside a locked-down container."""

    def __init__(
        self, workspace_root: Path, image: str, *, behavioral_bundle: Path = Path("/app/validation/ecommerce")
    ) -> None:
        self.workspace_root = workspace_root.resolve()
        self.image = image
        self.behavioral_bundle = behavioral_bundle
        self._active_containers: dict[str, str] = {}

    def execution_profile(self) -> SandboxExecutionProfile:
        return SandboxExecutionProfile(
            backend=ValidationBackend.DOCKER,
            executor_id=self.image,
            enforced_controls=[
                "OPERATOR_DEFINED_TASK",
                "FIXED_ARGV_NO_SHELL",
                "NETWORK_DISABLED",
                "NON_ROOT",
                "RESOURCE_LIMITS",
                "TIMEOUT_AND_OUTPUT_CAP",
            ],
        )

    def verification_fingerprint(self) -> str:
        from remediation_agent.adapters.behavioral import _ASSETS, _digest_files

        manifest = self.behavioral_bundle / "manifest.json"
        dependencies = manifest.read_bytes() if manifest.is_file() else b"NO_ECOMMERCE_BUNDLE"
        return (
            "sha256:" + hashlib.sha256(_digest_files(_ASSETS, ignore_bytecode=True).encode() + dependencies).hexdigest()
        )

    async def probe_capability(self, request: BehavioralTaskRequest) -> CapabilityReportV1:
        try:
            execution = await self.run_behavior(request.model_copy(update={"capability_only": True}))
            pair = execution.evidence
            ready = all(case.outcome in {"PASSED", "ASSERTION_FAILED"} for case in pair.base.cases)
            return CapabilityReportV1(
                task_name=request.task_name,
                available=ready and pair.cleanup_succeeded,
                base_commit=request.workspace.base_commit,
                assertions_digest=pair.assertions_digest,
                dependency_digest=pair.dependency_digest,
                runtime_digest=pair.base.runtime_digest,
                startup_verified=ready,
                cleanup_verified=pair.cleanup_succeeded,
                failure_code=None if ready else "BASE_SETUP_FAILED",
                detail="; ".join(c.detail for c in pair.base.cases if c.outcome == "SETUP_ERROR")[:2000],
            )
        except (OSError, RuntimeError, ValueError) as exc:
            from remediation_agent.adapters.evidence import SecretRedactor

            return CapabilityReportV1(
                task_name=request.task_name,
                available=False,
                base_commit=request.workspace.base_commit,
                failure_code="CAPABILITY_UNAVAILABLE",
                detail=SecretRedactor().redact(str(exc))[:2000],
            )

    async def check_patch(self, request: PatchApplyRequest) -> None:
        root = self._workspace(request.workspace)
        self._validate_patch_paths(root, request.unified_diff)
        await self._run_git_apply(root, request.unified_diff.encode("utf-8"), check_only=True)

    async def apply_patch(self, request: PatchApplyRequest) -> PatchApplyResult:
        root = self._workspace(request.workspace)
        self._validate_patch_paths(root, request.unified_diff)
        patch_bytes = request.unified_diff.encode("utf-8")
        await self._run_git_apply(root, patch_bytes, check_only=True)
        await self._run_git_apply(root, patch_bytes, check_only=False)
        return PatchApplyResult(applied=True, detail="Patch applied after git apply --check.")

    async def restore_base(self, workspace: WorkspaceRef) -> None:
        root = self._workspace(workspace)
        await self._run(self._git_argv(root, "reset", "--hard", workspace.base_commit), cwd=root, timeout=60.0)
        await self._run(self._git_argv(root, "clean", "-fdx"), cwd=root, timeout=60.0)

    async def run_behavior(self, request: BehavioralTaskRequest) -> BehavioralTaskExecution:
        from remediation_agent.adapters.behavioral import run_behavioral_pair

        return await run_behavioral_pair(self, request)

    async def run_task(self, request: ValidationTaskRequest) -> SandboxTaskExecution:
        root = self._workspace(request.workspace)
        unresolved_workdir = root / request.task.cwd
        cursor = root
        for part in Path(request.task.cwd).parts:
            cursor /= part
            if cursor.is_symlink():
                raise SandboxError("validation cwd contains a symlink")
        workdir = unresolved_workdir.resolve()
        if not workdir.is_relative_to(root) or not workdir.is_dir():
            raise SandboxError("validation cwd escapes or is absent from workspace")
        relative_workdir = workdir.relative_to(root).as_posix()
        container_workdir = "/workspace" if relative_workdir == "." else f"/workspace/{relative_workdir}"
        container_name = f"aios-remediation-{request.workspace.workspace_id[:30]}-{uuid4().hex[:12]}"
        self._active_containers[container_name] = request.workspace.workspace_id
        argv = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "128",
            "--memory",
            "1g",
            "--cpus",
            "1.0",
            "--user",
            "10001:10001",
            "--tmpfs",
            _CONTAINER_TMPFS,
            "--volume",
            f"{root}:/workspace:{'ro' if request.task.kind == 'BEHAVIORAL' else 'rw'}",
            "--volume",
            f"{root / '.git'}:/workspace/.git:ro",
            "--workdir",
            container_workdir,
        ]
        for key, value in sorted(request.task.environment.items()):
            argv.extend(["--env", f"{key}={value}"])
        argv.extend([self.image, *request.task.argv])

        started = time.monotonic()
        try:
            return_code, stdout, stderr, truncated = await self._run_capped(
                argv,
                cwd=root,
                timeout=float(request.task.timeout_seconds),
                output_limit=request.task.output_limit_bytes,
            )
        except TimeoutError:
            container_removed = await self._remove_container(container_name, root)
            if container_removed:
                self._active_containers.pop(container_name, None)
            duration_ms = int((time.monotonic() - started) * 1_000)
            result = ValidationTaskResult(
                task_name=request.task_name,
                outcome=ValidationOutcome.TIMED_OUT if container_removed else ValidationOutcome.ERROR,
                duration_ms=duration_ms,
                stderr=(
                    "Validation task exceeded its configured timeout."
                    if container_removed
                    else "Validation timed out and forced container cleanup failed."
                ),
            )
            return self._task_execution(
                request,
                result,
                ValidationCleanupStatus.SUCCEEDED if container_removed else ValidationCleanupStatus.FAILED,
            )
        except (OSError, RuntimeError):
            if await self._remove_container(container_name, root):
                self._active_containers.pop(container_name, None)
            raise
        else:
            self._active_containers.pop(container_name, None)
        duration_ms = int((time.monotonic() - started) * 1_000)
        outcome = ValidationOutcome.PASSED if return_code == 0 else ValidationOutcome.FAILED
        result = ValidationTaskResult(
            task_name=request.task_name,
            outcome=outcome,
            exit_code=return_code,
            duration_ms=duration_ms,
            stdout=stdout,
            stderr=stderr,
            output_truncated=truncated,
        )
        return self._task_execution(request, result, ValidationCleanupStatus.SUCCEEDED)

    def _task_execution(
        self,
        request: ValidationTaskRequest,
        result: ValidationTaskResult,
        cleanup_status: ValidationCleanupStatus,
    ) -> SandboxTaskExecution:
        profile = self.execution_profile()
        input_digest = "sha256:" + hashlib.sha256(request.model_dump_json().encode("utf-8")).hexdigest()
        return SandboxTaskExecution(
            result=result,
            execution=ValidationExecutionRecord(
                attempt=request.attempt,
                task_name=request.task_name,
                backend=profile.backend,
                executor_id=profile.executor_id,
                input_digest=input_digest,
                enforced_controls=profile.enforced_controls,
                cleanup_status=cleanup_status,
                outcome=result.outcome,
                duration_ms=result.duration_ms,
            ),
        )

    async def collect_artifacts(self, workspace: WorkspaceRef) -> ArtifactManifest:
        self._workspace(workspace)
        return ArtifactManifest(run_id=workspace.workspace_id, artifacts=[])

    async def destroy(self, workspace: WorkspaceRef) -> CleanupResult:
        try:
            root = self._workspace(workspace)
            container_names = [
                name for name, workspace_id in self._active_containers.items() if workspace_id == workspace.workspace_id
            ]
            for name in container_names:
                if not await self._remove_container(name, root):
                    raise SandboxError(f"could not remove active validation container: {name}")
                self._active_containers.pop(name, None)
            shutil.rmtree(root)
        except (OSError, RuntimeError) as exc:
            return CleanupResult(succeeded=False, detail=f"Workspace cleanup failed: {exc}")
        return CleanupResult(succeeded=True, detail="Workspace destroyed.")

    def _workspace(self, workspace: WorkspaceRef) -> Path:
        unresolved = Path(workspace.path)
        if unresolved.is_symlink():
            raise SandboxError("workspace root cannot be a symlink")
        root = unresolved.resolve()
        if not root.is_relative_to(self.workspace_root) or root == self.workspace_root:
            raise SandboxError("workspace is outside the configured workspace root")
        if not root.is_dir() or root.is_symlink():
            raise SandboxError("workspace is absent or unsafe")
        return root

    async def _run_git_apply(self, root: Path, patch: bytes, *, check_only: bool) -> None:
        argv = self._git_argv(root, "apply", "--whitespace=error")
        if check_only:
            argv.append("--check")
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=root,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(process.communicate(patch), timeout=60.0)
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise SandboxError("git apply timed out") from exc
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace")[:4_000]
            raise PatchApplicabilityError(f"git apply failed: {detail}")

    def _git_argv(self, root: Path, *arguments: str) -> list[str]:
        validated_root = self._workspace_path(root)
        return ["git", "-c", f"safe.directory={validated_root}", *arguments]

    def _workspace_path(self, root: Path) -> Path:
        resolved = root.resolve()
        if resolved == self.workspace_root or not resolved.is_relative_to(self.workspace_root):
            raise SandboxError("refused Git configuration outside the workspace root")
        return resolved

    async def _run(self, argv: list[str], *, cwd: Path, timeout: float) -> None:
        return_code, _, stderr, _ = await self._run_capped(
            argv,
            cwd=cwd,
            timeout=timeout,
            output_limit=65_536,
        )
        if return_code != 0:
            raise SandboxError(f"sandbox operation failed: {stderr}")

    async def _remove_container(self, container_name: str, cwd: Path) -> bool:
        try:
            return_code, _, _, _ = await self._run_capped(
                ["docker", "rm", "--force", container_name],
                cwd=cwd,
                timeout=30.0,
                output_limit=4_096,
            )
        except (OSError, RuntimeError, TimeoutError):
            return False
        return return_code == 0

    @staticmethod
    async def _run_capped(
        argv: list[str],
        *,
        cwd: Path,
        timeout: float,
        output_limit: int,
    ) -> tuple[int, str, str, bool]:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_stream = process.stdout
        stderr_stream = process.stderr
        if stdout_stream is None or stderr_stream is None:
            process.kill()
            await process.wait()
            raise SandboxError("subprocess output pipes were not created")

        remaining = output_limit
        truncated = False
        budget_lock = asyncio.Lock()

        async def drain(stream: asyncio.StreamReader) -> bytes:
            nonlocal remaining, truncated
            retained = bytearray()
            while chunk := await stream.read(8_192):
                async with budget_lock:
                    keep = min(remaining, len(chunk))
                    retained.extend(chunk[:keep])
                    remaining -= keep
                    if keep < len(chunk):
                        truncated = True
            return bytes(retained)

        async def collect() -> tuple[bytes, bytes]:
            stdout_bytes, stderr_bytes, _ = await asyncio.gather(
                drain(stdout_stream),
                drain(stderr_stream),
                process.wait(),
            )
            return stdout_bytes, stderr_bytes

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(collect(), timeout=timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        return (
            process.returncode or 0,
            stdout_bytes.decode("utf-8", errors="replace"),
            stderr_bytes.decode("utf-8", errors="replace"),
            truncated,
        )

    @staticmethod
    def _validate_patch_paths(root: Path, unified_diff: str) -> None:
        patch_set = PatchSet(unified_diff.splitlines(keepends=True))
        for patched_file in patch_set:
            for raw_path in (str(patched_file.source_file), str(patched_file.target_file)):
                if raw_path == "/dev/null":
                    continue
                normalized = raw_path[2:] if raw_path.startswith(("a/", "b/")) else raw_path
                relative = Path(normalized)
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or not relative.parts
                    or relative.parts[0] == ".git"
                ):
                    raise SandboxError(f"patch path is unsafe: {raw_path}")
                cursor = root
                for part in relative.parts:
                    cursor /= part
                    if cursor.is_symlink():
                        raise SandboxError(f"patch path contains a symlink: {normalized}")


def patch_digest(unified_diff: str) -> str:
    return "sha256:" + hashlib.sha256(unified_diff.encode("utf-8")).hexdigest()
