"""Strict assessment evaluation records, scoring, and report rendering."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from remediation_agent.domain.enums import (
    FinalStatus,
    InspectionToolStatus,
    ValidationBackend,
    ValidationCleanupStatus,
    ValidationOutcome,
)
from remediation_agent.domain.models import ExplainabilityTraceV1, RemediationRunView, StrictModel


class EvaluationManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    evaluation_id: str = Field(min_length=1, max_length=100)
    scenario_id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=200)
    handoff_path: str = Field(min_length=1, max_length=500)
    policy_path: str = Field(min_length=1, max_length=500)
    expected_terminal_status: Literal[FinalStatus.DRAFT_PR_PREPARED]
    required_validation_tasks: list[str] = Field(min_length=1, max_length=20)
    allowed_inspection_tools: list[str] = Field(min_length=1, max_length=20)
    minimum_commit_pinned_reads: int = Field(ge=1, le=20)
    maximum_trials: int = Field(ge=1, le=5)
    require_successful_cleanup: bool = True
    forbid_remote_writes: bool = True

    @model_validator(mode="after")
    def exact_inspection_allowlist(self) -> EvaluationManifest:
        expected = {
            "get_repository_tree",
            "get_file_contents",
            "search_code",
            "finish_inspection",
        }
        if set(self.allowed_inspection_tools) != expected or len(self.allowed_inspection_tools) != len(expected):
            raise ValueError("evaluation inspection allowlist must contain exactly the four approved tools")
        if len(self.required_validation_tasks) != len(set(self.required_validation_tasks)):
            raise ValueError("required validation tasks must be unique")
        return self


class EvaluationMetric(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    numerator: int = Field(ge=0)
    denominator: int = Field(gt=0)
    passed: bool
    detail: str = Field(max_length=1_000)

    @property
    def ratio(self) -> str:
        return f"{self.numerator}/{self.denominator}"


class EvaluationArtifactDigest(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class EvaluationRun(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    evaluation_id: str
    scenario_id: str
    title: str
    mode: Literal["deterministic", "hosted"]
    generated_at: datetime
    source_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    trial_count: int = Field(ge=1, le=5)
    passed_trials: int = Field(ge=0)
    final_status: FinalStatus
    metrics: list[EvaluationMetric]
    inspection_tools_called: list[str]
    commit_pinned_successes: int = Field(ge=0)
    validation_executions: list[dict[str, object]]
    model_call_count: int = Field(ge=0)
    model_latency_ms: int = Field(ge=0)
    model_input_tokens: int = Field(ge=0)
    model_output_tokens: int = Field(ge=0)
    cleanup_succeeded: bool
    remote_objects_created: int = Field(ge=0)
    error_codes: list[str] = Field(default_factory=list, max_length=50)
    artifact_digests: list[EvaluationArtifactDigest]
    passed: bool
    demonstration_only: bool


def load_evaluation_manifest(path: Path) -> EvaluationManifest:
    return EvaluationManifest.model_validate_json(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def score_evaluation(
    *,
    manifest: EvaluationManifest,
    mode: Literal["deterministic", "hosted"],
    view: RemediationRunView,
    source_commit: str,
    cleanup_succeeded: bool,
    remote_objects_created: int,
    artifact_paths: list[Path],
) -> EvaluationRun:
    trace = view.explainability or ExplainabilityTraceV1(run_id=view.run_id, status=view.status)
    validation = list(trace.validation_executions)
    required = set(manifest.required_validation_tasks)
    passed_tasks = {item.task_name for item in validation if item.outcome is ValidationOutcome.PASSED}
    called = [item.tool_name for item in trace.inspection_tool_calls]
    allowed = set(manifest.allowed_inspection_tools)
    pinned_successes = sum(
        1
        for item in trace.inspection_tool_calls
        if item.tool_name in {"get_repository_tree", "get_file_contents"}
        and item.status is InspectionToolStatus.SUCCEEDED
        and (item.arguments.get("tree_sha") == source_commit or item.arguments.get("sha") == source_commit)
    )
    expected_backend = (
        ValidationBackend.FAKE if mode == "deterministic" else ValidationBackend.AGENTCORE_CODE_INTERPRETER
    )
    accepted_cleanup = (
        {ValidationCleanupStatus.NOT_APPLICABLE} if mode == "deterministic" else {ValidationCleanupStatus.SUCCEEDED}
    )
    cleanup_ok = cleanup_succeeded and all(item.cleanup_status in accepted_cleanup for item in validation)
    metrics = [
        _metric("terminal_status", view.status is manifest.expected_terminal_status, str(view.status)),
        _metric(
            "required_validations",
            required.issubset(passed_tasks),
            f"passed={sorted(passed_tasks)}; required={sorted(required)}",
        ),
        _metric("inspection_allowlist", bool(called) and set(called).issubset(allowed), f"called={called}"),
        _metric(
            "commit_pinned_inspection",
            pinned_successes >= manifest.minimum_commit_pinned_reads,
            f"successful pinned tree/file calls={pinned_successes}",
        ),
        _metric(
            "validation_backend",
            bool(validation) and all(item.backend is expected_backend for item in validation),
            f"expected={expected_backend}; observed={[item.backend.value for item in validation]}",
        ),
        _metric("cleanup", cleanup_ok, f"workspace={cleanup_succeeded}"),
        _metric("no_remote_writes", remote_objects_created == 0, f"created={remote_objects_created}"),
        _metric("no_approval_interrupt", view.approval_request is None, "approval interrupt is an evaluation failure"),
    ]
    model_calls = trace.model_calls
    passed = all(item.passed for item in metrics)
    return EvaluationRun(
        evaluation_id=manifest.evaluation_id,
        scenario_id=manifest.scenario_id,
        title=manifest.title,
        mode=mode,
        generated_at=datetime.now(UTC),
        source_commit=source_commit,
        trial_count=1,
        passed_trials=1 if passed else 0,
        final_status=view.status,
        metrics=metrics,
        inspection_tools_called=called,
        commit_pinned_successes=pinned_successes,
        validation_executions=[item.model_dump(mode="json") for item in validation],
        model_call_count=len(model_calls),
        model_latency_ms=sum(item.duration_ms for item in model_calls),
        model_input_tokens=sum(item.input_tokens or 0 for item in model_calls),
        model_output_tokens=sum(item.output_tokens or 0 for item in model_calls),
        cleanup_succeeded=cleanup_ok,
        remote_objects_created=remote_objects_created,
        error_codes=[item.code for item in view.result.errors] if view.result else [],
        artifact_digests=[
            EvaluationArtifactDigest(
                name=path.resolve().relative_to(Path.cwd().resolve()).as_posix()
                if path.resolve().is_relative_to(Path.cwd().resolve())
                else path.name,
                sha256=sha256_file(path),
            )
            for path in artifact_paths
            if path.is_file()
        ],
        passed=passed,
        demonstration_only=mode == "hosted",
    )


def aggregate_evaluations(runs: list[EvaluationRun]) -> EvaluationRun:
    if not runs:
        raise ValueError("at least one evaluation run is required")
    first = runs[0]
    identity = {(item.evaluation_id, item.scenario_id, item.mode, item.source_commit) for item in runs}
    if len(identity) != 1:
        raise ValueError("evaluation runs must share scenario, mode, and source commit")
    metric_names = [item.name for item in first.metrics]
    if any([item.name for item in run.metrics] != metric_names for run in runs):
        raise ValueError("evaluation runs must share the same metric order")
    metrics = [
        EvaluationMetric(
            name=name,
            numerator=sum(run.metrics[index].numerator for run in runs),
            denominator=sum(run.metrics[index].denominator for run in runs),
            passed=all(run.metrics[index].passed for run in runs),
            detail=f"{sum(run.metrics[index].numerator for run in runs)}/{len(runs)} trials satisfied this assertion",
        )
        for index, name in enumerate(metric_names)
    ]
    digests = {(item.name, item.sha256): item for run in runs for item in run.artifact_digests}
    return first.model_copy(
        update={
            "generated_at": datetime.now(UTC),
            "trial_count": sum(item.trial_count for item in runs),
            "passed_trials": sum(item.passed_trials for item in runs),
            "final_status": runs[-1].final_status,
            "metrics": metrics,
            "inspection_tools_called": [tool for run in runs for tool in run.inspection_tools_called],
            "commit_pinned_successes": sum(item.commit_pinned_successes for item in runs),
            "validation_executions": [record for run in runs for record in run.validation_executions],
            "model_call_count": sum(item.model_call_count for item in runs),
            "model_latency_ms": sum(item.model_latency_ms for item in runs),
            "model_input_tokens": sum(item.model_input_tokens for item in runs),
            "model_output_tokens": sum(item.model_output_tokens for item in runs),
            "cleanup_succeeded": all(item.cleanup_succeeded for item in runs),
            "remote_objects_created": sum(item.remote_objects_created for item in runs),
            "error_codes": sorted({code for run in runs for code in run.error_codes}),
            "artifact_digests": list(digests.values()),
            "passed": all(item.passed for item in runs),
        }
    )


def write_evaluation(path: Path, evaluation: EvaluationRun) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(evaluation.model_dump_json(indent=2) + "\n", encoding="utf-8")


def load_evaluation(path: Path) -> EvaluationRun:
    return EvaluationRun.model_validate_json(path.read_text(encoding="utf-8"))


def render_assessment_report(
    manifest: EvaluationManifest,
    deterministic: EvaluationRun | None,
    hosted: EvaluationRun | None,
) -> str:
    source_commit = deterministic.source_commit if deterministic else hosted.source_commit if hosted else "not-run"
    lines = [
        "# Assessment Evidence",
        "",
        "> Generated from bounded evaluation JSON. Live evidence is never inferred or fabricated.",
        "",
        "## Evaluation method and provenance",
        "",
        f"Scenario: `{manifest.scenario_id}` — {_md(manifest.title)}. The handoff pins source commit "
        f"`{source_commit}`. "
        "Deterministic results use "
        "the real LangGraph workflow with scripted models and fake infrastructure; hosted results use the configured "
        "live model, GitHub MCP, immutable clone, and AgentCore Code Interpreter.",
        "",
        "## Tool and policy boundary",
        "",
        "```mermaid",
        "flowchart LR",
        "  M[Configured model] --> A[Four-tool inspection allowlist]",
        "  A --> P{Deterministic policy and approval boundary}",
        "  P --> R[Read-only GitHub inspection]",
        "  P --> W[Disposable workspace operations]",
        "  P --> V[Isolated validation backend]",
        "  P --> E[Redacted evidence and audit]",
        "  P -. config + policy gates .-> G[Optional remote draft PR write]",
        "  G -. never .-> X[Merge or deploy]",
        "```",
        "",
    ]
    lines.extend(_render_run("Deterministic evaluation", deterministic))
    lines.extend(_render_run("Hosted demonstration", hosted, hosted=True))
    lines.extend(
        [
            "## Security controls and negative assertions",
            "",
            "- Model calls are limited to the commit-pinned inspection/control allowlist.",
            "- Validation task names and fixed argument arrays come from operator policy; no model-generated shell is "
            "run.",
            "- Hosted evaluation forces both application GitHub write gates off and fails on approval or remote "
            "creation.",
            "- Evaluation JSON excludes prompts, repository contents, unrestricted task output, credentials, and raw "
            "session IDs.",
            "- Validation records contain only bounded metadata and a one-way session digest where applicable.",
            "",
            "## Reproduction",
            "",
            "```bash",
            "make evaluate",
            "make evaluate-hosted  # opt-in credentials and cloud access required",
            "make assessment-report",
            "```",
            "",
            "## Limitations and residual risks",
            "",
            "The deterministic run establishes repeatability, not live-provider performance. A single hosted run is "
            "demonstration evidence only and is not a statistically meaningful success rate. Provider availability, "
            "model variation, GitHub MCP schema changes, and cloud cleanup failures remain operational risks. The "
            "prepared draft "
            "payload is local; the evaluator neither creates nor merges a pull request and never deploys.",
            "",
        ]
    )
    return "\n".join(lines)


def _metric(name: str, passed: bool, detail: str) -> EvaluationMetric:
    return EvaluationMetric(name=name, numerator=int(passed), denominator=1, passed=passed, detail=detail)


def _render_run(title: str, run: EvaluationRun | None, *, hosted: bool = False) -> list[str]:
    output = [f"## {title}", ""]
    if run is None:
        return [*output, "**NOT RUN**", ""]
    if hosted:
        output.extend(
            [
                f"This {run.trial_count}-trial result is demonstration evidence, not a statistically meaningful "
                "success rate.",
                "",
            ]
        )
    output.extend(
        [
            f"Overall: **{run.passed_trials}/{run.trial_count}** trials passed; final status `{run.final_status}`.",
            f"Model evidence: **{run.model_call_count}** calls, **{run.model_latency_ms} ms** total latency, "
            f"**{run.model_input_tokens}/{run.model_output_tokens}** input/output tokens recorded.",
            "",
            "| Metric | Result | Detail |",
            "|---|---:|---|",
        ]
    )
    output.extend(f"| `{item.name}` | {item.ratio} | {_md(item.detail)} |" for item in run.metrics)
    if run.error_codes:
        output.extend(["", "Failure codes: " + ", ".join(f"`{_md(code)}`" for code in run.error_codes) + "."])
    output.extend(["", "### Validation execution evidence", ""])
    if not run.validation_executions:
        output.extend(["No validation execution records were produced.", ""])
    else:
        output.extend(
            [
                "| Task | Backend | Executor | Input digest | Session digest | Cleanup | Outcome |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for record in run.validation_executions:
            output.append(
                "| `{task_name}` | `{backend}` | `{executor_id}` | `{input_digest}` | `{session_digest}` | "
                "`{cleanup_status}` | `{outcome}` |".format(
                    **{key: _md(str(value if value is not None else "n/a")) for key, value in record.items()}
                )
            )
        output.append("")
    output.extend(["### Artifact digests", ""])
    output.extend(f"- `{item.name}`: `sha256:{item.sha256}`" for item in run.artifact_digests)
    output.append("")
    return output


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").replace("`", "'")
