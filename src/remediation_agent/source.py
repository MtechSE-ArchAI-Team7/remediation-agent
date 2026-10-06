"""Source projection and exact edit compilation, separate from diagnostic log redaction."""

from __future__ import annotations

import difflib
import hashlib
import re
from collections import defaultdict
from pathlib import PurePosixPath

from remediation_agent.domain.models import (
    EditProposal,
    EditReceipt,
    InspectionArtifact,
    PatchCandidate,
    ProtectedSourceSpan,
    SourceEdit,
    WorkflowFailure,
)

# A reference such as token: userToken is source code, not a credential value.
# Quoted assignments and known credential formats remain protected, including defaults.
_VALUE = re.compile(
    r"""(?ix)(?<![a-z0-9_])(?:["']?(?:[a-z0-9_]{0,100}(?:api[_-]?key|token|secret|password|credential)[a-z0-9_]{0,100})["']?)
        \s*[:=]\s*(?P<value>["'][^"'\r\n]+["']|[a-z0-9_]+-[a-z0-9_-]+|[0-9]+)"""
)
_CONFIG_VALUE = re.compile(r"(?im)\b(?:api[_-]?key|token|secret|password|credential)\s*[:=]\s*(?P<value>[^\s,;]+)")
_LITERALS = re.compile(
    r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|sk-[A-Za-z0-9_-]{20,}|(?i:Bearer)[ \t]+[A-Za-z0-9._-]{20,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    r"|(?<![A-Za-z0-9])/(?:Users|home)/[^/\s]+"
)


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def source_artifact(path: str, content: str, *, truncated: bool = False) -> InspectionArtifact:
    ranges = [(m.start("value"), m.end("value")) for m in _VALUE.finditer(content)]
    if PurePosixPath(path).suffix.lower() in {".yaml", ".yml", ".toml", ".ini", ".conf"}:
        ranges.extend((m.start("value"), m.end("value")) for m in _CONFIG_VALUE.finditer(content))
    ranges.extend((m.start(), m.end()) for m in _LITERALS.finditer(content))
    lines = content.splitlines(keepends=True)
    protected: set[int] = set()
    for start, end in ranges:
        protected.update(range(content.count("\n", 0, start) + 1, content.count("\n", 0, end) + 2))
    # Whole-line masking is deliberate: models cannot edit or reconstruct protected bytes.
    visible = "".join(
        ("[PROTECTED SOURCE]" + ("\n" if line.endswith("\n") else "")) if i in protected else line
        for i, line in enumerate(lines, 1)
    )
    return InspectionArtifact(
        kind="FILE",
        locator=path,
        content=visible,
        digest=digest(visible),
        base_content_digest=digest(content),
        truncated=truncated,
        protected_spans=[ProtectedSourceSpan(start_line=i, end_line=i) for i in sorted(protected)],
    )


class EditConstructionError(ValueError):
    def __init__(self, failure: WorkflowFailure):
        super().__init__(failure.detail)
        self.failure = failure


def _reject(code: str, detail: str, edit: SourceEdit, *, policy: bool = False) -> None:
    raise EditConstructionError(
        WorkflowFailure(
            category="POLICY_DENIAL" if policy else "SOURCE_MISMATCH",
            code=code,
            detail=detail,
            path=edit.path,
            line=edit.start_line,
            retryable=not policy,
        )
    )


def compile_edits(
    proposal: EditProposal,
    artifacts: list[InspectionArtifact],
    sources: dict[str, str],
    allowed_paths: set[str],
) -> tuple[PatchCandidate, list[EditReceipt]]:
    """Compile from verified bytes; no fuzzy matching, placeholder substitution, or model hash authority."""
    inspected = {item.locator: item for item in artifacts if item.kind == "FILE" and not item.truncated}
    sources = dict(sources)
    created: set[str] = set()
    grouped: dict[str, list[SourceEdit]] = defaultdict(list)
    for edit in proposal.edits:
        relative = PurePosixPath(edit.path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or ".git" in relative.parts
            or "\\" in edit.path
            or "\x00" in edit.path
            or relative.as_posix() != edit.path
            or edit.path not in allowed_paths
        ):
            _reject("EDIT_SCOPE_DENIED", "Edit path is outside the reviewed plan or is unsafe.", edit, policy=True)
        if edit.create:
            if (
                edit.path in sources
                or edit.path in inspected
                or not any(a.kind == "TREE" and not a.truncated for a in artifacts)
                or edit.start_line != 1
                or edit.end_line != 1
                or edit.expected_content
                or edit.base_content_digest != digest("")
            ):
                _reject(
                    "INVALID_FILE_CREATION",
                    "New files require reviewed scope, an inspected tree and an exact empty base.",
                    edit,
                )
            sources[edit.path] = ""
            inspected[edit.path] = source_artifact(edit.path, "")
            created.add(edit.path)
        if edit.path not in inspected or edit.path not in sources:
            _reject("UNINSPECTED_SOURCE", "Inspect the complete immutable file before editing it.", edit)
        grouped[edit.path].append(edit)
    diffs: list[str] = []
    receipts: list[EditReceipt] = []
    for path, edits in sorted(grouped.items()):
        original = sources[path]
        projected = source_artifact(path, original)
        artifact = inspected[path]
        lines = original.splitlines(keepends=True)
        visible = projected.content.splitlines(keepends=True)
        candidate = list(lines)
        ordered = sorted(edits, key=lambda edit: (edit.start_line, edit.end_line))
        previous_end = 0
        previous_start = 0
        for edit in ordered:
            if artifact != projected or edit.base_content_digest != digest(original):
                _reject(
                    "SOURCE_DIGEST_MISMATCH",
                    f"For {edit.path}, copy base_content_digest exactly: {digest(original)}. "
                    "Do not use the redacted-view digest; protected lines make it different.",
                    edit,
                )
            if not 1 <= edit.start_line <= edit.end_line <= len(lines) + 1:
                _reject(
                    "SOURCE_RANGE_MISMATCH", f"Use inclusive start and exclusive end in [1,{len(lines) + 1}].", edit
                )
            if edit.start_line < previous_end or edit.start_line == previous_start:
                _reject("OVERLAPPING_EDITS", "Source edit ranges must not overlap or share an insertion point.", edit)
            actual = visible[edit.start_line - 1 : edit.end_line - 1]
            if "".join(actual) != edit.expected_content:
                expected_lines = edit.expected_content.splitlines(keepends=True)
                index = next(
                    (
                        i
                        for i in range(max(len(actual), len(expected_lines)))
                        if (actual[i] if i < len(actual) else None)
                        != (expected_lines[i] if i < len(expected_lines) else None)
                    ),
                    0,
                )
                authoritative = repr(actual[index])[:1000] if index < len(actual) else "<end of range>"
                _reject(
                    "SOURCE_RANGE_MISMATCH",
                    f"expected_content differs at source line {edit.start_line + index}. "
                    f"The inspected line is {authoritative}; copy whitespace and newlines exactly. "
                    f"Range [{edit.start_line},{edit.end_line}) contains {len(actual)} lines.",
                    edit,
                )
            if any(
                span.start_line >= edit.start_line - 3 and span.start_line <= edit.end_line + 2
                for span in projected.protected_spans
            ):
                _reject(
                    "PROTECTED_SOURCE",
                    "Edit or diff context intersects protected source; narrow the edit.",
                    edit,
                    policy=True,
                )
            if "[REDACTED]" in edit.replacement or "[PROTECTED SOURCE]" in edit.replacement:
                _reject("PLACEHOLDER_EDIT", "Replacement contains a redaction placeholder.", edit)
            if edit.replacement and not edit.replacement.endswith("\n") and edit.end_line <= len(lines):
                _reject("EDIT_NEWLINE", "Replacement before another line must end with a newline.", edit)
            previous_end, previous_start = edit.end_line, edit.start_line
        for edit in reversed(ordered):
            candidate[edit.start_line - 1 : edit.end_line - 1] = edit.replacement.splitlines(keepends=True)
        updated = "".join(candidate)
        if updated == original:
            _reject("EMPTY_EDIT", "Proposal does not change the inspected source.", ordered[0])
        # Git's no-newline marker is required when either file lacks a trailing newline.
        diff = difflib.unified_diff(
            lines, updated.splitlines(keepends=True), "/dev/null" if path in created else f"a/{path}", f"b/{path}"
        )
        if path in created:
            diffs.append(f"diff --git a/{path} b/{path}\nnew file mode 100644\n")
        diffs.append(
            "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in diff)
        )
        receipts.append(
            EditReceipt(
                path=path,
                base_content_digest=digest(original),
                candidate_content_digest=digest(updated),
                edited_ranges=[(edit.start_line, edit.end_line) for edit in ordered],
            )
        )
    return PatchCandidate(
        unified_diff="".join(diffs),
        rationale=proposal.rationale,
        proposed_validation_tasks=proposal.proposed_validation_tasks,
    ), receipts
