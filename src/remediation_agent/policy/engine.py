"""Deterministic remediation policy decisions."""

from __future__ import annotations

import fnmatch
import hashlib
import re
from pathlib import PurePosixPath

from unidiff import PatchSet  # type: ignore[attr-defined]
from unidiff.errors import UnidiffParseError

from remediation_agent.domain.enums import PolicyDecision, RiskLevel
from remediation_agent.domain.models import (
    DiagnosisHandoffV1,
    PatchPolicyResult,
    RemediationPlan,
    RepositoryRef,
    RiskAssessment,
    RiskFinding,
)
from remediation_agent.policy.models import PolicyConfig, ValidationTaskConfig

_UNSAFE_SECURITY_PATTERNS = (
    re.compile(r"\bdisable(?:d|s|ing)?\s+(?:all\s+)?auth(?:entication|orization)?\b", re.IGNORECASE),
    re.compile(r"\bremove\s+(?:the\s+)?auth(?:entication|orization)?\b", re.IGNORECASE),
    re.compile(r"\bbypass\s+(?:the\s+)?(?:security|auth|permission)", re.IGNORECASE),
    re.compile(r"\bpermit[_ -]?all\b", re.IGNORECASE),
    re.compile(r"\bauth_required\s*[=:]\s*false\b", re.IGNORECASE),
    re.compile(r"\bverify\s*[=:]\s*false\b", re.IGNORECASE),
)

_UNSUPPORTED_DIFF_MARKERS = (
    "GIT binary patch",
    "Binary files ",
    "new file mode 120000",
    "old mode ",
    "new mode ",
    "Subproject commit ",
    "rename from ",
    "rename to ",
)

_RISK_RANK = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.PROHIBITED: 3,
}


class PolicyEngine:
    """Evaluate plans, patches, paths, and named validation tasks."""

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    @staticmethod
    def normalize_path(raw_path: str) -> str:
        if "\x00" in raw_path:
            raise ValueError("path contains NUL")
        path = raw_path.replace("\\", "/")
        if path.startswith(("a/", "b/")):
            path = path[2:]
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise ValueError(f"unsafe repository path: {raw_path}")
        normalized = pure.as_posix()
        if normalized in {".", "/dev/null"}:
            raise ValueError(f"unsafe repository path: {raw_path}")
        return normalized

    def classify_path(self, path: str) -> PolicyDecision:
        normalized = self.normalize_path(path)
        if self._matches_any(normalized, self.config.paths.forbidden):
            return PolicyDecision.DENY
        if self._matches_any(normalized, self.config.paths.approval_required):
            return PolicyDecision.REQUIRE_APPROVAL
        if self._matches_any(normalized, self.config.paths.autonomous):
            return PolicyDecision.ALLOW
        return PolicyDecision.REQUIRE_APPROVAL

    def validate_repository(self, repository: RepositoryRef) -> None:
        rules = self.config.repositories
        if repository.provider.value not in rules.allowed_providers:
            raise ValueError(f"repository provider is not allowed by operator policy: {repository.provider}")
        if not self._matches_any(repository.url, rules.allowed_url_patterns):
            raise ValueError("repository URL is not allowed by operator policy")

    def assess_plan(
        self,
        handoff: DiagnosisHandoffV1,
        plan: RemediationPlan,
        model_assessment: RiskAssessment,
    ) -> RiskAssessment:
        findings = list(model_assessment.findings)
        level = model_assessment.level
        decision = model_assessment.decision
        combined_text = "\n".join(
            [handoff.issue_summary, handoff.diagnosis.summary, plan.summary, *plan.steps, plan.rollback_strategy]
        )

        if self._contains_security_weakening(combined_text):
            findings.append(
                RiskFinding(
                    code="SECURITY_WEAKENING",
                    level=RiskLevel.PROHIBITED,
                    summary="The proposed remediation weakens or bypasses an authentication or security control.",
                    evidence_ids=handoff.diagnosis.evidence_ids,
                )
            )
            level = RiskLevel.PROHIBITED
            decision = PolicyDecision.DENY

        for target in plan.target_paths:
            try:
                path_decision = self.classify_path(target)
            except ValueError:
                path_decision = PolicyDecision.DENY
            if path_decision is PolicyDecision.DENY:
                findings.append(
                    RiskFinding(
                        code="FORBIDDEN_PLAN_PATH",
                        level=RiskLevel.PROHIBITED,
                        summary=f"Plan targets forbidden or unsafe path: {target}",
                    )
                )
                level = RiskLevel.PROHIBITED
                decision = PolicyDecision.DENY
            elif path_decision is PolicyDecision.REQUIRE_APPROVAL and decision is not PolicyDecision.DENY:
                findings.append(
                    RiskFinding(
                        code="SENSITIVE_PLAN_PATH",
                        level=RiskLevel.HIGH,
                        summary=f"Plan targets a path that requires approval: {target}",
                    )
                )
                level = self._higher_level(level, RiskLevel.HIGH)
                decision = PolicyDecision.REQUIRE_APPROVAL

        if handoff.diagnosis.contradictions or handoff.diagnosis.unresolved_questions:
            findings.append(
                RiskFinding(
                    code="UNRESOLVED_DIAGNOSIS",
                    level=RiskLevel.HIGH,
                    summary="The diagnosis contains contradictions or unresolved questions.",
                    evidence_ids=handoff.diagnosis.evidence_ids,
                )
            )
            level = self._higher_level(level, RiskLevel.HIGH)
            if decision is not PolicyDecision.DENY:
                decision = PolicyDecision.REQUIRE_APPROVAL

        if any(item.scope == "POST_DEPLOYMENT" for item in plan.verification):
            findings.append(
                RiskFinding(
                    code="POST_DEPLOYMENT_VERIFICATION",
                    level=RiskLevel.MEDIUM,
                    summary="Deferred acceptance checks require Agent 4 verification after deployment.",
                )
            )
            if decision is not PolicyDecision.DENY:
                decision = PolicyDecision.REQUIRE_APPROVAL
                level = self._higher_level(level, RiskLevel.MEDIUM)

        if level is RiskLevel.PROHIBITED:
            decision = PolicyDecision.DENY
        elif level in {RiskLevel.HIGH, RiskLevel.MEDIUM} and decision is PolicyDecision.ALLOW:
            decision = PolicyDecision.REQUIRE_APPROVAL

        rationale = "; ".join(item.summary for item in findings) or model_assessment.rationale
        return RiskAssessment(level=level, decision=decision, findings=findings, rationale=rationale)

    def preflight_patch(self, unified_diff: str) -> PatchPolicyResult:
        digest = self.digest_text(unified_diff)
        reasons: list[str] = []
        controls: list[str] = []

        if any(marker in unified_diff for marker in _UNSUPPORTED_DIFF_MARKERS):
            return PatchPolicyResult(
                decision=PolicyDecision.DENY,
                risk_level=RiskLevel.PROHIBITED,
                changed_files=[],
                changed_lines=0,
                reasons=["Patch uses binary, symlink, mode, submodule, or rename features that are not supported."],
                control_ids=["PATCH_UNSUPPORTED_FEATURE"],
                scope_digest=digest,
            )

        try:
            patch_set = PatchSet(unified_diff.splitlines(keepends=True))
        except (UnidiffParseError, ValueError) as exc:
            return PatchPolicyResult(
                decision=PolicyDecision.DENY,
                risk_level=RiskLevel.PROHIBITED,
                changed_files=[],
                changed_lines=0,
                reasons=[f"Patch is not valid unified diff: {exc}"],
                control_ids=["PATCH_PARSE"],
                scope_digest=digest,
            )

        changed_files: list[str] = []
        changed_lines = 0
        decision = PolicyDecision.ALLOW
        risk = RiskLevel.LOW

        for patched_file in patch_set:
            source_path = str(patched_file.source_file)
            target_path = str(patched_file.target_file)
            material_paths = [path for path in (source_path, target_path) if path != "/dev/null"]
            normalized_paths: list[str] = []
            try:
                normalized_paths = [self.normalize_path(path) for path in material_paths]
            except ValueError as exc:
                reasons.append(str(exc))
                controls.append("PATH_CANONICALIZATION")
                decision = PolicyDecision.DENY
                risk = RiskLevel.PROHIBITED
                continue
            if len(set(normalized_paths)) > 1:
                reasons.append("Patch changes source and target paths; renames are not supported.")
                controls.append("PATCH_PATH_CHANGE")
                decision = PolicyDecision.DENY
                risk = RiskLevel.PROHIBITED
                continue
            path = normalized_paths[0]
            changed_files.append(path)
            path_decision = self.classify_path(path)
            if path_decision is PolicyDecision.DENY:
                reasons.append(f"Patch targets forbidden path: {path}")
                controls.append("FORBIDDEN_PATH")
                decision = PolicyDecision.DENY
                risk = RiskLevel.PROHIBITED
            elif path_decision is PolicyDecision.REQUIRE_APPROVAL and decision is not PolicyDecision.DENY:
                reasons.append(f"Patch target requires approval: {path}")
                controls.append("PATH_APPROVAL")
                decision = PolicyDecision.REQUIRE_APPROVAL
                risk = self._higher_level(risk, RiskLevel.HIGH)
            changed_lines += int(patched_file.added) + int(patched_file.removed)
            if patched_file.is_removed_file and decision is not PolicyDecision.DENY:
                reasons.append(f"File deletion requires approval: {path}")
                controls.append("FILE_DELETION_APPROVAL")
                decision = PolicyDecision.REQUIRE_APPROVAL
                risk = self._higher_level(risk, RiskLevel.HIGH)
            if (
                self._matches_any(path, ["tests/**", "test/**", "**/tests/**", "**/test_*.py"])
                and int(patched_file.removed) > 0
                and decision is not PolicyDecision.DENY
            ):
                reasons.append(f"Removing test content requires approval: {path}")
                controls.append("TEST_WEAKENING_APPROVAL")
                decision = PolicyDecision.REQUIRE_APPROVAL
                risk = self._higher_level(risk, RiskLevel.HIGH)

        if not changed_files:
            reasons.append("Patch does not modify any files.")
            controls.append("PATCH_EMPTY")
            decision = PolicyDecision.DENY
            risk = RiskLevel.PROHIBITED

        unique_files = sorted(set(changed_files))
        limits = self.config.limits
        if len(unique_files) > limits.absolute_max_changed_files or changed_lines > limits.absolute_max_diff_lines:
            reasons.append("Patch exceeds an absolute file or diff-size limit.")
            controls.append("ABSOLUTE_DIFF_LIMIT")
            decision = PolicyDecision.DENY
            risk = RiskLevel.PROHIBITED
        elif (
            len(unique_files) > limits.autonomous_max_changed_files or changed_lines > limits.autonomous_max_diff_lines
        ) and decision is not PolicyDecision.DENY:
            reasons.append("Patch exceeds an autonomous file or diff-size limit.")
            controls.append("AUTONOMOUS_DIFF_LIMIT")
            decision = PolicyDecision.REQUIRE_APPROVAL
            risk = self._higher_level(risk, RiskLevel.HIGH)

        if self._contains_security_weakening(unified_diff):
            reasons.append("Patch contains a known authentication or security-control weakening pattern.")
            controls.append("SECURITY_WEAKENING")
            decision = PolicyDecision.DENY
            risk = RiskLevel.PROHIBITED

        if not reasons:
            reasons.append("Patch is within configured autonomous policy.")
            controls.append("PATCH_ALLOWED")

        return PatchPolicyResult(
            decision=decision,
            risk_level=risk,
            changed_files=unique_files,
            changed_lines=changed_lines,
            reasons=reasons,
            control_ids=controls,
            scope_digest=digest,
        )

    def select_validation_tasks(self, proposed: list[str], changed_files: list[str]) -> list[str]:
        selected = set(self.config.default_validation_tasks)
        selected.update(name for name in proposed if name in self.config.validation_tasks)
        for rule in self.config.mandatory_tasks:
            if any(self._matches_any(path, rule.path_patterns) for path in changed_files):
                selected.update(rule.task_names)
        return [name for name in self.config.validation_tasks if name in selected]

    def validation_task(self, name: str) -> ValidationTaskConfig:
        try:
            return self.config.validation_tasks[name]
        except KeyError as exc:
            raise ValueError(f"unknown validation task: {name}") from exc

    @staticmethod
    def digest_text(value: str) -> str:
        return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _matches_any(path: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)

    @staticmethod
    def _contains_security_weakening(value: str) -> bool:
        return any(pattern.search(value) for pattern in _UNSAFE_SECURITY_PATTERNS)

    @staticmethod
    def _higher_level(left: RiskLevel, right: RiskLevel) -> RiskLevel:
        return left if _RISK_RANK[left] >= _RISK_RANK[right] else right
