"""Patch, path, command, prompt-injection, and redaction policy tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from remediation_agent.adapters.evidence import SecretRedactor
from remediation_agent.domain.enums import PolicyDecision, RepositoryProvider
from remediation_agent.domain.models import RepositoryRef
from remediation_agent.policy.engine import PolicyEngine
from remediation_agent.policy.loader import load_policy
from tests.conftest import patch_for


@pytest.fixture
def policy() -> PolicyEngine:
    return PolicyEngine(load_policy(Path(__file__).parents[2] / "config" / "policies" / "reference.json"))


def test_demo_policy_is_exactly_scoped_and_reference_writes_stay_disabled() -> None:
    policy_root = Path(__file__).parents[2] / "config" / "policies"
    reference = load_policy(policy_root / "reference.json")
    demo = load_policy(policy_root / "demo.json")

    assert reference.github.writes_enabled is False
    assert demo.github.writes_enabled is True
    assert reference.repositories.allowed_providers == ["GITHUB"]
    assert demo.repositories.allowed_providers == ["GITHUB"]
    assert demo.repositories.allowed_url_patterns == [
        "https://github.com/MtechSE-ArchAI-Team7/buggy-ecommerce-demo.git"
    ]
    assert demo.default_validation_tasks == ["javascript_syntax", "average_regression"]


def test_demo_policy_is_bounded_to_the_ecommerce_scenario() -> None:
    policy_root = Path(__file__).parents[2] / "config" / "policies"
    policy = PolicyEngine(load_policy(policy_root / "demo.json"))
    allowed = RepositoryRef(
        provider=RepositoryProvider.GITHUB,
        url="https://github.com/MtechSE-ArchAI-Team7/buggy-ecommerce-demo.git",
        base_branch="main",
        commit_sha="ae4d89601a5b858994ec88695d8c624ebc510750",
    )
    policy.validate_repository(allowed)

    old_repository = allowed.model_copy(
        update={"url": "https://github.com/MtechSE-ArchAI-Team7/aios-remediation-demo.git"}
    )
    with pytest.raises(ValueError, match="not allowed"):
        policy.validate_repository(old_repository)

    assert policy.classify_path("server.js") is PolicyDecision.ALLOW
    assert policy.classify_path("lib/calculate-average.js") is PolicyDecision.ALLOW
    assert policy.classify_path("tests/calculate-average.test.js") is PolicyDecision.ALLOW
    assert policy.classify_path("package.json") is PolicyDecision.REQUIRE_APPROVAL
    assert policy.classify_path(".github/workflows/deploy.yml") is PolicyDecision.REQUIRE_APPROVAL
    assert policy.classify_path(".env") is PolicyDecision.DENY


def test_demo_policy_selects_only_fixed_node_validation_tasks() -> None:
    policy = PolicyEngine(load_policy(Path(__file__).parents[2] / "config" / "policies" / "demo.json"))

    selected = policy.select_validation_tasks(
        ["rm -rf /", "average_regression"],
        ["server.js", "lib/calculate-average.js", "tests/calculate-average.test.js"],
    )

    assert selected == ["javascript_syntax", "average_regression"]
    assert policy.validation_task("javascript_syntax").argv == ["node", "--check", "server.js"]
    assert policy.validation_task("average_regression").argv == [
        "node",
        "--test",
        "tests/calculate-average.test.js",
    ]


@pytest.mark.parametrize(
    ("diff", "control"),
    [
        (patch_for(".env"), "FORBIDDEN_PATH"),
        ("--- /etc/passwd\n+++ /etc/passwd\n@@ -1 +1 @@\n-x\n+y\n", "PATH_CANONICALIZATION"),
        ("GIT binary patch\n", "PATCH_UNSUPPORTED_FEATURE"),
        (patch_for("src/auth.py", new="auth_required = false"), "SECURITY_WEAKENING"),
        ("", "PATCH_EMPTY"),
    ],
)
def test_unsafe_patches_are_denied(policy: PolicyEngine, diff: str, control: str) -> None:
    result = policy.preflight_patch(diff)
    assert result.decision is PolicyDecision.DENY
    assert control in result.control_ids


def test_dependency_change_requires_diff_bound_approval(policy: PolicyEngine) -> None:
    result = policy.preflight_patch(patch_for("pyproject.toml", old='name = "old"', new='name = "new"'))
    assert result.decision is PolicyDecision.REQUIRE_APPROVAL
    assert result.scope_digest.startswith("sha256:")


def test_test_content_removal_requires_approval(policy: PolicyEngine) -> None:
    result = policy.preflight_patch(patch_for("tests/test_app.py", old="assert result == 1", new="result == 1"))
    assert result.decision is PolicyDecision.REQUIRE_APPROVAL
    assert "TEST_WEAKENING_APPROVAL" in result.control_ids


def test_unknown_model_task_is_never_resolved_to_a_command(policy: PolicyEngine) -> None:
    selected = policy.select_validation_tasks(["rm -rf /", "unit_tests"], ["src/app.py"])
    assert selected == ["unit_tests"]
    with pytest.raises(ValueError, match="unknown validation task"):
        policy.validation_task("rm -rf /")


def test_path_traversal_is_rejected(policy: PolicyEngine) -> None:
    with pytest.raises(ValueError, match="unsafe repository path"):
        policy.classify_path("../../outside")


def test_secret_redactor_masks_common_credentials() -> None:
    raw = (
        "token=super-secret AKIA1234567890ABCDEF ghp_abcdefghijklmnopqrstuvwxyz "
        "github_pat_abcdefghijklmnopqrstuvwxyz123456 /Users/alice/project"
    )
    redacted = SecretRedactor().redact(raw)
    assert "super-secret" not in redacted
    assert "AKIA1234567890ABCDEF" not in redacted
    assert "ghp_" not in redacted
    assert "github_pat_" not in redacted
    assert "/Users/alice" not in redacted
