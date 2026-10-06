"""Regression proof for the AH-56 source projection and deterministic edit boundary."""

import subprocess
from pathlib import Path

import pytest

from remediation_agent.domain.models import EditProposal, SourceEdit
from remediation_agent.source import EditConstructionError, compile_edits, digest, source_artifact


def proposal(source: str, replacement_text: str, **updates: object) -> EditProposal:
    edit = SourceEdit.model_validate(
        {
            "path": "public/app.js",
            "base_content_digest": digest(source),
            "start_line": 1,
            "end_line": len(source.splitlines()) + 1,
            "expected_content": source,
            "replacement": replacement_text,
            **updates,
        }
    )
    return EditProposal(edits=[edit], rationale="Await the real response.")


def test_non_secret_token_reference_remains_exact_source_and_patch_applies(tmp_path: Path) -> None:
    source = "const response = fetch('/checkout', {body: JSON.stringify({cart, token: userToken})});\n"
    fixed = source.replace("= fetch", "= await fetch")
    artifact = source_artifact("public/app.js", source)
    assert artifact.content == source
    candidate, receipts = compile_edits(
        proposal(source, fixed), [artifact], {artifact.locator: source}, {artifact.locator}
    )
    (tmp_path / "public").mkdir()
    (tmp_path / "public/app.js").write_text(source)
    result = subprocess.run(
        ["git", "apply", "--check", "-"],  # noqa: S607 - fixed test-only Git command
        cwd=tmp_path,
        input=candidate.unified_diff,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert receipts[0].candidate_content_digest == digest(fixed)


def test_actual_secret_values_are_protected_with_source_locations() -> None:
    source = "const secret_key = 'fixture-sensitive-value';\nconst token = userToken;\n"
    artifact = source_artifact("public/app.js", source)
    assert "fixture-sensitive-value" not in artifact.content
    assert "const token = userToken" in artifact.content
    assert artifact.protected_spans[0].start_line == 1
    with pytest.raises(EditConstructionError):
        compile_edits(
            proposal(source, "// removed\n", expected_content=artifact.content),
            [artifact],
            {artifact.locator: source},
            {artifact.locator},
        )


def test_redacted_view_digest_gets_exact_base_digest_correction_without_secret() -> None:
    source = "const secret_key = 'fixture-sensitive-value';\n" + "\n" * 4 + "let result = false;\n"
    artifact = source_artifact("public/app.js", source)
    assert artifact.digest != artifact.base_content_digest
    with pytest.raises(EditConstructionError) as caught:
        compile_edits(
            proposal(
                source,
                "let result = true;\n",
                start_line=6,
                end_line=7,
                expected_content="let result = false;\n",
                base_content_digest=artifact.digest,
            ),
            [artifact],
            {artifact.locator: source},
            {artifact.locator},
        )
    assert caught.value.failure.code == "SOURCE_DIGEST_MISMATCH"
    assert digest(source) in caught.value.failure.detail
    assert "fixture-sensitive-value" not in caught.value.failure.detail


def test_member_expressions_survive_but_unquoted_configuration_secrets_do_not() -> None:
    source = "const options = {token: user.token, password: process.env.PASSWORD};\n"
    assert source_artifact("app.js", source).content == source
    assert "sensitive-fixture" not in source_artifact("app.yaml", "password: sensitive-fixture\n").content


def test_large_identifiers_are_bounded_and_do_not_look_like_secrets() -> None:
    source = "a" * 100_000 + "\n"
    assert source_artifact("app.js", source).content == source


@pytest.mark.parametrize(
    "updates",
    [
        {"base_content_digest": "sha256:" + "0" * 64},
        {"start_line": 2},
        {"expected_content": "wrong\n"},
        {"replacement": "[REDACTED]\n"},
        {"path": "../outside.js"},
    ],
)
def test_stale_uninspected_or_placeholder_edits_cannot_become_a_patch(updates: dict[str, object]) -> None:
    source = "const response = fetch('/checkout');\n"
    artifact = source_artifact("public/app.js", source)
    with pytest.raises(EditConstructionError):
        compile_edits(
            proposal(source, "const response = await fetch('/checkout');\n", **updates),
            [artifact],
            {artifact.locator: source},
            {artifact.locator},
        )


def test_overlapping_edits_rejected() -> None:
    source = "one\ntwo\n"
    proposed = proposal(source, "fixed\n")
    proposed = proposed.model_copy(update={"edits": proposed.edits * 2})
    artifact = source_artifact("public/app.js", source)
    with pytest.raises(EditConstructionError):
        compile_edits(proposed, [artifact], {artifact.locator: source}, {artifact.locator})
