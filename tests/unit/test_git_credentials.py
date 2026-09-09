"""Git credential isolation and exact-host validation tests."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from remediation_agent.adapters.credentials import GitHubAskpassCredentialProvider, NoGitCredentials
from remediation_agent.adapters.repository import LocalGitRepository, RepositoryError
from remediation_agent.domain.enums import RepositoryProvider
from remediation_agent.domain.models import RepositoryRef


def test_github_credentials_are_scoped_to_exact_https_host() -> None:
    token = "github_pat_" + "a" * 32
    provider = GitHubAskpassCredentialProvider(token)

    environment = provider.environment_for("https://github.com/example/demo.git")

    assert environment["AIOS_GIT_ASKPASS_USERNAME"] == "x-access-token"
    assert environment["AIOS_GIT_ASKPASS_PASSWORD"] == token
    assert token not in environment["GIT_ASKPASS"]
    askpass_path = Path(environment["GIT_ASKPASS"])
    assert askpass_path.is_file()
    assert stat.S_IMODE(askpass_path.stat().st_mode) == 0o700
    assert token not in askpass_path.read_text(encoding="utf-8")
    assert provider.environment_for("file:///tmp/demo") == {}
    for unsafe in (
        "http://github.com/example/demo.git",
        "https://github.com.evil.invalid/example/demo.git",
        "https://user@github.com/example/demo.git",
        "https://github.com:443/example/demo.git",
        "ssh://git@github.com/example/demo.git",
    ):
        with pytest.raises(ValueError, match="authenticated Git remote"):
            provider.environment_for(unsafe)
    provider.close()
    assert not askpass_path.exists()


def test_askpass_launcher_is_a_real_executable() -> None:
    token = "test-" + "token-value"
    provider = GitHubAskpassCredentialProvider(token)
    environment = os.environ | provider.environment_for("https://github.com/example/demo.git")

    result = subprocess.run(  # noqa: S603 - the test resolves a provider-created fixed executable
        [environment["GIT_ASKPASS"], "Username for 'https://github.com':"],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == "x-access-token"
    assert token not in result.stderr
    provider.close()


def test_no_credentials_provider_never_adds_environment() -> None:
    provider = NoGitCredentials()
    assert provider.environment_for("https://github.com/example/public.git") == {}
    assert provider.redact("unchanged") == "unchanged"


def test_askpass_returns_only_the_requested_value(monkeypatch: pytest.MonkeyPatch) -> None:
    from remediation_agent.adapters import git_askpass

    monkeypatch.setenv("AIOS_GIT_ASKPASS_USERNAME", "x-access-token")
    monkeypatch.setenv("AIOS_GIT_ASKPASS_PASSWORD", "test-token")
    monkeypatch.setattr(sys, "argv", ["git_askpass", "Username for github.com:"])
    assert git_askpass.main() == 0
    monkeypatch.setattr(sys, "argv", ["git_askpass", "Unknown prompt"])
    assert git_askpass.main() == 1


async def test_repository_redacts_token_echoed_by_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    token = "github_pat_" + "z" * 32
    fake_git = tmp_path / "git"
    fake_git.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "sys.stderr.write('argv=' + repr(sys.argv) + ' token=' + os.environ.get('AIOS_GIT_ASKPASS_PASSWORD', ''))\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path))
    repository = LocalGitRepository(
        tmp_path / "workspaces",
        credential_provider=GitHubAskpassCredentialProvider(token),
    )

    with pytest.raises(RepositoryError) as captured:
        await repository.create_workspace(
            RepositoryRef(
                provider=RepositoryProvider.GITHUB,
                url="https://github.com/example/private-demo.git",
                base_branch="main",
                commit_sha="a" * 40,
            )
        )

    message = str(captured.value)
    assert token not in message
    assert "[REDACTED]" in message
    assert "https://github.com/example/private-demo.git" in message
    assert not any((tmp_path / "workspaces").iterdir())


def test_base_git_environment_disables_ambient_credentials() -> None:
    environment = LocalGitRepository._git_environment()
    assert environment["GIT_ASKPASS"] == "/bin/false"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GIT_CONFIG_VALUE_0"] == ""
    assert "AIOS_GITHUB_TOKEN" not in environment
    assert "GITHUB_TOKEN" not in environment
    assert os.environ.get("AIOS_GITHUB_TOKEN") not in environment.values()
