"""Run-scoped credentials for trusted GitHub HTTPS operations."""

from __future__ import annotations

import shlex
import stat
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


class NoGitCredentials:
    """Keep local and public Git operations non-interactive and unauthenticated."""

    def environment_for(self, remote_url: str) -> dict[str, str]:
        del remote_url
        return {}

    def redact(self, value: str) -> str:
        return value


class GitHubAskpassCredentialProvider:
    """Expose one injected token only to exact-host GitHub HTTPS subprocesses."""

    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("GitHub credential token must not be empty")
        self._token = token
        self._askpass_directory = tempfile.TemporaryDirectory(prefix="aios-git-askpass-")
        self._askpass_path = Path(self._askpass_directory.name) / "askpass"
        launcher = f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -m remediation_agent.adapters.git_askpass "$@"\n'
        self._askpass_path.write_text(launcher, encoding="utf-8")
        self._askpass_path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def environment_for(self, remote_url: str) -> dict[str, str]:
        parsed = urlsplit(remote_url)
        if parsed.scheme in {"", "file"}:
            return {}
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("authenticated Git remote must use credential-free HTTPS on github.com")
        path_parts = [part for part in parsed.path.split("/") if part]
        if len(path_parts) != 2:
            raise ValueError("authenticated GitHub remote must identify exactly one owner and repository")
        return {
            "GIT_ASKPASS": str(self._askpass_path),
            "GIT_ASKPASS_REQUIRE": "force",
            "AIOS_GIT_ASKPASS_USERNAME": "x-access-token",
            "AIOS_GIT_ASKPASS_PASSWORD": self._token,
        }

    def redact(self, value: str) -> str:
        return value.replace(self._token, "[REDACTED]")

    def close(self) -> None:
        """Remove the token-free askpass launcher and its private directory."""
        self._askpass_directory.cleanup()
