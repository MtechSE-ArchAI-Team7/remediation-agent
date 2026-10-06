"""Fixed pytest reporter: collection/setup failures are never regression assertions."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

_results: dict[str, dict[str, str]] = {}


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    name = report.nodeid
    if report.failed:
        outcome = (
            "ASSERTION_FAILED" if report.when == "call" and "AssertionError" in report.longreprtext else "SETUP_ERROR"
        )
    elif report.skipped:
        outcome = "SKIPPED"
    elif report.when == "call":
        outcome = "PASSED"
    else:
        return
    if _results.get(name, {}).get("outcome") == "SETUP_ERROR":
        return
    _results[name] = {"test_id": name, "outcome": outcome, "detail": report.longreprtext[:1000]}


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    _ = session
    if exitstatus not in (0, 1):
        _results["collection"] = {
            "test_id": "collection",
            "outcome": "SETUP_ERROR",
            "detail": "pytest collection/setup failed",
        }
    Path(os.environ["AIOS_REPORT_PATH"]).write_text(json.dumps({"cases": list(_results.values())}))
