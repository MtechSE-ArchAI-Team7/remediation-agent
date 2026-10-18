"""Failure cases that must not become a green release gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci_reports import check_junit, check_scan, main, scan_findings, summarize


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_dependency_findings_block_release(tmp_path: Path, severity: str) -> None:
    path = tmp_path / "scan.json"
    path.write_text(json.dumps({"ok": False, "vulnerabilities": [{"severity": severity}]}))
    with pytest.raises(ValueError, match="findings block"):
        check_scan("snyk-open-source", path, 1)


def test_lower_findings_are_retained_without_blocking(tmp_path: Path) -> None:
    data = {"vulnerabilities": [{"severity": "low"}, {"severity": "medium"}]}
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(data))
    check_scan("snyk-open-source", path, 1)
    assert scan_findings("snyk-open-source", data) == {"low": 1, "medium": 1}


@pytest.mark.parametrize("status", [2, 3, 127, -1])
def test_scanner_errors_never_pass(tmp_path: Path, status: int) -> None:
    with pytest.raises(ValueError, match="execution failed"):
        check_scan("snyk-code", tmp_path / "missing", status)


@pytest.mark.parametrize(
    "kind,data",
    [
        ("snyk-open-source", {}),
        ("snyk-open-source", []),
        ("snyk-open-source", {"error": "unauthorized"}),
        ("snyk-open-source", {"vulnerabilities": [{"severity": "new-level"}]}),
        ("snyk-code", {"runs": []}),
        ("snyk-code", {"runs": [{"results": [{"level": "unknown"}]}]}),
        ("snyk-code", {"runs": [{"invocations": [{"executionSuccessful": False}], "results": []}]}),
        ("trivy", {"SchemaVersion": 2, "ArtifactName": "image", "Results": []}),
        ("trivy", {"SchemaVersion": 1}),
    ],
)
def test_missing_or_invalid_analysis_is_not_clean(kind: str, data: object) -> None:
    with pytest.raises(ValueError):
        scan_findings(kind, data)


def test_sast_severity_and_multiple_dependency_projects() -> None:
    assert scan_findings("snyk-code", {"runs": [{"results": [{"level": "error"}, {"level": "warning"}]}]}) == {
        "high": 1,
        "medium": 1,
    }
    assert scan_findings(
        "snyk-open-source", [{"vulnerabilities": []}, {"vulnerabilities": [{"severity": "critical"}]}]
    ) == {"critical": 1}
    assert not scan_findings("snyk-code", {"runs": [{"results": []}]})


def test_container_scan_includes_unfixed_findings(tmp_path: Path) -> None:
    report = {
        "SchemaVersion": 2,
        "ArtifactName": "image",
        "Results": [{"Vulnerabilities": [{"Severity": "HIGH", "FixedVersion": ""}]}],
    }
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="findings block"):
        check_scan("trivy", path, 0)


def test_clean_exit_still_requires_report_and_failure_requires_findings(tmp_path: Path) -> None:
    path = tmp_path / "scan.json"
    with pytest.raises(ValueError, match="Missing"):
        check_scan("snyk-code", path, 0)
    path.write_text('{"runs": [{"results": []}]}')
    check_scan("snyk-code", path, 0)
    with pytest.raises(ValueError, match="without finding"):
        check_scan("snyk-code", path, 1)


@pytest.mark.parametrize("content", ["", "<skipped/>", "<failure/>", "<error/>"])
def test_integration_requires_executed_successful_tests(tmp_path: Path, content: str) -> None:
    report = tmp_path / "tests.xml"
    report.write_text(f"<testsuites><testsuite><testcase>{content}</testcase></testsuite></testsuites>")
    if content:
        with pytest.raises(ValueError, match="failed or skipped"):
            check_junit(report)
    else:
        check_junit(report)


@pytest.mark.parametrize("content", ["<testsuites/>", '<!DOCTYPE x [<!ENTITY e "bad">]><x/>'])
def test_empty_and_entity_reports_fail(tmp_path: Path, content: str) -> None:
    report = tmp_path / "tests.xml"
    report.write_text(content)
    with pytest.raises(ValueError):
        check_junit(report)


@pytest.mark.parametrize("outcome", ["success", "failure", "cancelled", "skipped", "missing"])
def test_aggregate_checks_each_required_stage(tmp_path: Path, outcome: str) -> None:
    summary = tmp_path / "summary.md"
    jobs = {"tests": {"result": "success"}}
    if outcome != "missing":
        jobs["scan"] = {"result": outcome}
    assert summarize(jobs, ["tests", "scan"], summary) == (outcome == "success")
    assert outcome in summary.read_text()


def test_cli_returns_failure_without_echoing_secret_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "scan.json"
    path.write_text('{"error":"credential-value"}')
    monkeypatch.setattr("sys.argv", ["ci_reports", "scan", "snyk-code", str(path), "0"])
    assert main() == 1
