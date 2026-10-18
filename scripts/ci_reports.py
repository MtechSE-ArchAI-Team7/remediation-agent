"""Fail-closed CI report checks and a bounded, secret-free job summary."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path
from typing import cast
from xml.etree import ElementTree


def mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("Expected a JSON object")
    return cast(dict[str, object], value)


def sequence(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("Expected a JSON array")
    return cast(list[object], value)


def report_path(value: str) -> Path:
    """CLI reports are runner-generated files under the checkout's reports directory."""
    root = Path.cwd() / "reports"
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    if ".." in path.parts or not path.is_relative_to(root):
        raise ValueError("Report path is outside reports directory")
    if root.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent.is_relative_to(root)):
        raise ValueError("Report symlinks are forbidden")
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Report symlinks are forbidden")
    return path


def read_json(path: Path) -> object:
    if not path.is_file() or path.stat().st_size > 50_000_000:
        raise ValueError("Missing or oversized report")
    return cast(object, json.loads(path.read_text(encoding="utf-8")))


def scan_findings(kind: str, report: object) -> Counter[str]:
    """Retain all severities while independently enforcing the release threshold."""
    counts: Counter[str] = Counter()
    documents = report if isinstance(report, list) else [report]
    if not documents:
        raise ValueError("Empty scanner response")
    for document in documents:
        data = mapping(document)
        if data.get("error") or data.get("ok") is False and "vulnerabilities" not in data:
            raise ValueError("Scanner returned an error")
        if kind == "snyk-code":
            runs = sequence(data.get("runs"))
            if not runs:
                raise ValueError("Missing SAST analysis")
            for run in runs:
                analysis = mapping(run)
                for invocation in sequence(analysis.get("invocations", [])):
                    if mapping(invocation).get("executionSuccessful") is not True:
                        raise ValueError("SAST analysis did not complete")
                for item in sequence(analysis.get("results")):
                    level = mapping(item).get("level")
                    severity = {"error": "high", "warning": "medium", "note": "low"}.get(str(level))
                    if severity is None:
                        raise ValueError("Unknown SAST severity")
                    counts[severity] += 1
        elif kind == "snyk-open-source":
            for item in sequence(data.get("vulnerabilities")):
                dependency_severity = mapping(item).get("severity")
                if dependency_severity not in ("low", "medium", "high", "critical"):
                    raise ValueError("Unknown dependency severity")
                counts[str(dependency_severity)] += 1
        elif kind == "trivy":
            if data.get("SchemaVersion") != 2 or not isinstance(data.get("ArtifactName"), str):
                raise ValueError("Invalid container scan report")
            results = sequence(data.get("Results"))
            if not results:
                raise ValueError("Container scan did not analyze any targets")
            for result in results:
                for item in sequence(mapping(result).get("Vulnerabilities") or []):
                    severity = str(mapping(item).get("Severity")).lower()
                    if severity not in ("unknown", "low", "medium", "high", "critical"):
                        raise ValueError("Unknown container severity")
                    counts[severity] += 1
        else:
            raise ValueError("Unsupported scanner")
    return counts


def check_scan(kind: str, path: Path, status: int) -> None:
    if status not in (0, 1) or kind == "trivy" and status != 0:
        raise ValueError("Scanner execution failed")
    counts = scan_findings(kind, read_json(path))
    print(json.dumps({"scanner": kind, "exit_code": status, "findings": dict(counts)}, sort_keys=True))
    if status == 1 and not counts:
        raise ValueError("Scanner failure without finding evidence")
    if counts["high"] or counts["critical"]:
        raise ValueError("High or critical findings block release")


def check_junit(path: Path) -> None:
    if not path.is_file() or path.stat().st_size > 10_000_000:
        raise ValueError("Missing or oversized test report")
    raw = path.read_bytes()
    if len(raw) > 10_000_000 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("Unsafe or oversized test report")
    root = ElementTree.fromstring(raw)  # noqa: S314 - CI-generated XML, DTD/entities rejected above.
    cases = list(root.iter("testcase"))
    if not cases:
        raise ValueError("No integration tests executed")
    if any(case.find(name) is not None for case in cases for name in ("skipped", "failure", "error")):
        raise ValueError("Integration tests failed or skipped")
    print(f"Verified {len(cases)} executed integration tests")


def summarize(results: object, required: list[str], destination: Path) -> bool:
    jobs = mapping(results)
    success = True
    lines = ["## Remediation pipeline", "", "| Stage | Result |", "| --- | --- |"]
    for name in required:
        job = mapping(jobs.get(name, {}))
        result = job.get("result", "missing")
        if result not in ("success", "failure", "cancelled", "skipped", "missing"):
            raise ValueError("Invalid job result")
        success = success and result == "success"
        lines.append(f"| {name} | {result} |")
    lines += ["", "All required stages must succeed. Reports are retained in this run's artifacts.", ""]
    with destination.open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines))
    return success


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("kind", choices=("snyk-code", "snyk-open-source", "trivy"))
    scan.add_argument("path", type=Path)
    scan.add_argument("status", type=int)
    junit = commands.add_parser("junit")
    junit.add_argument("path", type=Path)
    summary = commands.add_parser("summary")
    summary.add_argument("required", nargs="+")
    args = parser.parse_args()
    try:
        if args.command == "scan":
            check_scan(args.kind, report_path(str(args.path)), args.status)
        elif args.command == "junit":
            check_junit(report_path(str(args.path)))
        elif not summarize(
            json.loads(os.environ["JOB_RESULTS"]), args.required, Path(os.environ["GITHUB_STEP_SUMMARY"])
        ):
            return 1
    except (ValueError, OSError, KeyError, ElementTree.ParseError) as exc:
        print(f"CI evidence gate failed: {type(exc).__name__}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
