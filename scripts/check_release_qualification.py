"""Fail closed before UpdateAgentRuntime unless both immutable-image trials qualify."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from remediation_agent.domain.qualification import ReleaseQualificationV1, require_release_qualification
from scripts.qualification_environment import runtime_digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    digest = runtime_digest(json.loads(args.runtime.read_text()))
    reports = []
    for case in ("ah54", "ah56"):
        candidates = list(args.evidence.rglob(case + "-qualification.json"))
        if len(candidates) != 1 or candidates[0].stat().st_size > 100_000:
            raise ValueError("RELEASE_QUALIFICATION_ABSENT_OR_AMBIGUOUS")
        report = ReleaseQualificationV1.model_validate_json(candidates[0].read_text())
        if report.case != case or not timedelta(0) <= datetime.now(UTC) - report.qualified_at <= timedelta(hours=24):
            raise ValueError("RELEASE_QUALIFICATION_STALE")
        require_release_qualification(report, source=args.source, image=args.image, runtime_configuration=digest)
        reports.append(report)
    for field in ("policy_digest", "assets_digest", "model_configuration_digest", "prompt_version"):
        if getattr(reports[0], field) != getattr(reports[1], field):
            raise ValueError("RELEASE_QUALIFICATION_INPUT_MISMATCH")
    print("Six complete hosted workflow trials qualify this immutable image and runtime configuration.")


if __name__ == "__main__":
    main()
