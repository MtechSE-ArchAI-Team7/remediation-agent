"""OpenAPI metadata and safe representative payloads."""

from typing import Final

OPENAPI_TAGS: Final[list[dict[str, str]]] = [
    {
        "name": "Service",
        "description": "Service identity, liveness, and dependency readiness.",
    },
    {
        "name": "Remediations",
        "description": "Start, inspect, and approve bounded remediation workflow runs.",
    },
]

START_REMEDIATION_EXAMPLES: Final[dict[str, dict[str, object]]] = {
    "code_defect": {
        "summary": "Evidence-supported code defect",
        "value": {
            "schema_version": "1.0",
            "case_id": "CASE-2026-0042",
            "issue_summary": "Malformed quantity input causes an unhandled application error.",
            "remediation_type": "CODE",
            "diagnosis": {
                "summary": "The request handler does not handle non-numeric quantity input.",
                "confidence": 0.94,
                "evidence_ids": ["ev-log-42"],
                "contradictions": [],
                "unresolved_questions": [],
            },
            "supporting_evidence": [
                {
                    "evidence_id": "ev-log-42",
                    "source_type": "application_log",
                    "source_locator": "logs/api/request-42",
                    "observed_at": "2026-08-08T09:15:00Z",
                    "digest": "sha256:6ec7d7f7f98e3c5d2af117a9444fe4210a55ad42794f582fef880fc97c92465c",
                    "excerpt": "ValueError while parsing quantity",
                }
            ],
            "acceptance_criteria": [
                "Non-numeric quantity input returns a typed validation error.",
                "Existing valid quantity requests continue to pass their unit tests.",
            ],
            "repository": {
                "provider": "GITHUB",
                "url": "https://github.com/MtechSE-ArchAI-Team7/example-service.git",
                "base_branch": "main",
                "commit_sha": "34d8b82d6274a77b3627b52e8c09203fc58f6d8a",
            },
            "upstream_correlation_id": "investigation-run-9f31",
            "upstream_audit_refs": ["audit://agent-2/CASE-2026-0042"],
        },
    }
}

APPROVAL_DECISION_EXAMPLES: Final[dict[str, dict[str, object]]] = {
    "approve_exact_scope": {
        "summary": "Approve the pending plan or patch scope",
        "value": {
            "schema_version": "1.0",
            "approval_id": "approval-7dd19b23",
            "scope_digest": "sha256:ecb7689fbcc1d65d6f1e7509f9e5f3f6d7e46fd26978c94443a2f45a0a765a4c",
            "status": "APPROVED",
            "reviewer_id": "operator@example.org",
            "decided_at": "2026-08-08T09:30:00Z",
            "comment": "Reviewed against the evidence and policy findings.",
        },
    }
}

AWAITING_APPROVAL_EXAMPLE: Final[dict[str, object]] = {
    "run_id": "4d1ceef7-9dd5-47d0-b875-218e1682a8d7",
    "status": "AWAITING_APPROVAL",
    "approval_request": {
        "approval_id": "approval-7dd19b23",
        "case_id": "CASE-2026-0042",
        "kind": "PATCH",
        "scope_digest": "sha256:ecb7689fbcc1d65d6f1e7509f9e5f3f6d7e46fd26978c94443a2f45a0a765a4c",
        "summary": "The patch changes a policy-controlled path.",
        "reasons": ["A human must approve the exact patch scope."],
        "requested_at": "2026-08-08T09:25:00Z",
        "status": "PENDING",
    },
    "result": None,
}

TERMINAL_RUN_EXAMPLE: Final[dict[str, object]] = {
    "run_id": "4d1ceef7-9dd5-47d0-b875-218e1682a8d7",
    "status": "DRAFT_PR_PREPARED",
    "approval_request": None,
    "result": {
        "schema_version": "1.0",
        "case_id": "CASE-2026-0042",
        "run_id": "4d1ceef7-9dd5-47d0-b875-218e1682a8d7",
        "final_status": "DRAFT_PR_PREPARED",
        "repository": {
            "provider": "GITHUB",
            "url": "https://github.com/MtechSE-ArchAI-Team7/example-service.git",
            "base_branch": "main",
            "commit_sha": "34d8b82d6274a77b3627b52e8c09203fc58f6d8a",
        },
        "base_commit": "34d8b82d6274a77b3627b52e8c09203fc58f6d8a",
        "proposed_branch": "remediation/case-2026-0042-4d1ceef7",
        "proposed_commit": None,
        "changed_files": ["src/example.py", "tests/test_example.py"],
        "diff_digest": "sha256:ecb7689fbcc1d65d6f1e7509f9e5f3f6d7e46fd26978c94443a2f45a0a765a4c",
        "remediation_plan_summary": "Handle invalid quantity input and add regression coverage.",
        "risk_summary": "Bounded code and test change permitted by policy.",
        "policy_control_ids": ["PATCH_ALLOWED"],
        "approvals": [],
        "validation_attempts": [],
        "failed_attempt_summaries": [],
        "residual_risks": [],
        "rollback_instructions": None,
        "draft_pr": None,
        "artifact_manifest": None,
        "audit_bundle_ref": None,
        "errors": [],
    },
}

RUN_RESPONSE_EXAMPLES: Final[dict[str, dict[str, object]]] = {
    "awaiting_approval": {
        "summary": "Run paused at a hash-bound approval interrupt",
        "value": AWAITING_APPROVAL_EXAMPLE,
    },
    "terminal": {
        "summary": "Run completed with a validated draft-PR payload",
        "value": TERMINAL_RUN_EXAMPLE,
    },
}

ERROR_EXAMPLES: Final[dict[str, dict[str, object]]] = {
    "not_found": {
        "summary": "Unknown or invalid run identifier",
        "value": {"detail": "remediation run not found: 4d1ceef7-9dd5-47d0-b875-218e1682a8d7"},
    },
    "approval_conflict": {
        "summary": "Approval does not match the pending interrupt",
        "value": {"detail": "approval ID and scope digest must match the pending interrupt"},
    },
    "not_ready": {
        "summary": "Checkpoint persistence is unavailable",
        "value": {"detail": "checkpoint store is not ready"},
    },
}
