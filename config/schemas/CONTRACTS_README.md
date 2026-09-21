# AIOS Agent 2 → 3 and Agent 3 → 4 Contracts

This document is the integration handoff for the developers of:

- **Agent 2 — Investigation/Diagnosis Agent**, which sends a diagnosis to Agent 3.
- **Agent 3 — Resolution/Remediation Agent**, implemented in this repository.
- **Agent 4 — Verification/Monitoring Agent**, which consumes Agent 3's result.

The contracts below describe the implemented Agent 3 models, not a future proposal. They are provisional team
contracts at schema version `1.0` and should be ratified by the Agent 2 and Agent 4 owners before the final integration.

## Canonical artifacts

The machine-readable JSON Schemas are authoritative:

- `config/schemas/diagnosis-handoff-v1.schema.json` — Agent 2 → Agent 3.
- `config/schemas/approval-decision-v1.schema.json` — digest-bound approval resume.
- `config/schemas/approval-request-v1.schema.json` — digest-bound approval interrupt emitted by Agent 3.
- `config/schemas/remediation-handoff-v1.schema.json` — Agent 3 → Agent 4.
- `config/schemas/delivery-receipt-v1.schema.json` — supplementary direct-delivery evidence.
- `config/schemas/explainability-trace-v1.schema.json` — supplementary bounded decision and tool-call trace.
- `config/schemas/provider-probe-request-v1.schema.json` and `config/schemas/provider-probe-result-v1.schema.json` — bounded A2A readiness probe.

The source models are `DiagnosisHandoffV1` and `RemediationHandoffV1` in
`src/remediation_agent/domain/models.py`. Agent 3 validates all contract objects with Pydantic and rejects unknown
fields. Run `make schemas` after changing a public model; committed schemas must remain synchronized with the models.

## Shared conventions

- JSON property names use `snake_case`.
- `schema_version` must be exactly `"1.0"`.
- Timestamps are ISO 8601 date-times. Send UTC timestamps with a `Z` suffix or explicit `+00:00` offset.
- Digests should use the form `sha256:<hex digest>`.
- IDs must be stable within a case. Do not reuse an evidence ID for different evidence.
- Repository URLs must not contain credentials, query parameters, or fragments.
- Unknown JSON properties are rejected (`additionalProperties: false`).
- Empty strings are not substitutes for required values.
- Do not include API keys, access tokens, passwords, private keys, cookies, or unrestricted command/path permissions.
- Repository text and evidence excerpts are treated as untrusted content and cannot override Agent 3 policy.
- Operator policy, not an upstream agent, decides allowed paths, commands, approvals, and autonomous authority.

## Contract A: Agent 2 → Agent 3

Agent 2 sends a `DiagnosisHandoffV1` after it has completed evidence-supported diagnosis. Agent 3 accepts this object at:

```text
POST /v1/remediations
Content-Type: application/json
```

The HTTP response is a `RemediationRunView`. A `202` response can be terminal or paused at an approval interrupt;
consumers must inspect `status` rather than assuming completion.

The canonical hosted interface is A2A Protocol 1.0. Send the same object as the single data part with media type
`application/vnd.aios.diagnosis-handoff.v1+json`; resume the returned task with
`application/vnd.aios.approval-decision.v1+json`. The A2A task UUID is the Agent 3 `run_id` and is separate from the
AgentCore runtime session/A2A context ID.

Agent 3 may add `application/vnd.aios.explainability-trace.v1+json` beside the approval request or terminal remediation
artifact. Consumers may ignore this supplementary part. It contains redacted decisions, tool-call metadata, evidence
references, model metrics, and optional provider reasoning summaries; it never contains raw prompts, repository file
contents, patches, or hidden reasoning tokens.

### Top-level fields

| Field | Required | Contract |
|---|---:|---|
| `schema_version` | No | Defaults to `1.0`; if supplied, it must be `1.0`. |
| `case_id` | Yes | Stable case identifier, 1–200 characters. |
| `jira_ticket_id` | Yes | Jira issue key such as `TICKET-111`; mixed case is accepted and normalized to uppercase. |
| `issue_summary` | Yes | Concise incident/problem summary, 1–10,000 characters. |
| `remediation_type` | Yes | One value from the remediation-type enum below. |
| `diagnosis` | Yes | Structured diagnosis, confidence, evidence links, and uncertainties. |
| `supporting_evidence` | Yes | 1–100 bounded evidence records. |
| `acceptance_criteria` | Yes | 1–20 non-empty, testable success conditions. |
| `repository` | Yes | Repository provider, URL/reference, base branch, and optional immutable commit. |
| `upstream_correlation_id` | No | Agent 2 or shared-orchestrator correlation ID. |
| `upstream_audit_refs` | No | References to redacted upstream audit records; defaults to `[]`. |

### `diagnosis`

| Field | Required | Contract |
|---|---:|---|
| `summary` | Yes | Evidence-supported diagnosis, 1–20,000 characters. |
| `confidence` | Yes | Number from `0.0` to `1.0`. |
| `evidence_ids` | Yes | Non-empty list; every ID must exist in `supporting_evidence`. |
| `contradictions` | No | Up to 20 known contradictions; defaults to `[]`. |
| `unresolved_questions` | No | Up to 20 unresolved questions; defaults to `[]`. |

Contradictions or unresolved questions do not make the payload invalid. They cause Agent 3 to raise risk and normally
request human approval rather than silently assuming an answer.

### `supporting_evidence[]`

| Field | Required | Contract |
|---|---:|---|
| `evidence_id` | Yes | Stable unique ID, 1–200 characters. |
| `source_type` | Yes | Source classification such as `application_log`, `test_result`, or `metric`. |
| `source_locator` | Yes | Traceable locator, 1–2,048 characters; do not embed credentials. |
| `observed_at` | Yes | ISO 8601 timestamp. |
| `digest` | Yes | Integrity digest for the source record or bounded representation. |
| `excerpt` | No | Relevant bounded excerpt, maximum 10,000 characters; defaults to an empty string. |

Evidence should be sufficient to explain the diagnosis but minimized to avoid leaking sensitive information. Agent 3
redacts suspected secrets and may truncate evidence before model use or persistence.

### `repository`

| Field | Required | Contract |
|---|---:|---|
| `provider` | Yes | `LOCAL`, `GITHUB`, `GITLAB`, or `GENERIC_GIT`. |
| `url` | Yes | Repository URL or operator-recognized local reference, maximum 2,048 characters. |
| `base_branch` | Yes | Safe canonical Git ref, 1–200 characters. |
| `commit_sha` | No | 7–64 hexadecimal characters. A full immutable SHA is strongly recommended. |

Agent 3 checks the repository against operator allowlists. A syntactically valid repository can still be rejected by
policy. Agent 2 must not assume that its proposed paths or repository location grant Agent 3 permission.

### Remediation types

| Value | Current Agent 3 behavior |
|---|---|
| `CODE` | Supported workflow. |
| `CONFIGURATION` | Supported workflow. |
| `ACCOUNT_UNLOCK` | Deferred; typed unsupported/human-action result. |
| `PASSWORD_RESET` | Deferred; typed unsupported/human-action result. |
| `ACCESS_PROVISIONING` | Deferred; typed unsupported/human-action result. |
| `PRIVILEGED_ACCESS` | Deferred; typed unsupported/human-action result. |
| `SOFTWARE_REQUEST` | Deferred; typed unsupported/human-action result. |
| `PRODUCTION_CHANGE` | Outside autonomous authority. |
| `OTHER` | Unsupported unless a later version defines it. |

### Valid Agent 2 example

```json
{
  "schema_version": "1.0",
  "case_id": "CASE-2026-0042",
  "jira_ticket_id": "TICKET-111",
  "issue_summary": "Malformed quantity input causes an unhandled application error.",
  "remediation_type": "CODE",
  "diagnosis": {
    "summary": "The request handler calls int() without handling ValueError for non-numeric input.",
    "confidence": 0.94,
    "evidence_ids": ["ev-log-42", "ev-test-17"],
    "contradictions": [],
    "unresolved_questions": []
  },
  "supporting_evidence": [
    {
      "evidence_id": "ev-log-42",
      "source_type": "application_log",
      "source_locator": "logs/api/request-42",
      "observed_at": "2026-08-08T09:15:00+00:00",
      "digest": "sha256:6ec7d7f7f98e3c5d2af117a9444fe4210a55ad42794f582fef880fc97c92465c",
      "excerpt": "ValueError: invalid literal for int()"
    },
    {
      "evidence_id": "ev-test-17",
      "source_type": "test_result",
      "source_locator": "artifacts/diagnosis/test-17.json",
      "observed_at": "2026-08-08T09:18:00+00:00",
      "digest": "sha256:07d54d81b1bd284798b9639c67d18b5e34f6afc3ecf3bdeb8c66897118a1a508",
      "excerpt": "POST /items with quantity=abc returns HTTP 500"
    }
  ],
  "acceptance_criteria": [
    "Non-numeric quantity input returns HTTP 400 with a typed validation error.",
    "Existing valid quantity requests continue to pass their unit tests."
  ],
  "repository": {
    "provider": "GITHUB",
    "url": "https://github.com/example-org/example-service.git",
    "base_branch": "main",
    "commit_sha": "34d8b82d6274a77b3627b52e8c09203fc58f6d8a"
  },
  "upstream_correlation_id": "investigation-run-9f31",
  "upstream_audit_refs": ["audit://agent-2/CASE-2026-0042"]
}
```

### Agent 2 integration checklist

- Validate against `diagnosis-handoff-v1.schema.json` before sending.
- Ensure every `diagnosis.evidence_ids[]` value resolves to one supplied evidence record.
- Prefer a full immutable `commit_sha`; do not silently follow a moving branch.
- Write acceptance criteria that Agent 3 can map to configured validation tasks.
- Report contradictions and uncertainty explicitly.
- Keep excerpts bounded and redacted; use artifact references for large evidence.
- Do not send shell commands, credentials, production permissions, or instructions to bypass review.
- Treat `INVALID_REQUEST`, `UNSUPPORTED_REMEDIATION_TYPE`, and `HUMAN_ACTION_REQUIRED` as expected typed outcomes.

## Contract B: Agent 3 → Agent 4

Agent 4 consumes `RemediationHandoffV1` from the `result` property of a terminal `RemediationRunView`:

```text
GET /v1/remediations/{run_id}
```

While a run is paused, `status` is `AWAITING_APPROVAL`, `approval_request` is populated, and `result` is normally
`null`. Agent 4 should consume only a terminal, non-null `result`; approval handling belongs to the human approval
boundary, not Agent 4.

On A2A, the same handoff is attached to every terminal task as an artifact data part with media type
`application/vnd.aios.remediation-handoff.v1+json`. Optional direct delivery to Agent 4 is supplementary, success-only,
and disabled by default. Its `application/vnd.aios.delivery-receipt.v1+json` artifact does not modify this handoff.

### Top-level fields

| Field | Required | Contract |
|---|---:|---|
| `schema_version` | No | Defaults to `1.0`; if supplied, it must be `1.0`. |
| `case_id` | Yes | Original case ID. |
| `run_id` | Yes | Agent 3 execution/checkpoint thread ID. |
| `final_status` | Yes | Terminal outcome; Agent 4 must branch on this field. |
| `repository` | Yes | Validated repository reference from the input. |
| `base_commit` | No | Immutable base commit actually inspected. |
| `proposed_branch` | No | Proposed or created remediation branch. |
| `proposed_commit` | No | Proposed/created commit SHA when available. |
| `changed_files` | No | Sorted repository-relative paths; defaults to `[]`. |
| `diff_digest` | No | Digest of the validated final diff. The raw diff is not embedded here. |
| `remediation_plan_summary` | No | Concise summary of the selected plan. |
| `risk_summary` | No | Final risk rationale. |
| `policy_control_ids` | No | Policy controls applied to the plan/patch; defaults to `[]`. |
| `approvals` | No | Exact approval decisions bound to plan/diff hashes; defaults to `[]`. |
| `validation_attempts` | No | Ordered patch/check attempts; defaults to `[]`. |
| `failed_attempt_summaries` | No | Bounded summaries of failed attempts; defaults to `[]`. |
| `residual_risks` | No | Risks remaining after remediation; defaults to `[]`. |
| `rollback_instructions` | No | Before/after-commit rollback guidance and limitations. |
| `draft_pr` | No | Deterministic draft-PR payload and optional provider result. |
| `artifact_manifest` | No | References to retained, redacted artifacts. |
| `audit_bundle_ref` | No | Reference to the redacted hash-chained audit bundle. |
| `errors` | No | Typed execution errors; defaults to `[]`. |

### Validation attempts

Each `validation_attempts[]` object contains:

- `attempt`: one-based attempt number.
- `patch_digest`: digest of the patch tested during that attempt.
- `outcome`: `NOT_RUN`, `PASSED`, `FAILED`, `ERROR`, or `TIMED_OUT`.
- `results`: task-level results with `task_name`, `outcome`, optional `exit_code`, `duration_ms`, bounded/redacted
  `stdout` and `stderr`, and `output_truncated`.

Agent 4 should verify that the latest relevant attempt passed and should not treat the presence of a draft PR as proof
of production deployment. Agent 3 does not deploy, merge, or execute a production rollback.

### Final statuses

| Status | Meaning for Agent 4 |
|---|---|
| `INVALID_REQUEST` | Do not verify; return the contract/input problem for correction. |
| `UNSUPPORTED_REMEDIATION_TYPE` | No repository change was attempted. |
| `NOT_IMPLEMENTED` | Typed placeholder; human or another workflow is required. |
| `HUMAN_ACTION_REQUIRED` | Stop automated verification and surface the reason. |
| `UNSAFE_REMEDIATION` | No unsafe change should have been applied; verify zero change if required. |
| `VALIDATION_FAILED` | Patch attempts did not meet configured checks; do not treat as remediated. |
| `DRAFT_PR_PREPARED` | Validated payload/evidence exists, but no external PR was necessarily created. |
| `DRAFT_PR_CREATED` | A draft PR was created; human review and merge are still required. |
| `INTERNAL_ERROR` | Agent 3 failed; inspect `errors` and cleanup evidence. |
| `CLEANUP_FAILED` | Treat disposable-workspace cleanup as an unresolved operational risk. |

`PENDING` and `AWAITING_APPROVAL` are lifecycle states and should not be delivered to Agent 4 as completed results.

### Valid Agent 3 example

```json
{
  "schema_version": "1.0",
  "case_id": "CASE-2026-0042",
  "run_id": "4d1ceef7-9dd5-47d0-b875-218e1682a8d7",
  "final_status": "DRAFT_PR_PREPARED",
  "repository": {
    "provider": "GITHUB",
    "url": "https://github.com/example-org/example-service.git",
    "base_branch": "main",
    "commit_sha": "34d8b82d6274a77b3627b52e8c09203fc58f6d8a"
  },
  "base_commit": "34d8b82d6274a77b3627b52e8c09203fc58f6d8a",
  "proposed_branch": "remediation/CASE-2026-0042",
  "proposed_commit": null,
  "changed_files": ["src/items.py", "tests/test_items.py"],
  "diff_digest": "sha256:1f0f2b4ce670f0435b23e6d7f9c2d432b440953c6ad3f493c8ed3c79215ea596",
  "remediation_plan_summary": "Handle malformed quantities and add regression coverage.",
  "risk_summary": "Bounded application and test change; no sensitive control paths modified.",
  "policy_control_ids": ["PATCH_ALLOWED"],
  "approvals": [],
  "validation_attempts": [
    {
      "attempt": 1,
      "patch_digest": "sha256:1f0f2b4ce670f0435b23e6d7f9c2d432b440953c6ad3f493c8ed3c79215ea596",
      "results": [
        {
          "task_name": "unit_tests",
          "outcome": "PASSED",
          "exit_code": 0,
          "duration_ms": 1240,
          "stdout": "42 passed",
          "stderr": "",
          "output_truncated": false
        },
        {
          "task_name": "lint",
          "outcome": "PASSED",
          "exit_code": 0,
          "duration_ms": 380,
          "stdout": "All checks passed",
          "stderr": "",
          "output_truncated": false
        }
      ],
      "outcome": "PASSED"
    }
  ],
  "failed_attempt_summaries": [],
  "residual_risks": ["Human review is required before merge or deployment."],
  "rollback_instructions": {
    "summary": "Rollback applies only to the proposed repository change.",
    "before_commit": ["Discard the proposed branch or reverse the reviewed patch in a disposable workspace."],
    "after_commit": ["Create a reviewed revert commit for the remediation commit."],
    "limitations": ["Agent 3 does not execute production rollback."]
  },
  "draft_pr": {
    "payload": {
      "title": "[TICKET-111] Handle malformed quantity input",
      "body": "Draft remediation with diagnosis, validation evidence, residual risk, and rollback guidance.",
      "head_branch": "remediation/CASE-2026-0042",
      "base_branch": "main",
      "draft": true
    },
    "created": false,
    "provider_id": null,
    "url": null
  },
  "artifact_manifest": {
    "run_id": "4d1ceef7-9dd5-47d0-b875-218e1682a8d7",
    "artifacts": [
      {
        "name": "validation-summary",
        "path": "artifacts/CASE-2026-0042/validation-summary.json",
        "digest": "sha256:7b6aa7536237718318c5d87d10b7745513a1525f696d529bdc6173c371fab195",
        "media_type": "application/json"
      }
    ]
  },
  "audit_bundle_ref": {
    "name": "audit-bundle",
    "path": "artifacts/CASE-2026-0042/audit.jsonl",
    "digest": "sha256:ec3f7df81ca01b98e0fb3cd8f21c6b08e5475ae94c31b8dc68879297bd3322c8",
    "media_type": "application/x-ndjson"
  },
  "errors": []
}
```

### Agent 4 integration checklist

- Validate against `remediation-handoff-v1.schema.json` before processing.
- Correlate with both `case_id` and `run_id`.
- Branch deterministically on `final_status`; do not infer success from narrative text.
- Verify `base_commit`, `diff_digest`, changed-file scope, approvals, and the latest validation attempt.
- Treat logs and artifacts as redacted/bounded evidence; resolve artifact references through an authorized channel.
- Never infer that `DRAFT_PR_PREPARED` or `DRAFT_PR_CREATED` means merged or deployed.
- Preserve and surface `residual_risks`, rollback limitations, cleanup failures, and typed errors.
- Do not request Agent 3 to merge, deploy, mutate production, or execute rollback.

## Approval API contract

Approval is an Agent 3/human boundary but is included here for orchestration awareness. A paused
`RemediationRunView.approval_request` contains an `approval_id` and exact `scope_digest`. Resume with:

```text
POST /v1/remediations/{run_id}/approvals
Content-Type: application/json
```

The body is `ApprovalDecisionV1` with:

- `schema_version`: `1.0`.
- `approval_id`: exact pending approval ID.
- `scope_digest`: exact pending plan/patch digest.
- `status`: only `APPROVED` or `REJECTED`.
- `reviewer_id`: non-empty trusted reviewer identifier.
- `decided_at`: ISO 8601 timestamp not earlier than the approval request.
- `comment`: optional, maximum 2,000 characters.

A changed sensitive plan or patch has a different digest and requires a new approval. Agent 2 and Agent 4 must not
manufacture approvals or reuse approval decisions across scope digests.

## Error and compatibility rules

- Contract validation errors fail closed; do not retry the same invalid payload unchanged.
- Transport retries must preserve the same `case_id` and `jira_ticket_id` and use orchestration idempotency/correlation controls.
- A missing optional field means “not available/not produced,” not success.
- Consumers must tolerate empty arrays where the workflow stopped before that stage.
- Do not parse routing decisions from `risk_summary`, error messages, PR body text, or logs.
- Do not copy raw model output into either contract without deterministic validation.

## Versioning and change process

1. Version `1.0` is strict: extra fields are rejected.
2. No developer should silently rename, remove, repurpose, or change the type/meaning of a field.
3. Proposed changes must be reviewed by the Agent 2, Agent 3, and Agent 4 owners.
4. Because consumers are strict, even optional additions require coordinated schema/model rollout or a new version.
5. Breaking changes require a new versioned model and schema; keep old versions available during migration.
6. Regenerate schemas with `make schemas`, run contract tests, and exchange updated schemas with all owners.
