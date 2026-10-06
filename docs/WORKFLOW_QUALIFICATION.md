# Full workflow qualification and recovery

The release criterion is a validated candidate with a GitHub-confirmed draft, after required approvals. Agent 4 independently
judges deployed behavior. It is never appropriate to suppress baseline findings or weaken tests to guarantee a green verdict.

## Qualification boundaries

`config/evaluation/snapshots/manifest.json` pins the original AH-54/AH-56 archives by upstream commit and archive digest.
These archives include the real frontend, initialization and lockfile; the evaluation checkout is read-only. AH-54 uses its
historical defective snapshot, not an obsolete diagnosis submitted to an already-fixed live branch.

`scripts/qualify_workflow.py` exercises real configured model calls, bounded source inspection, plan/risk stages,
exact edit generation, test-only approval/resume, real Git, restricted application/browser execution and durable publication.
GitHub HTTP writes are simulated, while local branch/commit/push operations use a disposable bare Git remote. The script's
synthetic qualification diagnoses never go to a deployed runtime and must never be reused as native Agent 2 deliveries.

Set the normal provider/gateway settings and `AIOS_BEHAVIORAL_BUNDLE` to a compatible offline bundle, then opt in:

```bash
AIOS_RUN_WORKFLOW_QUALIFICATION=1 uv run python scripts/qualify_workflow.py \
  --backend docker --case all --trials 3 --output .artifacts/qualification/docker
AIOS_RUN_WORKFLOW_QUALIFICATION=1 uv run python scripts/qualify_workflow.py \
  --backend code-interpreter --case all --trials 3 --output .artifacts/qualification/hosted
```

A failed trial stops the series. Three consecutive complete trials of each case using the same source, policy, model
configuration and asset digests are required for release. Checkpoint routing benchmarks with fake models/sandboxes are
useful unit evidence, not end-to-end qualification. Default tests remain independent of live credentials.

## Failure recovery

- `SOURCE_MISMATCH` / `MALFORMED_PROPOSAL`: bounded edit correction uses the exact inspected line and whitespace.
  Three proposals may be attempted for one candidate; protected source and unreviewed paths remain denied.
- `ENVIRONMENT_SETUP`: inspect capability/startup/cleanup diagnostics and repair operator assets or availability.
  An import or browser startup failure is not a defect reproduction and does not authorize speculative code changes.
- `ASSERTION_FAILURE`: inspect the fixed assertion and full contract; bounded clean-base repair preserves all criteria.
- `PUBLICATION_FAILURE`: inspect the journal and exact prepared candidate. Retry only its digest on the same run using
  `PublicationRetryRequestV1`. The operation reconciles remote state and never generates a new fix, silently rebases,
  force-pushes or accepts another PR. Changed base/assets/policy require a fresh diagnosis and validation.

`verification-brief.json` is immutable validation evidence sealed before publication. `publication-journal.json`,
`cleanup.json`, and the final handoff describe delivery/recovery outcomes. All artifacts are manifest-digested and redacted.
Accepted risks remain visible; an approval is distinct from evidence resolving a risk.

## Native AH-56 demonstration

After the guarded release, obtain or locate one fresh native Agent 2 delivery. Use its actual `DiagnosisHandoffV1` or
correlated delivery receipt and existing Agent 3 task; do not manufacture criteria from a task summary or create a duplicate
run. Preserve genuine human plan/diff approvals. Verify GitHub reports an open draft in the configured repository and that
its head SHA is the journal's validated commit. Agent 4 receives the unchanged v1 handoff only with required PR references.

Email, user association, line items, inventory/idempotency, deployment and runtime soak are outside the selected AH-56
local contract. A specific `placed`/`pending` order status is not asserted. Header/cookie baseline issues remain visible and
do not automatically expand this patch. Mandatory operator security controls still apply.
