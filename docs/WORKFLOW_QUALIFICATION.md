# Full workflow qualification and recovery

The release criterion is a validated candidate with a GitHub-confirmed draft, after required approvals. Agent 4 independently
judges deployed behavior. It is never appropriate to suppress baseline findings or weaken tests to guarantee a green verdict.

## Qualification boundaries

`config/evaluation/snapshots/manifest.json` pins the original AH-54/AH-56 archives by upstream commit and archive digest.
These archives include the real frontend, initialization and lockfile; the evaluation checkout is read-only. AH-54 uses its
historical defective snapshot, not an obsolete diagnosis submitted to an already-fixed live branch.

`scripts/qualify_workflow.py` exercises real configured model calls, bounded source inspection, plan/risk stages,
exact edit generation, test-only approval/resume, real Git, restricted application/browser execution and durable publication.
GitHub MCP publication is simulated through the real provider and SDK, while local branch/commit/push operations use a disposable bare Git remote. The script's
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

The qualification container writes private evidence as its non-root runtime user. The workflow transfers ownership of
only its dedicated output directory back to the GitHub runner before artifact upload, preserving private file modes.
An evidence upload failure blocks deployment even when the trials themselves pass.

## Failure recovery

- `SOURCE_MISMATCH` / `MALFORMED_PROPOSAL`: bounded edit correction uses the exact inspected line and whitespace.
  Three proposals may be attempted for one candidate; protected source and unreviewed paths remain denied.
- `ENVIRONMENT_SETUP`: inspect capability/startup/cleanup diagnostics and repair operator assets or availability.
  An import or browser startup failure is not a defect reproduction and does not authorize speculative code changes.
- `ASSERTION_FAILURE`: inspect the fixed assertion and full contract; bounded clean-base repair preserves all criteria.
- `PUBLICATION_FAILURE`: inspect the journal and exact prepared candidate. Retry only its digest on the same run using
  `PublicationRetryRequestV1`. The operation reconciles remote state and never generates a new fix, silently rebases,
  force-pushes or accepts another PR. Changed base/assets/policy require a fresh diagnosis and validation.

An eligible publication failure retains workflow status `HUMAN_ACTION_REQUIRED` but uses A2A `INPUT_REQUIRED`, with
the exact `PublicationRetryRequestV1` in its status message. This permits retry on the same task; the A2A SDK rejects
messages sent to terminal failed tasks. Other human-action outcomes remain terminal and cannot bypass revalidation.

`verification-brief.json` is immutable validation evidence sealed before publication. `publication-journal.json`,
`cleanup.json`, and the final handoff describe delivery/recovery outcomes. All artifacts are manifest-digested and redacted.
Accepted risks remain visible; an approval is distinct from evidence resolving a risk.

## Native AH-56 demonstration

After the guarded release, obtain or locate one fresh native Agent 2 delivery. Use its actual `DiagnosisHandoffV1` or
correlated delivery receipt and existing Agent 3 task; do not manufacture criteria from a task summary or create a duplicate
run. For authorized trial runs, the operator test driver may submit approvals, recording each exact approval ID/scope digest.
Non-trial runs retain genuine human plan/diff approvals and all hard denials. Verify GitHub reports an open draft in the configured repository and that
its head SHA is the journal's validated commit. Agent 4 receives the unchanged v1 handoff only with required PR references.

Email, user association, line items, inventory/idempotency, deployment and runtime soak are outside the selected AH-56
local contract. A specific `placed`/`pending` order status is not asserted. Header/cookie baseline issues remain visible and
do not automatically expand this patch. Mandatory operator security controls still apply.

## Actual runtime filesystem qualification

Generated trials run on a CI parent filesystem with real hosted Code Interpreter. They do not prove managed storage
survival. The deployment job therefore invokes `RuntimeQualificationRequestV1` through A2A with media type
`application/vnd.aios.runtime-qualification-request.v1+json`. Only bundled `ah54`/`ah56` fixtures and fixed `prepare`/
`resume` operations are accepted; no command, path, repository or approval fields exist. The prepared receipt binds
session, release provenance, policy, assets, fixture and candidate. A new process must recover the receipt and Git tree.
`runtime-qualification.json` records real paired assertions, storage diagnostics, Git integrity and cleanup, and is
referenced by its immutable manifest. The result schema is additive; diagnosis/remediation/provider-probe v1 wires remain.

The operator driver requires explicit `AIOS_RUN_RUNTIME_QUALIFICATION=1`, exact source/image/version/release arguments
and an output directory. The guarded workflow supplies these values. A local process restart unit test is routing evidence;
only an actual managed-runtime result with `managed_filesystem` and `process_restarted` true qualifies the release.
The separate post-release native replay must still verify an actual GitHub draft and exact validated head SHA.
Retain `PUBLICATION_MCP_CALL` audit events proving create/read transport, including the runtime source and image bindings.

The release trial also verifies task-name contracts before approval: prose in `proposed_validation_tasks` triggers the
existing single planning correction; persistent unknown IDs block before patch generation. Edit proposals with unknown
task IDs use the bounded edit correction loop before application. Unknown text is never heuristically treated as a task
or as coverage. Explanations belong in plan steps; required tasks still come from the reviewed contract and policy.
