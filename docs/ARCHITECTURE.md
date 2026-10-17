# Agent 3 Architecture

Agent 3 is one stateful LangGraph workflow. Stages share one identity, state schema, model adapter, policy engine,
checkpointer and set of operator-owned ports.

```mermaid
flowchart LR
    Intake[Validate diagnosis handoff] --> Provenance[Verify release provenance]
    Provenance --> Scope[Classify scope]
    Scope --> Workspace[Create disposable workspace]
    Workspace --> Inspect[Inspect immutable repository]
    Inspect --> Plan[Create verification-backed plan]
    Plan --> Contract[Compile canonical coverage]
    Contract --> Capabilities[Execute base capability probe]
    Capabilities --> Risk[Assess risk]
    Risk --> Approval{Approval required?}
    Approval --> Patch[Compile typed exact edits and preflight]
    Patch --> Validate[Run base and candidate validation]
    Validate --> Evidence[Build evidence and draft PR payload]
    Evidence --> Seal[Persist verified candidate]
    Seal --> Branch[Branch]
    Branch --> Commit[Commit]
    Commit --> Push[Push and reconcile]
    Push --> Draft[GitHub MCP: create and verify exact draft]
    Draft --> Cleanup[Cleanup]
    Cleanup --> Durable[Persist cleanup and publication receipts]
    Durable --> Memory[Eligible incident memory]
    Memory --> Final[Finalize handoff]
    Provenance -->|missing or ambiguous| Human[HUMAN_ACTION_REQUIRED]
```

The hosted provenance stage uses `ReleaseProvenancePort` before repository access. It lists a bounded number of versions
for the configured AgentCore runtime, reads those exact versions and accepts exactly one whose release ID, source SHA,
image digest, ECR account/Region, runtime ID and ARN match the executing release. Local runs receive an explicit `LOCAL`
attestation. Unverified hosted provenance cannot create a workspace, prepare a PR or write incident memory.

Planning, risk, patch and revision remain schema-validated stages. The OpenAI adapter always uses LangChain function
calling for structured output. Bedrock and DeepSeek retain their existing provider method. Provider errors are normalized
to bounded `ModelCallRecord` fields and exclude response bodies, headers, request IDs and prompts. Request/schema errors
are terminal; timeouts, connection failures, rate limits and server errors use the configured bounded retry count.

`ReleaseProvenanceV1` is an exported evidence schema and `release-provenance.json` is included through the existing
artifact manifest. The Agent 2 and Agent 4 v1 handoff wire formats are unchanged. Completed older records remain
readable; an approval resume from a checkpoint that predates release provenance returns `REVALIDATION_REQUIRED` so the
operator starts a new run through the full gate.

The control-plane adapter is not model-callable. It receives a fixed runtime ID from trusted deployment configuration,
has no write method and performs no repository, patch, validation, PR or deployment operation.

Inspection guardrails return typed `DENIED` tool results so the model can correct a bounded call. In particular,
`get_file_contents` requires `ref` to be absent and the operator-assigned commit in `sha`; the host never forwards a
denied selector upstream. A denial remains in the audit trail, while `REPOSITORY_INSPECTED` is the terminal success
event and records how many denied calls were recovered. Without that event, an inspection error or exhausted budget
remains a stage failure and routes through cleanup.

Verification separates executable coverage gaps from reviewed plan limitations. Missing criterion mappings, trusted
behavioral tasks, request contracts, required source evidence, test IDs, or runtime capabilities fail closed before a
PR. Other unresolved plan details deterministically raise plan risk and require approval; after approval they remain
in the verification brief and PR, while the mapped local assertions must still reproduce the base defect and pass on
the candidate. Explicit post-deployment criteria remain pending for Agent 4 and never count as a local pass.

Application-level Node tests use an e-commerce profile. The host verifies and mounts the same sealed Express/sqlite3
dependency bundle used by the operator-owned purchase profile and selects the bundled Node executable.
`ecommerce_checkout` launches each snapshot over loopback and applies operator-owned durable-insert and rejected-write
assertions without relying on candidate-only exports. Generic `node_test` remains for dependency-free modules. The Node
reporter retains a bounded `test:stderr` diagnostic for setup failures, while pass/fail still comes only from structured
test events. This prevents a missing application dependency from being mistaken for a reproduced defect and leaves a
useful capability-gap explanation in validation evidence.

## Execution bindings and recovery

`CompiledContractV1`, `CapabilityReportV1`, `ExecutionBindingV1`, edit receipts and `PublicationJournalV1` are internal
supplementary artifacts. `DiagnosisHandoffV1` and `RemediationHandoffV1` are unchanged. The original accepted input is
redacted before checkpointing and retained with its manifest digest. A repeated run ID cannot replace that handoff.

Source projection is separate from diagnostic redaction. Commit-pinned MCP bytes must match the local immutable source;
secret spans cannot be edited or reconstructed. The host compiles `EditProposal`, verifies its applicability and actual
result, then binds review to the canonical change. Edit-construction attempts and executed behavioral-repair attempts
have separate limits. The fixed full contract remains in every revision, including browser obligations.

The compiled contract supplies immutable operator assertions. Extra generated assertions are frozen across candidate
repair; changing their digest requires review and a new baseline. Base setup errors never qualify as defect reproduction.
Applications and browsers run in disposable copies with real middleware, SQLite and deterministic fixtures. Browser
assets and application dependencies are independent locked offline graphs, verified before use. Chunked hosted uploads
retain the existing total asset limits and are reassembled with digest checks; commands remain operator-owned argv.

Publication is an idempotent sequence of graph stages. Fixed commit timestamps make exact candidate recovery reproduce
the same commit after workspace cleanup. Tree/base mismatches stop delivery. Draft creation retries reconcile before
writing; verification checks the actual head SHA, repository, base, open state and draft flag. The immutable validation
brief is sealed before publication; subsequent recovery outcomes live in the publication journal and final handoff.
Successful cleanup and persisted qualifying evidence precede incident-memory admission.

The real-model qualification harness uses immutable source archives, real Git, actual restricted validation and test-only
approval decisions. Only remote GitHub writes are simulated. Three consecutive hosted trials for each supported case are
required as release evidence; fake benchmark results establish routing coverage only.


## Executable release gate

CI builds the immutable image before `qualify-agentcore-runtime.yaml` runs three consecutive trials for each sealed
historical source snapshot. The qualification container uses that exact image and the existing runtime's model settings;
only remote GitHub writes are simulated. The deploy workflow verifies `ReleaseQualificationV1` reports from the same
Actions run, with unique successful trials, clean validation/cleanup/publication outcomes and unchanged assertion digests.
It checks source SHA, immutable ECR digest, policy/assets/model bindings and current runtime environment before any update.
Real native human approvals, GitHub writes and the Agent 4 handoff remain a separate post-release demonstration.

Execution bindings also include the model configuration digest. Every unfinished approval/publication resume compares
workflow/base/contract/policy/assets/prompt/model inputs. An incompatible checkpoint cannot reuse a prior approval.
Observed baseline failures in operator-declared regression checks remain in the brief, PR and memory evidence;
acceptance assertions and mandatory operator security tasks must pass, and introduced regressions always block.

The sealed headless browser includes its matching ELF loader and shared libraries. The loader is colocated with browser
resources; direct child-process launch avoids zygote re-executing the loader through `/proc/self/exe`. This preserves the
existing outer Docker/managed-sandbox isolation controls. Qualification includes actual page interaction and loopback
request interception; browser launch alone is insufficient evidence.

## Managed storage and validation lifecycle

The one workflow owns the reviewed Git checkout on managed session storage. A separate `ValidationSnapshotRef` is
accepted only by validation execution and cleanup; patch/repository operations still require `WorkspaceRef`.
An operator-owned scratch lease records exact base/candidate ownership and rejects traversal, other-run references,
symlinks and overlap with `/mnt/workspace`. Only one snapshot exists at a time. Trusted image assets are streamed to
Code Interpreter; Docker stages them only in private scratch. Storage preflight precedes snapshot writes.

`BehavioralTaskExecution` can retain partial executions and `ValidationStorageEvidence` even without a completed pair.
Cleanup cannot replace the primary failure. Transient filesystem cleanup retries at most three times; process/session
stop must be confirmed. Each completed snapshot and final storage report is persisted independently. The workflow
records infrastructure gaps without spending behavioral repair attempts and checks Git/HEAD/diff before and after execution.
The canonical patch and edit receipts are durable before this boundary. Execution binding version `remediation-v4`
rejects unfinished v3 approvals while old completed evidence remains readable.

`RuntimeQualificationPort` is an operator test boundary, not another agent or a remediation approval bypass.
Its A2A request accepts only prepare/resume, an enum fixture, a UUID and a prepared receipt digest. A fresh runtime
process must recover the fixed fixture's managed Git checkout and exact release/policy/assets/receipt before applying
its bundled patch. Real application/browser checks and cleanup produce a digest-addressed artifact. The deployment
client, not the runtime role, stops its isolated qualification session. Readiness and simulated publication trials cannot
substitute for this cold-resume proof; any failed qualification invokes guarded rollback.


## Deterministic MCP publication

`PullRequestProvider` uses an operation-scoped direct session to GitHub's fixed hosted MCP endpoint. Its allowlist is
`list_pull_requests`, `create_pull_request`, and `pull_request_read` with `method=get`. This connection is independent of
the three-tool read-only model inspection session and its optional IAM Gateway. One agent identity and policy engine
still own both boundaries; no model can invoke publication.

MCP readiness proves discovery and repository read access only. Both write gates, sealed candidate evidence and exact
approval bindings still precede publication. Git branch/commit/push remain unchanged. The provider reconciles the exact
head across all PR states, rejects ambiguity, forces draft creation, and verifies the returned number through an MCP read.
Creation IDs are GitHub database IDs, not PR numbers. Success requires matching repository/branches/head/base SHAs and an
open, unmerged draft. Unknown outcomes reconcile on retry; no REST fallback, merge, update or review operation exists.

Internal readiness/results/errors carry bounded `PublicationCallRecord` values. Workflow stages convert them into the
existing hash-chained audit before checkpointing; public v1 handoffs/journals remain compatible. Session objects, bearer
headers and raw provider bodies never enter state. HTTP responses are capped at 1 MiB and each discovery/tool operation
uses the operator MCP timeout. Tests and release qualification exercise the same SDK adapter using a captured GitHub-shaped
MCP contract without making remote writes.
