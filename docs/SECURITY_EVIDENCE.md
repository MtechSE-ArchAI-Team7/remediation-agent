# Security Evidence and OWASP LLM Top 10 (2025)

This is the implementation-time assessment for the local academic prototype. `MITIGATED` means a control is implemented and exercised within this prototype boundary; it does not claim production assurance. `PARTIALLY_MITIGATED` identifies remaining integration or operational work. `NOT_APPLICABLE` must be revisited if the architecture changes.

| OWASP risk | Status | Implemented control and inspectable evidence | Residual work |
|---|---|---|---|
| LLM01 Prompt Injection | PARTIALLY_MITIGATED | Repository and default-branch search text are labelled untrusted. The model can call only three native read-only GitHub MCP tools; the host enforces an exact repository, cloned SHA for tree/file evidence, locator-only search, deterministic path policy, and bounded context. `tests/security/test_prompt_injection.py` and `tests/graph/test_mcp_inspection.py` exercise malicious content, search-only finish denial, and cross-repository calls. | Add provider-specific adversarial evaluation and an ongoing prompt regression corpus. GitHub search remains a remotely supplied prompt-injection surface. |
| LLM02 Sensitive Information Disclosure | PARTIALLY_MITIGATED | The hosted-MCP bearer token remains outside model input/state and is redacted from errors. Forbidden secret paths, credential-bearing URL rejection, unsupported binary/external-resource denial, bounded context, AES-encrypted checkpoints, explicit non-pickle serialization, and leakage assertions are covered by `tests/mcp/test_repository_mcp.py`, `tests/security/test_policy.py`, and `tests/unit/test_checkpoint.py`. | Use a secret manager, encrypted durable artifact store, access controls, and retention enforcement. GitHub remains a trusted token recipient. |
| LLM03 Supply Chain | PARTIALLY_MITIGATED | Dependencies resolve through committed `uv.lock`; `make security` runs Bandit and pip-audit; hosted discovery must return exactly the approved tool names and compatible security-critical schemas; every hosted run resolves `ReleaseProvenanceV1` against its release ID, source SHA, image digest and exact AgentCore version before workspace creation. | `ListAgentRuntimeVersions` cannot be resource-scoped by AWS and can enumerate version metadata in the account. GitHub manages the remote MCP service, and base images are not digest-pinned. |
| LLM04 Data and Model Poisoning | NOT_APPLICABLE | No training, fine-tuning, RAG corpus, embeddings, or learned long-term memory exists. | Reopen if any learned or retrieved corpus is introduced. |
| LLM05 Improper Output Handling | MITIGATED | Every model output has a Pydantic schema; OpenAI structured stages select function calling explicitly; provider request failures become bounded redacted records; the release canary exercises defaulted/map schema features; critical routing uses enums; unified diffs are parsed and policy-checked. Evidence: `tests/unit/test_model_adapter.py`, `tests/integration/test_agentcore_gateway_live.py`, and graph tests. | Continue fuzzing diff parsers and requalify every provider/model upgrade with the opt-in live contract test. |
| LLM06 Excessive Agency | MITIGATED | One bounded graph, exactly three read-only model tools plus a local finish control, no generic shell or selectable MCP server, exact repository/SHA/search scoping, named commands, Docker isolation, post-validation diff integrity, exact approval interrupts, bounded attempts, no production/deploy/merge authority, and remote writes disabled by default. File inspection denies any supplied `ref`, requires the operator-bound `sha`, and records a denial separately from the terminal inspection outcome. Evidence: `tests/graph/`, `tests/mcp/test_repository_mcp.py`, and `tests/security/test_policy.py`. | Add production identity and authentication controls before service exposure; production mutation remains out of scope. |
| LLM07 System Prompt Leakage | PARTIALLY_MITIGATED | Prompts contain no credentials and are not a security boundary; prompt/model versions and response digests are recorded. The system remains safe if prompt text is known because policy is deterministic. | Add explicit prompt-extraction and refusal evaluations for each selected provider. |
| LLM08 Vector and Embedding Weaknesses | NOT_APPLICABLE | The prototype has no vector store, embedding model, or retrieval workflow. | Reopen if retrieval or long-term memory is added. |
| LLM09 Misinformation | PARTIALLY_MITIGATED | Diagnosis evidence IDs are referentially validated, plan evidence IDs must exist, pass/fail is deterministic, failures and residual risks are retained, and draft PR text mandates human review. | Agent 2 and Agent 4 owners must ratify contracts; human-review quality remains an operational dependency. |
| LLM10 Unbounded Consumption | PARTIALLY_MITIGATED | Required policy caps MCP rounds/calls/timeouts, pagination, tree entries, file bytes, search results, aggregate context, model output, attempts, task output/time, diff size, and active per-process runs. Sandbox output is capped while streaming rather than after accumulation. | Add distributed quotas, provider/GitHub budget alarms, request authentication/rate limiting, and multi-replica coordination. GitHub API limits and hosted availability are external dependencies. |

## Additional threat evidence

- Path traversal, absolute paths, forbidden files, dependency approval, test weakening, security weakening, and unknown command names: `tests/security/test_policy.py`.
- Symlink reads, immutable base matching, patch application, restore, and cleanup: `tests/integration/test_local_repository.py`.
- Interrupt approval, rejection, scope binding, and exact retry exhaustion: `tests/graph/test_retry_and_approval.py`.
- Validation-task workspace tampering detection: `tests/graph/test_failures.py`.
- Code, configuration, and unsafe remediation demonstrations: `tests/graph/test_scenarios.py`.
- Redacted hash chain and artifact traversal: `tests/unit/test_audit_artifacts.py`.
- PostgreSQL process/checkpointer recreation: `tests/integration/test_postgres_resume.py` (opt-in).
- Hosted endpoint/header locking, schema drift, repository/SHA scoping, response normalization, token redaction, transport failure, and session cleanup: `tests/unit/test_mcp_adapter.py` and `tests/mcp/test_repository_mcp.py`; the real endpoint contract is separately opt-in.

The local JSONL audit chain is tamper-evident, not immutable. WORM storage and independent verification are deferred.

## Release provenance and provider contract evidence (2026-10-07)

- `tests/unit/test_provenance.py` covers exact matching, missing/duplicate releases, malformed responses and scan bounds.
- `tests/graph/test_failures.py` proves provenance failure occurs before workspace/model/PR work and that failed structured
  call metadata survives final artifacts without raw provider content.
- `tests/security/test_github_workflows.py` binds source SHA, image digest, release ID, runtime ID, mount and account checks
  to the guarded deployment and rollback path.
- `make test-model-live` exercises `RemediationPlan`, `RiskAssessment`, and `EditProposal` through the authenticated
  OpenAI-compatible gateway. It remains explicitly opt-in and is complemented by the deployment canary.


## Behavioral validation threat model (2026-10-06)

The diagnosis, repository source, generated patch and generated tests remain untrusted. Operator task policy, fixed profile
runners and sealed dependency manifests define the validation boundary. Threats include syntax-only false success,
invented test coverage, setup failures presented as reproductions, altered regression assertions, runner replacement,
credential/network escape, stale checkpoints and approvals being mistaken for risk resolution.

| Control | Status | Evidence and residual limitation |
|---|---|---|
| Criterion coverage and base/candidate proof (LLM09) | PARTIALLY_MITIGATED | `tests/graph/test_behavioral_verification.py`, `tests/unit/test_verification.py`: no PR/memory on missing coverage, setup/skips/stale evidence or missing reproduction. Structured evidence cannot prove arbitrary generated assertions semantically match a natural-language diagnosis; human test review remains required. |
| Trusted execution and bounded output (LLM05/06/10) | PARTIALLY_MITIGATED | `adapters/behavioral.py`, fixed assets, `tests/unit/test_behavioral_runner.py`, Docker tests: explicit profiles, safe test overlays, digest checks, read-only Docker source, output/time/resource caps, child and sandbox cleanup. Application-level Node tests use the sealed e-commerce runtime; their reporter retains bounded setup stderr without allowing stdout/stderr to create a passing event. Managed Code Interpreter requires separate live qualification; same-process test reporters are not an adversarial-proof attestation system. |
| Offline dependency provenance (LLM03) | PARTIALLY_MITIGATED | Locked e-commerce dependency manifest, `scripts/seal_validation_bundle.py`, platform/file-digest checks, native-module build smoke tests and real checkout/purchase SQLite integration. Generic dependency-free Node tests cannot silently stand in for application integration. Application compatibility pins intentionally retain legacy libraries. Base image digest pinning, artifact signing and continuous npm vulnerability remediation remain operator work. |
| Secret exclusion and artifact integrity (LLM02) | PARTIALLY_MITIGATED | Snapshot/archive secret exclusions, redaction before checkpointing/reporting, existing digest-addressed artifact manifest and read verification. `verification-brief.json` uses structured redaction to preserve valid JSON. No production endpoint is a test target. Custom network-enabled Code Interpreters require a separately reviewed boundary. |
| Approval/compatibility integrity (LLM05/09) | MITIGATED | Graph tests cover pending deployment checks, retained approved plan limitations, exact criterion mapping and old evidence gates. Deterministic local coverage gaps still fail closed; an approved limitation remains a risk and never counts as executed verification. Both v1 handoffs remain unchanged; new brief/state types round-trip through the non-pickle checkpoint allowlist. |

An observed failure on the base is labelled as such, not automatically declared unrelated. Existing mandatory security
tasks remain gating; unrelated header/cookie findings do not grant permission to widen the patch. Agent 4's independent
verification and deployed monitoring are outside Agent 3's local proof. No production changes, merges or deployment
authority are introduced.


The first 2026-10-06 implementation audit passed Bandit but reported 18 pip-audit advisories in `langgraph-sdk 0.4.2`,
`PyJWT 2.13.0`, and `urllib3 2.7.0`. The guarded-release follow-up upgraded those packages to 0.4.5, 2.15.1, and 2.8.0;
the subsequent Bandit and pip-audit checks passed. The opt-in managed-runtime behavioral qualification remains separate
from dependency auditing; checkout and purchase profiles passed it in `ap-southeast-1` on 2026-10-07.

## Diagnosis-to-publication hardening

AH-56 failed because source redaction altered ordinary JavaScript and Agent 3 trusted fragile model-authored patch mechanics;
component probes did not exercise the complete generated workflow. Canonical contracts, exact source edits, real browser/database
assertions and reconciled publication address these gaps, with complete hosted qualification required before release.

| Threat | Status | Evidence and residual limits |
|---|---|---|
| Non-secret source corruption and placeholder patches (LLM05) | MITIGATED | `tests/unit/test_source_edits.py`: code references survive; real secret locations remain protected; exact ranges/digests, overlap and placeholder rejection precede host-generated diffs. Bounded identifier matching prevents pathological redaction scans. |
| Lost publication response or unrelated PR accepted (LLM05/06) | MITIGATED | `tests/unit/test_pr_provider.py`: exact commit/base/repository/open/draft checks, lost POST reconciliation, rate-limit classification; no duplicate create or force push. |
| Stale approvals and publication recovery (LLM05/09) | MITIGATED | `tests/graph/test_publication_recovery.py`: changed assets stop approval, failed artifact writes prevent publication, retries bind the verified candidate and preserve the sealed brief; memory waits for delivery evidence and cleanup. |
| Unqualified browser/runtime dependencies (LLM03/09) | PARTIALLY_MITIGATED | Locked application and independent Playwright manifests, sealed browser/shared libraries, platform and digest checks, actual storefront assertions. Every release must produce hosted application/browser qualification; a Docker pass alone is insufficient. |
| Incomplete inspected context or prose-sensitive contracts (LLM09) | PARTIALLY_MITIGATED | Required evidence paths and named assertions are operator-owned; missing coverage stops before approval, canonical request semantics replace descriptive equality. Natural-language diagnosis interpretation still requires review. |

The cloud sandbox is not equivalent to Docker `--network none`: AWS documents limited S3/DNS connectivity for its system
sandbox. No credentials or production endpoints are supplied; custom public/VPC interpreters remain rejected. Browser
requests are restricted to the disposable loopback origin. These boundaries do not claim adversarial-proof attestation
of arbitrary repository code. Production deployment, baseline security findings and Agent 4's runtime soak remain separate.


Release gate evidence: `tests/unit/test_release_qualification.py` rejects changed source/image/runtime configuration,
partial/duplicate trials and changed assertions. `tests/security/test_github_workflows.py` verifies image → qualification
→ guarded deployment ordering. `tests/integration/test_local_repository.py` demonstrates real Git lost-push recovery and
stale-base rejection. `tests/unit/test_source_edits.py` covers ordinary variable/member expressions, protected literals,
placeholder rejection, stale ranges/digests and overlapping edits. Operator qualifications are explicit opt-ins; default
checks do not call cloud services. The operator release role gains scoped gateway/system-sandbox invocation and ECR read
permissions; the runtime role does not gain them. ECR login requires account-level `GetAuthorizationToken` visibility.
