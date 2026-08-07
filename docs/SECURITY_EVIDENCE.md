# Security Evidence and OWASP LLM Top 10 (2025)

This is the implementation-time assessment for the local academic prototype. `MITIGATED` means a control is implemented and exercised within this prototype boundary; it does not claim production assurance. `PARTIALLY_MITIGATED` identifies remaining integration or operational work. `NOT_APPLICABLE` must be revisited if the architecture changes.

| OWASP risk | Status | Implemented control and inspectable evidence | Residual work |
|---|---|---|---|
| LLM01 Prompt Injection | PARTIALLY_MITIGATED | Repository text is labelled untrusted, the model receives no callable tools, inspection requests pass deterministic path policy, commands resolve only from operator JSON, and `tests/security/test_prompt_injection.py` exercises a malicious repository instruction. | Add provider-specific adversarial evaluation and an ongoing prompt regression corpus. |
| LLM02 Sensitive Information Disclosure | PARTIALLY_MITIGATED | Forbidden secret paths, credential-bearing repository URL rejection, bounded context, AES-encrypted checkpoints, explicit non-pickle serialization, redaction, and leakage assertions in `tests/security/test_policy.py` and `tests/unit/test_checkpoint.py`. | Use a secret manager, encrypted durable artifact store, access controls, and retention enforcement. |
| LLM03 Supply Chain | PARTIALLY_MITIGATED | Dependencies resolve through committed `uv.lock`; `make security` runs Bandit and pip-audit; dependency, Docker, workflow, and policy changes require review. | Pre-existing reusable Actions use mutable `@main`, and base images are not digest-pinned. Remediation requires explicit approval. |
| LLM04 Data and Model Poisoning | NOT_APPLICABLE | No training, fine-tuning, RAG corpus, embeddings, or learned long-term memory exists. | Reopen if any learned or retrieved corpus is introduced. |
| LLM05 Improper Output Handling | MITIGATED | Every model output has a Pydantic schema; critical routing uses enums; unified diffs are parsed and policy-checked; `git apply --check` precedes apply; model text is never executed. Evidence: `tests/security/test_policy.py`, `tests/unit/test_model_adapter.py`, and graph tests. | Continue fuzzing diff parsers and provider structured-output behavior. |
| LLM06 Excessive Agency | MITIGATED | One bounded graph, no model tools, no generic shell, named commands, Docker isolation, read-only Git metadata, post-validation diff integrity, exact approval interrupts, a three-attempt demo limit, no production/deploy/merge authority, and remote writes disabled by default. Evidence: `tests/graph/` and `tests/security/test_policy.py`. | Add production identity and authentication controls before any non-local exposure; production mutation remains out of scope. |
| LLM07 System Prompt Leakage | PARTIALLY_MITIGATED | Prompts contain no credentials and are not a security boundary; prompt/model versions and response digests are recorded. The system remains safe if prompt text is known because policy is deterministic. | Add explicit prompt-extraction and refusal evaluations for each selected provider. |
| LLM08 Vector and Embedding Weaknesses | NOT_APPLICABLE | The prototype has no vector store, embedding model, or retrieval workflow. | Reopen if retrieval or long-term memory is added. |
| LLM09 Misinformation | PARTIALLY_MITIGATED | Diagnosis evidence IDs are referentially validated, plan evidence IDs must exist, pass/fail is deterministic, failures and residual risks are retained, and draft PR text mandates human review. | Agent 2 and Agent 4 owners must ratify contracts; human-review quality remains an operational dependency. |
| LLM10 Unbounded Consumption | PARTIALLY_MITIGATED | Required policy caps context, files, search results, model output, attempts, task time/output, diff size, and active per-process runs. Sandbox output is capped while streaming rather than after accumulation. | Add distributed quotas, provider budget alarms, request authentication/rate limiting, and multi-replica coordination. |

## Additional threat evidence

- Path traversal, absolute paths, forbidden files, dependency approval, test weakening, security weakening, and unknown command names: `tests/security/test_policy.py`.
- Symlink reads, immutable base matching, patch application, restore, and cleanup: `tests/integration/test_local_repository.py`.
- Interrupt approval, rejection, scope binding, and exact retry exhaustion: `tests/graph/test_retry_and_approval.py`.
- Validation-task workspace tampering detection: `tests/graph/test_failures.py`.
- Code, configuration, and unsafe remediation demonstrations: `tests/graph/test_scenarios.py`.
- Redacted hash chain and artifact traversal: `tests/unit/test_audit_artifacts.py`.
- PostgreSQL process/checkpointer recreation: `tests/integration/test_postgres_resume.py` (opt-in).

The local JSONL audit chain is tamper-evident, not immutable. WORM storage and independent verification are deferred.
