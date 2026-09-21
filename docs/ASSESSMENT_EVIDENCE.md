# Assessment Evidence

> Generated from bounded evaluation JSON. Live evidence is never inferred or fabricated.

## Evaluation method and provenance

Scenario: `CASE-ECOM-AVG-001` — Division-by-zero e-commerce remediation. The handoff pins source commit `ae4d89601a5b858994ec88695d8c624ebc510750`. Deterministic results use the real LangGraph workflow with scripted models and fake infrastructure; hosted results use the configured live model, GitHub MCP, immutable clone, and AgentCore Code Interpreter.

## Tool and policy boundary

```mermaid
flowchart LR
  M[Configured model] --> A[Four-tool inspection allowlist]
  A --> P{Deterministic policy and approval boundary}
  P --> R[Read-only GitHub inspection]
  P --> W[Disposable workspace operations]
  P --> V[Isolated validation backend]
  P --> E[Redacted evidence and audit]
  P -. config + policy gates .-> G[Optional remote draft PR write]
  G -. never .-> X[Merge or deploy]
```

## Deterministic evaluation

Overall: **1/1** trials passed; final status `DRAFT_PR_PREPARED`.
Model evidence: **7** calls, **0 ms** total latency, **0/0** input/output tokens recorded.

| Metric | Result | Detail |
|---|---:|---|
| `terminal_status` | 1/1 | DRAFT_PR_PREPARED |
| `required_validations` | 1/1 | passed=['average_regression', 'javascript_syntax']; required=['average_regression', 'javascript_syntax'] |
| `inspection_allowlist` | 1/1 | called=['get_repository_tree', 'get_file_contents', 'search_code', 'finish_inspection'] |
| `commit_pinned_inspection` | 1/1 | successful pinned tree/file calls=2 |
| `validation_backend` | 1/1 | expected=FAKE; observed=['FAKE', 'FAKE'] |
| `cleanup` | 1/1 | workspace=True |
| `no_remote_writes` | 1/1 | created=0 |
| `no_approval_interrupt` | 1/1 | approval interrupt is an evaluation failure |

### Validation execution evidence

| Task | Backend | Executor | Input digest | Session digest | Cleanup | Outcome |
|---|---|---|---|---|---|---|
| `javascript_syntax` | `FAKE` | `fake-sandbox` | `sha256:23683e72eba7eda9830d142d18673e2826dbc94979bbbe1c3c7d97dd89380966` | `n/a` | `NOT_APPLICABLE` | `PASSED` |
| `average_regression` | `FAKE` | `fake-sandbox` | `sha256:39bb98c5edb34e08eef8498d7fb38c4b7447e886153df539b921d37c21cdfaea` | `n/a` | `NOT_APPLICABLE` | `PASSED` |

### Artifact digests

- `config/evaluation/division-by-zero.json`: `sha256:b3184b10792f9291d5efa073a353dc3cf2fc96d39c696b7ebbd1d83e33cd96b3`
- `demo-ui/src/scenarios/division-by-zero.json`: `sha256:7b5b0198f3636551b7928bda70ea6155c5ff66bb9d19fa5989d8f627453d4ece`
- `config/policies/agentcore-demo.json`: `sha256:04bd994f8c94cf34ccf1e9bf9c5cb3df732f18348ec2e9c02c440dcdd7ec557e`

## Hosted demonstration

This 1-trial result is demonstration evidence, not a statistically meaningful success rate.

Overall: **0/1** trials passed; final status `AWAITING_APPROVAL`.
Model evidence: **6** calls, **24995 ms** total latency, **16888/1733** input/output tokens recorded.

| Metric | Result | Detail |
|---|---:|---|
| `terminal_status` | 0/1 | AWAITING_APPROVAL |
| `required_validations` | 0/1 | passed=[]; required=['average_regression', 'javascript_syntax'] |
| `inspection_allowlist` | 1/1 | called=['get_repository_tree', 'get_file_contents', 'get_file_contents', 'finish_inspection'] |
| `commit_pinned_inspection` | 1/1 | successful pinned tree/file calls=1 |
| `validation_backend` | 0/1 | expected=AGENTCORE_CODE_INTERPRETER; observed=[] |
| `cleanup` | 0/1 | workspace=False |
| `no_remote_writes` | 1/1 | created=0 |
| `no_approval_interrupt` | 0/1 | approval interrupt is an evaluation failure |

### Validation execution evidence

No validation execution records were produced.

### Artifact digests

- `config/evaluation/division-by-zero.json`: `sha256:b3184b10792f9291d5efa073a353dc3cf2fc96d39c696b7ebbd1d83e33cd96b3`
- `demo-ui/src/scenarios/division-by-zero.json`: `sha256:7b5b0198f3636551b7928bda70ea6155c5ff66bb9d19fa5989d8f627453d4ece`
- `config/policies/agentcore-demo.json`: `sha256:04bd994f8c94cf34ccf1e9bf9c5cb3df732f18348ec2e9c02c440dcdd7ec557e`

## Security controls and negative assertions

- Model calls are limited to the commit-pinned inspection/control allowlist.
- Validation task names and fixed argument arrays come from operator policy; no model-generated shell is run.
- Hosted evaluation forces both application GitHub write gates off and fails on approval or remote creation.
- Evaluation JSON excludes prompts, repository contents, unrestricted task output, credentials, and raw session IDs.
- Validation records contain only bounded metadata and a one-way session digest where applicable.

## Reproduction

```bash
make evaluate
make evaluate-hosted  # opt-in credentials and cloud access required
make assessment-report
```

## Limitations and residual risks

The deterministic run establishes repeatability, not live-provider performance. A single hosted run is demonstration evidence only and is not a statistically meaningful success rate. Provider availability, model variation, GitHub MCP schema changes, and cloud cleanup failures remain operational risks. The prepared draft payload is local; the evaluator neither creates nor merges a pull request and never deploys.
