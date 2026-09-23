# AIOS Remediation Demo UI

This presentation-only module is a React dashboard and a small Python Lambda gateway. One public Lambda Function URL
serves the compiled application and signs calls to the existing AgentCore runtime. It deliberately has no login,
Cognito, API Gateway, database, or user-management layer.

The console is organized into four top-level views. **Run Console** contains the diagnosis handoff, workflow,
approval, explainability, and results. **Runs** keeps a versioned, browser-local list of at most 20 known runs and
refreshes only when the operator requests it; it is not shared history. **Agent** contains the deployed
region/runtime/model configuration and generated capability catalogue. **System Status** distinguishes page-serving
and configured dependencies from the only live dependency check: the operator-triggered OpenAI provider probe.
Switching views never starts a run or a connectivity check.

## Browser/API contract

| Route | Purpose |
|---|---|
| `GET /api/health` | Check only the Lambda gateway |
| `POST /api/probe` | Run one explicit OpenAI provider probe |
| `POST /api/runs` | Start with `{"run_id":"<uuid>","input":<DiagnosisHandoffV1>}` |
| `GET /api/runs/<task-uuid>?session_id=<session-uuid>` | Poll the A2A task with `GetTask` |
| `POST /api/runs/<task-uuid>/approval` | Submit a digest-bound approval with the stored `session_id` |
| `POST /api/runs/<task-uuid>/artifacts/preview` | Read one session-scoped, manifest-selected evidence artifact |

The `POST /api/runs` route is also the minimal Agent 2 integration point. A caller generates a canonical UUID for the
AgentCore session/A2A context and submits its existing `DiagnosisHandoffV1` as a structured A2A data part. The response
contains separate `session_id` and server-generated `task_id` values. The browser persists both, sends approvals with
A2A `SendMessage`, and polls with `GetTask`. The gateway translates task states/artifacts back into the existing
`{"output":<RemediationRunView>}` UI shape. Rejected and failed tasks may include a bounded `failure_code` copied from
the runtime's typed `text/plain` status part; malformed or free-form status text is not exposed.

When present, the additive `ExplainabilityTraceV1` part is normalized at approval checkpoints and terminal completion.
The console renders an accessible workflow graph, the ordered model/tool/evidence inspection flow, policy controls,
validation decisions, model latency/token metadata, and optional provider reasoning summaries. It never renders raw
prompts, credentials, hidden chain-of-thought, or arbitrary repository reads. At terminal completion, an operator who
holds the browser-local task/session locator may explicitly preview any redacted artifact named by that run's manifest,
including the stored patch, audit JSONL, and model-call records. The runtime resolves the source task through the
caller/tenant/session-scoped task store, rejects browser-supplied object paths, verifies the stored SHA-256 digest,
reapplies redaction, limits objects to 1 MiB, and returns at most 256 KiB of UTF-8 content. Older runtimes without a
trace remain compatible and simply omit the explainability section.

The recent-run repository is asynchronous and source-agnostic even though the initial adapter uses versioned
`localStorage`. A future authenticated shared-history API can replace that adapter; the current public demo must not
present its browser-local entries as global history. Artifact bodies are fetched only while the viewer is open and are
never persisted by the browser.

The four-lane tool boundary is generated from the Python operational catalogue and separates the configured model,
four model-callable inspection/control tools, deterministic policy/approval boundary, and thirteen workflow-only
operations. It is a configuration-focused catalogue; run-specific tool calls and policy controls remain in the Run
Console explainability trace. When typed validation execution records are present, the dedicated explainability panel
shows the backend, operator-owned task controls, input and hashed-session evidence, outcome, and cleanup status; older
traces without this additive field still render normally.

The same panel shows optional incident-memory status, bounded match identifiers, score, age, admission type, retrieval
latency, and final write status. It explicitly labels memory as advisory: it cannot replace commit-pinned inspection,
authorize tools or paths, reuse a historical patch, or bypass policy and validation. Disabled, no-match, and transient
error states all continue through normal repository inspection.

## Development and build

```bash
cd demo-ui
npm ci
npm run typecheck
npm test
npm run build
```

From `remediation-agent/`, `make demo-ui-deploy` runs those checks, builds an ARM64-compatible deployment package,
updates only the code of the existing `aios-remediation-demo-ui` Lambda in `ap-southeast-1`, and verifies the public
health route, compiled JavaScript asset, and explicit provider probe. The command refuses the wrong AWS account or
Lambda configuration and restores the previous code package when a post-deployment smoke check fails.

The production build is written to `backend/site/` and is intentionally ignored by Git. The deployment zip must place
`handler.py`, the generated `site/` directory, and the packages from `backend/requirements.txt` at its root. Configure:

- `AGENTCORE_RUNTIME_ARN`
- `AGENTCORE_REGION=ap-southeast-1`
- `AGENTCORE_QUALIFIER=DEFAULT`

Use a 900-second Lambda timeout. The handler gives the AgentCore client an 880-second read timeout while the workflow
retains its own 840-second deadline. The Lambda role needs only CloudWatch logging and
`bedrock-agentcore:InvokeAgentRuntime` on the configured runtime.

The default handoff targets Jira ticket `TICKET-111` and the division-by-zero defect at the immutable `main` commit
currently deployed from `MtechSE-ArchAI-Team7/buggy-ecommerce-demo`. The Elastic Beanstalk URL is displayed as
read-only diagnosis evidence.
Loading or deploying this UI does not submit the handoff; only the explicit **Create remediation run** action can start
the workflow and, when GitHub writes are enabled, eventually create a draft pull request.
