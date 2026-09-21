# AIOS Remediation Demo UI

This presentation-only module is a React dashboard and a small Python Lambda gateway. One public Lambda Function URL
serves the compiled application and signs calls to the existing AgentCore runtime. It deliberately has no login,
Cognito, API Gateway, database, or user-management layer.

The console is organized into three top-level views. **Run Console** contains the diagnosis handoff, workflow,
approval, explainability, and results. **Agent** contains the deployed region/runtime/model configuration and the
generated capability catalogue. **System Status** distinguishes page-serving and configured dependencies from the
only live dependency check: the operator-triggered OpenAI provider probe. Switching views never starts a run or a
connectivity check.

## Browser/API contract

| Route | Purpose |
|---|---|
| `GET /api/health` | Check only the Lambda gateway |
| `POST /api/probe` | Run one explicit OpenAI provider probe |
| `POST /api/runs` | Start with `{"run_id":"<uuid>","input":<DiagnosisHandoffV1>}` |
| `GET /api/runs/<task-uuid>?session_id=<session-uuid>` | Poll the A2A task with `GetTask` |
| `POST /api/runs/<task-uuid>/approval` | Submit a digest-bound approval with the stored `session_id` |

The `POST /api/runs` route is also the minimal Agent 2 integration point. A caller generates a canonical UUID for the
AgentCore session/A2A context and submits its existing `DiagnosisHandoffV1` as a structured A2A data part. The response
contains separate `session_id` and server-generated `task_id` values. The browser persists both, sends approvals with
A2A `SendMessage`, and polls with `GetTask`. The gateway translates task states/artifacts back into the existing
`{"output":<RemediationRunView>}` UI shape. Rejected and failed tasks may include a bounded `failure_code` copied from
the runtime's typed `text/plain` status part; malformed or free-form status text is not exposed.

When present, the additive `ExplainabilityTraceV1` part is normalized at approval checkpoints and terminal completion.
The console renders an accessible workflow graph, the ordered model/tool/evidence inspection flow, policy controls,
validation decisions, model latency/token metadata, and optional provider reasoning summaries. It never renders raw
prompts, repository file contents, diffs, credentials, or hidden chain-of-thought. Older runtimes without a trace remain
compatible and simply omit the explainability section.

The four-lane tool boundary is generated from the Python operational catalogue and separates the configured model,
four model-callable inspection/control tools, deterministic policy/approval boundary, and thirteen workflow-only
operations. It is a configuration-focused catalogue; run-specific tool calls and policy controls remain in the Run
Console explainability trace. When typed validation execution records are present, the dedicated explainability panel
shows the backend, operator-owned task controls, input and hashed-session evidence, outcome, and cleanup status; older
traces without this additive field still render normally.

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
