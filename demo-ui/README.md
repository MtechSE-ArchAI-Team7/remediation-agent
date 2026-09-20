# AIOS Remediation Demo UI

This presentation-only module is a React dashboard and a small Python Lambda gateway. One public Lambda Function URL
serves the compiled application and signs calls to the existing AgentCore runtime. It deliberately has no login,
Cognito, API Gateway, database, or user-management layer.

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
`{"output":<RemediationRunView>}` UI shape.

## Development and build

```bash
cd demo-ui
npm ci
npm run typecheck
npm test
npm run build
```

The production build is written to `backend/site/` and is intentionally ignored by Git. The deployment zip must place
`handler.py`, the generated `site/` directory, and the packages from `backend/requirements.txt` at its root. Configure:

- `AGENTCORE_RUNTIME_ARN`
- `AGENTCORE_REGION=ap-southeast-1`
- `AGENTCORE_QUALIFIER=DEFAULT`

Use a 900-second Lambda timeout. The handler gives the AgentCore client an 880-second read timeout while the workflow
retains its own 840-second deadline. The Lambda role needs only CloudWatch logging and
`bedrock-agentcore:InvokeAgentRuntime` on the configured runtime.
