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
| `GET /api/runs/<uuid>` | Retrieve or resume the run using the same AgentCore session UUID |
| `POST /api/runs/<uuid>/approval` | Submit an approval bound to the returned approval ID and scope digest |

The `POST /api/runs` route is also the minimal Agent 2 integration point. A caller generates and retains a canonical
UUID, submits its existing `DiagnosisHandoffV1` as `input`, and uses that UUID for retrieval. The gateway response keeps
the existing `{"output":<RemediationRunView>}` shape.

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
