# AgentCore Release Runbook

Release Agent 3 only through `.github/workflows/deploy-agentcore-runtime.yaml`. Never call `UpdateAgentRuntime` directly.
The workflow is bound to AWS account `734849394833`, Region `ap-southeast-1` and runtime
`remediation_agent-2425SXH9D3`.

## One-time runtime role permission

The runtime role needs these read-only additions:

```json
[
  {
    "Effect": "Allow",
    "Action": "bedrock-agentcore:ListAgentRuntimeVersions",
    "Resource": "*"
  },
  {
    "Effect": "Allow",
    "Action": "bedrock-agentcore:GetAgentRuntime",
    "Resource": "arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:runtime/remediation_agent-2425SXH9D3"
  }
]
```

AWS does not support resource scoping for `ListAgentRuntimeVersions`. The application still binds every list and get to
the configured runtime ID and caps the scan with `AIOS_RELEASE_MAX_RUNTIME_VERSIONS`.

## Guarded release

1. Run format, lint, strict mypy, default tests, MCP tests, security checks, package build and Docker integration.
2. Run the explicitly opted-in `make test-model-live`. It exercises the real `RemediationPlan`, `RiskAssessment` and
   `PatchCandidate` schemas through the configured IAM gateway.
3. Push the reviewed commit to `main`. The existing CI/image workflow builds and deploys the immutable digest.
4. The reusable deploy workflow injects `AIOS_RELEASE_ID`, `AIOS_RELEASE_SOURCE_SHA`,
   `AIOS_RELEASE_IMAGE_DIGEST` and `AIOS_AGENTCORE_RUNTIME_ID`. Do not hand-edit these values.
5. The job verifies the AWS account, Region, source SHA, image digest, ECR URI, unique release ID, exact runtime version,
   runtime status, `/mnt/workspace` session-storage mount and `AIOS_WORKSPACE_ROOT`.
6. The bounded provider canary resolves release provenance and exercises an internal schema with an optional/defaulted
   map. A return to strict provider JSON-schema mode therefore fails the release.

Each normal deployment uses `${github.run_id}-${github.run_attempt}` as its release ID. Automatic rollback creates a
new `rollback-...` release ID while retaining the previous source SHA and image digest. Rollback preserves unrelated
environment, lifecycle, network, metadata and filesystem settings and must also reach `READY` with the required mount.

After success, compare the ECR digest tagged by the pushed SHA with the exact AgentCore version and invoke the bounded
provider probe. A control-plane `READY` result alone is insufficient.

## Incident replay

Replay a failed case with a new task/run ID and runtime session. Obtain a newly issued `DiagnosisHandoffV1` from Agent 2;
never reconstruct a missing diagnosis from logs, summaries or Jira. A sensitive plan or patch may stop at an approval
interrupt. Do not auto-approve it. Agent 4 remains the independent post-deployment verifier.
