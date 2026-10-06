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
   `EditProposal` schemas (patch and revision) through the configured IAM gateway.
3. Push the reviewed commit to `main`. CI builds the immutable image, then the reusable qualification workflow runs
   three consecutive full hosted trials each for AH-54 and AH-56 from that image. No trial writes to GitHub or uses real
   approval decisions. One failed trial stops that case and blocks deployment; artifacts retain the failure evidence.
4. The deploy job downloads those reports from the same Actions run and rejects missing/duplicate/stale evidence,
   prepared-only outcomes, failed cleanup, changed assertion digests or mismatched source/image/runtime settings. It
   also resolves the ECR tag for the full pushed SHA and requires the qualified digest. Manual image releases use the
   same qualification gate; tag-only builds do not deploy.
5. The reusable deploy workflow injects `AIOS_RELEASE_ID`, `AIOS_RELEASE_SOURCE_SHA`,
   `AIOS_RELEASE_IMAGE_DIGEST` and `AIOS_AGENTCORE_RUNTIME_ID`. Do not hand-edit these values.
6. The job verifies the AWS account, Region, source SHA, image digest, ECR URI, unique release ID, exact runtime version,
   runtime status, `/mnt/workspace` session-storage mount and `AIOS_WORKSPACE_ROOT`.
7. The bounded provider canary resolves release provenance and exercises an internal schema with an optional/defaulted
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


## Operator qualification permissions

Apply `config/operator/release-qualification-policy.json` only to the existing
`github-actions-remediation-agentcore-deploy` role. It adds read access to the single Agent 3 ECR repository,
`ecr:GetAuthorizationToken` on `*` (AWS requires that scope), invocation of the configured IAM model gateway, and
start/invoke/stop access to the system `aws.codeinterpreter.v1` sandbox. The role's existing main-branch OIDC trust and
one-hour sessions remain unchanged. This does not add runtime-agent authority or provision cloud resources.

Each qualification job runs one case three times, with a 55-minute job limit and a one-hour OIDC session. Reports bind
policy, offline assets, model configuration, prompt version, source archive, source SHA and image digest. A runtime
configuration change after qualification invalidates the gate. Automatic rollback retains its existing guarded path;
rollback is recovery of the preceding attested version, not permission to bypass qualification for a new release.

`make qualify-workflow-docker` and `make qualify-workflow-hosted` are explicit development qualifications. Their outputs
are named `development-trials.json` unless source/image/runtime bindings are supplied by the release job. A synthetic
qualification handoff is never a substitute for the fresh native Agent 2 delivery used after release.
