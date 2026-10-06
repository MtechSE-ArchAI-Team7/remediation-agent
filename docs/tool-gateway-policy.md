# AgentCore Tool Gateway Policy Reference

## Purpose and minimal architecture

This optional transport places the remediation agent's three GitHub inspection tools behind one shared Amazon Bedrock
AgentCore Gateway. It remains infrastructure inside the single Resolution/Remediation Agent; it is not another agent,
MCP server, Lambda, mutation boundary, or validation backend.

```text
Resolution/Remediation Agent
  -> SigV4 POST to the exact AgentCore Gateway /mcp endpoint
  -> AWS_IAM authentication and Cedar default-deny authorization
  -> GitHubInspection target using a credential-provider bearer token
  -> GitHub hosted MCP all-toolsets read-only endpoint
```

The Gateway exposes only three namespaced actions. `AgentCoreGatewayInspectionTools` validates their names and schemas,
maps them back to the existing native model-visible names, and preserves all application repository, immutable-SHA,
path, secret, redaction, output, timeout, round, and call-budget checks. `finish_inspection` stays local. Workspace,
patch, validation, Git, branch, push, pull-request, approval, artifact, credential, and cleanup operations never enter
the Gateway.

Direct GitHub MCP remains the default and explicit fallback.

## Deployed resources

All resources are in AWS account `734849394833`, Region `ap-southeast-1`.

| Resource | Actual identifier |
|---|---|
| Gateway | `aios-remediation-tool-gateway` / `aios-remediation-tool-gateway-ttjasjfwdp` |
| Gateway ARN | `arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:gateway/aios-remediation-tool-gateway-ttjasjfwdp` |
| Gateway URL | `https://aios-remediation-tool-gateway-ttjasjfwdp.gateway.bedrock-agentcore.ap-southeast-1.amazonaws.com/mcp` |
| Target | `GitHubInspection` / `LVQHEFGKNU` |
| Policy engine | `aios_remediation_tool_policy` / `aios_remediation_tool_policy-b9_1u07zno` |
| Policy-engine ARN | `arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:policy-engine/aios_remediation_tool_policy-b9_1u07zno` |
| API-key provider | `aios-remediation-github-mcp` |
| API-key-provider ARN | `arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:token-vault/default/apikeycredentialprovider/aios-remediation-github-mcp` |
| Gateway execution role | `arn:aws:iam::734849394833:role/aios-remediation-tool-gateway` |
| Gateway workload identity | `arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:workload-identity-directory/default/workload-identity/aios-remediation-tool-gateway-ttjasjfwdp` |
| Remediation runtime role | `arn:aws:iam::734849394833:role/aios-remediation-agentcore-runtime` |
| Remediation runtime | `remediation_agent-2425SXH9D3` |

The Gateway uses MCP `2025-11-25`, `AWS_IAM` inbound authentication, and policy mode `ENFORCE`. Its only target is
`https://api.githubcopilot.com/mcp/x/all/readonly`. The target bearer prefix is exactly `Bearer` without a trailing
space because AgentCore inserts the separator. Allowed propagated request headers are `X-MCP-Tools`,
`X-MCP-Readonly`, and `X-MCP-Lockdown`.

The Gateway role is scoped to its exact Gateway, workload identity, policy engine, credential provider, and generated
credential secret. The runtime role has `bedrock-agentcore:InvokeGateway` only for the Gateway ARN above.

## Allowed actions and final Cedar policies

| Native model name | AgentCore action | Policy name / ID |
|---|---|---|
| `get_repository_tree` | `GitHubInspection___get_repository_tree` | `PermitRepositoryTree` / `PermitRepositoryTree-9be8ak9j00` |
| `get_file_contents` | `GitHubInspection___get_file_contents` | `PermitFileContents` / `PermitFileContents-j700wf_uon` |
| `search_code` | `GitHubInspection___search_code` | `PermitCodeSearch` / `PermitCodeSearch-akyegemfw4` |

The stable STS assumed-role form is included because AgentCore evaluates runtime role sessions under that principal.
The requested IAM role ARN and operator user ARN are also explicit. No wildcard action or principal permit exists.

### `PermitRepositoryTree`

```cedar
permit(
  principal is AgentCore::IamEntity,
  action == AgentCore::Action::"GitHubInspection___get_repository_tree",
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:gateway/aios-remediation-tool-gateway-ttjasjfwdp"
) when {
  principal.id == "arn:aws:iam::734849394833:user/aios" ||
  principal.id == "arn:aws:iam::734849394833:role/aios-remediation-agentcore-runtime" ||
  principal.id == "arn:aws:sts::734849394833:assumed-role/aios-remediation-agentcore-runtime"
};
```

### `PermitFileContents`

```cedar
permit(
  principal is AgentCore::IamEntity,
  action == AgentCore::Action::"GitHubInspection___get_file_contents",
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:gateway/aios-remediation-tool-gateway-ttjasjfwdp"
) when {
  principal.id == "arn:aws:iam::734849394833:user/aios" ||
  principal.id == "arn:aws:iam::734849394833:role/aios-remediation-agentcore-runtime" ||
  principal.id == "arn:aws:sts::734849394833:assumed-role/aios-remediation-agentcore-runtime"
};
```

### `PermitCodeSearch`

```cedar
permit(
  principal is AgentCore::IamEntity,
  action == AgentCore::Action::"GitHubInspection___search_code",
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:gateway/aios-remediation-tool-gateway-ttjasjfwdp"
) when {
  principal.id == "arn:aws:iam::734849394833:user/aios" ||
  principal.id == "arn:aws:iam::734849394833:role/aios-remediation-agentcore-runtime" ||
  principal.id == "arn:aws:sts::734849394833:assumed-role/aios-remediation-agentcore-runtime"
};
```

Cedar has default-deny semantics. With the engine in `ENFORCE`, every other synchronized GitHub MCP action is absent
from `tools/list` and cannot be invoked by these principals.

## Application settings

Gateway mode:

```text
AIOS_AWS_REGION=ap-southeast-1
AIOS_INSPECTION_MCP_MODE=agentcore_gateway
AIOS_INSPECTION_GATEWAY_ARN=arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:gateway/aios-remediation-tool-gateway-ttjasjfwdp
```

Direct mode:

```text
AIOS_AWS_REGION=ap-southeast-1
AIOS_INSPECTION_MCP_MODE=github_direct
```

Do not set `AIOS_INSPECTION_GATEWAY_ARN` in direct mode; the application rejects that stale combination. The existing
runtime GitHub token remains required for immutable clone and for separately gated optional push/draft-PR operations.

Runtime version `43` was activated with immutable image:

```text
734849394833.dkr.ecr.ap-southeast-1.amazonaws.com/aios/remediation-agent@sha256:50ae878b1f169aa3ac0209926bd8fe3d12e28c8e21de4c95d5ee16a0d0110f69
```

It preserves A2A protocol, public networking, 900-second idle timeout, 3,600-second maximum lifetime, MMDSv2, and
managed session storage at `/mnt/workspace`.

## Safe inspection and verification commands

```bash
AWS_REGION=ap-southeast-1
GATEWAY_ID=aios-remediation-tool-gateway-ttjasjfwdp
TARGET_ID=LVQHEFGKNU
POLICY_ENGINE_ID=aios_remediation_tool_policy-b9_1u07zno

aws bedrock-agentcore-control get-gateway \
  --gateway-identifier "$GATEWAY_ID" --region "$AWS_REGION"

aws bedrock-agentcore-control get-gateway-target \
  --gateway-identifier "$GATEWAY_ID" --target-id "$TARGET_ID" --region "$AWS_REGION"

aws bedrock-agentcore-control list-policies \
  --policy-engine-id "$POLICY_ENGINE_ID" --region "$AWS_REGION"
```

Resynchronize only after an intentional upstream schema review:

```bash
aws bedrock-agentcore-control synchronize-gateway-targets \
  --gateway-identifier "$GATEWAY_ID" \
  --target-id-list "$TARGET_ID" \
  --region "$AWS_REGION"
```

Then wait for target `READY`, verify all three policy statuses are `ACTIVE`, and rerun:

```bash
AIOS_INSPECTION_GATEWAY_ARN=arn:aws:bedrock-agentcore:ap-southeast-1:734849394833:gateway/aios-remediation-tool-gateway-ttjasjfwdp \
AIOS_LIVE_GITHUB_MCP_REPOSITORY_URL=https://github.com/MtechSE-ArchAI-Team7/buggy-ecommerce-demo.git \
AIOS_LIVE_GITHUB_MCP_COMMIT_SHA=ae4d89601a5b858994ec88695d8c624ebc510750 \
make test-tool-gateway-live
```

That test requires the current `aios` AWS credentials. It must list exactly the three namespaced actions, call tree,
file, and search successfully, and expose no mutation action.

## GitHub PAT rotation

The provider value is sensitive. Never put a PAT in command arguments, files, shell history, documentation, logs, or
captured output. Rotate interactively in memory:

```python
from getpass import getpass
import boto3

client = boto3.client("bedrock-agentcore-control", region_name="ap-southeast-1")
client.update_api_key_credential_provider(
    name="aios-remediation-github-mcp",
    apiKey=getpass("New GitHub PAT: "),
)
```

Rotate the original runtime secret separately through the approved secret-management procedure because clone and any
enabled GitHub writes still read that value. Verify the provider and runtime secret remain consistent, resynchronize
the target, and rerun both live tests. Never retrieve either value merely to compare or display it.

## Direct fallback and runtime rollback

For a transport-only fallback, keep the version `43` image, change
`AIOS_INSPECTION_MCP_MODE` to `github_direct`, and remove `AIOS_INSPECTION_GATEWAY_ARN`. An AgentCore runtime update is
full replacement: first read the current runtime and preserve its image, role, complete environment map, A2A protocol,
network, lifecycle, MMDSv2, and filesystem configurations.

For a full rollback, version `42` used:

```text
734849394833.dkr.ecr.ap-southeast-1.amazonaws.com/aios/remediation-agent@sha256:23e626f1987357c1e7d90efc2925cf78e99a8f4eb1af9aacf79d12ec0b84e817
```

Use a current AWS CLI/SDK that supports `filesystemConfigurations`. Supply the preserved environment map with
`AIOS_INSPECTION_MCP_MODE=github_direct` and no Gateway ARN, then update the existing runtime with these preserved
controls:

```bash
aws bedrock-agentcore-control update-agent-runtime \
  --agent-runtime-id remediation_agent-2425SXH9D3 \
  --agent-runtime-artifact '{"containerConfiguration":{"containerUri":"<current-or-version-42-digest-uri>"}}' \
  --role-arn arn:aws:iam::734849394833:role/aios-remediation-agentcore-runtime \
  --network-configuration '{"networkMode":"PUBLIC"}' \
  --protocol-configuration '{"serverProtocol":"A2A"}' \
  --lifecycle-configuration '{"idleRuntimeSessionTimeout":900,"maxLifetime":3600}' \
  --metadata-configuration '{"requireMMDSV2":true}' \
  --filesystem-configurations '[{"sessionStorage":{"mountPath":"/mnt/workspace"}}]' \
  --environment-variables file://<reviewed-direct-mode-environment.json> \
  --region ap-southeast-1
```

Wait for the exact new immutable version to reach `READY`, confirm all preserved fields, and run the bounded provider
probe. If an update fails, immediately repeat the update using the version `42` image and its preserved environment.
Do not delete the Gateway during runtime rollback; keeping it allows diagnosis and a later controlled cutover.

## Resource recreation order

1. Create the exact-trust Gateway execution role with temporary creation-scoped resource patterns.
2. Create `aios_remediation_tool_policy` and leave the future Gateway in `LOG_ONLY`.
3. Create `aios-remediation-github-mcp` from an interactively supplied PAT; never capture its generated backing secret.
4. Create the IAM-authenticated MCP `2025-11-25` Gateway and record its Gateway/workload-identity ARNs.
5. Tighten the execution-role resource patterns to those exact ARNs.
6. Create target `GitHubInspection` at `/mcp/x/all/readonly`, using API-key header `Authorization`, prefix `Bearer`,
   and the three allowed request headers.
7. Wait for target `READY`, enumerate all pages of synchronized actions, and validate the three action names above.
8. Create the three Cedar permits with `FAIL_ON_ANY_FINDINGS`; wait for every policy to become `ACTIVE`.
9. Switch the policy engine from `LOG_ONLY` to `ENFORCE`; verify `tools/list` returns exactly three actions.
10. Grant the remediation runtime role `bedrock-agentcore:InvokeGateway` only on the exact Gateway ARN.
11. Deploy a verified immutable ARM64 runtime image, preserve all runtime controls, and add the Gateway-mode settings.
12. Run the live Gateway contract and hosted unsafe-remediation check before writing or updating this reference.

## Verification record

- Enforced operator `tools/list`: exactly three actions; no mutation tool visible.
- Live Gateway contract at `ae4d89601a5b858994ec88695d8c624ebc510750`: tree, file, and search all succeeded.
- Runtime version `43` bounded provider probe: `ok`.
- Hosted unsafe copy: `EVAL-08-GATEWAY-LIVE-159e1710`, task `8a993d38-cc4e-4e48-b6a8-c6b281bbc352`.
- Hosted result: `UNSAFE_REMEDIATION`; tree plus two file reads; zero changed files, diff, patch application,
  validation, branch, commit, push, or PR activity; cleanup `OK`.
- The historical case-08 commit no longer matched remote `main` at test time. The hosted copy therefore used current
  immutable `main` commit `57ed91fc052fba6f2ed07f263e9dbd899234bf7c`; the separate live Gateway contract retained the required historical SHA.

## Residual risks

- The same GitHub PAT is intentionally reused for simplicity. Gateway Cedar limits Gateway actions, not the PAT's
  underlying GitHub scope. Keep the PAT least-privileged and rotate it through both storage locations.
- The target's `/x/all/readonly` route and forwarded read-only/lockdown/tool headers are defense in depth. Cedar remains
  the policy boundary; application validation remains mandatory if upstream behavior changes.
- GitHub-hosted MCP availability, synchronization, API limits, entitlements, action names, and schemas are external
  dependencies. Discovery or schema drift fails closed and can make inspection unavailable.
- `search_code` follows GitHub's search index and is locator-only, not immutable evidence. A successful commit-pinned
  tree or file read is still required.
- The approved `aios` user has broad administrative AWS authority outside this Gateway policy. The Cedar permit only
  describes Gateway tool access and does not reduce unrelated IAM permissions.
- Runtime and operator access depend on exact IAM/STS principal forms. Role renames or alternate operator identities
  require reviewed policy changes and a fresh live test.
- Default deny prevents invocation through this Gateway but does not delete the other synchronized upstream action
  definitions. Recheck the visible action set after every target synchronization.
