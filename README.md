# AIOS Remediation Agent

The remediation agent for AIOS (Agentic AI for IT Operations Support). It receives a `DiagnosisHandoffV1` from the
diagnosis agent, inspects the repository, plans and validates a code or configuration fix in a disposable workspace,
and returns a `RemediationHandoffV1` with a draft pull request for the verification agent.

Built with Python 3.12, FastAPI, LangGraph and Pydantic v2, and hosted on Amazon Bedrock AgentCore Runtime.

## Tools

The model calls four tools during inspection:

| Tool | Source | Purpose |
|---|---|---|
| `get_repository_tree` | GitHub MCP | List files at the pinned base commit |
| `get_file_contents` | GitHub MCP | Read a file at the pinned base commit |
| `search_code` | GitHub MCP | Locate candidate files |
| `finish_inspection` | Local | End inspection with a rationale |

The workflow host runs the other 13 tools through typed ports:

| Integration | Tools |
|---|---|
| Repository workspace | `create_workspace`, `current_diff`, `create_branch`, `commit`, `push` |
| Validation sandbox (Docker or AgentCore Code Interpreter) | `apply_patch`, `restore_base`, `run_task`, `destroy` |
| Draft pull request | `prepare`, `create_draft` |
| Evidence and audit | `write_bundle`, `write` |

`GET /v1/tools` returns the full catalogue.

## Model providers

| `AIOS_LLM_PROVIDER` | Adapter | Settings |
|---|---|---|
| `bedrock` | `ChatBedrockConverse` | `AIOS_LLM_MODEL`, `AIOS_AWS_REGION` |
| `openai` | `ChatOpenAI` | `AIOS_LLM_MODEL`, `AIOS_OPENAI_AUTH_MODE`, then `AIOS_OPENAI_GATEWAY_ARN` or `OPENAI_API_KEY` |
| `deepseek` | `ChatDeepSeek` | `AIOS_LLM_MODEL`, `DEEPSEEK_API_KEY` |
| `fake` | `FakeStructuredModel` | Tests only |

## Repository structure

```text
├── src/remediation_agent/
│   ├── api/          # FastAPI routes
│   ├── workflow/     # LangGraph graph, nodes and state
│   ├── domain/       # Handoff, plan and outcome models
│   ├── policy/       # Operator policy engine
│   ├── ports/        # Typed interfaces
│   ├── adapters/     # Model, GitHub MCP, Git, sandbox, checkpoint and evidence adapters
│   ├── tools/        # Tool catalogue and finish_inspection
│   └── prompts/      # Versioned prompts
├── config/
│   ├── policies/     # Operator policies
│   └── schemas/      # Generated JSON Schemas
├── tests/            # Unit, graph, MCP, security and integration tests
├── docker/           # Validation sandbox image
├── Dockerfile.agentcore
└── openapi.yaml
```

## Quick start

Requires Python 3.12, [uv](https://docs.astral.sh/uv/), Git and Docker.

```bash
cp .env.example .env
uv sync --frozen
make sandbox-build
make db-up
make db-init
uv run remediation-agent
```

The API runs at `http://127.0.0.1:8080`, with interactive docs at `/docs`.

```bash
curl --request POST http://127.0.0.1:8080/v1/remediations \
  --header 'Content-Type: application/json' \
  --data @diagnosis-handoff.json
```

## Configuration

| Setting | Purpose |
|---|---|
| `AIOS_POLICY_FILE` | Operator policy, for example `config/policies/reference.json` |
| `AIOS_LLM_PROVIDER`, `AIOS_LLM_MODEL` | Model provider and model ID |
| `AIOS_AWS_REGION` | AWS Region for Bedrock and AgentCore |
| `AIOS_GITHUB_TOKEN` | GitHub token for MCP inspection and cloning |
| `AIOS_GITHUB_WRITES_ENABLED`, `AIOS_GITHUB_REPOSITORY` | Enable draft pull requests for a repository |
| `AIOS_POSTGRES_DSN` | PostgreSQL checkpoint store |
| `AIOS_CHECKPOINT_ENCRYPTION_KEY` | 16, 24 or 32-byte checkpoint encryption key |
| `AIOS_INCIDENT_MEMORY_ENABLED` | Enable AgentCore incident memory retrieval |

`.env.example` lists every setting.

## Commands

```bash
make lint
make typecheck
make test
make test-integration
make evaluate
make security
make build
```

Pushes to `main` run the CI pipeline, which tests, scans, qualifies and releases the image to AgentCore.
