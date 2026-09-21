export type ApprovalStatus = "APPROVED" | "REJECTED";

export interface ApprovalRequest {
  approval_id: string;
  case_id: string;
  kind: "PLAN" | "PATCH";
  scope_digest: string;
  summary: string;
  reasons: string[];
  requested_at: string;
  status: string;
}

export interface ValidationTaskResult {
  task_name: string;
  outcome: string;
  exit_code: number | null;
  duration_ms: number;
  stdout: string;
  stderr: string;
  output_truncated: boolean;
}

export interface ValidationAttempt {
  attempt: number;
  patch_digest: string;
  results: ValidationTaskResult[];
  outcome: string;
}

export interface ErrorRecord {
  code: string;
  stage: string;
  message: string;
  retryable: boolean;
}

export interface ExplainabilityEvent {
  sequence: number;
  timestamp: string;
  stage: string;
  actor_type: "DETERMINISTIC" | "MODEL_ASSISTED" | "TOOL" | "HUMAN";
  event_type: string;
  status: string;
  summary: string;
  policy_control_ids: string[];
}

export interface ExplainabilityToolCall {
  call_id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  status: string;
  result_digest: string;
}

export interface ExplainabilityEvidence {
  kind: "TREE" | "FILE" | "SEARCH";
  locator: string;
  digest: string;
  truncated: boolean;
}

export interface ExplainabilityModelCall {
  operation: string;
  provider: string;
  model: string;
  prompt_version: string;
  duration_ms: number;
  input_digest: string;
  output_digest: string;
  input_tokens: number | null;
  output_tokens: number | null;
  refused: boolean;
  reasoning_summary: string | null;
}

export interface ValidationExecutionRecord {
  attempt: number;
  task_name: string;
  backend: "DOCKER" | "AGENTCORE_CODE_INTERPRETER" | "FAKE";
  executor_id: string;
  input_digest: string;
  session_digest: string | null;
  enforced_controls: string[];
  cleanup_status: "SUCCEEDED" | "FAILED" | "NOT_APPLICABLE" | "UNKNOWN";
  outcome: string;
  duration_ms: number;
}

export interface ExplainabilityTrace {
  schema_version: "1.0";
  run_id: string;
  status: string;
  events: ExplainabilityEvent[];
  inspection_tool_calls: ExplainabilityToolCall[];
  evidence: ExplainabilityEvidence[];
  model_calls: ExplainabilityModelCall[];
  validation_executions?: ValidationExecutionRecord[];
}

export interface ArtifactRef {
  name: string;
  path: string;
  digest: string;
  media_type: string;
}

export interface RemediationResult {
  final_status: string;
  changed_files: string[];
  remediation_plan_summary: string | null;
  risk_summary: string | null;
  validation_attempts: ValidationAttempt[];
  errors: ErrorRecord[];
  draft_pr: {
    created: boolean;
    url: string | null;
    payload: { title: string; head_branch: string; base_branch: string };
  } | null;
  artifact_manifest: { artifacts: ArtifactRef[] } | null;
  audit_bundle_ref: ArtifactRef | null;
}

export interface RemediationRunView {
  run_id: string;
  task_id: string;
  session_id: string;
  status: string;
  failure_code: string | null;
  approval_request: ApprovalRequest | null;
  result: RemediationResult | null;
  explainability: ExplainabilityTrace | null;
}

export interface RunResponse {
  output: RemediationRunView;
}

export interface ProbeResponse {
  output: {
    status: string;
    provider: string;
    model: string;
    duration_ms: number;
    input_tokens: number | null;
    output_tokens: number | null;
    response_digest: string;
  };
}
