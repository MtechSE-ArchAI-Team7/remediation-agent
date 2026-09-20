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
  approval_request: ApprovalRequest | null;
  result: RemediationResult | null;
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
