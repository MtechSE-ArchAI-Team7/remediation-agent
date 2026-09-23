import type { ApprovalStatus, ArtifactPreviewResponse, ProbeResponse, RunResponse } from "./types";
import type { RecentRunV1 } from "./run-history";

export class GatewayError extends Error {
  constructor(
    public readonly code: string,
    public readonly status: number,
  ) {
    super(code);
    this.name = "GatewayError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "content-type": "application/json", ...init?.headers },
  });
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    throw new GatewayError("INVALID_GATEWAY_RESPONSE", response.ok ? 502 : response.status);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new GatewayError("INVALID_GATEWAY_RESPONSE", response.ok ? 502 : response.status);
  }
  const body = parsed as Record<string, unknown>;
  if (!response.ok) {
    const code = body.error ?? body.detail ?? `HTTP_${response.status}`;
    throw new GatewayError(String(code), response.status);
  }
  return body as T;
}

export function probeModel(): Promise<ProbeResponse> {
  return request("/api/probe", { method: "POST", body: "{}" });
}

export function startRun(runId: string, input: Record<string, unknown>): Promise<RunResponse> {
  return request("/api/runs", { method: "POST", body: JSON.stringify({ run_id: runId, input }) });
}

export function listRuns(): Promise<{ output: { schema_version: "1.0"; runs: RecentRunV1[] } }> {
  return request("/api/runs");
}

export function getRun(taskId: string, sessionId: string): Promise<RunResponse> {
  return request(`/api/runs/${taskId}?session_id=${encodeURIComponent(sessionId)}`);
}

export function decideRun(
  runId: string,
  sessionId: string,
  decision: {
    approval_id: string;
    scope_digest: string;
    status: ApprovalStatus;
    reviewer_id: string;
    comment: string;
  },
): Promise<RunResponse> {
  return request(`/api/runs/${runId}/approval`, {
    method: "POST",
    body: JSON.stringify({ ...decision, session_id: sessionId }),
  });
}

export function getArtifactPreview(
  taskId: string,
  sessionId: string,
  artifactName: string,
  digest: string,
): Promise<ArtifactPreviewResponse> {
  return request(`/api/runs/${taskId}/artifacts/preview`, {
    method: "POST",
    body: JSON.stringify({ session_id: sessionId, artifact_name: artifactName, digest }),
  });
}
