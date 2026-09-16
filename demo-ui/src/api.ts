import type { ApprovalStatus, ProbeResponse, RunResponse } from "./types";

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
  const body = (await response.json()) as Record<string, unknown>;
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

export function getRun(runId: string): Promise<RunResponse> {
  return request(`/api/runs/${runId}`);
}

export function decideRun(
  runId: string,
  decision: {
    approval_id: string;
    scope_digest: string;
    status: ApprovalStatus;
    reviewer_id: string;
    comment: string;
  },
): Promise<RunResponse> {
  return request(`/api/runs/${runId}/approval`, { method: "POST", body: JSON.stringify(decision) });
}
