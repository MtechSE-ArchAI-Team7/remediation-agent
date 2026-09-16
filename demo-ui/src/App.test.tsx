import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";

const RUN_ID = "2db1f13e-7351-4a1f-a4c6-630646366d52";

function response(body: object, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response;
}

function runView(status: string, extra: Record<string, unknown> = {}) {
  return { output: { run_id: RUN_ID, status, approval_request: null, result: null, ...extra } };
}

describe("AgentCore demo console", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    localStorage.clear();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => RUN_ID });
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("starts the preloaded handoff and persists the run id", async () => {
    fetchMock.mockResolvedValue(response(runView("DRAFT_PR_CREATED")));
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Start remediation" }));

    expect(await screen.findByRole("heading", { name: "DRAFT PR CREATED" })).toBeInTheDocument();
    expect(localStorage.getItem("aios-remediation-demo-run-id")).toBe(RUN_ID);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/runs",
      expect.objectContaining({ method: "POST", body: expect.stringContaining("CASE-DEMO-02") }),
    );
  });

  it("resumes a saved run", async () => {
    localStorage.setItem("aios-remediation-demo-run-id", RUN_ID);
    fetchMock.mockResolvedValue(response(runView("INTERNAL_ERROR")));
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Resume saved run" }));

    expect(await screen.findByRole("heading", { name: "INTERNAL ERROR" })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/runs/${RUN_ID}`,
      expect.objectContaining({ headers: expect.any(Object) }),
    );
  });

  it("submits the exact approval binding and default reviewer", async () => {
    fetchMock
      .mockResolvedValueOnce(
        response(
          runView("AWAITING_APPROVAL", {
            approval_request: {
              approval_id: "approval-1",
              case_id: "CASE-DEMO-02",
              kind: "PATCH",
              scope_digest: "sha256:abc",
              summary: "Review the patch scope",
              reasons: ["A sensitive path requires approval."],
              requested_at: "2026-09-16T00:00:00Z",
              status: "PENDING",
            },
          }),
        ),
      )
      .mockResolvedValueOnce(response(runView("DRAFT_PR_CREATED")));
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Start remediation" }));
    fireEvent.click(await screen.findByRole("button", { name: "Approve and continue" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    const approvalCall = fetchMock.mock.calls[1];
    expect(approvalCall[0]).toBe(`/api/runs/${RUN_ID}/approval`);
    expect(String(approvalCall[1]?.body)).toContain('"reviewer_id":"Arabasta"');
    expect(String(approvalCall[1]?.body)).toContain('"scope_digest":"sha256:abc"');
  });

  it("shows stable gateway failures in readable form", async () => {
    fetchMock.mockResolvedValue(response({ error: "AGENTCORE_TIMEOUT" }, 504));
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Test OpenAI connection" }));
    expect(await screen.findByText("agentcore timeout")).toBeInTheDocument();
  });
});
