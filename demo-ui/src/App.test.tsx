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

describe("AIOS remediation console", () => {
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

    fireEvent.click(screen.getByRole("button", { name: "Create remediation run" }));

    expect((await screen.findAllByText("DRAFT PR CREATED")).length).toBeGreaterThan(0);
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

    fireEvent.click(screen.getByRole("button", { name: "Refresh saved run" }));

    const errorStatuses = await screen.findAllByText("INTERNAL ERROR");
    expect(errorStatuses.length).toBeGreaterThan(0);
    expect(errorStatuses.some((item) => item.classList.contains("error"))).toBe(true);
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
              reasons: ["Review the patch scope", "A sensitive path requires approval."],
              requested_at: "2026-09-16T00:00:00Z",
              status: "PENDING",
            },
          }),
        ),
      )
      .mockResolvedValueOnce(response(runView("DRAFT_PR_CREATED")));
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Create remediation run" }));
    expect(await screen.findAllByText("Review the patch scope")).toHaveLength(1);
    expect(screen.getAllByText("AWAITING APPROVAL").some((item) => item.classList.contains("warning"))).toBe(true);
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
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText("agentcore timeout")).toBeInTheDocument();
  });

  it("presents workflow, validation, evidence, and the draft PR as console results", async () => {
    fetchMock.mockResolvedValue(
      response(
        runView("DRAFT_PR_CREATED", {
          result: {
            final_status: "DRAFT_PR_CREATED",
            changed_files: ["src/orders.py", "tests/test_orders.py"],
            remediation_plan_summary: "Correct the inclusive stock boundary and add regression coverage.",
            risk_summary: "The change is limited to order availability behavior.",
            validation_attempts: [
              {
                attempt: 1,
                patch_digest: "sha256:patch",
                outcome: "PASSED",
                results: [
                  {
                    task_name: "unit_tests",
                    outcome: "PASSED",
                    exit_code: 0,
                    duration_ms: 1842,
                    stdout: "2 passed",
                    stderr: "",
                    output_truncated: false,
                  },
                ],
              },
            ],
            errors: [],
            draft_pr: {
              created: true,
              url: "https://github.com/MtechSE-ArchAI-Team7/aios-remediation-demo/pull/2",
              payload: {
                title: "Fix stock boundary",
                head_branch: "aios/remediation-demo",
                base_branch: "scenario/02-stock-boundary",
              },
            },
            artifact_manifest: {
              artifacts: [
                {
                  name: "validation-results.json",
                  path: "s3://demo/runs/run/validation-results.json",
                  digest: "sha256:validation",
                  media_type: "application/json",
                },
                {
                  name: "patch.diff",
                  path: "s3://demo/runs/run/patch.diff",
                  digest: "sha256:patch",
                  media_type: "text/x-diff",
                },
              ],
            },
            audit_bundle_ref: {
              name: "audit-manifest.json",
              path: "s3://demo/runs/run/audit-manifest.json",
              digest: "sha256:audit",
              media_type: "application/json",
            },
          },
        }),
      ),
    );
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Create remediation run" }));

    expect((await screen.findAllByText("DRAFT PR CREATED")).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Open draft pull request ↗" })).toHaveAttribute(
      "href",
      "https://github.com/MtechSE-ArchAI-Team7/aios-remediation-demo/pull/2",
    );
    expect(screen.getByText("unit_tests")).toBeInTheDocument();
    expect(screen.getAllByText("PASSED").some((item) => item.classList.contains("success"))).toBe(true);
    expect(screen.getByText("validation-results.json")).toBeInTheDocument();
    expect(screen.getByText("patch.diff")).toBeInTheDocument();
    expect(screen.getByText("Audit bundle")).toBeInTheDocument();
    expect(screen.getAllByText("complete")).toHaveLength(5);
  });
});
