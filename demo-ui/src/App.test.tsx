import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";

const RUN_ID = "2db1f13e-7351-4a1f-a4c6-630646366d52";

function response(body: object, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response;
}

function nonJsonResponse(status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => Promise.reject(new SyntaxError("Unexpected token '<'")),
  } as unknown as Response;
}

function runView(status: string, extra: Record<string, unknown> = {}) {
  return {
    output: {
      run_id: RUN_ID,
      task_id: RUN_ID,
      session_id: RUN_ID,
      status,
      failure_code: null,
      approval_request: null,
      result: null,
      ...extra,
    },
  };
}

function runList(status: string) {
  return {
    output: {
      schema_version: "1.0",
      runs: [{
        schema_version: "1.0",
        task_id: RUN_ID,
        session_id: RUN_ID,
        case_id: "CASE-ECOM-AVG-001",
        jira_ticket_id: "TICKET-111",
        repository: "MtechSE-ArchAI-Team7/buggy-ecommerce-demo",
        status,
        created_at: "2026-09-23T00:00:00Z",
        updated_at: "2026-09-23T00:01:00Z",
        draft_pr_url: null,
        artifact_count: 0,
        stale: false,
      }],
    },
  };
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
    fetchMock
      .mockResolvedValueOnce(response(runView("DRAFT_PR_CREATED")))
      .mockResolvedValueOnce(response(runList("DRAFT_PR_CREATED")));
    render(<App />);

    expect(screen.getByRole("tab", { name: "Run Console" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("Tool and policy boundary")).not.toBeVisible();
    fireEvent.click(screen.getByRole("tab", { name: "Agent" }));
    expect(screen.getByText("Tool and policy boundary")).toBeInTheDocument();
    expect(screen.getByText("4", { selector: ".boundary-summary strong" })).toBeInTheDocument();
    expect(screen.getByText("13", { selector: ".boundary-summary strong" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Run Console" }));
    expect(screen.getByText("MtechSE-ArchAI-Team7/buggy-ecommerce-demo")).toBeInTheDocument();
    expect(screen.getByText("TICKET-111")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /aios-ecommerce\.ap-southeast-1\.elasticbeanstalk\.com/ })).toHaveAttribute(
      "href",
      "http://aios-ecommerce.ap-southeast-1.elasticbeanstalk.com/",
    );
    fireEvent.click(screen.getByRole("button", { name: "Create remediation run" }));

    expect((await screen.findAllByText("DRAFT PR CREATED")).length).toBeGreaterThan(0);
    expect(localStorage.getItem("aios-remediation-ecommerce-run-id")).toBe(RUN_ID);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/runs",
      expect.objectContaining({ method: "POST", body: expect.stringContaining("CASE-ECOM-AVG-001") }),
    );
    expect(String(fetchMock.mock.calls[0][1]?.body)).toContain("ae4d89601a5b858994ec88695d8c624ebc510750");
    expect(String(fetchMock.mock.calls[0][1]?.body)).toContain('"jira_ticket_id":"TICKET-111"');
  });

  it("resumes a saved run", async () => {
    localStorage.setItem("aios-remediation-ecommerce-run-id", RUN_ID);
    localStorage.setItem("aios-remediation-ecommerce-run-id:session", RUN_ID);
    fetchMock.mockResolvedValue(
      response(
        runView("INTERNAL_ERROR", {
          explainability: {
            schema_version: "1.0",
            run_id: RUN_ID,
            status: "INTERNAL_ERROR",
            events: [
              {
                sequence: 1,
                timestamp: "2026-09-20T00:00:00Z",
                stage: "workspace",
                actor_type: "DETERMINISTIC",
                event_type: "WORKSPACE_CREATE_FAILED",
                status: "ERROR",
                summary: "Repository access failed.",
                policy_control_ids: [],
              },
            ],
            inspection_tool_calls: [],
            evidence: [],
            model_calls: [],
          },
        }),
      ),
    );
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Refresh saved run" }));

    const errorStatuses = await screen.findAllByText("INTERNAL ERROR");
    expect(errorStatuses.length).toBeGreaterThan(0);
    expect(errorStatuses.some((item) => item.classList.contains("error"))).toBe(true);
    expect(screen.getByText("failed", { selector: ".step-status" })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/runs/${RUN_ID}?session_id=${RUN_ID}`,
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
              case_id: "CASE-ECOM-AVG-001",
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
      .mockResolvedValueOnce(response(runList("AWAITING_APPROVAL")))
      .mockResolvedValueOnce(response(runView("DRAFT_PR_CREATED")))
      .mockResolvedValueOnce(response(runList("DRAFT_PR_CREATED")));
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Create remediation run" }));
    expect(await screen.findAllByText("Review the patch scope")).toHaveLength(1);
    expect(screen.getAllByText("AWAITING APPROVAL").some((item) => item.classList.contains("warning"))).toBe(true);
    fireEvent.click(await screen.findByRole("button", { name: "Approve and continue" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4));
    const approvalCall = fetchMock.mock.calls[2];
    expect(approvalCall[0]).toBe(`/api/runs/${RUN_ID}/approval`);
    expect(String(approvalCall[1]?.body)).toContain('"reviewer_id":"Arabasta"');
    expect(String(approvalCall[1]?.body)).toContain('"scope_digest":"sha256:abc"');
  });

  it("shows stable gateway failures in readable form", async () => {
    fetchMock.mockResolvedValue(response({ error: "AGENTCORE_TIMEOUT" }, 504));
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "System Status" }));
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText("agentcore timeout")).toBeInTheDocument();
    expect(screen.getByText("UNAVAILABLE")).toHaveClass("error");
    fireEvent.click(screen.getByRole("tab", { name: "Run Console" }));
    expect(screen.getByText("agentcore timeout")).not.toBeVisible();
  });

  it("shows the bounded A2A failure code for rejected runs", async () => {
    fetchMock.mockResolvedValue(response(runView("INVALID_REQUEST", { failure_code: "INVALID_DATA_PART" })));
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Create remediation run" }));

    expect(await screen.findByText("invalid data part")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Request failed");
  });

  it("does not mislabel non-JSON gateway responses as invalid handoff JSON", async () => {
    fetchMock.mockResolvedValue(nonJsonResponse());
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "System Status" }));
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));

    expect(await screen.findByText("invalid gateway response")).toBeInTheDocument();
    expect(screen.queryByText("The handoff JSON is not valid.")).not.toBeInTheDocument();
  });

  it("disables run creation when the handoff JSON is invalid", () => {
    render(<App />);
    fireEvent.click(screen.getByText("Advanced input"));
    fireEvent.change(screen.getByLabelText("Diagnosis handoff JSON"), { target: { value: "{" } });

    expect(screen.getByRole("button", { name: "Create remediation run" })).toBeDisabled();
  });

  it("supports keyboard tab navigation and preserves Run Console input", () => {
    render(<App />);
    fireEvent.click(screen.getByText("Advanced input"));
    const input = screen.getByLabelText("Diagnosis handoff JSON");
    fireEvent.change(input, { target: { value: '{"case_id":"preserved"}' } });

    const runTab = screen.getByRole("tab", { name: "Run Console" });
    runTab.focus();
    fireEvent.keyDown(runTab, { key: "ArrowRight" });

    const runsTab = screen.getByRole("tab", { name: "Runs" });
    expect(runsTab).toHaveFocus();
    expect(runsTab).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByRole("complementary", { name: "Run Console sections" })).not.toBeInTheDocument();

    fireEvent.keyDown(runsTab, { key: "End" });
    expect(screen.getByRole("tab", { name: "System Status" })).toHaveFocus();
    fireEvent.click(screen.getByRole("tab", { name: "Run Console" }));
    expect(screen.getByLabelText("Diagnosis handoff JSON")).toHaveValue('{"case_id":"preserved"}');
    expect(screen.getByRole("complementary", { name: "Run Console sections" })).toBeInTheDocument();
  });

  it("shows explicit provider probe results only in System Status", async () => {
    fetchMock.mockResolvedValue(response({
      output: {
        status: "SUCCEEDED",
        provider: "openai",
        model: "kei-openai-target/gpt-5.6-terra",
        duration_ms: 321,
        input_tokens: 8,
        output_tokens: 2,
        response_digest: "sha256:probe",
      },
    }));
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "System Status" }));

    expect(screen.getByText("NOT TESTED")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));

    expect(await screen.findByText("openai · kei-openai-target/gpt-5.6-terra · 321 ms")).toBeInTheDocument();
    expect(screen.getByText("AVAILABLE")).toHaveClass("success");
    expect(fetchMock).toHaveBeenCalledWith("/api/probe", expect.objectContaining({ method: "POST" }));
  });

  it("presents workflow, validation, evidence, and the draft PR as console results", async () => {
    fetchMock.mockResolvedValue(
      response(
        runView("DRAFT_PR_CREATED", {
          result: {
            final_status: "DRAFT_PR_CREATED",
            changed_files: ["server.js", "lib/calculate-average.js", "tests/calculate-average.test.js"],
            remediation_plan_summary: "Reject a zero divisor and preserve valid average calculations.",
            risk_summary: "The change is limited to the average calculation route and dependency-free tests.",
            validation_attempts: [
              {
                attempt: 1,
                patch_digest: "sha256:patch",
                outcome: "PASSED",
                results: [
                  {
                    task_name: "javascript_syntax",
                    outcome: "PASSED",
                    exit_code: 0,
                    duration_ms: 142,
                    stdout: "",
                    stderr: "",
                    output_truncated: false,
                  },
                  {
                    task_name: "average_regression",
                    outcome: "PASSED",
                    exit_code: 0,
                    duration_ms: 318,
                    stdout: "2 tests passed",
                    stderr: "",
                    output_truncated: false,
                  },
                ],
              },
            ],
            errors: [],
            draft_pr: {
              created: true,
              url: "https://github.com/MtechSE-ArchAI-Team7/buggy-ecommerce-demo/pull/8",
              payload: {
                title: "Reject division by zero in average calculation",
                head_branch: "aios/remediation/case-ecom-avg-001",
                base_branch: "main",
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
          explainability: {
            schema_version: "1.0",
            run_id: RUN_ID,
            status: "DRAFT_PR_CREATED",
            events: [
              {
                sequence: 1,
                timestamp: "2026-09-20T00:00:00Z",
                stage: "inspection",
                actor_type: "TOOL",
                event_type: "INSPECTION_TOOL_CALL",
                status: "SUCCEEDED",
                summary: "tool=get_file_contents; code=OK",
                policy_control_ids: [],
              },
              {
                sequence: 2,
                timestamp: "2026-09-20T00:00:01Z",
                stage: "risk",
                actor_type: "MODEL_ASSISTED",
                event_type: "RISK_ASSESSED",
                status: "REQUIRE_APPROVAL",
                summary: "The boundary change requires review.",
                policy_control_ids: ["BOUNDARY_CONTRACT_CHANGE"],
              },
            ],
            inspection_tool_calls: [
              {
                call_id: "call-1",
                tool_name: "get_file_contents",
                arguments: { path: "server.js" },
                status: "SUCCEEDED",
                result_digest: "sha256:tool-result",
              },
            ],
            evidence: [
              {
                kind: "FILE",
                locator: "server.js",
                digest: "sha256:evidence",
                truncated: false,
              },
            ],
            model_calls: [
              {
                operation: "RISK",
                provider: "openai",
                model: "kei-openai-target/gpt-5.6-terra",
                prompt_version: "remediation-v1",
                duration_ms: 2400,
                input_digest: "sha256:input",
                output_digest: "sha256:output",
                input_tokens: 800,
                output_tokens: 210,
                refused: false,
                reasoning_summary: "Reviewed the evidence and identified a business-rule boundary.",
              },
            ],
            validation_executions: [
              {
                attempt: 1,
                task_name: "average_regression",
                backend: "AGENTCORE_CODE_INTERPRETER",
                executor_id: "aws.codeinterpreter.v1",
                input_digest: "sha256:workspace",
                session_digest: "sha256:session",
                enforced_controls: ["OPERATOR_DEFINED_TASK", "FRESH_MANAGED_SESSION", "SESSION_CLEANUP"],
                cleanup_status: "SUCCEEDED",
                outcome: "PASSED",
                duration_ms: 318,
              },
            ],
            memory_retrieval: {
              status: "RETRIEVED",
              query_digest: "sha256:memory-query",
              duration_ms: 42,
              error_code: null,
              matches: [
                {
                  incident_id: "incident-safe-01",
                  admission_type: "EVALUATION_SEED",
                  score: 0.91,
                  age_days: 2.5,
                  repository: "MtechSE-ArchAI-Team7/buggy-ecommerce-demo",
                  incident_signature: "Average calculation rejected an empty item list.",
                  root_cause: "The divisor could become zero.",
                  remediation_summary: "Guard the empty-list branch.",
                  changed_paths: ["server.js"],
                },
              ],
            },
            memory_write: {
              status: "STORED",
              incident_id: "incident-current-01",
              duration_ms: 31,
              error_code: null,
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
      "https://github.com/MtechSE-ArchAI-Team7/buggy-ecommerce-demo/pull/8",
    );
    expect(screen.getByText("javascript_syntax")).toBeInTheDocument();
    expect(screen.getAllByText("average_regression").length).toBeGreaterThan(0);
    expect(screen.getAllByText("PASSED").some((item) => item.classList.contains("success"))).toBe(true);
    expect(screen.getByText("validation-results.json")).toBeInTheDocument();
    expect(screen.getByText("patch.diff")).toBeInTheDocument();
    expect(screen.getByText("Audit bundle")).toBeInTheDocument();
    expect(screen.getAllByText("complete", { selector: ".step-status" })).toHaveLength(5);
    expect(screen.getByText("Agent explainability")).toBeInTheDocument();
    expect(screen.getAllByText("get_file_contents").length).toBeGreaterThan(0);
    expect(screen.getByText("Reviewed the evidence and identified a business-rule boundary.")).toBeInTheDocument();
    expect(screen.getByText("server.js", { selector: ".evidence-chip-list code" })).toBeInTheDocument();
    expect(screen.getAllByText("AGENTCORE CODE INTERPRETER").length).toBeGreaterThan(0);
    expect(screen.getByText("aws.codeinterpreter.v1")).toBeInTheDocument();
    expect(screen.getByText("SESSION CLEANUP")).toBeInTheDocument();
    expect(screen.getByText("Historical incident memory")).toBeInTheDocument();
    expect(screen.getByText("incident-safe-01")).toBeInTheDocument();
    expect(screen.getByText("91% match")).toBeInTheDocument();
    expect(screen.getByText("Memory cannot authorize paths or tools, replace repository inspection, reuse a patch, or bypass policy and validation.")).toBeInTheDocument();
  });

  it("lists, refreshes, and opens shared public runs", async () => {
    fetchMock
      .mockResolvedValueOnce(response(runView("AWAITING_APPROVAL")))
      .mockResolvedValueOnce(response(runList("AWAITING_APPROVAL")))
      .mockResolvedValueOnce(response(runList("AWAITING_APPROVAL")))
      .mockResolvedValueOnce(response(runView("DRAFT_PR_CREATED")))
      .mockResolvedValueOnce(response(runView("DRAFT_PR_CREATED")));
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Create remediation run" }));
    await screen.findAllByText("AWAITING APPROVAL");
    fireEvent.click(screen.getByRole("tab", { name: "Runs" }));

    expect((await screen.findAllByText("CASE-ECOM-AVG-001")).length).toBeGreaterThan(0);
    expect(screen.getByText(/Shared public demo runs from Agent 2/)).toBeInTheDocument();
    expect(screen.getByText(/Every visitor to this demo can view these runs/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect((await screen.findAllByText("DRAFT PR CREATED")).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Open" }));
    await waitFor(() => expect(screen.getByRole("tab", { name: "Run Console" })).toHaveAttribute("aria-selected", "true"));
    expect(screen.queryByRole("button", { name: "Forget" })).not.toBeInTheDocument();
  });

  it("retains the last known run summary when a refresh fails", async () => {
    fetchMock
      .mockResolvedValueOnce(response(runView("DRAFT_PR_CREATED")))
      .mockResolvedValueOnce(response(runList("DRAFT_PR_CREATED")))
      .mockResolvedValueOnce(response(runList("DRAFT_PR_CREATED")))
      .mockResolvedValueOnce(response({ error: "AGENTCORE_TIMEOUT" }, 504));
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Create remediation run" }));
    await screen.findAllByText("DRAFT PR CREATED");
    fireEvent.click(screen.getByRole("tab", { name: "Runs" }));
    fireEvent.click(await screen.findByRole("button", { name: "Refresh" }));

    expect(await screen.findByText("agentcore timeout")).toBeInTheDocument();
    expect(screen.getByText("Last known state")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open" })).toBeInTheDocument();
  });

  it("loads an integrity-checked artifact in an accessible searchable modal", async () => {
    const digest = `sha256:${"a".repeat(64)}`;
    fetchMock
      .mockResolvedValueOnce(response(runView("DRAFT_PR_CREATED", {
        result: {
          final_status: "DRAFT_PR_CREATED",
          changed_files: ["server.js"],
          remediation_plan_summary: "Fix the route.",
          risk_summary: "Bounded change.",
          validation_attempts: [],
          errors: [],
          draft_pr: null,
          artifact_manifest: {
            artifacts: [{ name: "result.json", path: "s3://demo/result.json", digest, media_type: "application/json" }],
          },
          audit_bundle_ref: null,
        },
      })))
      .mockResolvedValueOnce(response(runList("DRAFT_PR_CREATED")))
      .mockResolvedValueOnce(response({
        output: {
          schema_version: "1.0",
          run_id: RUN_ID,
          name: "result.json",
          media_type: "application/json",
          digest,
          content: '{"status":"redacted","count":2}',
          size_bytes: 31,
          truncated: true,
          digest_verified: true,
        },
      }));
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Create remediation run" }));
    const viewButton = await screen.findByRole("button", { name: "View" });
    fireEvent.click(viewButton);

    const dialog = await screen.findByRole("dialog", { name: "result.json" });
    expect(dialog).toHaveTextContent("Redacted demo evidence");
    expect(await screen.findByText(/stored object digest was verified in full/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Search preview"), { target: { value: "redacted" } });
    expect(screen.getByText("1 match")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Copy content" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('{"status":"redacted","count":2}'));
    fireEvent.click(screen.getByRole("button", { name: "Details" }));
    expect(screen.getByText("SHA-256 verified")).toBeInTheDocument();
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(viewButton).toHaveFocus();
    expect(fetchMock).toHaveBeenLastCalledWith(
      `/api/runs/${RUN_ID}/artifacts/preview`,
      expect.objectContaining({ body: expect.not.stringContaining("s3://") }),
    );
  });
});
