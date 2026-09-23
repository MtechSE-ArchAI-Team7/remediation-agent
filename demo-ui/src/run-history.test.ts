import { describe, expect, it } from "vitest";
import { sortRecentRuns } from "./run-history";
import type { RecentRunV1 } from "./run-history";

function item(index: number, status = "DRAFT_PR_CREATED"): RecentRunV1 {
  const value = String(index).padStart(12, "0");
  return {
    schema_version: "1.0",
    task_id: `00000000-0000-4000-8000-${value}`,
    session_id: `10000000-0000-4000-8000-${value}`,
    case_id: `CASE-${index}`,
    jira_ticket_id: `TICKET-${index}`,
    repository: "owner/repository",
    status,
    created_at: new Date(2026, 0, 1, 0, index).toISOString(),
    updated_at: new Date(2026, 0, 1, 0, index).toISOString(),
    draft_pr_url: null,
    artifact_count: index,
    stale: false,
  };
}

describe("sortRecentRuns", () => {
  it("prioritizes actionable runs and then the most recently updated run", () => {
    const runs = sortRecentRuns([
      item(1),
      item(3, "PENDING"),
      item(2, "AWAITING_APPROVAL"),
      item(4),
    ]);

    expect(runs.map((run) => run.status)).toEqual([
      "AWAITING_APPROVAL",
      "PENDING",
      "DRAFT_PR_CREATED",
      "DRAFT_PR_CREATED",
    ]);
    expect(runs.slice(2).map((run) => run.task_id)).toEqual([item(4).task_id, item(1).task_id]);
  });
});
