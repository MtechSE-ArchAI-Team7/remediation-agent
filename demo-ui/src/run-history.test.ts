import { beforeEach, describe, expect, it } from "vitest";
import {
  LEGACY_RUN_STORAGE_KEY,
  LocalRunHistoryRepository,
  RUN_HISTORY_STORAGE_KEY,
} from "./run-history";
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

describe("LocalRunHistoryRepository", () => {
  beforeEach(() => localStorage.clear());

  it("ignores malformed records and migrates the legacy locator", async () => {
    localStorage.setItem(RUN_HISTORY_STORAGE_KEY, "not-json");
    localStorage.setItem(LEGACY_RUN_STORAGE_KEY, "2db1f13e-7351-4a1f-a4c6-630646366d52");
    localStorage.setItem(`${LEGACY_RUN_STORAGE_KEY}:session`, "3db1f13e-7351-4a1f-a4c6-630646366d53");

    const runs = await new LocalRunHistoryRepository().list();

    expect(runs).toHaveLength(1);
    expect(runs[0]).toMatchObject({ status: "SAVED", stale: true });
    expect(JSON.parse(localStorage.getItem(RUN_HISTORY_STORAGE_KEY) ?? "{}").schema_version).toBe("1.0");
  });

  it("deduplicates, caps history at 20, and prioritizes actionable runs", async () => {
    const repository = new LocalRunHistoryRepository();
    for (let index = 0; index < 22; index += 1) await repository.upsert(item(index));
    await repository.upsert({ ...item(10), status: "AWAITING_APPROVAL", artifact_count: 99 });

    const runs = await repository.list();

    expect(runs).toHaveLength(20);
    expect(runs[0]).toMatchObject({ task_id: item(10).task_id, status: "AWAITING_APPROVAL", artifact_count: 99 });
    expect(new Set(runs.map((run) => run.task_id)).size).toBe(20);
  });

  it("removes only the selected local record", async () => {
    const repository = new LocalRunHistoryRepository();
    await repository.upsert(item(1));
    await repository.upsert(item(2));

    const runs = await repository.remove(item(1).task_id);

    expect(runs.map((run) => run.task_id)).toEqual([item(2).task_id]);
  });
});
