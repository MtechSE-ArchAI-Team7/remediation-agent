import type { RemediationRunView } from "./types";

export const RUN_HISTORY_STORAGE_KEY = "aios-remediation-run-history-v1";
export const LEGACY_RUN_STORAGE_KEY = "aios-remediation-ecommerce-run-id";
const MAX_RUNS = 20;

export interface RecentRunV1 {
  schema_version: "1.0";
  task_id: string;
  session_id: string;
  case_id: string | null;
  jira_ticket_id: string | null;
  repository: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  draft_pr_url: string | null;
  artifact_count: number;
  stale: boolean;
}

export interface RunHistoryRepository {
  list(): Promise<RecentRunV1[]>;
  upsert(run: RecentRunV1): Promise<RecentRunV1[]>;
  remove(taskId: string): Promise<RecentRunV1[]>;
}

interface StoredHistoryV1 {
  schema_version: "1.0";
  runs: RecentRunV1[];
}

function isStringOrNull(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function parseRun(value: unknown): RecentRunV1 | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const run = value as Record<string, unknown>;
  if (
    run.schema_version !== "1.0"
    || typeof run.task_id !== "string"
    || !run.task_id
    || typeof run.session_id !== "string"
    || !run.session_id
    || !isStringOrNull(run.case_id)
    || !isStringOrNull(run.jira_ticket_id)
    || !isStringOrNull(run.repository)
    || typeof run.status !== "string"
    || !run.status
    || typeof run.created_at !== "string"
    || Number.isNaN(Date.parse(run.created_at))
    || typeof run.updated_at !== "string"
    || Number.isNaN(Date.parse(run.updated_at))
    || !isStringOrNull(run.draft_pr_url)
    || typeof run.artifact_count !== "number"
    || !Number.isInteger(run.artifact_count)
    || run.artifact_count < 0
    || typeof run.stale !== "boolean"
  ) return null;
  return run as unknown as RecentRunV1;
}

function priority(status: string): number {
  if (status === "AWAITING_APPROVAL") return 0;
  if (status === "PENDING") return 1;
  return 2;
}

export function sortRecentRuns(runs: RecentRunV1[]): RecentRunV1[] {
  return [...runs].sort((left, right) => {
    const statusOrder = priority(left.status) - priority(right.status);
    return statusOrder || Date.parse(right.updated_at) - Date.parse(left.updated_at);
  });
}

export class LocalRunHistoryRepository implements RunHistoryRepository {
  constructor(private readonly storage: Storage = window.localStorage) {}

  async list(): Promise<RecentRunV1[]> {
    const stored = this.read();
    if (stored.length > 0) return sortRecentRuns(stored);
    const legacyTaskId = this.storage.getItem(LEGACY_RUN_STORAGE_KEY);
    const legacySessionId = this.storage.getItem(`${LEGACY_RUN_STORAGE_KEY}:session`);
    if (!legacyTaskId || !legacySessionId) return [];
    const timestamp = new Date().toISOString();
    const migrated: RecentRunV1 = {
      schema_version: "1.0",
      task_id: legacyTaskId,
      session_id: legacySessionId,
      case_id: null,
      jira_ticket_id: null,
      repository: null,
      status: "SAVED",
      created_at: timestamp,
      updated_at: timestamp,
      draft_pr_url: null,
      artifact_count: 0,
      stale: true,
    };
    this.write([migrated]);
    return [migrated];
  }

  async upsert(run: RecentRunV1): Promise<RecentRunV1[]> {
    const parsed = parseRun(run);
    if (parsed === null) throw new Error("Invalid recent run record");
    const runs = [parsed, ...this.read().filter((item) => item.task_id !== parsed.task_id)];
    const sorted = sortRecentRuns(runs).slice(0, MAX_RUNS);
    this.write(sorted);
    return sorted;
  }

  async remove(taskId: string): Promise<RecentRunV1[]> {
    const runs = this.read().filter((item) => item.task_id !== taskId);
    this.write(runs);
    return sortRecentRuns(runs);
  }

  private read(): RecentRunV1[] {
    const raw = this.storage.getItem(RUN_HISTORY_STORAGE_KEY);
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return [];
      const history = parsed as Record<string, unknown>;
      if (history.schema_version !== "1.0" || !Array.isArray(history.runs)) return [];
      return history.runs.map(parseRun).filter((item): item is RecentRunV1 => item !== null);
    } catch {
      return [];
    }
  }

  private write(runs: RecentRunV1[]): void {
    const history: StoredHistoryV1 = { schema_version: "1.0", runs };
    this.storage.setItem(RUN_HISTORY_STORAGE_KEY, JSON.stringify(history));
  }
}

export function recentRunFromView(
  view: RemediationRunView,
  input: Record<string, unknown> | null,
  previous?: RecentRunV1,
): RecentRunV1 {
  const now = new Date().toISOString();
  const repository = input?.repository;
  let repositoryLabel = previous?.repository ?? null;
  if (typeof repository === "object" && repository !== null) {
    const url = (repository as Record<string, unknown>).url;
    if (typeof url === "string") {
      try {
        repositoryLabel = new URL(url).pathname.replace(/^\//, "").replace(/\.git$/, "");
      } catch {
        repositoryLabel = null;
      }
    }
  }
  return {
    schema_version: "1.0",
    task_id: view.task_id,
    session_id: view.session_id,
    case_id: typeof input?.case_id === "string" ? input.case_id : previous?.case_id ?? view.approval_request?.case_id ?? null,
    jira_ticket_id: typeof input?.jira_ticket_id === "string" ? input.jira_ticket_id : previous?.jira_ticket_id ?? null,
    repository: repositoryLabel,
    status: view.status,
    created_at: previous?.created_at ?? now,
    updated_at: now,
    draft_pr_url: view.result?.draft_pr?.url ?? previous?.draft_pr_url ?? null,
    artifact_count: view.result?.artifact_manifest?.artifacts.length ?? previous?.artifact_count ?? 0,
    stale: false,
  };
}
