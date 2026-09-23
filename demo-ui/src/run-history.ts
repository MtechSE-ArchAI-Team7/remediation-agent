export const LEGACY_RUN_STORAGE_KEY = "aios-remediation-ecommerce-run-id";

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
