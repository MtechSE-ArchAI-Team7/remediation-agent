import { useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { ArtifactModal } from "./ArtifactModal";
import { decideRun, GatewayError, getRun, listRuns, probeModel, startRun } from "./api";
import {
  LEGACY_RUN_STORAGE_KEY,
  sortRecentRuns,
} from "./run-history";
import type { RecentRunV1 } from "./run-history";
import toolCatalog from "./generated/tool-catalog.json";
import divisionByZero from "./scenarios/division-by-zero.json";
import type { ApprovalStatus, ArtifactRef, ExplainabilityTrace, RemediationRunView } from "./types";

const RUN_STORAGE_KEY = LEGACY_RUN_STORAGE_KEY;
const SUCCESS_STATUSES = new Set(["DRAFT_PR_CREATED", "DRAFT_PR_PREPARED"]);

const AGENT_CONFIG = {
  region: "ap-southeast-1",
  runtime: "AgentCore",
  provider: "OpenAI",
  model: "kei-openai-target/gpt-5.6-terra",
} as const;

const CONSOLE_TABS = [
  { id: "run", label: "Run Console" },
  { id: "runs", label: "Runs" },
  { id: "agent", label: "Agent" },
  { id: "status", label: "System Status" },
] as const;

type ConsoleTab = (typeof CONSOLE_TABS)[number]["id"];

const WORKFLOW_STEPS = [
  ["Handoff", "Diagnosis accepted"],
  ["Inspect", "Repository evidence reviewed"],
  ["Policy", "Risk and approval evaluated"],
  ["Validate", "Patch tested in isolation"],
  ["Draft PR", "Change prepared for review"],
] as const;

const WORKFLOW_TRACE_STAGES = [
  ["intake", "scope"],
  ["workspace", "inspection"],
  ["planning", "risk", "approval", "policy"],
  ["patch", "validation"],
  ["rollback", "draft_pr", "cleanup", "finalize"],
] as const;

const EXPLAINABILITY_STAGES = [
  { id: "intake", label: "Intake", stages: ["intake", "scope"] },
  { id: "memory", label: "Memory", stages: ["memory"] },
  { id: "inspection", label: "Inspect", stages: ["workspace", "inspection"] },
  { id: "planning", label: "Plan", stages: ["planning", "risk"] },
  { id: "approval", label: "Approve", stages: ["approval"] },
  { id: "patch", label: "Patch", stages: ["patch", "policy"] },
  { id: "validation", label: "Validate", stages: ["validation"] },
  { id: "evidence", label: "Evidence", stages: ["rollback"] },
  { id: "delivery", label: "Draft PR", stages: ["draft_pr", "cleanup", "finalize"] },
] as const;

function errorMessage(error: unknown): string {
  if (error instanceof GatewayError) {
    return error.code.replaceAll("_", " ").toLowerCase();
  }
  if (error instanceof SyntaxError) {
    return "The handoff JSON is not valid.";
  }
  return "The request could not be completed. Check CloudWatch and try refreshing the saved run.";
}

function shortDigest(value: string): string {
  return value.length > 23 ? `${value.slice(0, 15)}…${value.slice(-7)}` : value;
}

function displayStatus(value: string): string {
  return value.replaceAll("_", " ");
}

function statusTone(value: string): string {
  if (["PASSED", "APPROVED", "AVAILABLE", "DRAFT_PR_CREATED", "DRAFT_PR_PREPARED"].includes(value)) return "success";
  if (["PENDING", "TESTING", "AWAITING_APPROVAL"].includes(value) || value.includes("TIMED_OUT")) return "warning";
  if (value.includes("FAILED") || value.includes("ERROR") || value.includes("DENIED") || ["REJECTED", "UNAVAILABLE"].includes(value)) {
    return "error";
  }
  return "neutral";
}

function workflowState(index: number, run: RemediationRunView | null, busy: boolean, successful: boolean): string {
  if (successful) return "complete";
  if (run?.explainability) return explanationStageState(run.explainability, WORKFLOW_TRACE_STAGES[index]);
  if (run?.status === "AWAITING_APPROVAL") {
    if (index < 2) return "complete";
    return index === 2 ? "active" : "pending";
  }
  if (busy) {
    if (index === 0) return "complete";
    return index === 1 ? "active" : "pending";
  }
  if (run) return index < 3 ? "complete" : "pending";
  return index === 0 ? "active" : "pending";
}

function explanationStageState(
  trace: ExplainabilityTrace,
  stages: readonly string[],
): "complete" | "waiting" | "failed" | "pending" {
  const events = trace.events.filter((event) => stages.some((stage) => stage === event.stage));
  if (events.some((event) => statusTone(event.status) === "error")) return "failed";
  if (events.some((event) => event.event_type === "APPROVAL_REQUESTED" && event.status === "PENDING")) {
    return "waiting";
  }
  return events.length > 0 ? "complete" : "pending";
}

function formatArguments(argumentsValue: Record<string, unknown>): string {
  const entries = Object.entries(argumentsValue);
  if (entries.length === 0) return "No exposed arguments";
  return entries.map(([key, value]) => `${key}=${typeof value === "string" ? value : JSON.stringify(value)}`).join(" · ");
}

function ToolBoundaryPanel() {
  const modelTools = toolCatalog.tools.filter((tool) => tool.execution_mode !== "DETERMINISTIC_WORKFLOW");
  const workflowTools = toolCatalog.tools.filter((tool) => tool.execution_mode === "DETERMINISTIC_WORKFLOW");
  const groupedWorkflowTools = workflowTools.reduce<Record<string, typeof workflowTools>>((groups, tool) => {
    groups[tool.category] = [...(groups[tool.category] ?? []), tool];
    return groups;
  }, {});

  return (
    <section className="content-card boundary-card" id="tool-boundary">
      <header className="card-header">
        <div>
          <span className="section-kicker">Generated capability catalogue</span>
          <h2>Tool and policy boundary</h2>
          <p>The model receives four bounded controls. All mutation and validation remain deterministic workflow actions.</p>
        </div>
        <span className="identifier-badge">CATALOG V{toolCatalog.catalog_version}</span>
      </header>
      <div className="boundary-summary" aria-label="Tool catalogue summary">
        <span><strong>{toolCatalog.model_callable_tools}</strong> model-callable</span>
        <span><strong>{toolCatalog.workflow_only_tools}</strong> workflow-only</span>
        <span><strong>{toolCatalog.total_tools}</strong> total operations</span>
      </div>
      <ol className="boundary-lanes" aria-label="Tool authority lanes">
        <li className="boundary-lane">
          <div className="lane-heading"><span>1</span><div><strong>Configured model</strong><small>Proposes and selects; cannot grant authority</small></div></div>
          <div className="lane-content">
            <span className="boundary-node neutral">
              {AGENT_CONFIG.provider} / {AGENT_CONFIG.model}
              <small>Structured output and bounded tool calling</small>
            </span>
          </div>
        </li>
        <li className="boundary-lane">
          <div className="lane-heading"><span>2</span><div><strong>Model-callable allowlist</strong><small>Read-only inspection and one local finish control</small></div></div>
          <div className="lane-content tool-node-list">
            {modelTools.map((tool) => (
              <span className={`boundary-node effect-${tool.effect.toLowerCase().replaceAll("_", "-")}`} key={tool.tool_id}>
                <code>{tool.operation}</code><small>{tool.effect.replaceAll("_", " ")}</small>
              </span>
            ))}
          </div>
        </li>
        <li className="boundary-lane policy-lane">
          <div className="lane-heading"><span>3</span><div><strong>Host policy and approval boundary</strong><small>Repository, commit, path, limits, task names, and write gates</small></div></div>
          <div className="lane-content">
            <span className="boundary-node policy">Operator policy is authoritative</span>
          </div>
        </li>
        <li className="boundary-lane">
          <div className="lane-heading"><span>4</span><div><strong>Deterministic workflow operations</strong><small>Never bound to the model</small></div></div>
          <div className="lane-content workflow-groups">
            {Object.entries(groupedWorkflowTools).map(([category, tools]) => (
              <div className="workflow-tool-group" key={category}>
                <strong>{displayStatus(category)}</strong>
                <div>{tools?.map((tool) => (
                  <span className={`effect-chip effect-${tool.effect.toLowerCase().replaceAll("_", "-")}`} key={tool.tool_id}>
                    <code>{tool.operation}</code><small>{displayStatus(tool.effect)}</small>
                  </span>
                ))}</div>
              </div>
            ))}
            <div className="remote-write-boundary">
              <strong>Optional remote write</strong>
              <span>Application gate + operator-policy gate · draft only · never merge or deploy</span>
            </div>
          </div>
        </li>
      </ol>
    </section>
  );
}

function ExplainabilityPanel({ trace }: { trace: ExplainabilityTrace }) {
  const [selectedStage, setSelectedStage] = useState("inspection");
  const stageDefinition = EXPLAINABILITY_STAGES.find((item) => item.id === selectedStage) ?? EXPLAINABILITY_STAGES[0];
  const selectedEvents = trace.events.filter((event) =>
    stageDefinition.stages.some((stage) => stage === event.stage),
  );
  const totalInputTokens = trace.model_calls.reduce((total, item) => total + (item.input_tokens ?? 0), 0);
  const totalOutputTokens = trace.model_calls.reduce((total, item) => total + (item.output_tokens ?? 0), 0);
  const totalLatency = trace.model_calls.reduce((total, item) => total + item.duration_ms, 0);
  const validationExecutions = trace.validation_executions ?? [];
  const memory = trace.memory_retrieval;
  const memoryWrite = trace.memory_write;

  return (
    <section className="content-card explainability-card" id="explainability">
      <header className="card-header">
        <div>
          <span className="section-kicker">Auditable decision trace</span>
          <h2>Agent explainability</h2>
          <p>Shows bounded summaries and recorded actions—not private reasoning tokens or raw prompts.</p>
        </div>
        <span className="identifier-badge">TRACE V{trace.schema_version}</span>
      </header>

      <div className="explainability-metrics" aria-label="Trace summary">
        <div><span>Model calls</span><strong>{trace.model_calls.length}</strong></div>
        <div><span>Tool calls</span><strong>{trace.inspection_tool_calls.length}</strong></div>
        <div><span>Evidence items</span><strong>{trace.evidence.length}</strong></div>
        <div><span>Model latency</span><strong>{totalLatency.toLocaleString()} ms</strong></div>
        <div><span>Tokens</span><strong>{totalInputTokens.toLocaleString()} in · {totalOutputTokens.toLocaleString()} out</strong></div>
      </div>

      <div className="explainability-body">
        <article className="trace-panel memory-panel" aria-label="Incident memory">
          <header>
            <div><h3>Historical incident memory</h3><p>Advisory suggestions only; current commit evidence remains authoritative.</p></div>
            <span className={`status-badge ${statusTone(memory?.status ?? "DISABLED")}`}>{memory?.status ?? "DISABLED"}</span>
          </header>
          {memory?.status === "RETRIEVED" ? (
            <div className="memory-match-list">
              {memory.matches.map((match) => (
                <section key={match.incident_id}>
                  <div className="event-heading"><code>{match.incident_id}</code><strong>{Math.round(match.score * 100)}% match</strong></div>
                  <p>{match.incident_signature}</p>
                  <small>{match.repository} · {match.age_days.toFixed(1)} days old · {displayStatus(match.admission_type)}</small>
                </section>
              ))}
            </div>
          ) : (
            <p className="empty-state">
              {memory?.status === "ERROR"
                ? "Memory was unavailable—continued safely with normal commit-pinned inspection."
                : memory?.status === "NO_MATCH"
                  ? "No relevant historical incident—continued with normal commit-pinned inspection."
                  : "Long-term incident memory was disabled for this run."}
            </p>
          )}
          <dl className="property-table compact">
            <div><dt>Retrieval latency</dt><dd>{memory ? `${memory.duration_ms.toLocaleString()} ms` : "Not run"}</dd></div>
            <div><dt>Accepted matches</dt><dd>{memory?.matches.length ?? 0}</dd></div>
            <div><dt>Final write</dt><dd><span className={`status-badge ${statusTone(memoryWrite?.status ?? "NOT_ELIGIBLE")}`}>{displayStatus(memoryWrite?.status ?? "NOT_ELIGIBLE")}</span></dd></div>
          </dl>
          <p className="memory-warning">Memory cannot authorize paths or tools, replace repository inspection, reuse a patch, or bypass policy and validation.</p>
        </article>

        <h3>Workflow decision flow</h3>
        <div className="flow-legend" aria-label="Decision actor legend">
          <span><i className="actor deterministic" />Deterministic</span>
          <span><i className="actor model" />Model-assisted</span>
          <span><i className="actor tool" />Tool</span>
          <span><i className="actor human" />Human</span>
        </div>
        <ol className="decision-flow" aria-label="Remediation workflow stages">
          {EXPLAINABILITY_STAGES.map((item, index) => {
            const state = explanationStageState(trace, item.stages);
            return (
              <li key={item.id}>
                <button
                  type="button"
                  className={`${state} ${selectedStage === item.id ? "selected" : ""}`}
                  aria-pressed={selectedStage === item.id}
                  onClick={() => setSelectedStage(item.id)}
                >
                  <span>{state === "complete" ? "✓" : index + 1}</span>
                  <strong>{item.label}</strong>
                  <small>{state}</small>
                </button>
              </li>
            );
          })}
        </ol>

        <div className="decision-detail" aria-live="polite">
          <div className="decision-detail-heading">
            <div><span className="section-kicker">Selected stage</span><h3>{stageDefinition.label}</h3></div>
            <span className="count-badge">{selectedEvents.length}</span>
          </div>
          {selectedEvents.length === 0 ? (
            <p className="empty-state">This stage has not executed yet.</p>
          ) : (
            <ol className="decision-events">
              {selectedEvents.map((event) => (
                <li key={`${event.sequence}-${event.event_type}`}>
                  <i className={`actor ${event.actor_type.toLowerCase().replace("_assisted", "")}`} />
                  <div>
                    <div className="event-heading">
                      <strong>{displayStatus(event.event_type)}</strong>
                      <span className={`status-badge ${statusTone(event.status)}`}>{displayStatus(event.status)}</span>
                    </div>
                    <p>{event.summary}</p>
                    {event.policy_control_ids.length > 0 && (
                      <div className="control-list" aria-label="Triggered policy controls">
                        {event.policy_control_ids.map((control) => <code key={control}>{control}</code>)}
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>

        <div className="explainability-grid">
          <article className="trace-panel">
            <header><div><h3>Inspection tool-call flow</h3><p>Model choice followed by policy-bounded MCP execution.</p></div><span className="count-badge">{trace.inspection_tool_calls.length}</span></header>
            {trace.inspection_tool_calls.length === 0 ? <p className="empty-state">No inspection calls recorded yet.</p> : (
              <ol className="tool-flow">
                {trace.inspection_tool_calls.map((call, index) => (
                  <li key={call.call_id}>
                    <span className="tool-sequence">{index + 1}</span>
                    <div>
                      <div className="event-heading"><code>{call.tool_name}</code><span className={`status-badge ${statusTone(call.status)}`}>{call.status}</span></div>
                      <p>{formatArguments(call.arguments)}</p>
                      <small>Result {shortDigest(call.result_digest)}</small>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </article>

          <article className="trace-panel">
            <header><div><h3>Model decision summaries</h3><p>Provider summaries are optional and redacted.</p></div><span className="count-badge">{trace.model_calls.length}</span></header>
            {trace.model_calls.length === 0 ? <p className="empty-state">No model calls recorded yet.</p> : (
              <div className="model-call-list">
                {trace.model_calls.map((call, index) => (
                  <details key={`${call.operation}-${index}`} open={Boolean(call.reasoning_summary) && index === 0}>
                    <summary><strong>{displayStatus(call.operation)}</strong><span>{call.duration_ms.toLocaleString()} ms · {call.output_tokens ?? "—"} output tokens</span></summary>
                    <div>
                      <span className="reasoning-label">Provider reasoning summary</span>
                      <p>{call.reasoning_summary ?? "The provider did not return a reasoning summary for this call."}</p>
                      <small>{call.provider} · {call.model} · prompt {call.prompt_version}</small>
                    </div>
                  </details>
                ))}
              </div>
            )}
          </article>
        </div>

        <article className="trace-panel validation-boundary-panel">
          <header><div><h3>Validation execution boundary</h3><p>Typed proof from the sandbox adapter, without raw session identifiers.</p></div><span className="count-badge">{validationExecutions.length}</span></header>
          {validationExecutions.length === 0 ? <p className="empty-state">No typed validation-execution evidence is available for this run.</p> : (
            <div className="validation-execution-list">
              {validationExecutions.map((execution) => (
                <section key={`${execution.attempt}-${execution.task_name}`}>
                  <div className="event-heading"><code>{execution.task_name}</code><span className={`status-badge ${statusTone(execution.outcome)}`}>{execution.outcome}</span></div>
                  <dl className="property-table compact">
                    <div><dt>Backend</dt><dd>{displayStatus(execution.backend)}</dd></div>
                    <div><dt>Executor</dt><dd><code>{execution.executor_id}</code></dd></div>
                    <div><dt>Cleanup</dt><dd><span className={`status-badge ${statusTone(execution.cleanup_status)}`}>{execution.cleanup_status}</span></dd></div>
                    <div><dt>Input digest</dt><dd><code>{shortDigest(execution.input_digest)}</code></dd></div>
                    <div><dt>Session digest</dt><dd><code>{execution.session_digest ? shortDigest(execution.session_digest) : "Not applicable"}</code></dd></div>
                  </dl>
                  <div className="control-list" aria-label={`Controls for ${execution.task_name}`}>
                    {execution.enforced_controls.map((control) => <code key={control}>{displayStatus(control)}</code>)}
                  </div>
                </section>
              ))}
            </div>
          )}
        </article>

        {trace.evidence.length > 0 && (
          <div className="trace-evidence">
            <h3>Inspection evidence</h3>
            <div className="evidence-chip-list">
              {trace.evidence.map((item) => (
                <span key={`${item.kind}-${item.digest}`}><strong>{item.kind}</strong><code>{item.locator}</code><small>{shortDigest(item.digest)}</small></span>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState<ConsoleTab>("run");
  const [handoffText, setHandoffText] = useState(JSON.stringify(divisionByZero, null, 2));
  const [runId, setRunId] = useState(() => localStorage.getItem(RUN_STORAGE_KEY) ?? "");
  const [run, setRun] = useState<RemediationRunView | null>(null);
  const [busy, setBusy] = useState<"run" | "probe" | null>(null);
  const [runError, setRunError] = useState("");
  const [probeError, setProbeError] = useState("");
  const [probe, setProbe] = useState("");
  const [recentRuns, setRecentRuns] = useState<RecentRunV1[]>([]);
  const [historyError, setHistoryError] = useState("");
  const [historyBusy, setHistoryBusy] = useState<string | null>(null);
  const [selectedArtifact, setSelectedArtifact] = useState<{ artifact: ArtifactRef; trigger: HTMLElement } | null>(null);
  const [reviewer, setReviewer] = useState("Arabasta");
  const [comment, setComment] = useState("Approved for the AgentCore demonstration.");
  const tabRefs = useRef<Record<ConsoleTab, HTMLButtonElement | null>>({ run: null, runs: null, agent: null, status: null });

  useEffect(() => {
    if (activeTab !== "runs") return undefined;
    let active = true;
    setHistoryBusy("__list__");
    void listRuns()
      .then((response) => {
        if (active) {
          setRecentRuns(sortRecentRuns(response.output.runs));
          setHistoryError("");
        }
      })
      .catch((caught: unknown) => { if (active) setHistoryError(errorMessage(caught)); })
      .finally(() => { if (active) setHistoryBusy(null); });
    return () => { active = false; };
  }, [activeTab]);

  const parsedHandoff = useMemo(() => {
    try {
      return JSON.parse(handoffText) as Record<string, unknown>;
    } catch {
      return null;
    }
  }, [handoffText]);

  async function refreshRunHistory() {
    setHistoryError("");
    setHistoryBusy("__list__");
    try {
      const response = await listRuns();
      setRecentRuns(sortRecentRuns(response.output.runs));
    } catch (caught) {
      setHistoryError(errorMessage(caught));
    } finally {
      setHistoryBusy(null);
    }
  }

  async function start() {
    setRunError("");
    if (parsedHandoff === null) {
      setRunError("The handoff JSON is not valid.");
      return;
    }
    const nextRunId = crypto.randomUUID();
    setRunId(nextRunId);
    localStorage.setItem(RUN_STORAGE_KEY, nextRunId);
    setBusy("run");
    try {
      const response = await startRun(nextRunId, parsedHandoff);
      setRun(response.output);
      setRunId(response.output.task_id);
      localStorage.setItem(RUN_STORAGE_KEY, response.output.task_id);
      localStorage.setItem(`${RUN_STORAGE_KEY}:session`, response.output.session_id);
      await refreshRunHistory();
    } catch (caught) {
      setRunError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function resume() {
    setRunError("");
    if (!runId) {
      setRunError("Create a run before attempting to refresh it.");
      return;
    }
    setBusy("run");
    try {
      const sessionId = localStorage.getItem(`${RUN_STORAGE_KEY}:session`);
      if (!sessionId) throw new GatewayError("MISSING_RUNTIME_SESSION", 400);
      const response = await getRun(runId, sessionId);
      setRun(response.output);
    } catch (caught) {
      setRunError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function decide(status: ApprovalStatus) {
    if (!run?.approval_request) return;
    setRunError("");
    setBusy("run");
    try {
      const response = await decideRun(run.run_id, run.session_id, {
        approval_id: run.approval_request.approval_id,
        scope_digest: run.approval_request.scope_digest,
        status,
        reviewer_id: reviewer,
        comment,
      });
      setRun(response.output);
      await refreshRunHistory();
    } catch (caught) {
      setRunError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function probeOpenAI() {
    setProbeError("");
    setProbe("");
    setBusy("probe");
    try {
      const response = await probeModel();
      setProbe(`${response.output.provider} · ${response.output.model} · ${response.output.duration_ms} ms`);
    } catch (caught) {
      setProbeError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function loadRecentRun(item: RecentRunV1, open: boolean) {
    setHistoryError("");
    setHistoryBusy(item.task_id);
    if (open) {
      setRunError("");
      setRun(null);
      setRunId(item.task_id);
      localStorage.setItem(RUN_STORAGE_KEY, item.task_id);
      localStorage.setItem(`${RUN_STORAGE_KEY}:session`, item.session_id);
      setActiveTab("run");
      setBusy("run");
    }
    try {
      const response = await getRun(item.task_id, item.session_id);
      setRun(response.output);
      setRecentRuns((current) => current.map((runItem) => (
        runItem.task_id === item.task_id
          ? { ...runItem, status: response.output.status, updated_at: new Date().toISOString(), stale: false }
          : runItem
      )));
    } catch (caught) {
      const stale = { ...item, stale: true };
      setRecentRuns((current) => current.map((runItem) => runItem.task_id === item.task_id ? stale : runItem));
      const message = errorMessage(caught);
      if (open) setRunError(message);
      else setHistoryError(message);
    } finally {
      setHistoryBusy(null);
      if (open) setBusy(null);
    }
  }

  const result = run?.result;
  const successful = run ? SUCCESS_STATUSES.has(run.status) : false;
  const runStatus = run?.status ?? (busy === "run" ? "PENDING" : "READY");
  const requestFailure = runError || (run?.failure_code ? run.failure_code.replaceAll("_", " ").toLowerCase() : "");
  const probeStatus = busy === "probe" ? "TESTING" : probe ? "AVAILABLE" : probeError ? "UNAVAILABLE" : "NOT TESTED";
  const approvalReasons = run?.approval_request
    ? run.approval_request.reasons.filter((reason) => reason.trim() !== run.approval_request?.summary.trim())
    : [];

  function handleTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    let nextIndex = index;
    if (event.key === "ArrowRight") nextIndex = (index + 1) % CONSOLE_TABS.length;
    else if (event.key === "ArrowLeft") nextIndex = (index - 1 + CONSOLE_TABS.length) % CONSOLE_TABS.length;
    else if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = CONSOLE_TABS.length - 1;
    else return;

    event.preventDefault();
    const nextTab = CONSOLE_TABS[nextIndex].id;
    setActiveTab(nextTab);
    tabRefs.current[nextTab]?.focus();
  }

  return (
    <div className="console-root">
      <header className="utility-header">
        <a className="product-brand" href="#overview" aria-label="AIOS Operations home" onClick={() => setActiveTab("run")}>
          <span className="product-mark">A</span>
          <span>AIOS Operations</span>
        </a>
        <div className="utility-context">
          <span>Singapore</span>
          <span className="utility-divider" />
          <span>Resolution service</span>
          <span className="health-indicator"><i /> Available</span>
        </div>
      </header>

      <nav className="console-tabs" aria-label="Remediation console views" role="tablist">
        {CONSOLE_TABS.map((tab, index) => (
          <button
            key={tab.id}
            id={`tab-${tab.id}`}
            ref={(element) => { tabRefs.current[tab.id] = element; }}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.id}
            aria-controls={`panel-${tab.id}`}
            tabIndex={activeTab === tab.id ? 0 : -1}
            onClick={() => setActiveTab(tab.id)}
            onKeyDown={(event) => handleTabKeyDown(event, index)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className={`console-frame ${activeTab === "run" ? "has-service-nav" : ""}`}>
        {activeTab === "run" && <aside className="service-nav" aria-label="Run Console sections">
          <div className="service-nav-title">
            <span>Run Console</span>
            <strong>Sections</strong>
          </div>
          <nav>
            <a href="#overview" className="active">Overview</a>
            <a href="#handoff">Handoff</a>
            <a href="#workflow">Workflow</a>
            {run?.approval_request && <a href="#approval">Approval</a>}
            {run?.explainability && <a href="#explainability">Explainability</a>}
            {result && <a href="#results">Results</a>}
          </nav>
          <div className="service-nav-meta">
            <span>Environment</span>
            <strong>Demo</strong>
          </div>
        </aside>}

        <main className="console-main">
          <section id="panel-run" role="tabpanel" aria-labelledby="tab-run" hidden={activeTab !== "run"}>
            <nav className="breadcrumbs" aria-label="Breadcrumb">
              <a href="#overview">AIOS</a><span>/</span><a href="#handoff">Remediation</a><span>/</span><strong>Run Console</strong>
            </nav>

            <section className="page-header" id="overview">
              <div>
                <h1>Remediation console</h1>
                <p>Create and monitor a bounded remediation run from an Agent 2 diagnosis handoff.</p>
              </div>
              <span className={`status-badge ${statusTone(runStatus)}`}><i />{displayStatus(runStatus)}</span>
            </section>

            {requestFailure && (
              <div className="alert error" role="alert">
                <span className="alert-icon">!</span>
                <div><strong>Request failed</strong><p>{requestFailure}</p></div>
              </div>
            )}

            <div className="primary-grid">
            <section className="content-card" id="handoff">
              <header className="card-header">
                <div><h2>Create remediation run</h2><p>Submit a typed diagnosis against an immutable repository commit.</p></div>
                <span className="identifier-badge">CASE-ECOM-AVG-001</span>
              </header>

              <div className="card-body">
                <h3>Diagnosis handoff</h3>
                <dl className="property-table">
                  <div><dt>Scenario</dt><dd>Division-by-zero average calculation</dd></div>
                  <div><dt>Jira ticket</dt><dd><code>{divisionByZero.jira_ticket_id}</code></dd></div>
                  <div><dt>Repository</dt><dd><code>MtechSE-ArchAI-Team7/buggy-ecommerce-demo</code></dd></div>
                  <div><dt>Base branch</dt><dd><code>main</code></dd></div>
                  <div><dt>Target</dt><dd><code>server.js</code></dd></div>
                  <div>
                    <dt>Deployed service</dt>
                    <dd>
                      <a href="http://aios-ecommerce.ap-southeast-1.elasticbeanstalk.com/" target="_blank" rel="noreferrer">
                        aios-ecommerce.ap-southeast-1.elasticbeanstalk.com ↗
                      </a>
                    </dd>
                  </div>
                  <div><dt>Run ID</dt><dd><code>{runId || "Generated when the run is created"}</code></dd></div>
                </dl>

                <div className="info-panel">
                  <strong>Diagnosis</strong>
                  <p>The average endpoint divides by zero and returns HTTP 200 with a null result instead of a typed client error.</p>
                </div>

                <details className="advanced-input">
                  <summary>Advanced input</summary>
                  <div>
                    <label htmlFor="handoff-json">DiagnosisHandoffV1 JSON</label>
                    <textarea
                      id="handoff-json"
                      aria-label="Diagnosis handoff JSON"
                      spellCheck={false}
                      value={handoffText}
                      onChange={(event) => setHandoffText(event.target.value)}
                    />
                  </div>
                </details>
              </div>

              <footer className="card-actions">
                <button className="secondary" disabled={busy !== null || !runId} onClick={resume}>Refresh saved run</button>
                <button className="primary" disabled={busy !== null || parsedHandoff === null} onClick={start}>
                  {busy === "run" ? "Creating run…" : "Create remediation run"}
                </button>
              </footer>
            </section>

            <section className="content-card" id="workflow" aria-live="polite">
              <header className="card-header">
                <div><h2>Workflow status</h2><p>Current progress for the active runtime session.</p></div>
                <span className={`status-badge ${statusTone(runStatus)}`}><i />{displayStatus(runStatus)}</span>
              </header>
              <div className="card-body">
                <ol className="workflow-steps">
                  {WORKFLOW_STEPS.map(([label, description], index) => {
                    const state = workflowState(index, run, busy === "run", successful);
                    return (
                      <li className={state} key={label}>
                        <span className="step-marker">{state === "complete" ? "✓" : index + 1}</span>
                        <div><strong>{label}</strong><small>{description}</small></div>
                        <span className={`step-status ${state}`}>{state}</span>
                      </li>
                    );
                  })}
                </ol>
                {!run && busy !== "run" && <div className="empty-state">No active run. Submit the diagnosis handoff to begin.</div>}
                {busy === "run" && (
                  <div className="working-state"><span className="spinner" /><div><strong>Operation in progress</strong><p>Keep this page open or refresh the saved run later with its UUID.</p></div></div>
                )}
              </div>
            </section>
            </div>

            {run?.approval_request && (
            <section className="content-card approval-card" id="approval">
              <header className="card-header warning-header">
                <div><span className="section-kicker">Review required · {run.approval_request.kind}</span><h2>Approval checkpoint</h2></div>
                <span className="status-badge warning"><i />Pending</span>
              </header>
              <div className="approval-layout">
                <div className="approval-details">
                  <p className="approval-summary">{run.approval_request.summary}</p>
                  {approvalReasons.length > 0 && <ul>{approvalReasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
                  <dl className="property-table compact">
                    <div><dt>Approval ID</dt><dd><code>{run.approval_request.approval_id}</code></dd></div>
                    <div><dt>Scope digest</dt><dd><code title={run.approval_request.scope_digest}>{shortDigest(run.approval_request.scope_digest)}</code></dd></div>
                    <div><dt>Requested</dt><dd>{run.approval_request.requested_at}</dd></div>
                  </dl>
                </div>
                <div className="approval-form">
                  <label>Reviewer ID<input value={reviewer} onChange={(event) => setReviewer(event.target.value)} /></label>
                  <label>Review comment<textarea value={comment} onChange={(event) => setComment(event.target.value)} /></label>
                  <div className="inline-actions">
                    <button className="danger" disabled={busy !== null || !reviewer.trim()} onClick={() => decide("REJECTED")}>Reject</button>
                    <button className="primary" disabled={busy !== null || !reviewer.trim()} onClick={() => decide("APPROVED")}>Approve and continue</button>
                  </div>
                </div>
              </div>
            </section>
            )}

            {run?.explainability && <ExplainabilityPanel trace={run.explainability} />}

            {result && (
            <section id="results" className="results-section">
              <div className={`outcome-banner ${statusTone(result.final_status)}`}>
                <div><span className="outcome-icon">{successful ? "✓" : "!"}</span><div><strong>{displayStatus(result.final_status)}</strong><p>The remediation workflow has reached a terminal state.</p></div></div>
                {result.draft_pr?.url && <a className="primary-link" href={result.draft_pr.url} target="_blank" rel="noreferrer">Open draft pull request ↗</a>}
              </div>

              <div className="results-grid">
                <article className="content-card summary-card">
                  <header className="card-header"><div><h2>Remediation summary</h2><p>Plan, risk, and changed file scope.</p></div></header>
                  <div className="card-body">
                    <h3>Plan</h3><p>{result.remediation_plan_summary ?? "Workflow completed without a plan summary."}</p>
                    <h3>Risk assessment</h3><p>{result.risk_summary ?? "No additional risks were reported."}</p>
                    <h3>Changed files</h3>
                    <div className="file-list">{result.changed_files.map((file) => <code key={file}>{file}</code>)}</div>
                  </div>
                </article>

                <article className="content-card">
                  <header className="card-header"><div><h2>Validation</h2><p>{result.validation_attempts.length} recorded attempt{result.validation_attempts.length === 1 ? "" : "s"}.</p></div></header>
                  <div className="table-scroll">
                    <table>
                      <thead><tr><th>Attempt</th><th>Task</th><th>Status</th><th>Duration</th></tr></thead>
                      <tbody>
                        {result.validation_attempts.flatMap((attempt) => attempt.results.map((item) => (
                          <tr key={`${attempt.attempt}-${item.task_name}`}>
                            <td>{attempt.attempt}</td><td><code>{item.task_name}</code></td>
                            <td><span className={`status-badge ${statusTone(item.outcome)}`}>{item.outcome}</span></td>
                            <td>{item.duration_ms.toLocaleString()} ms</td>
                          </tr>
                        )))}
                      </tbody>
                    </table>
                  </div>
                </article>

                <article className="content-card artifacts-card">
                  <header className="card-header"><div><h2>Evidence artifacts</h2><p>Immutable references produced by this run.</p></div><span className="count-badge">{result.artifact_manifest?.artifacts.length ?? 0}</span></header>
                  <div className="table-scroll">
                    <table>
                      <thead><tr><th>Name</th><th>Media type</th><th>Digest</th><th>Object reference</th><th>Action</th></tr></thead>
                      <tbody>
                        {(result.artifact_manifest?.artifacts ?? []).map((artifact) => (
                          <tr key={artifact.path}><td><strong>{artifact.name}</strong></td><td>{artifact.media_type}</td><td><code title={artifact.digest}>{shortDigest(artifact.digest)}</code></td><td><code title={artifact.path}>{artifact.path}</code></td><td><button className="secondary compact-button" type="button" onClick={(event) => setSelectedArtifact({ artifact, trigger: event.currentTarget })}>View</button></td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {result.audit_bundle_ref && <div className="audit-reference"><span>Audit bundle</span><code>{result.audit_bundle_ref.path}</code><button className="secondary compact-button" type="button" onClick={(event) => setSelectedArtifact({ artifact: result.audit_bundle_ref!, trigger: event.currentTarget })}>View</button></div>}
                </article>

                {result.errors.length > 0 && (
                  <article className="content-card errors-card">
                    <header className="card-header"><div><h2>Errors</h2><p>Stable error records returned by the workflow.</p></div></header>
                    <div className="table-scroll"><table><thead><tr><th>Code</th><th>Stage</th><th>Message</th></tr></thead><tbody>
                      {result.errors.map((item) => <tr key={`${item.stage}-${item.code}`}><td><code>{item.code}</code></td><td>{item.stage}</td><td>{item.message}</td></tr>)}
                    </tbody></table></div>
                  </article>
                )}
              </div>
            </section>
            )}
          </section>

          <section id="panel-runs" role="tabpanel" aria-labelledby="tab-runs" hidden={activeTab !== "runs"}>
            <nav className="breadcrumbs" aria-label="Breadcrumb">
              <span>AIOS</span><span>/</span><span>Remediation</span><span>/</span><strong>Runs</strong>
            </nav>
            <section className="page-header">
              <div>
                <h1>Recent runs</h1>
                <p>Shared public demo runs from Agent 2 and this console. Opening a run retrieves its latest runtime state.</p>
              </div>
              <div className="page-header-actions">
                <span className="identifier-badge">{recentRuns.length} shared</span>
                <button className="secondary" type="button" disabled={historyBusy !== null} onClick={() => void refreshRunHistory()}>
                  {historyBusy === "__list__" ? "Refreshing…" : "Refresh runs"}
                </button>
              </div>
            </section>
            {historyError && (
              <div className="alert error" role="alert">
                <span className="alert-icon">!</span>
                <div><strong>Run history update failed</strong><p>{historyError}</p></div>
              </div>
            )}
            <section className="content-card recent-runs-card">
              <header className="card-header">
                <div><span className="section-kicker">Public demo queue</span><h2>Shared remediation runs</h2><p>Every visitor to this demo can view these runs and submit an approval decision.</p></div>
              </header>
              {recentRuns.length === 0 ? (
                <div className="card-body"><div className="empty-state">No shared runs. Create a remediation run or send one from Agent 2.</div></div>
              ) : (
                <div className="table-scroll">
                  <table className="recent-runs-table">
                    <thead><tr><th>Case</th><th>Status</th><th>Updated</th><th>Run ID</th><th>Evidence</th><th>Actions</th></tr></thead>
                    <tbody>
                      {recentRuns.map((item) => (
                        <tr key={item.task_id}>
                          <td><strong>{item.case_id ?? "Saved run"}</strong><small>{item.jira_ticket_id ?? item.repository ?? "Details available after refresh"}</small></td>
                          <td><span className={`status-badge ${statusTone(item.status)}`}>{displayStatus(item.status)}</span>{item.stale && <small className="stale-label">Last known state</small>}</td>
                          <td>{new Date(item.updated_at).toLocaleString()}</td>
                          <td><code title={item.task_id}>{item.task_id}</code></td>
                          <td>{item.artifact_count}</td>
                          <td>
                            <div className="table-actions">
                              <button className="secondary" type="button" disabled={historyBusy !== null} onClick={() => void loadRecentRun(item, false)}>{historyBusy === item.task_id ? "Refreshing…" : "Refresh"}</button>
                              <button className="primary" type="button" disabled={historyBusy !== null} onClick={() => void loadRecentRun(item, true)}>Open</button>
                              {item.draft_pr_url && <a className="table-link" href={item.draft_pr_url} target="_blank" rel="noreferrer">Draft PR ↗</a>}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </section>

          <section id="panel-agent" role="tabpanel" aria-labelledby="tab-agent" hidden={activeTab !== "agent"}>
            <nav className="breadcrumbs" aria-label="Breadcrumb">
              <span>AIOS</span><span>/</span><span>Remediation</span><span>/</span><strong>Agent</strong>
            </nav>
            <section className="page-header">
              <div>
                <h1>Remediation agent</h1>
                <p>Deployment configuration and the generated capability boundary for Agent 3.</p>
              </div>
              <span className="status-badge neutral"><i />Configured</span>
            </section>
            <section className="service-summary" aria-label="Runtime configuration">
              <div><span>Region</span><strong>{AGENT_CONFIG.region}</strong></div>
              <div><span>Runtime</span><strong>{AGENT_CONFIG.runtime}</strong></div>
              <div><span>Model provider</span><strong>{AGENT_CONFIG.provider}</strong></div>
              <div><span>Model</span><strong>{AGENT_CONFIG.model}</strong></div>
            </section>
            <ToolBoundaryPanel />
          </section>

          <section id="panel-status" role="tabpanel" aria-labelledby="tab-status" hidden={activeTab !== "status"}>
            <nav className="breadcrumbs" aria-label="Breadcrumb">
              <span>AIOS</span><span>/</span><span>Remediation</span><span>/</span><strong>System Status</strong>
            </nav>
            <section className="page-header">
              <div>
                <h1>System status</h1>
                <p>Upstream dependencies and explicitly tested provider connectivity.</p>
              </div>
            </section>

            {probeError && (
              <div className="alert error" role="alert">
                <span className="alert-icon">!</span>
                <div><strong>Provider check failed</strong><p>{probeError}</p></div>
              </div>
            )}

            <section className="content-card dependency-card" aria-label="Upstream dependencies">
              <header className="card-header">
                <div><span className="section-kicker">Demo environment</span><h2>Dependency status</h2><p>Only the model provider row performs a live check.</p></div>
              </header>
              <div className="dependency-list">
                <article className="dependency-row">
                  <div><strong>Demo UI gateway</strong><p>This console loaded successfully. No additional health request is made.</p></div>
                  <span className="status-badge success"><i />Serving</span>
                </article>
                <article className="dependency-row">
                  <div><strong>Remediation runtime</strong><p>The AgentCore dependency is configured; this page does not actively probe runtime health.</p></div>
                  <span className="status-badge neutral"><i />Configured</span>
                </article>
                <article className="dependency-row provider-row">
                  <div>
                    <strong>OpenAI model provider</strong>
                    <p>Runs one explicit provider request through the configured AgentCore runtime.</p>
                    <span className={probe ? "probe-result available" : "probe-result"}>{probe || "No provider check has been run."}</span>
                  </div>
                  <div className="dependency-actions">
                    <span className={`status-badge ${statusTone(probeStatus)}`}><i />{probeStatus}</span>
                    <button className="secondary" disabled={busy !== null} onClick={probeOpenAI}>{busy === "probe" ? "Testing…" : "Test connection"}</button>
                  </div>
                </article>
              </div>
            </section>
          </section>
        </main>
      </div>
      {selectedArtifact && run && (
        <ArtifactModal
          artifact={selectedArtifact.artifact}
          runId={run.task_id}
          sessionId={run.session_id}
          returnFocusTo={selectedArtifact.trigger}
          onClose={() => setSelectedArtifact(null)}
        />
      )}
    </div>
  );
}
