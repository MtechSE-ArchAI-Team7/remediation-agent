import { useMemo, useState } from "react";
import { decideRun, GatewayError, getRun, probeModel, startRun } from "./api";
import stockBoundary from "./scenarios/stock-boundary.json";
import type { ApprovalStatus, RemediationRunView } from "./types";

const RUN_STORAGE_KEY = "aios-remediation-demo-run-id";
const SUCCESS_STATUSES = new Set(["DRAFT_PR_CREATED", "DRAFT_PR_PREPARED"]);

const WORKFLOW_STEPS = [
  ["Handoff", "Diagnosis accepted"],
  ["Inspect", "Repository evidence reviewed"],
  ["Policy", "Risk and approval evaluated"],
  ["Validate", "Patch tested in isolation"],
  ["Draft PR", "Change prepared for review"],
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
  if (["PASSED", "APPROVED", "DRAFT_PR_CREATED", "DRAFT_PR_PREPARED"].includes(value)) return "success";
  if (value === "PENDING" || value === "AWAITING_APPROVAL" || value.includes("TIMED_OUT")) return "warning";
  if (value.includes("FAILED") || value.includes("ERROR") || value.includes("DENIED") || value === "REJECTED") {
    return "error";
  }
  return "neutral";
}

function workflowState(index: number, run: RemediationRunView | null, busy: boolean, successful: boolean): string {
  if (successful) return "complete";
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

export default function App() {
  const [handoffText, setHandoffText] = useState(JSON.stringify(stockBoundary, null, 2));
  const [runId, setRunId] = useState(() => localStorage.getItem(RUN_STORAGE_KEY) ?? "");
  const [run, setRun] = useState<RemediationRunView | null>(null);
  const [busy, setBusy] = useState<"run" | "probe" | null>(null);
  const [error, setError] = useState("");
  const [probe, setProbe] = useState("");
  const [reviewer, setReviewer] = useState("Arabasta");
  const [comment, setComment] = useState("Approved for the AgentCore demonstration.");

  const parsedHandoff = useMemo(() => {
    try {
      return JSON.parse(handoffText) as Record<string, unknown>;
    } catch {
      return null;
    }
  }, [handoffText]);

  async function start() {
    setError("");
    setProbe("");
    if (parsedHandoff === null) {
      setError("The handoff JSON is not valid.");
      return;
    }
    const nextRunId = crypto.randomUUID();
    setRunId(nextRunId);
    localStorage.setItem(RUN_STORAGE_KEY, nextRunId);
    setBusy("run");
    try {
      const response = await startRun(nextRunId, parsedHandoff);
      setRun(response.output);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function resume() {
    setError("");
    if (!runId) {
      setError("Create a run before attempting to refresh it.");
      return;
    }
    setBusy("run");
    try {
      const response = await getRun(runId);
      setRun(response.output);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function decide(status: ApprovalStatus) {
    if (!run?.approval_request) return;
    setError("");
    setBusy("run");
    try {
      const response = await decideRun(run.run_id, {
        approval_id: run.approval_request.approval_id,
        scope_digest: run.approval_request.scope_digest,
        status,
        reviewer_id: reviewer,
        comment,
      });
      setRun(response.output);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function probeOpenAI() {
    setError("");
    setProbe("");
    setBusy("probe");
    try {
      const response = await probeModel();
      setProbe(`${response.output.provider} · ${response.output.model} · ${response.output.duration_ms} ms`);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  const result = run?.result;
  const successful = run ? SUCCESS_STATUSES.has(run.status) : false;
  const runStatus = run?.status ?? (busy === "run" ? "PENDING" : "READY");
  const approvalReasons = run?.approval_request
    ? run.approval_request.reasons.filter((reason) => reason.trim() !== run.approval_request?.summary.trim())
    : [];

  return (
    <div className="console-root">
      <header className="utility-header">
        <a className="product-brand" href="#overview" aria-label="AIOS Operations home">
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

      <div className="console-frame">
        <aside className="service-nav" aria-label="Page sections">
          <div className="service-nav-title">
            <span>Service</span>
            <strong>Remediation</strong>
          </div>
          <nav>
            <a href="#overview" className="active">Overview</a>
            <a href="#handoff">Handoff</a>
            <a href="#workflow">Workflow</a>
            {run?.approval_request && <a href="#approval">Approval</a>}
            {result && <a href="#results">Results</a>}
            <a href="#connectivity">Connectivity</a>
          </nav>
          <div className="service-nav-meta">
            <span>Environment</span>
            <strong>Demo</strong>
          </div>
        </aside>

        <main className="console-main">
          <nav className="breadcrumbs" aria-label="Breadcrumb">
            <a href="#overview">AIOS</a><span>/</span><a href="#handoff">Remediation</a><span>/</span><strong>Run console</strong>
          </nav>

          <section className="page-header" id="overview">
            <div>
              <h1>Remediation console</h1>
              <p>Create and monitor a bounded remediation run from an Agent 2 diagnosis handoff.</p>
            </div>
            <span className={`status-badge ${statusTone(runStatus)}`}><i />{displayStatus(runStatus)}</span>
          </section>

          <section className="service-summary" aria-label="Runtime configuration">
            <div><span>Region</span><strong>ap-southeast-1</strong></div>
            <div><span>Runtime</span><strong>AgentCore</strong></div>
            <div><span>Model provider</span><strong>OpenAI</strong></div>
            <div><span>Model</span><strong>gpt-5.6-terra</strong></div>
          </section>

          {error && (
            <div className="alert error" role="alert">
              <span className="alert-icon">!</span>
              <div><strong>Request failed</strong><p>{error}</p></div>
            </div>
          )}

          <div className="primary-grid">
            <section className="content-card" id="handoff">
              <header className="card-header">
                <div><h2>Create remediation run</h2><p>Submit a typed diagnosis against an immutable repository commit.</p></div>
                <span className="identifier-badge">CASE-DEMO-02</span>
              </header>

              <div className="card-body">
                <h3>Diagnosis handoff</h3>
                <dl className="property-table">
                  <div><dt>Scenario</dt><dd>Stock boundary off by one</dd></div>
                  <div><dt>Repository</dt><dd><code>MtechSE-ArchAI-Team7/aios-remediation-demo</code></dd></div>
                  <div><dt>Base branch</dt><dd><code>scenario/02-stock-boundary</code></dd></div>
                  <div><dt>Target</dt><dd><code>src/orders.py</code></dd></div>
                  <div><dt>Run ID</dt><dd><code>{runId || "Generated when the run is created"}</code></dd></div>
                </dl>

                <div className="info-panel">
                  <strong>Diagnosis</strong>
                  <p>The stock predicate excludes an order equal to the available inventory boundary.</p>
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
                      <thead><tr><th>Name</th><th>Media type</th><th>Digest</th><th>Object reference</th></tr></thead>
                      <tbody>
                        {(result.artifact_manifest?.artifacts ?? []).map((artifact) => (
                          <tr key={artifact.path}><td><strong>{artifact.name}</strong></td><td>{artifact.media_type}</td><td><code title={artifact.digest}>{shortDigest(artifact.digest)}</code></td><td><code title={artifact.path}>{artifact.path}</code></td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {result.audit_bundle_ref && <div className="audit-reference"><span>Audit bundle</span><code>{result.audit_bundle_ref.path}</code></div>}
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

          <section className="content-card connectivity-card" id="connectivity">
            <div><h2>Provider connectivity</h2><p>Run an explicit OpenAI connectivity check. No request is sent automatically when this page loads.</p></div>
            <div className="connectivity-actions">
              <span className={probe ? "probe-result available" : "probe-result"}>{probe || "Not tested"}</span>
              <button className="secondary" disabled={busy !== null} onClick={probeOpenAI}>{busy === "probe" ? "Testing…" : "Test connection"}</button>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
