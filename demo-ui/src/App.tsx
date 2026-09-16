import { useMemo, useState } from "react";
import { decideRun, GatewayError, getRun, probeModel, startRun } from "./api";
import stockBoundary from "./scenarios/stock-boundary.json";
import type { ApprovalStatus, RemediationRunView } from "./types";

const RUN_STORAGE_KEY = "aios-remediation-demo-run-id";
const SUCCESS_STATUSES = new Set(["DRAFT_PR_CREATED", "DRAFT_PR_PREPARED"]);

function errorMessage(error: unknown): string {
  if (error instanceof GatewayError) {
    return error.code.replaceAll("_", " ").toLowerCase();
  }
  if (error instanceof SyntaxError) {
    return "The handoff JSON is not valid.";
  }
  return "The request could not be completed. Check CloudWatch and try resuming the run.";
}

function shortDigest(value: string): string {
  return value.length > 23 ? `${value.slice(0, 15)}…${value.slice(-7)}` : value;
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
      setError("Start a run before attempting to resume it.");
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

  return (
    <main className="shell">
      <header className="masthead">
        <div className="brand-mark" aria-hidden="true">
          A3
        </div>
        <div>
          <p className="eyebrow">AIOS · Resolution / Remediation</p>
          <h1>AgentCore demo console</h1>
        </div>
        <span className="environment"><i /> Singapore · GPT-5.6 Terra</span>
      </header>

      <section className="hero">
        <div>
          <p className="eyebrow">Presentation scenario</p>
          <h2>Turn a diagnosed defect into a validated draft PR.</h2>
          <p className="hero-copy">
            This screen submits Agent 2’s typed handoff, follows the AgentCore run, handles human approval, and
            surfaces the final evidence without exposing provider credentials.
          </p>
        </div>
        <div className="hero-stat">
          <strong>01</strong>
          <span>bounded workflow</span>
          <small>one run · one session</small>
        </div>
      </section>

      <div className="layout">
        <section className="panel intake-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Agent 2 handoff</p>
              <h3>Stock boundary off by one</h3>
            </div>
            <span className="case-pill">CASE-DEMO-02</span>
          </div>

          <dl className="facts">
            <div><dt>Repository</dt><dd>MtechSE-ArchAI-Team7/aios-remediation-demo</dd></div>
            <div><dt>Base</dt><dd>scenario/02-stock-boundary</dd></div>
            <div><dt>Target</dt><dd>src/orders.py</dd></div>
          </dl>

          <div className="diagnosis">
            <span>Diagnosis</span>
            <p>The stock predicate excludes an order equal to the available inventory boundary.</p>
          </div>

          <details className="json-editor">
            <summary>Edit typed handoff JSON</summary>
            <textarea
              aria-label="Diagnosis handoff JSON"
              spellCheck={false}
              value={handoffText}
              onChange={(event) => setHandoffText(event.target.value)}
            />
          </details>

          <div className="button-row">
            <button className="primary" disabled={busy !== null || parsedHandoff === null} onClick={start}>
              {busy === "run" ? "Agent working…" : "Start remediation"}
            </button>
            <button className="secondary" disabled={busy !== null || !runId} onClick={resume}>
              Resume saved run
            </button>
          </div>

          <div className="session-line">
            <span>Run ID</span>
            <code>{runId || "generated when the run starts"}</code>
          </div>
        </section>

        <section className="panel progress-panel" aria-live="polite">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Live outcome</p>
              <h3>{run ? run.status.replaceAll("_", " ") : busy === "run" ? "Workflow running" : "Ready"}</h3>
            </div>
            <span className={`status-dot ${busy === "run" ? "active" : successful ? "success" : ""}`} />
          </div>

          <ol className="timeline">
            <li className={runId ? "complete" : "active"}><b>1</b><span>Handoff accepted<small>Typed diagnosis and immutable commit</small></span></li>
            <li className={busy === "run" ? "active" : run ? "complete" : ""}><b>2</b><span>Inspect and plan<small>Bounded repository evidence</small></span></li>
            <li className={run?.status === "AWAITING_APPROVAL" ? "active" : run ? "complete" : ""}><b>3</b><span>Policy decision<small>Approval only when required</small></span></li>
            <li className={successful ? "complete" : busy === "run" ? "active" : ""}><b>4</b><span>Patch and validate<small>AgentCore Code Interpreter</small></span></li>
            <li className={successful ? "complete" : ""}><b>5</b><span>Draft pull request<small>Never merged automatically</small></span></li>
          </ol>

          {!run && busy !== "run" && <p className="empty-state">Start the scenario to see the bounded remediation outcome.</p>}
          {busy === "run" && <div className="working"><span /><p>AgentCore is processing this synchronous run. Keep this tab open or resume with the saved UUID.</p></div>}
        </section>
      </div>

      {error && <div className="alert error"><strong>Request failed</strong><span>{error}</span></div>}

      {run?.approval_request && (
        <section className="panel approval-panel">
          <div>
            <p className="eyebrow">Human checkpoint · {run.approval_request.kind}</p>
            <h3>{run.approval_request.summary}</h3>
            <ul>{run.approval_request.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
            <code>{shortDigest(run.approval_request.scope_digest)}</code>
          </div>
          <div className="approval-form">
            <label>Reviewer<input value={reviewer} onChange={(event) => setReviewer(event.target.value)} /></label>
            <label>Comment<textarea value={comment} onChange={(event) => setComment(event.target.value)} /></label>
            <div className="button-row">
              <button className="primary" disabled={busy !== null || !reviewer.trim()} onClick={() => decide("APPROVED")}>Approve and continue</button>
              <button className="danger" disabled={busy !== null || !reviewer.trim()} onClick={() => decide("REJECTED")}>Reject</button>
            </div>
          </div>
        </section>
      )}

      {result && (
        <section className="results-grid">
          <article className="panel result-card wide">
            <p className="eyebrow">Remediation result</p>
            <h3>{result.remediation_plan_summary ?? "Workflow completed"}</h3>
            <p>{result.risk_summary ?? "No additional risk summary was returned."}</p>
            <div className="tag-row">{result.changed_files.map((file) => <code key={file}>{file}</code>)}</div>
            {result.draft_pr?.url && <a className="pr-link" href={result.draft_pr.url} target="_blank" rel="noreferrer">Open draft pull request <span>↗</span></a>}
          </article>

          <article className="panel result-card">
            <p className="eyebrow">Validation</p>
            <h3>{result.validation_attempts.length || 0} attempt{result.validation_attempts.length === 1 ? "" : "s"}</h3>
            {result.validation_attempts.map((attempt) => (
              <div className="validation" key={attempt.attempt}>
                <strong>Attempt {attempt.attempt} · {attempt.outcome}</strong>
                {attempt.results.map((item) => <span key={item.task_name}>{item.task_name}<b>{item.outcome}</b></span>)}
              </div>
            ))}
          </article>

          <article className="panel result-card">
            <p className="eyebrow">Evidence</p>
            <h3>{result.artifact_manifest?.artifacts.length ?? 0} artifacts</h3>
            {(result.artifact_manifest?.artifacts ?? []).slice(0, 4).map((artifact) => (
              <div className="artifact" key={artifact.path}><span>{artifact.name}</span><code>{shortDigest(artifact.digest)}</code></div>
            ))}
            {result.audit_bundle_ref && <div className="artifact"><span>Audit manifest</span><code>{shortDigest(result.audit_bundle_ref.digest)}</code></div>}
          </article>

          {result.errors.length > 0 && (
            <article className="panel result-card wide errors-card">
              <p className="eyebrow">Errors</p>
              {result.errors.map((item) => <div key={`${item.stage}-${item.code}`}><strong>{item.code}</strong><span>{item.stage} · {item.message}</span></div>)}
            </article>
          )}
        </section>
      )}

      <footer>
        <div><strong>Infrastructure check</strong><span>{probe || "Manual only — no model tokens spent on page load."}</span></div>
        <button className="text-button" disabled={busy !== null} onClick={probeOpenAI}>{busy === "probe" ? "Testing…" : "Test OpenAI connection"}</button>
      </footer>
    </main>
  );
}
