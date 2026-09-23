import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { GatewayError, getArtifactPreview } from "./api";
import type { ArtifactPreview, ArtifactRef } from "./types";

interface ArtifactModalProps {
  artifact: ArtifactRef;
  runId: string;
  sessionId: string;
  returnFocusTo: HTMLElement;
  onClose: () => void;
}

export function formatArtifactContent(preview: ArtifactPreview): string {
  if (preview.media_type === "application/json" && !preview.truncated) {
    try {
      return JSON.stringify(JSON.parse(preview.content), null, 2);
    } catch {
      return preview.content;
    }
  }
  if (preview.media_type === "application/x-ndjson" && !preview.truncated) {
    return preview.content.split("\n").map((line) => {
      if (!line.trim()) return line;
      try {
        return JSON.stringify(JSON.parse(line), null, 2);
      } catch {
        return line;
      }
    }).join("\n");
  }
  return preview.content;
}

function previewError(error: unknown): string {
  if (error instanceof GatewayError) return error.code.replaceAll("_", " ").toLowerCase();
  return "The artifact preview could not be loaded.";
}

export function ArtifactModal({ artifact, runId, sessionId, returnFocusTo, onClose }: ArtifactModalProps) {
  const [preview, setPreview] = useState<ArtifactPreview | null>(null);
  const [error, setError] = useState("");
  const [activeView, setActiveView] = useState<"preview" | "details">("preview");
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState(false);
  const modalRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    returnFocusRef.current = returnFocusTo;
    closeRef.current?.focus();
    return () => returnFocusRef.current?.focus();
  }, [returnFocusTo]);

  useEffect(() => {
    let active = true;
    setPreview(null);
    setError("");
    void getArtifactPreview(runId, sessionId, artifact.name, artifact.digest)
      .then((response) => { if (active) setPreview(response.output); })
      .catch((caught: unknown) => { if (active) setError(previewError(caught)); });
    return () => { active = false; };
  }, [artifact.digest, artifact.name, runId, sessionId]);

  const rendered = useMemo(() => preview ? formatArtifactContent(preview) : "", [preview]);
  const matches = useMemo(() => {
    if (!query) return 0;
    return rendered.toLocaleLowerCase().split(query.toLocaleLowerCase()).length - 1;
  }, [query, rendered]);

  function closeModal() {
    returnFocusRef.current?.focus();
    onClose();
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      closeModal();
      return;
    }
    if (event.key !== "Tab" || !modalRef.current) return;
    const focusable = Array.from(
      modalRef.current.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), [href], [tabindex]:not([tabindex='-1'])"),
    );
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  async function copyContent() {
    if (!preview) return;
    try {
      await navigator.clipboard.writeText(rendered);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  function highlightedContent() {
    if (!query) return rendered;
    const expression = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi");
    return rendered.split(expression).map((part, index) =>
      part.toLocaleLowerCase() === query.toLocaleLowerCase()
        ? <mark key={`${part}-${index}`}>{part}</mark>
        : <Fragment key={`${part}-${index}`}>{part}</Fragment>,
    );
  }

  return (
    <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) closeModal(); }}>
      <div
        className="artifact-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="artifact-modal-title"
        ref={modalRef}
        onKeyDown={handleKeyDown}
      >
        <header className="modal-header">
          <div><span className="section-kicker">Redacted demo evidence</span><h2 id="artifact-modal-title">{artifact.name}</h2></div>
          <button ref={closeRef} className="icon-button" type="button" aria-label="Close artifact viewer" onClick={closeModal}>×</button>
        </header>
        <div className="modal-notice">Artifact content is redacted, integrity-checked, and bounded before display.</div>
        <nav className="modal-tabs" aria-label="Artifact views">
          <button type="button" aria-pressed={activeView === "preview"} onClick={() => setActiveView("preview")}>Preview</button>
          <button type="button" aria-pressed={activeView === "details"} onClick={() => setActiveView("details")}>Details</button>
        </nav>
        <div className="modal-body">
          {activeView === "preview" ? (
            <>
              {!preview && !error && <div className="working-state"><span className="spinner" /><div><strong>Loading evidence</strong><p>Retrieving the manifest-bound artifact.</p></div></div>}
              {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><div><strong>Preview unavailable</strong><p>{error}</p></div></div>}
              {preview && (
                <>
                  <div className="preview-toolbar">
                    <label>Search preview<input value={query} onChange={(event) => setQuery(event.target.value)} /></label>
                    <span>{query ? `${matches} match${matches === 1 ? "" : "es"}` : `${preview.size_bytes.toLocaleString()} bytes`}</span>
                    <button className="secondary" type="button" onClick={() => void copyContent()}>{copied ? "Copied" : "Copy content"}</button>
                  </div>
                  {preview.truncated && <div className="truncation-notice">Preview truncated at 256 KiB; the stored object digest was verified in full.</div>}
                  <pre className={`artifact-preview ${preview.media_type === "text/x-diff" ? "diff-preview" : ""}`}><code>{highlightedContent()}</code></pre>
                </>
              )}
            </>
          ) : (
            <dl className="property-table artifact-details">
              <div><dt>Name</dt><dd>{artifact.name}</dd></div>
              <div><dt>Media type</dt><dd><code>{preview?.media_type ?? artifact.media_type}</code></dd></div>
              <div><dt>Size</dt><dd>{preview ? `${preview.size_bytes.toLocaleString()} bytes` : "Unavailable until preview loads"}</dd></div>
              <div><dt>Digest</dt><dd><code>{artifact.digest}</code></dd></div>
              <div><dt>Integrity</dt><dd>{preview?.digest_verified ? "SHA-256 verified" : "Not verified in this view"}</dd></div>
              <div><dt>Object reference</dt><dd><code>{artifact.path}</code></dd></div>
              <div><dt>Preview</dt><dd>{preview?.truncated ? "Truncated" : preview ? "Complete" : "Unavailable"}</dd></div>
            </dl>
          )}
        </div>
      </div>
    </div>
  );
}
