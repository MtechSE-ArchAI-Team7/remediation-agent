import { describe, expect, it } from "vitest";
import { formatArtifactContent } from "./ArtifactModal";
import type { ArtifactPreview } from "./types";

function preview(mediaType: string, content: string, truncated = false): ArtifactPreview {
  return {
    schema_version: "1.0",
    run_id: "run-1",
    name: "evidence",
    media_type: mediaType,
    digest: `sha256:${"a".repeat(64)}`,
    content,
    size_bytes: content.length,
    truncated,
    digest_verified: true,
  };
}

describe("formatArtifactContent", () => {
  it("pretty-prints complete JSON and JSONL previews", () => {
    expect(formatArtifactContent(preview("application/json", '{"status":"ok"}'))).toBe(
      '{\n  "status": "ok"\n}',
    );
    expect(formatArtifactContent(preview("application/x-ndjson", '{"event":1}\n{"event":2}\n'))).toContain(
      '  "event": 2',
    );
  });

  it("preserves diffs and truncated JSON exactly", () => {
    const diff = "--- a/file\n+++ b/file\n+value";
    const partialJson = '{"status":';
    expect(formatArtifactContent(preview("text/x-diff", diff))).toBe(diff);
    expect(formatArtifactContent(preview("application/json", partialJson, true))).toBe(partialJson);
  });
});
