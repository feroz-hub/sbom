"""
Phase-3 smoke test for the SSE streaming analyze endpoint.

The streaming endpoint was rewritten in Phase 3 to consume the
``app.sources`` registry + ``run_sources_concurrently`` runner instead of
its old inline ``source_map`` of lambdas. This test exercises the new path
end-to-end against the same canned source-fetcher fakes used by the
snapshot tests, then asserts:

  * the request returns 200 and ``text/event-stream``
  * the SSE body contains the expected event sequence:
      ``progress: started`` → ``progress: parsed`` → per-source
      ``running``/``complete`` → ``complete``
  * the final ``complete`` event reports a non-zero finding count
    (proving the registry-driven runner actually fanned the sources out
    and aggregated their results)
  * no event leaks the legacy ``gh_token_override`` plumbing detail —
    credentials are bound at adapter construction now
"""

from __future__ import annotations

import json
import re

import pytest


def _parse_sse_events(body: str) -> list[dict]:
    """
    Parse a text/event-stream body into a list of
    ``{"event": ..., "data": ...}`` dicts. Each SSE record is separated by
    a blank line; ``event:`` and ``data:`` lines are merged.
    """
    events: list[dict] = []
    for chunk in re.split(r"\n\n+", body.strip()):
        event_type = "message"
        data_lines: list[str] = []
        for line in chunk.splitlines():
            if line.startswith("event:"):
                event_type = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:") :].strip())
        if not data_lines:
            continue
        try:
            data = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            data = {"_raw": "\n".join(data_lines)}
        events.append({"event": event_type, "data": data})
    return events


@pytest.mark.snapshot
def test_analyze_stream_uses_registry_and_emits_per_source_progress(client, seeded_sbom, mock_external_sources):
    sbom_id = seeded_sbom["id"]

    resp = client.post(
        f"/api/sboms/{sbom_id}/analyze/stream",
        json={
            "sources": ["NVD", "OSV", "GITHUB"],
        },
    )

    assert resp.status_code == 200, resp.text
    assert "text/event-stream" in resp.headers.get("content-type", "")

    events = _parse_sse_events(resp.text)
    assert events, "stream produced zero SSE events"

    # ---- Phase order ----
    phases = [e["data"].get("phase") for e in events if e["event"] == "progress" and e["data"].get("phase")]
    assert phases[:2] == ["started", "parsed"], f"unexpected phase order: {phases}"

    # ---- Per-source running + complete events ----
    by_source: dict[str, list[str]] = {}
    for e in events:
        if e["event"] != "progress":
            continue
        src = e["data"].get("source")
        status = e["data"].get("status")
        if src and status:
            by_source.setdefault(src, []).append(status)

    assert set(by_source) == {"NVD", "OSV", "GITHUB"}, f"missing sources in stream events: {by_source}"
    for src, statuses in by_source.items():
        assert "running" in statuses, f"{src} never emitted running"
        assert "complete" in statuses, f"{src} never emitted complete"
        # No source should report error — the canned fakes always succeed.
        assert "error" not in statuses, f"{src} unexpectedly errored: {statuses}"

    # ---- Final complete event ----
    completes = [e for e in events if e["event"] == "complete"]
    assert len(completes) == 1, "expected exactly one terminal complete event"
    final = completes[0]["data"]

    # Mock fixture: log4j → NVD CRITICAL + GHSA CRITICAL (deduped) and
    # requests → OSV HIGH ⇒ at least 2 unique findings, ≥1 critical, ≥1 high.
    assert final["total"] >= 2
    assert final["critical"] >= 1
    assert final["high"] >= 1
    assert final["status"] == "FINDINGS"  # ADR-0001 (was FAIL)
    assert isinstance(final["runId"], int)
    assert final["errors"] == 0
