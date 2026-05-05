# AI fix generator

> Audience: developers + security engineers using the SBOM Analyzer.
> Operator-facing: see [docs/runbook-ai-fixes.md](../runbook-ai-fixes.md).

The AI fix generator turns each finding in your SBOM scan into three
pieces of contextual remediation guidance:

1. **Remediation prose** — 2-4 sentences explaining the vulnerability
   in the context of the specific component and version found in your
   SBOM, plus the recommended path forward.
2. **Upgrade command** — a copy-paste-ready command for the relevant
   ecosystem (`npm install`, `pip install`, a `<dependency>` snippet
   for Maven, etc.) plus a one-line rationale and a breaking-change
   risk assessment.
3. **Decision recommendation** — a structured "should you act on this
   now" recommendation: priority (urgent / soon / scheduled / defer),
   confidence (high / medium / low), the reasoning trail, and explicit
   citations to OSV / GHSA / NVD / EPSS / KEV data the model used.

---

## How to use it

### Single finding (CVE detail modal)

1. Open a run page (`/analysis/{run_id}`).
2. Click any finding in the table to open the CVE detail modal.
3. Scroll past the deterministic CVE data; the AI section is at the
   bottom.
4. If a fix bundle is already cached (most common case), it renders
   instantly. Otherwise click **Generate AI remediation** and wait
   3-8 seconds.
5. The **Regenerate** link is always visible — use it after a prompt
   bump or when you suspect the model misread the context.

### Whole run (batch)

1. On the run detail page, look for the AI banner above the findings
   table.
2. Click **Generate AI fixes**. The pipeline processes every finding
   with bounded concurrency (10-32 in flight per provider).
3. Progress is reported live via Server-Sent Events; the banner shows
   cache hits, generated fixes, failures, and cumulative cost.
4. Click **Cancel** to stop the run cooperatively. In-flight LLM calls
   complete (we paid for those tokens); subsequent findings are
   skipped.

### Scoping a batch (filters or selection)

A run with hundreds of findings doesn't need every finding processed
at once. Three ways to scope a batch:

* **Filter chips on the findings table.** Click a severity tab,
  toggle "KEV only" or "Fix available", or type into search. The CTA
  card above the table reactively updates: the label shows the
  active scope ("Critical findings", "KEV findings", "Findings
  matching 'log4j'"), the estimate recomputes (count, cache hits,
  cost, ETA), and clicking Generate fires a batch over only those
  findings.
* **Row checkboxes.** Tick the checkbox column to multi-select
  specific rows. The CTA flips to "Generate AI fixes for N selected
  findings" — selection takes precedence over filters when both are
  active. A bulk toolbar shows the count and "across X severities";
  click "Clear selection" or use the "Clear selection to use filters"
  link on the CTA to revert to filter-driven scope.
* **No scope (default).** Empty filter, no selection → the batch
  covers every finding in the run.

Filter and selection state are page-local; refreshing the page
resets them. Selection persists across filter changes (selecting
Critical rows then narrowing to Medium does NOT deselect the
Criticals — they remain selected even when not visible).

### Multiple concurrent batches per run

Up to **3** scope-aware batches can run in parallel for a single
run. The cache layer is shared, so a second batch with overlapping
scope picks up the first batch's results as cache hits in real time.

* Fire "Generate for Criticals" first. While it's running, change
  the filter to "KEV only" and fire a second batch — both run in
  parallel, both appear as separate rows in the global progress
  banner with their scope label visible.
* The 4th concurrent batch returns a typed 409 error
  (`TOO_MANY_ACTIVE_BATCHES`); the CTA disables itself with a
  "wait for one to complete" message until an active batch
  terminates.
* Cancel one batch via its individual Cancel button; other active
  batches on the same run keep running.

The banner shows up to 3 rows in full, with overflow collapsed
behind "+N more AI batches in progress."

### Cost optimization patterns

* **Triage-first.** On a 500-finding run with a paid provider, fire
  the Criticals batch first (~50 findings, ~$0.30, ~12 seconds).
  Validate the output, then expand to High + Medium with a second
  batch. The CTA's pre-flight estimate makes the cost trade-off
  explicit before you click Generate.
* **Free-tier batching.** Gemini's free tier caps at 15 RPM, so a
  500-finding batch takes ~33 minutes serial. A KEV-only batch
  ($0, ~30 sec for 6 findings) gets the highest-priority guidance
  in under a minute. Then run a paid Criticals batch in parallel
  for everything else.
* **Cache-aware re-runs.** Re-firing the same scope after a partial
  cancel costs nothing for the rows that completed — the cache
  layer dedups by `(vuln_id, component_name, component_version)`
  regardless of run id, so two scope-overlapping batches on the
  same run never call the LLM twice for the same finding.

---

## What "grounded" means

The model is **not** allowed to invent fix versions. Before each call
the orchestrator builds a `GroundingContext` from the merged
OSV / GHSA / NVD / EPSS / KEV cache and the SBOM component data, and
the system prompt explicitly forbids inferring versions outside that
list. After the model responds, the orchestrator validates the
suggestion: if the model named a version not in the data, the
`tested_against_data` flag is flipped to `false` and the UI renders
the suggestion with an "⚠ Inferred recommendation" caveat.

The same defence applies to:

* **Exploitation likelihood** — `actively_exploited` is only allowed
  when the finding is on the CISA KEV list. Other claims get demoted
  to `high`.
* **Citations** — the model can only cite sources that contributed to
  the grounding context.

---

## Cost model

Roughly **$0.001 - $0.020 per finding**, depending on the provider and
the size of the grounding context. With sensible cache reuse (typical
runs see 70-90% cache hits), a 1,000-finding scan costs **$0.05 - $5**
in steady state. Cold-cache cost can briefly spike to $5-$20 the first
time the org runs the feature; after that the cache absorbs everything.

Three budget caps protect you:

* **Per-request** — single LLM call. Default $0.10. Estimated cost
  > cap → call rejected pre-flight.
* **Per-scan** — single batch run. Default $5.00. Hit → batch flips
  to `paused_budget` status; remaining findings are skipped (you can
  bump the cap and re-run; the cache absorbs everything generated so
  far so the resume is essentially free).
* **Per-day org** — daily cap. Default $50.00. Reset at UTC midnight.

See [docs/runbook-ai-fixes.md](../runbook-ai-fixes.md) for tuning.

---

## Provider switching

Set `AI_DEFAULT_PROVIDER` to `anthropic`, `openai`, `ollama`, or
`vllm`. The AI surface uses the new provider on the next request — no
code change. Settings → AI shows which providers are configured and
which is active.

---

## Privacy

* The vulnerability data fed to the model is the same data already
  visible in the modal — your SBOM contents, public CVE / GHSA
  payloads, EPSS / KEV signals.
* No source code or proprietary internals are sent.
* The full LLM response body is **never logged**; only a SHA-256 of it
  is kept for debug correlation.
* Cache entries are **tenant-shared** by design — the AI advice for
  `(CVE, package, version)` is not user-specific.
