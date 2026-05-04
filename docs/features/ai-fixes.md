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
