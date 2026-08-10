# Compare runs

Compare two analysis runs side-by-side and answer the four release-decision
questions in under a minute:

1. **Is this build safer than the last one?** — posture delta header
2. **What new exposure did this build introduce?** — Findings tab, "+ NEW" rows
3. **What did this build fix?** — Findings tab, "✓ RESOLVED" rows, with credit to the upgrade that fixed each
4. **What components changed, and how does that map to vulnerability changes?** — Components tab, with cross-link to the matching findings

Open the page from the Analysis Runs list (Compare button) or directly at
`/analysis/compare?run_a=<id>&run_b=<id>`.

> **Architecture & rationale:** see [ADR-0008](adr/0008-compare-runs-architecture.md).
> **Operator runbook:** [runbook-compare.md](../runbook-compare.md).
> **Visual language reference:** [compare-visual-language.md](../design/compare-visual-language.md).

---

## Workflow

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Region 1 — Selection bar                                  sticky top    │
│   [▼ Run A picker]   →   [▼ Run B picker]      [Swap ⇄] [Share 🔗]      │
│   Same project · 2 days apart                                            │
├──────────────────────────────────────────────────────────────────────────┤
│ Region 2 — Posture delta                                  sticky        │
│   ████████████░░░░░░░░░░░░░████████████  +1 / -19 / 3 unchanged          │
│   ┌─KEV exposure─┐  ┌─Fix-available─┐  ┌─High+Critical─┐                 │
│   │  2 → 1  ▼-1  │  │ 60% → 80% +20pp│  │  12 → 8  ▼-4  │                │
│   └──────────────┘  └────────────────┘  └───────────────┘                │
├──────────────────────────────────────────────────────────────────────────┤
│ Region 3 — Tabs                                                         │
│   [Findings (30)] [Components (33)] [Posture detail]                    │
│   ▼ filter chips ▼ free-text search ▼ table                             │
└──────────────────────────────────────────────────────────────────────────┘
```

### 1. Pick two runs

Use the in-page pickers — no need to bounce back to the Analysis Runs list.

- Default open: 20 most recent runs you've touched.
- Type to search by SBOM name, project name, or run id.
- "Same project as Run A" filter chip narrows Run B in one click.
- The picker remembers nothing across sessions; the URL is the source of truth.

If the descriptor below the pickers reads "Run B is older than Run A", click
the warning chip to swap (or use the **Swap ⇄** button).

### 2. Read the headline first

The hero shows a data-driven headline that tells you what kind of change the diff is in one line. The colour and phrasing are dictated by the underlying numbers — same numbers always produce the same headline, so the page is shareable in a release ticket without a screenshot.

| If the diff is… | Headline reads | Tone |
|---|---|---|
| Both runs empty | "No vulnerabilities in either run." | neutral |
| Identical (same findings, no diff) | (the page collapses to the celebratory check card; not a regular hero) | green |
| Only new findings | "+N new findings. Nothing resolved." | red |
| Only resolved findings | "−N findings resolved. No new exposure." | green |
| Only severity reclassifications | "N findings reclassified. No additions or removals." | amber |
| Mixed, more resolved than added | "Net safer: −R resolved vs +A added." | green |
| Mixed, more added than resolved | "Net worse: +A new vs −R resolved." | red |
| Equal mix | "Mixed: +A new, −R resolved." | amber |

If severity reclassifications are present alongside any of the above, the headline appends "Plus N severity reclassifications." with the same tone.

The italic sub-line beneath tells you the *kind* of change the diff is — when the same SBOM is re-scanned, you'll see "Same SBOM, re-scanned 11h later — feed-only changes possible." That phrasing is the highest-information line on the page: it tells you the entire delta (or non-delta) is attributable to the vulnerability feed, not the codebase.

### 3. Read the posture delta

Three independently-defensible deltas, anchored to public sources:

| Tile | What it measures | Direction = better |
|---|---|---|
| **KEV exposure** | Findings whose CVE is currently listed in the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Down |
| **Fix-available coverage** | Percentage of findings whose `fixed_versions` is non-empty | Up |
| **High+Critical exposure** | Findings at HIGH or CRITICAL severity | Down |

> **Why no overall "risk score"?** A scalar that mashes severity, KEV, and
> EPSS together hides which signal moved. Two independently-defensible
> deltas (KEV count, fix-available coverage) plus the high+critical headline
> tell you more in less screen real-estate. See [ADR-0008 §11 PB-1](adr/0008-compare-runs-architecture.md#pb-1-highest--drop-the-risk-score-scalar-entirely)
> and [risk-index.md](../risk-index.md).

The horizontal distribution bar above the tiles shows finding-event
proportions: red (added), amber (severity-changed), slate (unchanged), and
green (resolved). Green sweeping in from the right tells you the diff is
net-positive at a glance.

### 4. Drill into a tab

#### Findings (default)

One row per **finding diff event**. Each row's `change_kind` is one of:

| Chip | Meaning |
|---|---|
| **+ NEW** | finding present in B, absent in A |
| **✓ RESOLVED** | finding present in A, absent in B (row is greyed) |
| **↕ SEVERITY** | same finding in both, different severity |
| (hidden) | unchanged — toggle "Show unchanged" to reveal |

Sort order: severity_changed first, then added, then resolved, with severity
descending and CVE id alphabetical inside each kind.

**Filters** (all live in the URL):

- Change-kind chips — multi-select, default excludes `unchanged`
- Severity chips — Critical / High / Medium / Low
- 🔥 **KEV** — only findings currently in CISA KEV
- 🔧 **Fix-available** — only findings with a known fix
- **Show unchanged** — reveals the "no change between runs" rows
- Free-text — matches CVE id, component name, or PURL

**Click any row** to open the in-app CVE detail modal (severity, CVSS, KEV,
EPSS, fix versions, references, recommended upgrade). For non-CVE/GHSA
identifiers (PYSEC, RUSTSEC, OSV-generic) where the modal can't render, the
inline external link to OSV.dev is the fallback.

#### Components

One row per **component diff event**. Same chip + filter pattern as
Findings. Each row shows `version_a → version_b` with an arrow direction,
and a "Linked findings" cell that says "−2 resolved" or "+1 new" — clickable
to jump to the matching Findings rows.

If any component has the same name+version but a different content hash, a
red **supply-chain alert** banner appears at the top of the tab. This is
uncommon and may indicate registry tampering.

> **Note:** license_changed and hash_changed change_kinds are stubbed in v1
> — neither column is stored on `sbom_component` today, and a hard env-var
> guard (`COMPARE_LICENSE_HASH_ENABLED`, default `false`) prevents accidental
> activation. See [ADR-0008 §10](adr/0008-compare-runs-architecture.md).

#### Posture detail

Read-only analytical view:

- Side-by-side severity composition bar for Run A and Run B
- Top 5 risk reductions (resolved findings, ranked KEV-first → severity →
  fix-available → alphabetical)
- Top 5 risk introductions (added findings, same ranking)

The ranking is **ordinal**, not a weighted score — same anti-scalar principle
as the Region 2 tiles.

---

## Keyboard shortcuts

Press `?` anywhere on the page to toggle the shortcuts overlay.

| Key | Action |
|---|---|
| `1` / `2` / `3` | Switch to Findings / Components / Posture detail |
| `s`, `/` | Focus the filter input |
| `e` | Open the export dialog |
| `?` | Toggle shortcuts overlay |
| `Esc` | Close any open overlay |

Shortcuts are silenced while typing into an input, textarea, or
contenteditable — typing into the search box never accidentally swaps tabs.

---

## Export

Click **Export** (top-right) or press `e` to open the dialog. Three formats:

| Format | Use case |
|---|---|
| **Markdown** | Paste into a Slack channel, Notion page, or release ticket |
| **CSV** | Open in a spreadsheet for triage / triage spreadsheet imports |
| **JSON** | Full payload for automation (the same schema the API returns) |

Markdown sample:

```md
# Compare: Run #1 → Run #3
_sample-sbom (2026-04-15) → sample-sbom (2026-04-30)_

## Posture
- **KEV exposure**: 2 → 1 (-1)
- **Fix-available coverage**: 50.0% → 80.0% (+30.0pp)
- **High+Critical exposure**: 12 → 8 (-4)

## Resolved (19)
- ✓ `CVE-2021-44832` (CRITICAL, KEV) — `log4j-core@2.16.0` _via upgrade log4j-core 2.16.0 → 2.17.1_
...

## Newly introduced (8)
- + `CVE-2024-12345` (HIGH) — `pyyaml@6.0.1` _via new dependency pyyaml@6.0.1_
```

Exports stream from the server using the cached comparison; if the cache
has expired (24h TTL), the page recomputes the diff on demand before
serving the file.

---

## URL state for sharing

The URL captures every selection and filter. Click **Share 🔗** to copy
the current URL — anyone with access to the same runs sees the exact same
view, including filter chip states, severity selection, KEV-only toggle,
and search text.

| Parameter | Type | Notes |
|---|---|---|
| `run_a`, `run_b` | int | Run IDs |
| `tab` | findings/components/delta | Default: findings |
| `change` | comma list | Default: added,resolved,severity_changed |
| `severity` | comma list | Default: critical,high,medium,low,unknown |
| `kev_only` | true/false | |
| `fix_available` | true/false | |
| `show_unchanged` | true/false | |
| `q` | string | Free-text search |

Default values are omitted from the URL to keep share links short.

---

## Limitations (v1)

These are deliberate scope choices for v1; each has a tracked follow-up.

| Limitation | Why | Follow-up |
|---|---|---|
| **No tenant scoping** | Single-org product today | Add `tenant_id` columns + RLS |
| **License changes never fire** | `sbom_component.license` not stored | Schema migration |
| **Content-hash supply-chain alerts never fire** | `sbom_component.content_hash` not stored | Schema migration |
| **KEV / EPSS reflect *current* catalog state, not at-scan-time** | Findings don't snapshot KEV/EPSS | Snapshot on persist |
| **No three-way compare** | UI complexity | v2 feature |
| **No saved comparisons / "watch this diff"** | Requires user-prefs surface that doesn't exist | v2 feature |
| **No streaming for very large diffs** | Single-JSON path serves up to ~5000 findings | Add SSE on the server |
| **No AI narrative summary** | Defer to a focused follow-up after this ships clean | Separate prompt |

---

## Data sources

- **Compare endpoint:** `POST /api/v1/compare`
- **Cache:** `compare_cache` table — keyed by `sha256(min(a,b):max(a,b))`, TTL 24h
- **Picker:** `GET /api/runs/recent`, `GET /api/runs/search`
- **Export:** `POST /api/v1/compare/{cache_key}/export`
- **CVE enrichment:** `cve_cache` table (read-only — diff engine never refetches)

The deprecated `GET /api/analysis-runs/compare` (v1) is preserved during the
strangler period for back-compat with external scripts. Every response carries
`Deprecation: true` and `Sunset` headers so SDK consumers see the warning.
