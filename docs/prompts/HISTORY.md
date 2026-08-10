# Prompt versioning history

> Bumping `PROMPT_VERSION` in
> [`app/ai/prompts/__init__.py`](../../app/ai/prompts/__init__.py)
> invalidates every `ai_fix_cache` row on next read. Plan a budget
> bump alongside any prompt change — the next batch run is full
> cold-cache cost.

This file is an append-only log of prompt evolutions. New entries go at
the **top**.

---

## v3 — 2026-06-09 (overall-response confidence)

**Files:**
* [`v3.system.txt`](../../app/ai/prompts/v3.system.txt)
* [`v3.user.txt`](../../app/ai/prompts/v3.user.txt)

**Schema version:** 1 (unchanged — see below).

**Change in plain language:**
The bundle gained a fourth top-level key, `overall_confidence`
(`high` / `medium` / `low`) — the model's self-assessed confidence in the
*entire* response, distinct from the existing per-section `confidence`
fields on `remediation_prose` and `decision_recommendation` (each of which
scopes only its own section). A new hard rule (§9 in `v3.system.txt`)
tells the model to reserve `"high"` for a grounded fix version plus an
unambiguous exploitation picture and to drop to `"low"` when
`fix_versions` is empty or the data is sparse/conflicting. The UI surfaces
this prominently at the top of the AI-fix section so a reader can
calibrate trust before reading the detail. The value is **model
self-reported and NOT server-clamped** — `_post_validate` leaves it alone.

**Cache impact:** Full invalidation on next read. `PROMPT_VERSION` is part
of the cache key, so the v2→v3 bump re-keys every `ai_fix_cache` row; the
next batch run is full cold-cache cost. This is deliberate — stale v2
bundles predate the field and would otherwise serve a defaulted
`"medium"`. Old v2 rows are orphaned and expire naturally (7d KEV / 30d).

**Why `SCHEMA_VERSION` was NOT bumped:** The new field is backward
compatible — it carries a default (`"medium"`), so any historical
serialized bundle (three keys) still validates. Bumping `SCHEMA_VERSION`
would mark *all* rows stale on read regardless of prompt version, which is
redundant with the prompt re-key and contradicts the rule in
[`schemas.py`](../../app/ai/schemas.py) ("only bump when the bundle shape
changes in a backward-incompatible way"). Persistence is handled by a new
nullable `overall_confidence` column on `AiFixCache`
([migration 019](../../alembic/versions/019_ai_fix_cache_overall_confidence.py));
`read_cache` coerces `NULL` (pre-019 rows) to `"medium"`.

**Validation evidence:**
* Prompt-level: hard rule §9 + the user-prompt constraint summary.
* Schema-level: `_normalize_overall_confidence` (casing) + the `ConfidenceTier`
  Literal (rejects junk).
* Tests: `tests/ai/test_schemas.py` (default-when-omitted, case
  normalisation, invalid-value rejection, 4-key JSON-schema export);
  `tests/ai/test_prompts_and_cache.py` (`PROMPT_VERSION == "v3"`, prompt
  contains `overall_confidence`, cache round-trip persists it, UPSERT
  updates it, `NULL`→`"medium"` fallback); `tests/ai/test_fix_generator.py`
  (E2E miss+hit threading and capitalised-enum normalisation);
  `frontend/.../OverallConfidenceBadge.test.tsx` (all three tier branches).

---

## v2 — 2026-05-XX (Phase 5 format hardening) — backfilled 2026-06-09

> Backfilled retroactively: the v2 bump shipped without a HISTORY entry.
> Reconstructed here from the prompt files and `PROMPT_VERSION` comment so
> the log is complete and the on-disk prompts are no longer undocumented.

**Files:**
* [`v2.system.txt`](../../app/ai/prompts/v2.system.txt)
* [`v2.user.txt`](../../app/ai/prompts/v2.user.txt)

**Schema version:** 1.

**Change in plain language:**
Format-only hardening (no semantic change to the advice). Added explicit
instructions to address Gemini / OpenAI-compat malformed output that
surfaced as `schema_parse_failed`: no markdown code fences, no
preamble/trailing commentary, lowercase `snake_case` enums, exact
`snake_case` field names, and "first char `{`, last char `}`". The schema
loosening that accompanied this era (case-insensitive enums, ignored
extra fields, sensible defaults for the secondary classification fields)
lives in [`schemas.py`](../../app/ai/schemas.py) and is covered by
`tests/ai/test_schemas_lenient.py`.

**Cache impact:** Full invalidation on next read (the v1→v2 re-key).

---

## v1 — 2026-05-03 (Phase 2 launch)

**Files:**
* [`v1.system.txt`](../../app/ai/prompts/v1.system.txt)
* [`v1.user.txt`](../../app/ai/prompts/v1.user.txt)

**Schema version:** 1 (the `AiFixBundle` shape in
[`app/ai/schemas.py`](../../app/ai/schemas.py)).

**Hard rules in this prompt:**

1. Speak in concrete, technical terms. No marketing language.
2. `actively_exploited` ONLY when `kev_listed=true`. Otherwise choose
   from `high`, `moderate`, `low`, `theoretical`.
3. NEVER invent fix versions. Use ONLY versions in the input
   `fix_versions[]` array. When the array is empty:
   * `target_version` MUST be `"n/a"`
   * `tested_against_data` MUST be `false`
   * `breaking_change_risk` MUST be `"unknown"`
   * `recommended_path` SHOULD describe replacement / removal / sandbox
4. Honest confidence flags. `"high"` requires full data support;
   downgrade otherwise.
5. `citations[]` MUST be a subset of input `sources_used[]`. Cite
   `"fix_version_data"` only when `fix_versions` is non-empty.
6. Output JSON only — no prose, no code fences, no comments, no extra
   fields.

**Output shape:** single JSON object with three top-level keys
(`remediation_prose`, `upgrade_command`, `decision_recommendation`).
One LLM call produces all three artifacts; folding cuts cost ~67% vs
three serial calls.

**Defense in depth:** even if the model violates the prompt rules,
`AiFixGenerator._post_validate` flips `tested_against_data → false`
when the model invents a version, demotes
`actively_exploited → high` when the finding isn't KEV-listed, and
prunes citations referencing sources not in the grounding context.

**Initial deployment:**
* Default provider: `anthropic` / `claude-sonnet-4-5`
* Approximate cost per finding: $0.001 - $0.020 depending on grounding
  context size
* Expected cache hit ratio in steady state: 70-90%

**Why these rules in this order:**

The order matters. The model parses rules sequentially; structural
constraints (output JSON) come last so the LLM commits to the format
after it's already heard the semantic constraints (no invented
versions, no unsupported claims). Putting "output JSON only" first led
in pre-launch testing to one of two failure modes: either the model
over-indexed on the structural constraint and ignored the semantic
ones, or it dumped JSON then appended an explanatory paragraph the
parser had to strip.

**Known quirks:**
* On low-EPSS, low-CVSS findings, the model occasionally argues for
  `priority="defer"` even when fix data is available. Acceptable —
  the user can still apply the upgrade if they choose.
* When `cve_summary_from_db` is empty (newly published CVE), the model
  tends to hedge with `confidence="medium"`. Also acceptable — exactly
  the calibration we want.

---

## How to add a new prompt version

1. Copy `v1.system.txt` → `v2.system.txt` (and same for `.user.txt`).
2. Edit the new files. Do NOT modify v1 — the cache key still references
   v1 for any row that hasn't aged out, so v1 must stay reproducible.
3. Bump `PROMPT_VERSION` in
   [`app/ai/prompts/__init__.py`](../../app/ai/prompts/__init__.py)
   from `"v1"` to `"v2"`.
4. Add a new entry to the **top** of this file. Include:
   * The change in plain language.
   * The expected cache impact (full invalidation? partial?).
   * The validation evidence: prompt-level + post-validation + at least
     one new test.
5. Update the smoke script if the change affects the output shape.
6. Re-run [`scripts/ai_fix_smoke.py`](../../scripts/ai_fix_smoke.py)
   against a real provider and review the output. Five canonical
   examples must remain quality-acceptable per Phase 2 §6 gate.

---

## How NOT to use this file

This file is **not** a changelog for the rest of the AI subsystem.
Code-level changes (provider edits, schema bumps, new endpoints) go
in [`CHANGELOG.md`](../../CHANGELOG.md).

This file tracks what the *model* is being asked to do and why. If the
prompt changes but the schema, providers, and orchestration are
identical, only this file gets a new entry.
