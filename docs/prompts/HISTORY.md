# Prompt versioning history

> Bumping `PROMPT_VERSION` in
> [`app/ai/prompts/__init__.py`](../../app/ai/prompts/__init__.py)
> invalidates every `ai_fix_cache` row on next read. Plan a budget
> bump alongside any prompt change — the next batch run is full
> cold-cache cost.

This file is an append-only log of prompt evolutions. New entries go at
the **top**.

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
