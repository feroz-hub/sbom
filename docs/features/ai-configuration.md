# AI configuration

> Audience: workspace administrators.
> Operator runbook: [docs/runbook-ai-credentials.md](../runbook-ai-credentials.md).
> Engineer reference: [docs/architecture/ai-pipeline.md](../architecture/ai-pipeline.md).

The Settings → AI page (``/settings/ai``) is where you configure which
AI providers the SBOM Analyzer talks to. Everything saved here is
encrypted at rest and applied at runtime — no service restart, no
file edits, no SSH access required.

---

## What you can do here

* Add a new AI provider — Anthropic, OpenAI, Google Gemini (free tier
  available), xAI Grok (free tier available), Ollama (self-hosted),
  vLLM (self-hosted), or any custom OpenAI-compatible endpoint.
* Switch the default provider — every AI fix generation request after
  the next save uses the new provider.
* Set a fallback — one controlled attempt is made after a transient provider
  outage, network failure, throttling, upstream 5xx, or open circuit.
* Toggle the kill switch — immediately blocks every AI call across
  the deployment.
* Adjust budget caps — per request, per scan, per day.
* See live usage — total spent this month, cache hit rate, top
  provider. The full dashboard lives at ``/admin/ai-usage``.
* Refresh the live model catalog, run a low-cost structured-output test, and
  explicitly choose the active model for each saved credential.

## Model discovery and selection

After a connection test succeeds, save the credential and use this production
workflow:

```
Configure provider → Test connection → Save → Refresh models
→ Test model → Set active → Enable AI
```

Refresh queries the provider through its adapter and stores normalized rows in
`ai_provider_model`. New rows are shown as available but are never selected
automatically. A model that disappears remains in history and is marked
unavailable; if it was active, it remains active until an administrator makes
an explicit change. This avoids an upstream catalog change silently changing
production behavior.

The UI distinguishes provider IDs from runtime IDs where the adapter must
normalize them (for example, Gemini's `models/...` resource name). Capability
values are three-state: yes, no, or unknown. Unknown does not mean unsupported.

Current model precedence is:

1. Feature-specific assignment (reserved extension point; no feature-specific
   assignments are stored yet).
2. Selected registry model for the exact provider credential.
3. Preserved legacy `default_model` from the DB or environment.
4. A provider constructor bootstrap value only for an unsaved/legacy setup.

AI Fix, Copilot, validation repair, batch processing, regeneration, API
processes, and Celery workers all consume the same effective provider config.
The registry stamps the resolved model on every generation request and stamps
the fallback provider's own resolved model if fallback is used.

| Provider | Discovery mechanism |
|---|---|
| OpenAI | Native `GET /v1/models` |
| Anthropic | Paginated native `GET /v1/models` |
| Gemini | Native Models API; retains `models/...` provider IDs |
| xAI / Grok | xAI OpenAI-compatible `GET /v1/models` |
| Ollama | Local `GET /api/tags` installed-model list |
| vLLM | OpenAI-compatible `GET /v1/models` |
| Custom OpenAI-compatible | Attempts validated-base `GET /v1/models`; reports unsupported on 404 |
| Sarvam | Attempts the current integration's `/v1/models`; reports unsupported when that chat endpoint does not expose listing. Sarvam's separate v2 catalog is not presented as compatible with the current v1 runtime. |

---

## Recommended starting setup

| If you're … | Recommended |
|---|---|
| Trying it out / evaluating | **Gemini Flash (free tier)** as default. No credit card. 15 req/min limit means ~70 minutes for a 1000-finding scan, but it's free and the cache absorbs the second pass. |
| Running production at low cost | **Gemini Flash (paid)** as default. Same prompt, no rate limit, ~$0.0003 per finding. |
| Running production at highest quality | **Anthropic Claude Sonnet 4.5** as default. Best fix-generation quality in our testing. ~$0.015 per finding average. |
| Air-gapped or on-prem | **Ollama with Llama 3.3 70B**. Zero per-call cost. You provide the GPU. |

You can change providers any time. The cache is shared across providers
— once a fix bundle is generated, switching to a different provider
keeps the cached entries valid.

---

## Adding a provider — full walkthrough

### 1. Open the dialog

From any page: navigate to Settings → AI configuration. If the
section is missing, AI fixes aren't enabled for this deployment yet —
contact your administrator.

Click **Add provider** in the AI providers section.

### 2. Pick the provider

The dropdown lists the eight supported providers. Free-tier providers
are flagged with ⭐. Self-hosted options (Ollama / vLLM / Custom) are
labeled "local".

### 3. Fill in the fields

The form changes based on what each provider needs:

| Provider | Fields | Where to get a key |
|---|---|---|
| Anthropic | API key + model | https://console.anthropic.com/settings/keys |
| OpenAI | API key + model | https://platform.openai.com/api-keys |
| Google Gemini | API key + model + tier | https://aistudio.google.com/app/apikey |
| xAI Grok | API key + model + tier | https://console.x.ai/ |
| Sarvam AI | API key + model | https://dashboard.sarvam.ai/ |
| Ollama | Base URL + model | (self-hosted, no API key) |
| vLLM | Base URL + model | (self-hosted) |
| Custom OpenAI-compatible | Base URL + optional API key + model + cost overrides | (your endpoint) |

For free-tier providers you'll see a "Tier" dropdown — leave it on
"Free" until you're ready to upgrade. The platform respects free-tier
rate limits automatically.

### 4. Test connection

Click **Test connection**. The platform makes a no-cost probe (a
``GET /models`` call where the provider supports it, falling back to
a 4-token chat completion otherwise) and reports the result inline:

| What you see | What it means |
|---|---|
| ✅ Connected. N model(s) available. Latency: 412ms | All good — Save is unlocked. |
| ❌ Invalid API key | The key didn't authenticate. Re-check it. |
| ⚠ Couldn't reach the provider | Network issue. Check the base URL or your firewall. |
| ℹ Connected, but rate-limited | Free-tier daily cap hit. Wait, switch tier, or try later. |
| ⚠ Connected, but {model} isn't available | The model name is wrong. The dialog shows the available list. |

**Save is disabled until the test passes.** This is the single
biggest UX rule — it prevents 80% of "I saved bad config and now
nothing works" issues. You can change anything in the form and
re-test as many times as you need; nothing is persisted until Save.

### 5. Save

Save persists the credential, encrypts the API key with the
deployment's master key, and invalidates the runtime cache so the
next request uses the new credential. You'll see the new card appear
in the providers list.

---

## Editing a credential

Click the kebab menu (`⋯`) on any provider card → **Edit**. The dialog
opens pre-populated with the saved values. The API key field shows
"Leave blank to keep existing" — only enter a new value if you're
rotating the key.

The saved key's preview (`sk-ant…AhB7`) is visible above the input so
you can confirm which key you're about to replace.

---

## Setting default + fallback

The kebab menu offers **Set as default** and **Set as fallback**.
Promotion is atomic — promoting a new default automatically demotes
the previous one in the same transaction (no momentary "two
defaults" state).

* **Default** — used for every AI fix generation request unless
  overridden per-request.
* **Fallback** — attempted at most once when the primary has a transient
  provider outage, network failure, throttling/quota response, upstream 5xx,
  or open circuit. Authentication, model, request/schema, grounding, budget,
  and local configuration failures do not fall back. Usage telemetry records
  the primary failure and selected fallback without credential material.

---

## Disabling and deleting

* **Disable** keeps the credential row but makes the orchestrator
  skip it. Useful for "I'm out of free quota for the day, switch to
  paid". Toggleable from the kebab menu.
* **Delete** removes the credential entirely. The dialog requires you
  to type the provider name to confirm — a deliberate friction
  against accidental deletion.

Deletion does NOT revoke the API key with the upstream provider. If
the deployment had been compromised, rotate the key in the upstream
console (Anthropic / OpenAI / Google AI Studio / etc.) immediately,
not just in the SBOM Analyzer.

---

## Budget caps

Three caps protect you from runaway spend:

| Cap | What it blocks | Recommended starting value |
|---|---|---|
| **Per request** | A single LLM call costing more than this. Pre-flight estimate is checked against the cap. | **$0.10** |
| **Per scan** | A single batch run accumulating cost above this. When hit, the batch flips to ``paused_budget`` status. | **$5.00** |
| **Per day total** | Total daily spend across the workspace. Resets at UTC midnight. | **$5.00** for the first 14 days, **$50.00** afterwards |

Caps must satisfy ``per_request ≤ per_scan ≤ daily``. The form
validates this client-side and the backend re-validates.

All three displayed caps are read from the same effective configuration used
by AI Fixes, Security Copilot, validation repair, API processes, and workers.
Daily spend is reconciled against the durable `ai_usage_log` ledger before an
external call, so a second process does not start from a zero local counter.

---

## Effective configuration precedence

There is one runtime read path: `AiConfigLoader` resolves an
`EffectiveAiConfig` and the provider registry consumes the same credential
snapshot.

1. A DB `ai_settings` row is authoritative for enabled state, kill switch,
   and budgets. Environment values are used only while that row is absent or
   the database is unavailable during migration/startup.
2. Any DB credential row for a provider makes that provider authoritative.
   A disabled or unreadable DB row does not resurrect an older environment
   credential.
3. Multiple labelled credentials are selected by credential identity; the
   default and fallback flags do not enter provider HTTP fields.
4. `AI_FIXES_UI_CONFIG_ENABLED` and `AI_CANARY_PERCENTAGE` remain environment-
   only deployment controls. Canary applies to AI Fix generation; the global
   enabled and kill-switch gates apply to every LLM invocation.

Changes invalidate the shared configuration version, so API processes and
workers pick them up on their next call without restart. Administrators can
inspect the safe snapshot at `GET /api/v1/ai/effective-config`; it never
returns keys, ciphertext, tokens, or authorization headers.

Hit caps don't lose your work — the cache absorbs everything that
completed before the cap fired. After bumping the cap, trigger the
batch again; it picks up from where the previous run halted.

---

## Free-tier rate limit awareness

Before kicking off a batch on a free-tier provider, the platform
calculates the projected wall-clock time. If it exceeds 5 minutes
you'll see a warning:

```
⚠ Free tier rate limit detected

Generating fixes for 1,000 findings using Gemini Flash (free).
Estimated time: ~12 minutes due to 15 req/min rate limit.

Options:
 • Continue with Gemini free  →  ~12 min
 • Switch to Anthropic (paid) → ~90 sec, est. cost $0.85
 • Cancel
```

The warning is calculated, not estimated — it factors in the cache
hit ratio (cached findings don't burn rate limit), the provider's
concurrency, and the documented free-tier RPM. Numbers are accurate
within ±15% in our testing.

---

## Privacy

* The API key you paste is encrypted at rest with AES-256-GCM.
* It's never returned by any endpoint — the UI shows only the
  preview (first 6 + last 4 characters with ellipsis).
* It's never written to any log line. The platform's audit trail
  records who configured what and when, but never the credential
  payload.
* The deployment's master encryption key lives in environment
  variables only (or your secrets manager / KMS, depending on
  deployment). Never in the database, never in code, never in this UI.

If you suspect a credential has been exposed: rotate it upstream
(Anthropic / OpenAI / etc.) first, then update the row in Settings →
AI to use the new key. The platform's audit log records the
update — search ``ai_credential_audit_log`` for the row's history.

---

## Troubleshooting

| Symptom | Try |
|---|---|
| Add provider dropdown is empty | Backend can't reach ``/api/v1/ai/providers/available``. Check API health. |
| Test connection always fails with "Couldn't reach" | Check your network — is the API able to make outbound HTTPS calls? Some corporate proxies require explicit configuration. |
| Settings page shows "Configuration not enabled" | Operator hasn't flipped ``AI_FIXES_UI_CONFIG_ENABLED=true`` yet. See the rollout playbook. |
| Save button stays disabled even after a successful test | The successful test was for a different config. Re-test after any field change. |
| Provider card shows "Failing" with auth error | Key was valid at save-time, has been revoked / rotated upstream. Edit the credential and paste the new key. |
| Provider card shows "Failing" with network error | Provider is down or a proxy / firewall is blocking the API. The provider's status page is the next stop. |

For deeper operational issues see [the credentials runbook](../runbook-ai-credentials.md).

---

## Per-provider quick-starts

* [Gemini free tier](../quickstart/gemini-free-tier.md) — 3 steps, 2 minutes
* [Anthropic Claude](../quickstart/anthropic-claude.md) — 3 steps
* [Ollama (local)](../quickstart/ollama-local.md) — 5 steps including model pull
* [Custom OpenAI-compatible / vLLM / LiteLLM proxy](../quickstart/custom-openai-compatible.md)
