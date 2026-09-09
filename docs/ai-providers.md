# AI providers — supported list

> Last verified 2026-09-09. Pricing and rate limits drift quarterly —
> verify against the upstream "API key" link before relying on numbers
> in this doc.

The SBOM Analyzer supports eight providers. A catalog-driven contract test
requires every entry to work through request validation, unsaved Test
Connection, encrypted save/decrypt, saved Test Connection, config loading,
registry selection, and mocked generation. Adding a provider therefore means
supporting the complete factory contract, not only adding a provider class.

Model names in the tables below are bootstrap examples for the initial,
unsaved form; they are not the production availability catalog. After saving
a credential, use **Refresh Models** to populate the persistent registry from
the provider, **Test Model**, then explicitly **Set active**. Discovery never
changes the active production model by itself.

---

## Cloud — paid

| Provider | Bootstrap model | Pricing (per 1k tokens) | Notes |
|---|---|---|---|
| **Anthropic** | `claude-sonnet-4-5` | in $0.003 · out $0.015 | Initial form value; refresh before production selection. |
| **OpenAI**    | `gpt-4o-mini`       | in $0.00015 · out $0.0006 | Initial form value; refresh before production selection. |

**API keys:**
* Anthropic: https://console.anthropic.com/settings/keys
* OpenAI:    https://platform.openai.com/api-keys

---

## Cloud — free tier available ⭐

These are the providers added in the Phase 1 expansion. Both have
genuine free tiers — no credit card required, no expiration — making
them the recommended starting point for evaluation.

### Google Gemini

| | |
|---|---|
| Bootstrap model | `gemini-3.6-flash` |
| Free tier limits | **15 req/min · 1M tokens/day · 1500 req/day** |
| Free tier pricing | $0 |
| Paid tier pricing | Flash: in $0.000075 · out $0.0003 per 1k tokens |
| Pro tier free limit | 5 req/min — **too tight for batch use** |
| API key | https://aistudio.google.com/app/apikey |
| Endpoint | `https://generativelanguage.googleapis.com/v1beta/openai/` (OpenAI-compatible) |

**When to use:** evaluation, small workloads, dev environments.

**When to avoid:** batch processing > 100 findings (the 15 RPM cap
makes a 1k-finding batch take ~70 minutes; the orchestrator will
surface a warning before starting).

### xAI Grok

| | |
|---|---|
| Bootstrap model | `grok-2-mini` |
| Free tier limits | **~60 req/min · ~25k tokens/day** |
| Free tier pricing | $0 |
| Paid tier pricing | grok-2-mini: in $0.0002 · out $0.001 per 1k tokens |
| API key | https://console.x.ai/ |
| Endpoint | `https://api.x.ai/v1` (OpenAI-compatible) |

**When to use:** one-off CVE detail clicks, exploration. The 25k
tokens/day cap fills quickly with batch use.

**When to avoid:** any batch run — the daily token cap is the
binding constraint, not RPM.

### Sarvam AI

Sarvam uses its OpenAI-compatible chat endpoint and is supported through the
same runtime and Test Connection factory as every other catalog provider.
Configure the API key, model, and optional base URL in Settings -> AI.

---

## Self-hosted — free

### Ollama

| | |
|---|---|
| Bootstrap model | `llama3.3:70b` |
| Pricing | $0 (you provide the GPU) |
| Default URL | `http://localhost:11434` |
| Docs | https://github.com/ollama/ollama/blob/main/docs/api.md |

**Setup:**
1. Install Ollama: `brew install ollama` or download from https://ollama.com
2. `ollama pull llama3.3:70b` (warning: ~40GB download, needs 48GB+ VRAM)
3. Smaller alternative: `ollama pull qwen2.5:32b` (~20GB, fits 24GB GPUs)
4. Start the service: `ollama serve`
5. Configure in Settings → AI → Add provider → Ollama

### vLLM

| | |
|---|---|
| Bootstrap model | varies (free-text per deployment) |
| Pricing | $0 (you provide the GPU) |
| Default URL | none — operator-supplied |
| Docs | https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html |

**Setup:** point at your vLLM deployment's OpenAI-compatible endpoint.

---

## The escape hatch — Custom OpenAI-compatible

For LM Studio, LocalAI, LiteLLM proxies, fly.io-hosted Llama servers,
or any endpoint speaking the OpenAI Chat Completions protocol that
isn't in the curated list above.

| Field | Required? | Notes |
|---|---|---|
| Base URL | Yes | Must start with `https://` or `http://localhost`. Plaintext public URLs are rejected at validation time. |
| API key | No | Defaults to `EMPTY` (most local setups don't need one). Provide if your endpoint requires it. |
| Bootstrap model | Yes | Free-text for the first save; Refresh Models then attempts the endpoint's standard `GET /v1/models`. |
| Cost per 1k input | No | Defaults to $0. Set if you want to track local-compute equivalents. |
| Cost per 1k output | No | Same. |

**Validation:** `http://` URLs are only accepted for `localhost`,
`127.0.0.1`, `::1`, or `host.docker.internal`. Public-internet
plaintext is rejected with a `ProviderUnavailableError` — no exception
for "I'll fix the cert later, just let me through" because that
exception ships keys in the clear.

---

## Choosing a starting setup

| Goal | Recommended setup |
|---|---|
| **Try it for free** | Gemini Flash (free) as default · Anthropic as fallback (when paid) |
| **Production at low cost** | Gemini Flash (paid) as default · Anthropic Sonnet as fallback for hard cases |
| **Production at highest quality** | Anthropic Sonnet 4.5 as default · OpenAI gpt-4o as fallback |
| **Air-gapped / on-prem** | Ollama (Llama 3.3 70B) as default · no fallback |

Default-and-fallback semantics: the Settings UI selects exact credential
identities, including two labelled credentials for the same provider. The
orchestrator makes at most one fallback attempt for transient network,
throttling/quota, upstream 5xx, or open-circuit failures. It never falls back
for authentication, invalid model/request/schema, grounding, budget, or local
configuration failures.

---

## Free-tier rate-limit awareness

Before kicking off a batch run, the platform calls
`/api/v1/runs/{run_id}/ai-fixes/estimate` to compute the projected
wall-clock duration based on:

1. The **cached count** (subtracted from total — already-cached
   findings are zero-cost, near-instant).
2. The **rate limit** of the active provider (free-tier Gemini = 15
   RPM, free-tier Grok = 60 RPM).
3. The **concurrency** the provider tolerates.
4. A **per-call latency** heuristic (4s paid, 6s free, 8s local).

When the estimate exceeds 5 minutes, the UI surfaces a one-time
warning ("Free tier processing will take ~12 minutes — switch to
paid?") so the user can choose between waiting or upgrading.

---

## Adding a new provider in code

Provider implementations must support the shared `list_models()` contract. If
an upstream genuinely has no compatible listing endpoint, raise the typed
`unsupported` discovery result and document the adapter fallback instead of
presenting a static list as live data.

Four files:

1. `app/ai/providers/<name>.py` — implement `generate`, `test_connection`, and `list_models` from the `LlmProvider` protocol.
2. `app/ai/cost.py` — add the per-1k-token pricing table entry.
3. `app/ai/registry.py` — add the env→config branch and the
   factory branch in `_build_provider`.
4. `app/ai/catalog.py` — add the curated `ProviderCatalogEntry`.

Tests live next to the existing patterns in `tests/ai/test_providers.py`
+ `test_test_connection.py`.
