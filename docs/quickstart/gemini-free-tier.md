# Quick-start — Google Gemini free tier

> 3 steps · 2 minutes · zero cost.

The fastest way to evaluate the AI fix generator without spending
anything. Gemini's free tier ships 15 requests/minute, 1,500
requests/day, and 1,000,000 tokens/day on Flash 2.5 — plenty for
hundreds of findings per day.

---

## 1. Get a Gemini API key

1. Go to **https://aistudio.google.com/app/apikey**
2. Sign in with a Google account.
3. Click **Create API key** → **Create API key in new project** (or pick an existing project).
4. Copy the key. It looks like ``AIzaSy...`` — note the ``AIzaSy`` prefix is part of the key, not a label.

---

## 2. Add Gemini to the SBOM Analyzer

1. Open **Settings → AI configuration**.
2. Click **Add provider**.
3. In the dropdown, select **Google Gemini — free tier available ⭐**.
4. **API key** — paste the key you just copied.
5. **Model** — leave on **Gemini 2.5 Flash** (the free-tier sweet spot).
6. **Tier** — leave on **Free (15 req/min)**.
7. Click **Test connection**.
   * On success you'll see ✅ with the latency in milliseconds.
   * On failure: re-check the key. The most common gotcha is a stray
     space at the end of the paste.
8. Click **Save provider**.

---

## 3. Set Gemini as the default

1. On the new provider card, click the kebab menu (`⋯`) → **Set as default**.
2. The card's role badge updates to "default".

You're done. The next AI fix request — single finding click in the
CVE modal or batch generate on a run page — uses Gemini Flash.

---

## What to expect

* **First batch on a 1,000-finding scan:** ~70 minutes due to the 15
  req/min cap. The progress banner shows the rate limit during the run.
* **Same scan re-run:** seconds, because cache hits don't burn rate
  limit. This is why the cache is the most important architectural
  feature for free-tier usage.
* **Switching to paid later:** Update the tier dropdown on the
  Gemini card from "Free" to "Paid". The same key continues to work;
  rate limits relax to ~1500 req/min on Flash.

---

## When Gemini free isn't enough

The 1M tokens/day cap is generous but finite. If you start hitting it:

1. **Switch the tier to Paid.** Same provider, same key, no rate
   limits, ~$0.0003 per finding average.
2. **Add Anthropic as a paid alternative.** Better quality on
   ambiguous CVEs (no fix data, multiple candidate patches). See
   [the Anthropic quick-start](anthropic-claude.md).
3. **Go local with Ollama.** Zero per-call cost, you provide the GPU.
   See [the Ollama quick-start](ollama-local.md).

You can also keep multiple providers configured simultaneously — the
default decides which one runs by default; per-request overrides
(via the API) let you A/B test quality.
