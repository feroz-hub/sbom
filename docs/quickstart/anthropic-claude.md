# Quick-start — Anthropic Claude

> 3 steps · ~3 minutes · ~$5 of pre-paid credit gets you ~300 findings.

Anthropic Claude is the recommended **production** default for the AI
fix generator. Best fix-generation quality in our testing — particularly
on ambiguous cases where the model has to weigh multiple candidate
patches against the CVE's grounding data.

---

## 1. Get an Anthropic API key

1. Go to **https://console.anthropic.com/settings/keys**
2. Sign in. (If you don't have an account: sign up first; you'll
   need a credit card to add credit.)
3. **Add credit** if your workspace doesn't have any. $5 minimum is
   plenty for evaluation; production deployments typically pre-pay $50-$500.
4. Click **Create Key** → name it something like "sbom-analyzer-prod".
5. Copy the key. Format: ``sk-ant-api03-...``. It's only shown once
   — store it in your password manager immediately.

---

## 2. Add Anthropic to the SBOM Analyzer

1. **Settings → AI configuration → Add provider**.
2. Select **Anthropic Claude** in the dropdown.
3. **API key** — paste the ``sk-ant-...`` value.
4. **Model** — pick one:
   | Model | When to use |
   |---|---|
   | **Claude Sonnet 4.5** | Default. Best balance of cost ($0.003/1k input, $0.015/1k output) and quality. |
   | Claude Opus 4.7 | Highest quality. ~5x cost. Use for executive-facing remediation reports where prose tone matters. |
   | Claude Haiku 4.5 | Cheapest in family (~4x cheaper than Sonnet). Acceptable quality for low-stakes findings. |
5. Click **Test connection** → expect ✅ in <1s.
6. Click **Save provider**.

---

## 3. Set Anthropic as the default

1. Kebab menu (`⋯`) on the new card → **Set as default**.

That's it. The next AI fix request uses Claude.

---

## Cost expectations

Roughly **$0.005 - $0.020 per net-new finding** at v1 prompt sizes.
With sensible cache reuse (typical ratios: 70-95%):

| Scenario | Approximate monthly cost |
|---|---|
| 10 active users, 2 scans/week each, 400 findings/scan | ~$30 |
| 100 active users, same shape | ~$290 |
| 1000 active users, same shape | ~$2,900 |

The 1000-user number assumes a 90-95% cache hit rate (the cache is
tenant-shared, so two orgs scanning Spring Boot stacks share most
heavy CVEs). New users carry a one-time onboarding cost on their
first 1-2 scans.

The platform's daily cap (default $5 during the rollout window,
raisable to $50+ after 14 days of clean telemetry) protects against
runaway spend regardless.

---

## Rotation

Best practice: rotate the API key every 90 days, or immediately if
you suspect compromise.

1. Create a new key in the Anthropic console.
2. **Settings → AI configuration**, kebab menu on the Anthropic card,
   **Edit**.
3. Paste the new key into the API key field. (The current key's
   preview is shown; the placeholder reads "Leave blank to keep
   existing".)
4. Click **Test connection** → success.
5. Click **Save changes**.
6. Back in the Anthropic console, **delete the old key**.

The platform's audit log records the rotation. The orchestrator
picks up the new key on the next request — no batch interruption,
no service restart.

---

## When to use a different default

| Reason | Switch to |
|---|---|
| Cost is the binding constraint | Gemini Flash (paid) or OpenAI gpt-4o-mini (~6x cheaper) |
| Want to try the free path first | [Gemini free tier](gemini-free-tier.md) |
| Air-gapped / on-prem requirement | [Ollama (local)](ollama-local.md) |
| Existing LiteLLM / Bedrock proxy in place | [Custom OpenAI-compatible](custom-openai-compatible.md) |
