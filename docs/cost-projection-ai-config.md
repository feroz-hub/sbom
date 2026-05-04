# Cost projection — AI configuration rollout (Phase 4)

> Audience: finance + release manager.
> Companion to [docs/rollout-ai-fixes.md](rollout-ai-fixes.md).

This document projects monthly LLM cost across three production-ready
configurations, at three usage scales (10 / 100 / 1000 active users).

---

## 1. Assumptions

Common workload model (matches the Phase 6 rollout doc):

* Active user runs **2 scans / week**.
* Average scan: **400 findings**.
* Steady-state cache hit ratio: **80%** at single-tenant scale.
* Cross-tenant cache reuse at multi-tenant scale: **+10-15%** on top
  of single-tenant (most heavy CVEs are shared — log4j, Spring,
  requests, etc.).
* Cold-cache call: ~700 input tokens + ~600 output tokens at v1 prompt
  sizes.
* No batch retries; no force refreshes.

Per-finding cost-per-cold-cache-call by provider (paid tier where
applicable, current-as-of-2026-05-04 pricing):

| Provider | Input / 1k | Output / 1k | Per-finding |
|---|---|---|---|
| Anthropic Claude Sonnet 4.5 | $0.003 | $0.015 | **~$0.0111** |
| OpenAI gpt-4o-mini | $0.00015 | $0.00060 | **~$0.00046** |
| Gemini Flash 2.5 (paid) | $0.000075 | $0.0003 | **~$0.00023** |
| Gemini Flash 2.5 (free) | $0 | $0 | **$0** (rate-limited) |
| Ollama local | $0 | $0 | $0 (your GPU) |

---

## 2. Configurations

### Config A — Gemini-free-default (evaluation, low-volume production)

Default: Gemini Flash 2.5 free tier
Fallback: none

Best for evaluation, internal dogfooding, sites < 10 active users.
Free-tier rate limits cap throughput at 15 req/min — a 400-finding
cold-cache scan takes ~30 minutes.

### Config B — Anthropic-paid-default (highest quality, production)

Default: Anthropic Claude Sonnet 4.5
Fallback: Anthropic Claude Haiku 4.5 (informational; no auto-failover in v1)

Best for production sites where fix quality is the binding constraint.
Cold-cache scan latency: ~90 seconds at default concurrency (10).

### Config C — Mixed (cost-optimized production)

Default: Gemini Flash 2.5 paid
Fallback: Anthropic Claude Sonnet 4.5

Best for cost-conscious production sites. ~50× cheaper than Config B
on the cold-cache path; quality is good-enough for the vast majority
of CVEs (the long-tail "ambiguous fix" cases benefit from Anthropic
which sites can call out per-finding via the API).

---

## 3. Projections

### 3.1 Monthly cost by configuration × scale

Calculated as:

```
findings_per_month = users × scans_per_week × findings_per_scan × 4.33
cold_cache_calls   = findings_per_month × (1 - cache_hit_ratio)
monthly_cost       = cold_cache_calls × per_finding_cost
```

| Active users | Cache ratio | Findings / month | Cold calls / month | Config A (Gemini free) | Config B (Anthropic) | Config C (Gemini paid) |
|---:|---:|---:|---:|---:|---:|---:|
| 10 | 80% | 34,640 | 6,928 | **$0** | **$77** | **$1.59** |
| 100 | 85% | 346,400 | 51,960 | rate-limit infeasible | **$577** | **$11.95** |
| 1,000 | 90% | 3,464,000 | 346,400 | rate-limit infeasible | **$3,845** | **$79.67** |

**Notes:**

* Config A at 100+ users hits Gemini's daily 1M-token cap multiple
  times per day. Functionally usable but with 12-72 hour batch
  delays. **Not recommended for ≥100 users.**
* Config B's 1000-user number assumes the cache hits 90%. New users
  carry a one-time onboarding spike on day 1 of their first scan
  (~$10-50 each).
* Config C numbers assume seamless free→paid Gemini flow (same key,
  tier flag flips). If you stay on free with Gemini and only use
  Anthropic as a manual override, costs sit between A and B.

### 3.2 Daily cap implications

The default `AI_BUDGET_PER_DAY_ORG_USD` is **$5.00** for the first 14
days of rollout, raising to **$50.00** afterwards. This shapes
behaviour:

| Config × scale | Day 1-14 ($5/day) | Day 15+ ($50/day) |
|---|---|---|
| A × 10 | comfortable | comfortable |
| A × 100 | infeasible (rate-limit) | infeasible |
| B × 10 | comfortable ($2.57/day) | comfortable |
| B × 100 | hits cap most days ($19/day avg) | comfortable |
| B × 1000 | hits cap every day ($128/day avg) | hits cap most days |
| C × 100 | comfortable ($0.40/day avg) | comfortable |
| C × 1000 | comfortable ($2.66/day avg) | comfortable |

Config B at ≥100 users needs the $50/day cap raised after the rollout
window. Configs A and C are within $5/day at 10 users and $50/day at
1000 users respectively.

### 3.3 Onboarding spike (one-time)

A new user's first scan is full cold-cache (no prior bundles for
their components). At 400 findings:

| Config | Onboarding cost (one-time, per new user) |
|---|---|
| A | $0 (rate-limited but free) |
| B | $4.44 |
| C | $0.09 |

Subsequent scans for the same user are 80%+ cache hits because
component-level dedup catches Spring / log4j / requests / etc.

---

## 4. Recommendation by site shape

| Site profile | Recommended config | Why |
|---|---|---|
| Solo developer / OSS project | A (Gemini free) | Fits free tier comfortably |
| Small team (3-10 engineers) | A or C | A if you can tolerate batch latency; C ($1.59/month) if you can't |
| Mid-size product (50-100 engineers) | C | $12/month is a rounding error; Gemini quality is sufficient |
| Enterprise (1000+ engineers) | B | Quality differentiator; $3,845/month is well below typical security-tooling budgets |
| Air-gapped on-prem | Ollama local | No outbound calls; one-time GPU capex |

---

## 5. Cost guardrails

The platform's three-level budget cap (per-request / per-scan /
per-day) protects against runaway spend regardless of configuration.

**Recommended initial values (matching the Phase 6 rollout window):**

| Config | per-request | per-scan | per-day org |
|---|---|---|---|
| A | $0.001 | $1.00 | $1.00 |
| B | $0.10 | $5.00 | $5.00 (then $50) |
| C | $0.01 | $1.00 | $5.00 |

These are floors, not ceilings — admins can raise them via
Settings → AI once telemetry shows steady-state behaviour. The
defaults err on the side of "fail closed if something's wrong".

---

## 6. Provider switching cost analytics

The Settings → AI surface lets admins switch the default provider
in seconds. This means cost-vs-quality tradeoffs are reversible:

* Start on Config A. Spend $0 evaluating.
* Promote to Config C when you want production-grade reliability
  without provider lock-in.
* Reach for Config B on the long-tail "tricky CVE" findings via
  per-request override (the API surfaces this; the UI hasn't shipped
  it as a v1 affordance).

The cache is provider-agnostic — switching providers doesn't
invalidate previously-generated bundles. A site that ran Config A
for 30 days, then promoted to Config B, only pays Config B's
per-finding cost on net-new findings going forward. The Config-A
bundles continue serving from cache.
