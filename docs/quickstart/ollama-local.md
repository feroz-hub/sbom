# Quick-start — Ollama (local)

> 5 steps · ~10 minutes (excluding model download time) · zero per-call cost.

Run AI fix generation entirely on your own hardware. No outbound
HTTPS calls, no API keys, no per-token pricing. You provide the GPU
(or CPU — slower but workable for 32B-class models).

---

## 1. Install Ollama

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Or download from https://ollama.com
```

---

## 2. Pull a model

The recommended default is **Llama 3.3 70B** — strong reasoning, good
JSON-mode adherence, fits on a 48GB GPU.

```bash
ollama pull llama3.3:70b
```

This is a ~40GB download. While it's running, finish step 3.

**Hardware requirements:**

| Model | VRAM | Disk |
|---|---|---|
| `llama3.3:70b` | 48 GB | ~40 GB |
| `qwen2.5:72b` | 48 GB | ~42 GB |
| `qwen2.5:32b` | 24 GB | ~20 GB ← cheaper alternative |
| `llama3.1:8b` | 8 GB | ~5 GB ← acceptable for evaluation |

If you don't have a GPU at all, Ollama runs on CPU but a single
fix-generation call will take 30-90 seconds on a 32B model. Use the
8B variant for CPU-only setups.

---

## 3. Start the Ollama service

```bash
ollama serve
# (or: brew services start ollama on macOS)
```

The service listens on **http://localhost:11434** by default.

Verify in another terminal:

```bash
curl http://localhost:11434/api/tags
# Should return JSON listing your installed models.
```

---

## 4. Add Ollama to the SBOM Analyzer

1. **Settings → AI configuration → Add provider**.
2. Select **Ollama (local)** in the dropdown.
3. **Base URL** — defaults to ``http://localhost:11434``. Change it if
   Ollama runs on a different host/port (e.g. another machine on the
   LAN: ``http://gpu-host.lan:11434``).
4. **Model** — pick one from the dropdown matching what you pulled.
5. Click **Test connection** → expect ✅ within 5 seconds.
   * If it fails with "Couldn't reach": confirm `ollama serve` is
     running and the URL matches.
6. Click **Save provider**.

---

## 5. Set Ollama as the default

Kebab menu (`⋯`) → **Set as default**. Done.

---

## Performance expectations

With a 70B model on a 48GB GPU:

* **Single finding:** 5-15 seconds per call.
* **1,000-finding cold-cache batch:** 90-120 minutes (concurrency
  bound — local inference doesn't parallelize cleanly).
* **Same batch warm-cache:** seconds (cache hits skip the model entirely).

Recommended `max_concurrent` setting: **8**. Higher values create
head-of-line blocking on the GPU because Ollama batches sequentially.

---

## Network considerations

Local-only — no outbound HTTPS calls during AI fix generation. The
SBOM Analyzer's other features (CVE enrichment, OSV / GHSA / NVD
calls) still need internet access; only the AI provider goes local.

If you need a fully air-gapped deployment, the platform supports
that — pull the SBOM Analyzer's CVE mirror first, then disable
internet access. See the air-gap deployment guide (separate doc).

---

## Multi-host setup

Ollama on a different machine? Configure the URL accordingly:

```
Base URL: http://your-gpu-server.lan:11434
```

The connection from the SBOM Analyzer host to the Ollama host
should be on a trusted network (the platform doesn't authenticate
Ollama calls — Ollama itself has no auth in v1). For internet-facing
GPU servers use [Custom OpenAI-compatible](custom-openai-compatible.md)
with an API-key-protected proxy in front.

---

## When Ollama isn't enough

* **Quality** — 70B local models are strong but Anthropic Sonnet
  still outperforms on edge cases. If quality matters more than cost,
  use [Anthropic Claude](anthropic-claude.md).
* **Latency** — local inference is bounded by your GPU. Cloud
  providers parallelize better. Production sites with thousands of
  daily scans should stay on cloud.
* **No GPU** — fall back to a paid free-tier path:
  [Gemini Flash](gemini-free-tier.md) is free and fast.
