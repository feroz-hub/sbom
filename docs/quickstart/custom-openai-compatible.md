# Quick-start — Custom OpenAI-compatible endpoint

> For LM Studio · LocalAI · LiteLLM proxy · vLLM · self-hosted Llama servers ·
> any endpoint speaking the OpenAI Chat Completions protocol that isn't
> in the curated provider list.

The "Custom OpenAI-compatible" provider is the escape hatch. It
accepts an arbitrary base URL and a free-text model name, with
optional API-key auth and optional cost overrides.

---

## When to use this vs Ollama / vLLM

* **Use Ollama** if you're running Ollama locally — the curated
  Ollama provider knows about its `/api/tags` model enumeration and
  presents a model dropdown.
* **Use vLLM** if you're running vLLM directly — same reasoning.
* **Use Custom OpenAI-compatible** for everything else: LM Studio,
  LocalAI, LiteLLM proxies (which route to multiple backends),
  Bedrock fronted by an OpenAI-compatible adapter, fly.io GPU pods,
  etc.

---

## What the platform expects

The endpoint must implement **POST /v1/chat/completions** with the
OpenAI Chat Completions request/response shape:

```bash
# Request:
curl $BASE_URL/chat/completions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "your-model-name",
    "messages": [
      {"role": "system", "content": "..."},
      {"role": "user",   "content": "..."}
    ],
    "max_tokens": 1024,
    "temperature": 0.2
  }'

# Response (relevant fields):
{
  "choices": [{"message": {"content": "<the LLM output>"}}],
  "usage":   {"prompt_tokens": N, "completion_tokens": M}
}
```

Optional but supported:

* **GET /v1/models** — if your endpoint exposes it, the test-connection
  probe uses it (no token spend). Otherwise the probe falls back to
  a 4-token chat completion.
* **`response_format: {"type": "json_schema", ...}`** — if your
  endpoint understands strict JSON schema enforcement, the AI fix
  generator passes the schema. Endpoints that ignore it still work
  (the generator's structured-output parser handles plain JSON).

---

## Adding it

1. **Settings → AI configuration → Add provider**.
2. Select **Custom OpenAI-compatible** in the dropdown.
3. **Base URL** — enter the endpoint's base URL.
   * Must start with `https://` (any host) or `http://localhost`,
     `http://127.0.0.1`, `http://::1`, or `http://host.docker.internal`.
   * Plaintext public URLs are rejected at validation time.
4. **API key** — optional. Most local setups don't need one (the
   default `EMPTY` placeholder is fine). Provide if your endpoint
   requires it (LiteLLM proxies usually do).
5. **Model** — free-text. The platform doesn't enumerate available
   models for custom endpoints; type the exact model name your
   endpoint expects.
6. **Cost per 1k input/output** — optional. Defaults to `$0`. Set if
   you want the cost ledger to track local-compute equivalents.
7. **Treat as local** — checkbox. When true, the cost ledger reports
   zero regardless of the per-1k overrides. Useful for self-hosted
   endpoints where you've configured the per-1k values for capacity
   planning but don't want them showing up in cost dashboards.
8. **Test connection**. Save unlocks on success.

---

## Common configurations

### LiteLLM proxy

```
Base URL: https://litellm.your-company.internal/v1
API key:  sk-litellm-...                       (your proxy key)
Model:    claude-3-opus-20240229                (or whatever your
                                                 proxy routes to)
```

### LM Studio

```
Base URL: http://localhost:1234/v1
API key:  EMPTY                                 (or whatever's set)
Model:    your-loaded-model-name                (visible in LM Studio's UI)
```

### LocalAI

```
Base URL: http://localhost:8080/v1
Model:    luna-ai-llama2                        (or whichever is loaded)
```

### vLLM (the curated `vLLM` provider does this too — use the
escape hatch only when the curated one isn't a fit, e.g. when you've
fronted vLLM with a different model name space)

```
Base URL: http://your-vllm-host:8000/v1
Model:    meta-llama/Meta-Llama-3.1-70B-Instruct
```

### AWS Bedrock via LiteLLM

```
Base URL: https://your-litellm-bedrock-proxy/v1
API key:  sk-litellm-... or your proxy's auth scheme
Model:    bedrock/anthropic.claude-3-sonnet-20240229-v1:0
```

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| "Couldn't reach the provider" | Base URL is wrong, or your platform host can't route to it. Try `curl -v $BASE_URL/v1/models` from the platform host. |
| "Invalid API key" | The endpoint authenticated and rejected the credential. Verify the key works directly with `curl`. |
| "Connected, but {model} isn't available" | The model name doesn't match what the endpoint exposes. Check the model list in the test-connection result. |
| Successful test but generation returns gibberish | The endpoint's JSON-schema enforcement is missing or incomplete. The orchestrator does its own post-validation, but garbage in → garbage caught at parse time. Switch to a curated provider for production-quality. |
| Test passes but is slow (>10s) | Local inference latency. Reduce concurrency in the registry config (lowering `max_concurrent` for this provider). |

---

## Why HTTPS-or-localhost-only

Plaintext `http://` URLs to public hosts would leak the API key on
every request. The validator rejects these specifically:

```
http://api.example.com/v1     ← rejected
https://api.example.com/v1    ← accepted
http://localhost:8000/v1      ← accepted (loopback)
http://127.0.0.1:1234/v1      ← accepted (loopback)
http://gpu-server.lan:8000/v1 ← rejected (use https or VPN)
```

For LAN-to-LAN setups without TLS terminate via an HTTPS-fronting
proxy (Caddy, Traefik, nginx) on the GPU host. Worth the 5 minutes
to set up.
