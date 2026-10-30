# OpenAI model compatibility

Native OpenAI requests use reviewed capability profiles in
`app/ai/providers/openai_models.py`. Discovery preserves exact provider IDs;
the model list is not an entitlement check or proof of generation support.
Profiles describe the preferred endpoint, token parameter, reasoning efforts,
sampling support, structured output, tools, limits and standard text pricing.
Unknown models remain discoverable and cannot incur generation charges until
a reviewed profile and pricing are configured. Known non-generation models
are marked incompatible.

## Request and output handling

GPT-4o and GPT-4.1 retain Chat Completions. Reviewed reasoning models use
Responses with `max_output_tokens`, supported `reasoning.effort`, and
`store: false`. Sampling parameters are omitted when unsupported. An explicit
profile can select Chat Completions with `max_completion_tokens` instead.
The exact requested model ID is sent without alias substitution.

The provider preserves the caller's output-token cap, including reasoning.
It does not silently increase runtime budgets or retry deterministic invalid
requests. Reasoning model calls can exhaust their cap before producing visible
output; this is reported as incomplete generation.

Structured schemas are copied and normalized for OpenAI's strict subset:
objects are closed, declared properties are required, and defaults are removed.
Schemas containing arbitrary dictionaries or unconstrained JSON patch values use JSON mode with the schema in
the prompt and local validation. Both paths validate the generated object
against the original schema. Free-text requests retain free-text results.
Reasoning items are excluded from the visible response. Refusals, incomplete
responses and invalid output are controlled errors rather than successful
empty generations.

Usage retains the provider's input/output token counts. Output usage already
includes reasoning tokens and is not counted twice. Standard text rates, schema prompt overhead and
documented long-context premiums feed existing budget checks. These are cost
estimates; cached-token discounts and account-specific billing adjustments
are not invoice reconciliation. Billable usage attached to output errors is
recorded by fixes, Copilot, validation repair and verification. Missing or
interrupted upstream usage remains an accounting limitation.

Gemini, Grok, vLLM and custom providers explicitly retain the existing
OpenAI-compatible path. Sarvam retains its provider identity and existing
behavior. Anthropic and Ollama implementations are unchanged.

## Verification states

The model panel separates:

- **Discovered:** returned by the model list; this says nothing about invocation.
- **Accessible:** an invocation reached the model successfully.
- **Generation verified:** visible output was produced.
- **Workload compatible:** output passed the bounded structured JSON probe.
- **Active:** explicitly selected by an administrator.

Unknown evidence is displayed as not tested. Activation is independent of test
results to preserve existing operator selection behavior. Testing a candidate
does not change the active model or disable a working credential. Authentication
rejection still follows the existing credential-disable rule; permission,
quota and model failures do not become invalid-key errors.

Connection and registry tests share a JSON-schema probe. Its output allowance
is 256 tokens for non-reasoning models and 2,048 for reviewed reasoning models.
Tests check existing spending limits, record usage and make one generation
attempt. No unsupported-parameter adaptation loop or paid model sweep runs
automatically.

Verification evidence uses existing model metadata, with no schema migration.
Discovery refreshes preserve application-owned verification evidence and cannot
replace it with provider metadata. Public model responses add optional state
fields; existing IDs and response fields remain compatible.

## Adding a model

1. Check the exact identifier and capabilities in the current official model
   page and the account's discovered model list. Do not invent a family alias.
2. Add a reviewed `OpenAiModelProfile` with its pricing to `PROFILES`. Prefer
   an explicit snapshot when needed. No wildcard family rule establishes
   compatibility. Integrators may also inject explicit profiles into the
   provider constructor.
3. Extend the model matrix and representative workflow tests. Include request
   parameters, original-schema validation, reasoning-inclusive usage and the
   unsupported-model case.
4. Run mocked tests against a disposable test database. Live inference needs
   explicit approval and a spending limit. Mocked access never establishes
   real account permission or live workload quality.

## Local validation

Use the repository's disposable PostgreSQL test configuration. Do not point
tests at a development or production database.

```sh
python -m pytest tests/ai --ignore=tests/ai/test_real_provider_smoke.py -q
```

The local HTTP simulation uses synthetic data and requires no OpenAI key or
Postman login:

```sh
postman simulation run postman/simulations/openai-compat.sim.yaml --port auto --output ndjson --no-history
```

Use its printed port for `SBO99_MOCK_BASE_URL`, with the path
`/openai/v1`, then run `tests/ai/test_openai_simulation.py`. That test refuses
non-loopback targets and uses an explicitly synthetic credential. The
simulation covers model listing, both endpoints, request bounds, structured
output, reasoning-inclusive usage and quota classification. It is a caller
contract check, not live OpenAI acceptance.

## Reference contracts

Reviewed for SBO-99 on 2026-10-30:

- [OpenAI model catalog](https://developers.openai.com/api/docs/models)
- [GPT-6 compatibility guidance](https://developers.openai.com/api/docs/guides/latest-model)
- [Structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [Reasoning and token budgets](https://developers.openai.com/api/docs/guides/reasoning)

The model matrix includes exact GPT-4o, GPT-4.1, GPT-5, GPT-5.1, GPT-5.2,
GPT-5.4, GPT-5.5, GPT-5.6 and GPT-6 profile IDs. For Terra the reviewed current
ID is `gpt-6.1-terra`; `gpt-6-terra` is not assumed to be an alias. Review
the profile table for the supported snapshots and capabilities.
