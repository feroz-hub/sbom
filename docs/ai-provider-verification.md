# AI provider configuration and verification

Saving a provider no longer requires a successful connection test. The Add dialog
requires permission, valid local fields and no save in flight. An explicit typed
credential rejection blocks Add/Edit submission until the configuration changes
or a subsequent test succeeds; transient, quota and network failures do not.

The credential creation endpoint remains local-only: validate, encrypt, persist.
It does not contact an external provider. New credentials are verification pending;
client-side test results are not trusted as persisted verification evidence.
Saved credentials can be tested using their existing encrypted secret server-side.
No decrypted secret is returned to the browser.

## Verification classification

- Success: VERIFIED.
- 401/403 or explicit Google API_KEY_INVALID/API_KEY_EXPIRED reason: INVALID_CREDENTIALS.
- 429 or 5xx: TEMPORARILY_UNAVAILABLE.
- 408, timeout, DNS/connection failures: UNVERIFIED.
- Other provider 400/404: configuration/model verification failure, never automatically invalid credentials.
- Invalid local form fields: cannot save.

The shared probe helper serves all eight existing adapters: Anthropic, OpenAI,
Gemini, Grok, Sarvam, Ollama, vLLM and custom OpenAI-compatible endpoints.
Provider bodies and exception strings are not displayed or persisted as test
errors. Only safe categories and optional HTTP status are retained. Existing
credential.test audit entries now distinguish the outcome/category/status.

## Existing storage and runtime

No schema changes or migration. `verification_status` is derived from existing
`last_test_at`, `last_test_success` and sanitized `last_test_error` fields.
Legacy raw stored errors are suppressed in API responses.

A saved credential rejected by authentication is disabled and the loader cache is
invalidated. It cannot be enabled until a successful saved-credential retest.
Correcting its configuration preserves this restriction. After verification, an
administrator can explicitly enable it.

Transient verification failures never gate runtime selection. Later real requests
can succeed normally. Existing last-test metadata represents explicit verification;
normal AI requests do not overwrite those timestamps or imply that a test ran.

## Changed implementation files

Frontend: `src/lib/aiVerification.ts`, `src/types/ai.ts`, AI settings Add/Edit
provider dialogs, TestResultDisplay, ProviderCard and ProviderStatusIndicator.
Tests: AddProviderDialog, TestResultDisplay, ProviderStatusIndicator, AI settings
accessibility, backend test_test_connection and test_credentials_router.

Backend: `app/ai/providers/{base,_probe,openai}.py`,
`app/ai/provider_factory.py`, `app/routers/ai_credentials.py`.

## Validation (29 September 2026)

- Backend AI suite: 477 passed, 5 skipped, 2 deselected. Skips require Redis or
  live provider keys. Existing dependency/Alembic deprecation warnings remain.
- Frontend suite excluding the unavailable Redis-server integration: 146 files,
  1,083 tests passed. The initial full run exposed a tenant activation cache
  invalidation omission, now fixed and verified; Redis integration still needs
  the `redis-server` executable.
- Focused AI, tenant details and mutation invalidation regression: 66 passed.
- Targeted ESLint and git diff whitespace checks passed.
- Frontend production build passed without warnings.
- Provider failure tests use simulated HTTP responses; live-provider smoke tests
  were skipped because no provider keys were configured for this run.
