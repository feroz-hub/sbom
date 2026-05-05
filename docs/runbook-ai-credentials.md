# Runbook — AI credentials & encryption key management

> Audience: on-call SRE / platform engineer.
> Companion to [docs/features/ai-fixes.md](features/ai-fixes.md) +
> [docs/runbook-ai-fixes.md](runbook-ai-fixes.md).

This runbook covers the operational mechanics of the Phase 2 credential
storage layer: encryption-key lifecycle, DB-row management, audit log
access, and the env-to-DB migration.

---

## 1. Encryption key — the single point of failure

The platform encrypts every saved AI provider API key with AES-256-GCM
under a single master key sourced from
``AI_CONFIG_ENCRYPTION_KEY`` (32 raw bytes, base64-encoded in env).

**Hard rule:** if this key is lost, every saved credential becomes
unrecoverable. The DB column ``ai_provider_credential.api_key_encrypted``
is opaque ciphertext; without the key there is no recovery path beyond
"admins re-enter every API key by hand".

### 1.1 Generating the key (first-time setup)

```bash
python scripts/generate_encryption_key.py
# prints AI_CONFIG_ENCRYPTION_KEY=<base64>
# … paste into your secrets store (env / vault / KMS)
```

Restart the API + Celery workers so the env var is in process memory.

### 1.2 Verifying the key is present

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST $API/api/v1/ai/credentials \
  -H 'content-type: application/json' \
  -d '{"provider_name":"anthropic","api_key":"sk-test","default_model":"claude-sonnet-4-5"}'
# 201 (or 409 if a row already exists)  → key OK
# 500 with "AI_CONFIG_ENCRYPTION_KEY is not set"  → fix the env
```

### 1.3 Rotation

Rotation re-encrypts every row under a new key. Atomic — never run
this against a live prod without taking a DB backup first.

```python
# scripts/rotate_encryption_key.py  (write before first rotation)

import base64
import os
from app.db import SessionLocal
from app.models import AiProviderCredential
from app.security.secrets import SecretCipher

old_b64 = os.environ["AI_CONFIG_ENCRYPTION_KEY"]
new_b64 = os.environ["AI_CONFIG_ENCRYPTION_KEY_NEW"]
old = SecretCipher.from_b64(old_b64)
new = SecretCipher.from_b64(new_b64)

with SessionLocal() as db:
    rows = db.query(AiProviderCredential).all()
    for r in rows:
        if not r.api_key_encrypted:
            continue
        plaintext = old.decrypt(r.api_key_encrypted)
        r.api_key_encrypted = new.encrypt(plaintext)
    db.commit()
```

After confirming a sample read with the new key:

1. Update `AI_CONFIG_ENCRYPTION_KEY` in production env (replace old
   with new).
2. Delete `AI_CONFIG_ENCRYPTION_KEY_NEW`.
3. Restart API + workers.
4. Run the verification curl above.

### 1.4 If the key is lost

Recovery is impossible. Procedure:

1. Generate a new encryption key (§1.1).
2. Wipe the credential ciphertext column:
   ```sql
   UPDATE ai_provider_credential SET api_key_encrypted = NULL;
   ```
3. Notify admins to re-enter every credential via Settings → AI.
4. Run `verify_ai_rollout.py` to confirm the surface still works.

This is the explicit accepted cost of single-key envelope encryption
without KMS. The KMS upgrade path is in the architecture doc §11.

---

## 2. Credential rows

### 2.1 Listing what's there

```sql
-- All credentials (ciphertext column elided; the DB stores it but
-- the API never returns it).
SELECT id, provider_name, label, default_model, tier, is_default,
       is_fallback, enabled, last_test_success, last_test_at
FROM ai_provider_credential
ORDER BY id;
```

### 2.2 Constraint: one default, one fallback

The schema enforces this via partial unique indices:

```sql
CREATE UNIQUE INDEX ix_ai_only_one_default
  ON ai_provider_credential (is_default) WHERE is_default = 1;
CREATE UNIQUE INDEX ix_ai_only_one_fallback
  ON ai_provider_credential (is_fallback) WHERE is_fallback = 1;
```

Direct DB writes that violate this raise an `IntegrityError`. The
router's `set-default` / `set-fallback` endpoints clear all-but-the-target
in the same transaction so the intermediate state is never visible.

### 2.3 Manually disabling a credential

If a credential starts misbehaving (provider outage, exhausted free
tier) and you can't reach the UI:

```sql
UPDATE ai_provider_credential
SET enabled = 0, updated_at = '2026-05-04T00:00:00+00:00'
WHERE provider_name = 'gemini';
```

Then bump the cross-process version counter so running processes drop
their cache:

```bash
redis-cli INCR ai:config:version
```

(The 60s TTL would catch it eventually anyway, but the bump makes it
instant.)

---

## 3. Audit log

Every credential / settings mutation writes a row to
`ai_credential_audit_log`. The detail field is capped at 240 chars and
runs through a redaction pass before persisting (sk-/AIzaSy/xai-/long
base64 patterns → `[REDACTED]`).

```sql
-- Recent credential mutations (last 24h).
SELECT created_at, user_id, action, target_kind, target_id,
       provider_name, detail
FROM ai_credential_audit_log
WHERE created_at >= datetime('now', '-1 day')
ORDER BY created_at DESC;
```

Available actions:

| Action | Written by |
|---|---|
| `credential.create` | `POST /credentials` |
| `credential.update` | `PUT /credentials/{id}` |
| `credential.delete` | `DELETE /credentials/{id}` |
| `credential.test` | `POST /credentials/test` and `POST /credentials/{id}/test` |
| `credential.set_default` | `PUT /credentials/{id}/set-default` |
| `credential.set_fallback` | `PUT /credentials/{id}/set-fallback` |
| `settings.update` | `PUT /settings` |

**Retention:** the audit table is unbounded by design. Set up a
monthly cleanup job once volume justifies it (the table is small —
< 100 rows/month at typical admin activity).

---

## 4. Migration from env to DB

For deployments running the Phase 1 env-only configuration:

```bash
# 1. Generate + install the encryption key.
python scripts/generate_encryption_key.py
# ...add AI_CONFIG_ENCRYPTION_KEY to env

# 2. Pre-flight (no writes).
python scripts/migrate_env_to_db.py --dry-run

# 3. Migrate.
python scripts/migrate_env_to_db.py

# 4. Verify in UI: Settings → AI shows the migrated providers
#    with api_key_preview values.

# 5. (Optional, recommended) After 14 days of clean operation,
#    remove the env vars from secrets — the DB is now authoritative.
```

The migration is **idempotent**: re-running it after a successful
migration prints "row already exists — skipping" for each provider
that already lives in the DB. The env variables continue to work as
fallbacks for any provider that doesn't yet have a DB row, so
partial migrations are safe.

### 4.1 Forced re-migration

`--force --i-know-what-i-am-doing` overwrites existing DB rows from
env. Only use this when the env was the source of truth and the DB
got corrupted. Take a DB backup first.

---

## 5. Cache invalidation

The config loader caches resolved provider configs for 60 seconds
in-process. Every credential / settings write bumps a Redis key
(`ai:config:version`) so other processes drop their caches on the
next read.

When this matters:

* **Multi-process deployments** (Uvicorn + Celery) — Redis is the
  cross-process invalidation channel. If Redis is down, each process
  honors only its 60s TTL and changes propagate slower.
* **Manual DB writes** — bypass the bump. After a manual SQL change
  to `ai_provider_credential` or `ai_settings`, run
  `redis-cli INCR ai:config:version` to force-invalidate.

---

## 6. Common incidents

### 6.1 "Saved credential test passes but generation fails with auth"

Cause: the saved key was correct at test time but expired / was rotated
upstream.

```bash
# Re-test from the API.
curl -X POST $API/api/v1/ai/credentials/{id}/test
```

If `last_test_success` flips false, ask the admin to re-enter via the
UI. The audit log records every test.

### 6.2 "Decryption failed in logs after a deploy"

Cause: `AI_CONFIG_ENCRYPTION_KEY` doesn't match the key that encrypted
the rows. The loader logs `ai.config.decrypt_failed` and skips the
affected rows.

```bash
# Confirm it's a key mismatch, not corruption.
grep 'decrypt_failed' /var/log/sbom-api.log | head -5
```

Recovery:
* If you know the previous key value, swap it back in env and restart.
* If not, follow §1.4.

### 6.3 "Settings page shows stale config after a UI save"

Cause: cross-process invalidation isn't propagating. Check Redis
connectivity:

```bash
redis-cli PING                   # → PONG
redis-cli GET ai:config:version  # → some integer
```

If Redis is up, the API process logs should show
`ai.config.version_read_failed` if the bump itself failed. The 60s TTL
will recover on its own; `POST /api/v1/ai/registry/reset` forces a
hard reset on the API process.

---

## 7. Hard rules — what NEVER happens

1. **No raw API key in any HTTP response.** Read endpoints return
   `api_key_preview` (first 6 + last 4 with ellipsis) and
   `api_key_present` only.
2. **No raw API key in any log line.** Verified by
   `tests/ai/test_credentials_router.py::test_no_raw_key_leaks_into_log_records`
   — the sentinel-key sweep would catch a regression.
3. **No raw API key in audit log details.** The redactor strips
   provider-prefixed runs (`sk-…`, `AIzaSy…`, `xai-…`) and any base64
   blob of length ≥ 32.
4. **No encryption master key in DB or code.** Lives in env / vault
   only; loaded once per process.

If any of these regress, treat as a security incident.
