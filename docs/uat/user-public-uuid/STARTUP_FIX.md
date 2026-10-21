# Greenfield startup schema preflight and process monitoring

The reported `Cannot inspect PID 73880` masked an API startup failure. The actual
backend log required `101_iam_user_public_uuid`, while the populated Greenfield
database remained at `100_greenfield_uuid_final`. PID 73880 was the exited API
child. The Greenfield launcher bypassed the legacy launcher's migration step,
and `Runtime.refresh()` inspected exited children without first reaping them.

## Corrected behavior

Run the normal command:

```bash
python3 scripts/dev.py start
```

Before starting API, worker or frontend, the Greenfield path now verifies the
fixed local database, PostgreSQL 16.15, current marker and exact reviewed migration
source hashes. A database already at 101 continues without a migration prompt.
For the reviewed populated 100→101 transition, it displays the actual cluster and
user count and requests this exact operator confirmation:

```text
UPGRADE sbom_greenfield_uuid 100 TO 101
```

Pressing Enter cancels without database changes or application startup.
Noninteractive startup refuses a pending migration. `--check` remains a
metadata-only operation without passwords, database connections or prompts.
Unknown revisions and partial upgrades are never stamped or repaired.

Confirmation authorizes the displayed local backup/rehearsal and one migration:

1. Check no competing database clients, unexpected IAM triggers, owner/runtime
   privilege changes or external/replication objects. Keep endpoint fixed to
   `127.0.0.1:56044/sbom_greenfield_uuid`; refuse ambient `PG*` overrides.
2. Export a full custom-format archive using the verified original PostgreSQL
   container, encrypt it with a new private backup key, and retain both under
   `~/.sbom-greenfield-uuid/upgrade-backups/` (0700 directory, 0600 files). Never
   write a plaintext archive path or print rows/credentials.
3. Restore into a new `sbom_greenfield_uuid_pre101_<random>` recovery database.
   Preserve owner/ACL semantics and compare data, relations, columns, integer
   constraints, functions, triggers, roles, sequence state and database settings.
   The recovery database and encrypted backup remain available; no automatic
   cleanup or recreation occurs.
4. Recheck sources, target, writer exclusion and the reviewed snapshot. Claim the
   attempt privately, lock the version table and IAM table, enter the existing
   `greenfield_owner` role, and execute the unchanged 101 body and marker update
   within one owned transaction. Timeouts remain 2 seconds per statement,
   250 milliseconds for lock acquisition and 5 seconds idle in transaction.
5. Verify exact IAM-only catalog additions, UUIDv4 uniqueness/NOT NULL/default,
   guard ownership/security, preserved existing data and integer relationships.
   Acknowledge COMMIT, physically close the writer, and independently verify on
   a new read-only connection before allowing services to start.

A known precommit failure rolls back and closes. Unknown COMMIT or incomplete
acceptance stops. A `pending-schema-upgrade.json` claim blocks subsequent starts
until independently reconciled; never delete it just to retry. Restoring the
populated database from backup remains a separately reviewed recovery action.

The PG16 backup comparison accounts only for its observed built-in literal
varchar-array-to-text CHECK cast representation and ACL NULL/default equivalence;
it does not ignore constraints, ownership, grants, labels or validation flags.
The original migration100, migration101 and IAM guard/helper bytes are unchanged.

`Runtime.refresh()` now calls `Popen.poll()` before inspecting each owned child,
matching the existing shutdown reaping behavior. Process birth-identity checks
and refusal to signal unrelated/reused PIDs remain intact.

## Actual verification — 2026-10-21

- **209 PASS**, offline lifecycle, launcher, Greenfield schema-confirmation and
  HTTPS regressions. No live service startup is represented by these mocks.
- **5 PASS**, real PostgreSQL using only `sbom_iam_public_uuid_test`, the existing
  reserved synthetic upgrade fixture database, and newly created backup rehearsal
  databases. Includes confirmed backup/restore→101→independent read-back, injected
  precommit rollback→100, retry refusal, existing Native login identity/credential
  and membership preservation, and wrong-revision refusal.
- Main-database read-only preflight observed cluster `7698349709013049382`, marker
  **100**, and **19 IAM users**, then exercised cancellation. **No populated
  migration, backup export, UUID allocation or service startup was performed.**
- Ruff/static/whitespace checks run on changed source; full 4,421-case application
  regression and a new live application/browser session were not rerun for this
  launcher fix. The historical accepted runs remain separately documented.

Initial development failures are retained in private evidence: ordinary pytest
invoked the repository-wide legacy database hook and failed to connect to stopped
port55439; launcher tests then used `--noconftest`. The first disposable restore
incorrectly removed PG16's expected public schema. After preserving that schema,
strict parity identified the literal-array CHECK cast and default-ACL
representations. Focused regressions cover the narrow semantic comparison. The
corrected final disposable run passed all five tests; earlier failures are not
rewritten as successful runs. Ruff was initially invoked from an unavailable
`.venv/bin/ruff`; the installed `/opt/anaconda3/bin/ruff` was used instead.

Commands:

```bash
PYTHON_DOTENV_DISABLED=1 .venv/bin/python -B -m pytest --noconftest -q \
  tests/test_greenfield_startup_migrations.py tests/test_dev_greenfield.py \
  tests/test_dev_lifecycle.py tests/test_dev_launcher.py tests/test_greenfield_https.py \
  -o addopts= --tb=short
```

Real PostgreSQL tests use the existing isolated IAM test environment and explicit
`SBOM_RUN_GREENFIELD_STARTUP_ACCEPTANCE=1`; they must never be redirected to the
populated application database. Protected evidence is under the private
`~/.sbom-iam-public-uuid/startup-fix-20261021T125611Z/` directory. Private backups,
keys, driver diagnostics and database contents must not be committed.

No commit, push, deployment, protected historical database access or populated
100→101 migration was performed during this fix. The next normal interactive
start can request the operator's exact local migration confirmation. Startup is
not yet claimed successful on the populated database because that confirmation
has not been given.
