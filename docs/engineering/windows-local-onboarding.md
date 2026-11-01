# Windows development without Docker or WSL

Use a current checkout of `dev` and a dedicated Git worktree. Install Python
3.11 or newer (including venv), Node.js 20.9 or newer with npm, PostgreSQL,
a Redis-compatible Windows service such as Garnet with Lua enabled, and Mailpit.
Reopen the terminal after installation. The launcher installs project packages;
it does not install or elevate Windows services.

Start PostgreSQL on `127.0.0.1:5432`, Redis/Garnet on `127.0.0.1:6379`, and
Mailpit with explicit loopback bindings:

```powershell
mailpit --smtp 127.0.0.1:1025 --listen 127.0.0.1:8025
```

Garnet must support Lua (`--lua` on versions offering that option), transactions,
WATCH, blocking list reads, hashes, sorted sets and sets. Setup tests actual
behavior, rather than treating PING as compatibility proof. Some Garnet versions
accept SELECT but execute Lua in database zero: fresh local provisioning uses
database zero with a persistent, unique resource UUID for queue, session and
rate-limit namespaces. Saved installations retain their existing layout.

## Fresh Native Login installation

Review the exact target before applying any changes:

```powershell
python scripts/dev.py setup --profile legacy --legacy-config managed --provision-local-postgres --initialize-database --confirm-database sbom_analyser_dev --postgres-provider local --redis-provider local --mailpit-provider local --plan
```

Repeat without `--plan` and approve each displayed category. Enter the local
PostgreSQL administrator login at the private prompt. The administrator password
stays in memory. The launcher creates `sbom_analyser_dev_setup` and
`sbom_analyser_dev_app`, both without superuser, role-creation, database-creation,
replication or RLS-bypass privileges. Setup owns this one database; the app has
DML access and read-only access to the schema revision marker.

The protected `.env.dev.postgres.json` retains generated setup/runtime passwords
and an ownership token for recovery. Only the app URL is put in `.env.dev.local`.
Neither file belongs in Git. Retain both files and the original keys/certificates.
The launcher never changes passwords on an existing role or adopts an unrecorded
database, even if its name matches.

For a separate disposable target, add
`--local-database sbom_analyser_dev_<suffix>` and repeat that exact name in
`--confirm-database`. A suffix is 1–24 lowercase letters, digits or underscores.
`--local-postgres-port` selects a different already-running local server.
For a new, separate Mailpit, use `--local-mailpit-smtp-port 51025
--local-mailpit-ui-port 58025` and bind that instance to loopback. These options
never modify saved service settings.

Setup creates missing signing/encryption keys and a missing localhost certificate
pair only after consent. It prepares the environment-free Next workspace and its
verified source/dependency links. It does not install browser/OS certificate
trust. Review the generated localhost certificate through the organization's
approved trust procedure before using it in a browser. TLS verification stays on.

```powershell
python scripts/dev.py setup --profile legacy --legacy-config managed --check-local-services --plan
python scripts/dev.py setup --profile legacy --legacy-config managed --check-local-services
python scripts/dev.py start --profile legacy --legacy-config managed
```

Startup verifies the schema, API/IAM, certificate-verified frontend, default and
reports Celery workers, their queues, and one progressing Beat. On Windows the
workers use the existing solo-pool adapter. Use `status`, `diagnose`, and component
`logs` to inspect failures. Ctrl+C or `stop` stops only verified owned application
processes; data services and databases remain available.

Native Login stays enabled and the development authentication bypass stays off.
First-account enrollment is a separate approved operator action. Setup never
creates a privileged Native administrator; the existing launcher enrollment
attestation gate remains in effect.

## Existing configuration and recovery

Ordinary setup never overwrites `.env.dev.local`, keys or certificates. Repeating
setup reuses valid preparation. Repeating the exact local provisioning command
can resume owned resources using the recovery record, without password rotation.
A completed schema is verified instead of bootstrapped again. An incomplete or
unknown schema is retained for review; setup never resets it or deletes resources.

To adopt a separately provisioned runtime login for the same saved database:

```powershell
python scripts/dev.py setup --profile legacy --legacy-config managed --transition-database-credentials --confirm-database <saved-database-name> --plan
```

Repeat without `--plan`, consent, and enter the new login privately. It must
authenticate to the same endpoint/database and cannot be an administrator,
schema-creating role or member of another role. The action retains a private
byte-for-byte backup and changes only `DATABASE_URL`, preserving comments,
unknown settings, keys and certificates. It never alters a database role.
Installations with a protected provisioning record retain their recorded runtime
role: this action adopts its externally renewed password. Replacing that role
requires a separate reviewed provisioning procedure, preserving setup ownership.

Windows private-file permission failures have a separate exact-file action:

```powershell
python scripts/dev.py setup --repair-private-file frontend/certificates/localhost-key.pem --plan
python scripts/dev.py setup --repair-private-file frontend/certificates/localhost-key.pem
```

Other allowlisted targets are `.env.dev.local` and `.env.dev.postgres.json`.
Consent requires repeating the full displayed path. The current owner must
already have Full Control. Repair refuses redirects, hardlinks, aliases, changed
file identities, unknown owners and complex ACLs requiring manual review. It pins
the file handle, saves the original security descriptor in a new private
`.env.dev.acl-backup-*.json`, protects the DACL and removes untrusted grants.
It adds no access rights and never changes ownership. If verification fails,
retain the descriptor backup and inspect Windows Security/Advanced; broader
permissions are never automatically restored. No recursive ACL command is used.

`setup --plan` and `diagnose` do not provision resources, repair permissions,
write Redis keys, send mail, prepare packages or start services. The explicit
compatibility action uses only random disposable Redis keys with short TTLs and
targeted cleanup; it never publishes tasks, changes Garnet options or flushes
data/scripts. Mailpit validation checks bindings, API and SMTP EHLO without
sending, reading or deleting captured messages. Non-loopback exposure is flagged.
