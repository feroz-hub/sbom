# SBOM Analyzer — Ubuntu Docker Deployment

This runbook deploys SBOM Analyzer 2.0.0 as two application images on
`linux/amd64`. The backend image is reused by the API, Alembic migration,
Celery worker, and single Celery Beat scheduler. PostgreSQL and Redis use their
official images and are not published to the host.

## Applicability and mandatory database gate

Source configuration checked against e62951c2 on 28 October 2026. This procedure
describes the repository's linux/amd64 server topology, not an approved production
support matrix. Native Windows/macOS production, arm64 images, horizontal scale
and provider-specific acceptance remain unverified here.

Before any bootstrap, migration or Compose up command, classify the exact target
using [database operations](DATABASE_BOOTSTRAP_AND_UPGRADE.md):

- A fresh installation requires a separately identified, empty PostgreSQL target.
- An existing compatible UUID installation requires approval of the exact
  transition, physical schema/identity validation and backup/restore evidence.
- A populated pre-UUID installation **must not cross revision 100** through this
  procedure. Revision 100 refuses populated application tables. No approved
  conversion is supplied here; stop for a separately reviewed design.
- Unknown, drifted or ahead schemas require reconciliation, not marker stamping.

The migrate service invokes upgrade head on an existing database; it does not
implement that missing conversion or Greenfield's interactive backup contract.
All write commands below are conditional on the operator's target/release review.
[Configuration](reference/configuration.md) separates public build values from
private runtime settings.

## 1. Install Docker Engine

Install Docker Engine and the Compose and Buildx plugins from Docker's Ubuntu
repository. Confirm the server is reachable:

```bash
docker version
docker compose version
docker buildx version
```

Add the deployment operator to the `docker` group only if your security policy
permits root-equivalent Docker access.

Redis recommends Linux memory overcommit so background persistence remains
reliable during memory pressure. Configure it on the Ubuntu host:

```bash
echo 'vm.overcommit_memory = 1' | sudo tee /etc/sysctl.d/99-sbom-redis.conf
sudo sysctl --system
```

## 2. Copy and load the application images

Copy these files to a fixed deployment directory such as `/opt/sbom-analyser`:

- `sbom-analyser-images-2.0.0.tar`
- `docker-compose.server.yml`
- `.env.server.example`

Load the two application images:

```bash
cd /opt/sbom-analyser
docker load -i sbom-analyser-images-2.0.0.tar
docker image inspect sbom-analyser-backend:2.0.0 --format '{{.Os}}/{{.Architecture}} {{.Size}}'
docker image inspect sbom-analyser-frontend:2.0.0 --format '{{.Os}}/{{.Architecture}} {{.Size}}'
```

Compose will pull `postgres:16` and `redis:7-alpine` from the configured Docker
registry. Mirror and pre-load those images as well on an air-gapped server.

## 3. Create the server environment

```bash
cp .env.server.example .env.server
chmod 600 .env.server
editor .env.server
```

Replace every `CHANGE_ME`, `SBOM_HOST`, and `HCL_IAM_HOST` value. Generate long,
independent secrets. If a database password contains reserved URL characters,
URL-encode it in `DATABASE_URL` while keeping the literal password in
`POSTGRES_PASSWORD`.

The `NEXT_PUBLIC_*` variables are compiled into the frontend image. They are
public settings—not secrets—and changing them requires rebuilding the frontend.
`SBOM_API_URL`, certificate paths, database/broker URLs, API credentials, and
mail credentials are runtime settings.

The application does not consume `NEXT_PUBLIC_APP_URL`; the redirect and logout
URLs are the canonical browser-facing application URLs.

## 4. Configure HCL IAM and certificates

Create private mount directories without copying keys into an image:

```bash
install -d -o 10001 -g 10001 -m 0750 deploy/certs deploy/secrets
install -m 0644 /secure/source/hcl-ca.crt deploy/certs/hcl-ca.crt
openssl rand -out deploy/secrets/auth-transaction.key 32
chown 10001:10001 deploy/secrets/auth-transaction.key
chmod 0400 deploy/secrets/auth-transaction.key
```

`HCL_IAM_CA_BUNDLE` and `FRONTEND_HCL_IAM_CA_BUNDLE` should point to
`/opt/sbom/certs/hcl-ca.crt`. Do not disable TLS verification. Set
`SSL_CERT_FILE` only when the mounted file is a combined corporate and public
root bundle; an HCL-only CA file could otherwise break NVD, OSV, KEV, GitHub,
VulDB, or AI HTTPS calls.

Configure the HCL.CS public PKCE client outside Docker with:

- exact issuer and API audience expected by the backend;
- `SBOM_IDENTITY_BACKFILL_ISSUER` set to that same exact trusted issuer for
  migration 046 (it is harmless after the backfill is complete);
- exact redirect URI `https://SBOM_HOST/auth/callback`;
- exact post-logout URI `https://SBOM_HOST/logged-out`, registered as an allowed Post Logout Redirect URI for `sbom-analyser-web` in HCL.CS (retain other valid URIs);
- client ID and allowed scopes matching the build arguments;
- RS256 signing and reachable discovery/JWKS endpoints;
- role, tenant, subject, email, and (when required) `employee_id` claims;
- the server certificate chain trusted by the mounted CA.

Terminate public HTTPS at a reverse proxy/load balancer and forward to frontend
port 3000. Preserve `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and client
IP headers. The application uses `Secure`, `HttpOnly`, `SameSite=Lax`,
`__Host-` cookies, so production authentication must be accessed over HTTPS.

Server Compose configures shared Redis BFF sessions. Production session access
refuses the in-memory fallback. Supply AUTH_SESSION_REDIS_URL and a stable,
independent 32-byte base64 AUTH_SESSION_ENCRYPTION_KEY; the Compose configuration
requires the encryption key. Preserve the protected transaction-key file as
well. Redis support alone does not establish multi-replica or failover acceptance;
validate the intended topology before changing replica counts. Always run
exactly one Beat replica to avoid duplicate scheduled jobs.

HCL is the provider described in this section. Native-only deployment requires
matching backend/BFF and public image-build flags plus all Native production
prerequisites; see [Native staging guidance](native-iam-greenfield-setup.md)
and [security/IAM](security/README.md). Current server Compose does not forward
ENTRA_* variables; Entra deployment through this manifest is unverified. This
phase neither enables providers nor changes authentication configuration.

## 5. Validate and start

Proceed only after the mandatory database gate above. A successful Compose
render checks configuration shape; it does not prove schema compatibility,
secrets validity or production readiness.

```bash
docker compose --env-file .env.server -f docker-compose.server.yml config --quiet
docker compose --env-file .env.server -f docker-compose.server.yml up -d
docker compose --env-file .env.server -f docker-compose.server.yml ps -a
```

The `migrate` service must show `Exited (0)`. On a provably empty PostgreSQL
database its launcher uses the repository's guarded frozen schema baseline and
then runs `alembic upgrade head`; on an existing database it runs
`alembic upgrade head` directly. Backend, worker, and Beat are gated on migration
success, so a failed migration prevents the new stale-schema API from starting.
This ordering does not stop existing writers. In particular, it is not an
approved way to discover whether a populated pre-UUID deployment can cross 100.

## 6. Verify the deployment

```bash
docker compose --env-file .env.server -f docker-compose.server.yml logs migrate
docker compose --env-file .env.server -f docker-compose.server.yml logs backend
docker compose --env-file .env.server -f docker-compose.server.yml logs worker
docker compose --env-file .env.server -f docker-compose.server.yml logs beat
docker compose --env-file .env.server -f docker-compose.server.yml logs frontend
docker compose --env-file .env.server -f docker-compose.server.yml exec backend alembic current
docker compose --env-file .env.server -f docker-compose.server.yml exec redis redis-cli ping
docker compose --env-file .env.server -f docker-compose.server.yml exec worker \
  celery -A app.workers.celery_app inspect ping --timeout 10
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:3000/
```

If `BACKEND_BIND_ADDRESS` remains `127.0.0.1`, the backend health check is local
to the server. Verify the public HTTPS frontend and OIDC login through the
reverse proxy. `/docs` is available at the backend origin when Swagger is
enabled.

After login, verify tenant selection and role permissions, create or select a
project/product, upload both CycloneDX and SPDX samples, run analysis, inspect
NVD/OSV/GitHub/VulDB and KEV/lifecycle results, and export PDF and Excel reports.
Create one short-interval schedule in a non-production test tenant, observe Beat
enqueue `scheduled_analysis.tick`, and observe the worker consume the analysis
task. Remove that test schedule afterward.

Large SBOM validation workspaces and private generated report artifacts persist
in the `app_data` volume. PostgreSQL data persists in `postgres_data`, and Redis
AOF data in `redis_data`. If the optional local Xeol database is used, place it
under `/var/lib/sbom/xeol` in `app_data` or provide a separate read-only volume.
Console logging is recommended; configure the platform log collector rather
than writing logs into the container filesystem.

## 7. Operations

```bash
docker compose --env-file .env.server -f docker-compose.server.yml ps
docker compose --env-file .env.server -f docker-compose.server.yml logs -f backend
docker compose --env-file .env.server -f docker-compose.server.yml logs -f worker
docker compose --env-file .env.server -f docker-compose.server.yml logs -f beat
docker compose --env-file .env.server -f docker-compose.server.yml restart backend
docker compose --env-file .env.server -f docker-compose.server.yml up -d
docker compose --env-file .env.server -f docker-compose.server.yml down
```

`down` preserves named volumes. Do not add `--volumes` unless permanently
deleting all PostgreSQL, Redis, uploaded-workspace, and report data is intended.

## 8. Upgrade

This section applies only to an operator-reviewed compatible UUID transition.
Do not use it to cross revision 100 from a populated pre-UUID target. This
documentation change approves no production source-to-target pair.

1. Identify the cluster/database, source and target image/source revisions,
   actual schema/identity guards and exact pending revisions. Resolve drift or
   unknown state before writes.
2. Back up PostgreSQL and persistent application files to an approved encrypted
   destination, preserve required keys and rehearse restore in isolation.
3. Plan and carry out writer drain/stop as required by the reviewed transition:
   old API, workers and Beat must not race an incompatible migration. Compose
   depends_on is startup ordering, not an old-writer drain.
4. Load the approved images and set SBOM_ANALYSER_VERSION in protected server
   configuration. Review provider/build/runtime compatibility.
5. For that approved transition only, validate Compose and recreate services:

```bash
docker compose --env-file .env.server -f docker-compose.server.yml config --quiet
docker compose --env-file .env.server -f docker-compose.server.yml up -d
docker compose --env-file .env.server -f docker-compose.server.yml ps -a
docker compose --env-file .env.server -f docker-compose.server.yml logs migrate
```

The migration container runs before the new API/worker/scheduler starts. Verify
migration exit, accepted schema, authenticated BFF/IAM readiness, intended queues
and application storage before release. A failed or uncertain COMMIT requires
operator reconciliation; do not retry, stamp or downgrade to force success.

## 9. Rollback

Application rollback is safe only when the database schema remains compatible
with the previous release. Consult that release's migration notes first. Then
restore the pre-upgrade database backup if required, set
`SBOM_ANALYSER_VERSION` to the previous loaded tag, and run:

```bash
docker compose --env-file .env.server -f docker-compose.server.yml up -d
```

Revision 100 deliberately refuses public-identity downgrade. Do not treat
Alembic downgrade as a generic rollback. Use only the reviewed per-transition
recovery plan, accounting for writes since backup and a compatible image,
schema, configuration and keys before any Compose restart.

## 10. Back up PostgreSQL and persistent files

Use an approved encrypted backup destination with adequate free space.
The directory permissions and pg_dump/tar commands below do not themselves
encrypt data; encryption and recoverable key custody must already be provided
by the approved destination/process:

```bash
install -d -m 0700 backups
docker compose --env-file .env.server -f docker-compose.server.yml exec -T postgres \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc > backups/sbom-analyser.dump
docker run --rm \
  -v sbom-analyser-server_app_data:/source:ro \
  -v "$PWD/backups:/backup" \
  alpine:3.22 tar -C /source -czf /backup/sbom-app-data.tar.gz .
```

The shell variables in the first command must be exported from the protected
environment file (or replaced explicitly). Regularly test restoration into an
isolated PostgreSQL instance. Redis contains broker/result state and uses AOF,
but PostgreSQL and `app_data` are the authoritative business-data backups.

## 11. Build the images again

From the repository root on a trusted build host:

```bash
set -a
. ./.env.server
set +a

docker buildx build --platform linux/amd64 --load \
  -t sbom-analyser-backend:2.0.0 .

docker buildx build --platform linux/amd64 --load \
  -t sbom-analyser-frontend:2.0.0 \
  --build-arg NEXT_PUBLIC_AUTH_ENABLED="$NEXT_PUBLIC_AUTH_ENABLED" \
  --build-arg NEXT_PUBLIC_HCL_AUTH_ENABLED="${NEXT_PUBLIC_HCL_AUTH_ENABLED:-true}" \
  --build-arg NEXT_PUBLIC_API_URL="$NEXT_PUBLIC_API_URL" \
  --build-arg NEXT_PUBLIC_HCL_IAM_ISSUER="$NEXT_PUBLIC_HCL_IAM_ISSUER" \
  --build-arg NEXT_PUBLIC_HCL_IAM_CLIENT_ID="$NEXT_PUBLIC_HCL_IAM_CLIENT_ID" \
  --build-arg NEXT_PUBLIC_HCL_IAM_REDIRECT_URI="$NEXT_PUBLIC_HCL_IAM_REDIRECT_URI" \
  --build-arg NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI="$NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI" \
  --build-arg NEXT_PUBLIC_HCL_IAM_SCOPES="$NEXT_PUBLIC_HCL_IAM_SCOPES" \
  --build-arg NEXT_PUBLIC_COMPARE_V1_FALLBACK="$NEXT_PUBLIC_COMPARE_V1_FALLBACK" \
  -f frontend/Dockerfile frontend
```

NEXT_PUBLIC_HCL_AUTH_ENABLED defaults to true above, matching the Dockerfile.
For a reviewed Native-only image, explicitly set it false and keep public and
runtime auth flags consistent; a runtime edit does not reliably replace
compiled browser values. Do not pass database, IAM private keys, provider tokens
or other secrets as build arguments.

Export the validated application images for transfer:

```bash
docker save -o sbom-analyser-images-2.0.0.tar \
  sbom-analyser-backend:2.0.0 \
  sbom-analyser-frontend:2.0.0
ls -lh sbom-analyser-images-2.0.0.tar
```

The TAR is ignored by Git and must be transferred through an approved artifact
channel.
