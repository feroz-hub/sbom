# SBOM Analyzer — Ubuntu Docker Deployment

This runbook deploys SBOM Analyzer 2.0.0 as two application images on
`linux/amd64`. The backend image is reused by the API, Alembic migration,
Celery worker, and single Celery Beat scheduler. PostgreSQL and Redis use their
official images and are not published to the host.

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
install -d -m 0750 deploy/certs deploy/secrets
install -m 0644 /secure/source/hcl-ca.crt deploy/certs/hcl-ca.crt
openssl rand -out deploy/secrets/auth-transaction.key 32
chmod 0400 deploy/secrets/auth-transaction.key
```

`HCL_IAM_CA_BUNDLE` and `FRONTEND_HCL_IAM_CA_BUNDLE` should point to
`/opt/sbom/certs/hcl-ca.crt`. Do not disable TLS verification. Set
`SSL_CERT_FILE` only when the mounted file is a combined corporate and public
root bundle; an HCL-only CA file could otherwise break NVD, OSV, KEV, GitHub,
VulDB, or AI HTTPS calls.

Configure the HCL.CS public PKCE client outside Docker with:

- exact issuer and API audience expected by the backend;
- exact redirect URI `https://SBOM_HOST/auth/callback`;
- exact post-logout URI `https://SBOM_HOST`;
- client ID and allowed scopes matching the build arguments;
- RS256 signing and reachable discovery/JWKS endpoints;
- role, tenant, subject, email, and (when required) `employee_id` claims;
- the server certificate chain trusted by the mounted CA.

Terminate public HTTPS at a reverse proxy/load balancer and forward to frontend
port 3000. Preserve `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and client
IP headers. The application uses `Secure`, `HttpOnly`, `SameSite=Lax`,
`__Host-` cookies, so production authentication must be accessed over HTTPS.

The current frontend session store is process memory. Run exactly one frontend
replica unless the application is enhanced with a shared session store; a
frontend restart requires users to sign in again. Always run exactly one Beat
replica to avoid duplicate scheduled jobs.

## 5. Validate and start

```bash
docker compose --env-file .env.server -f docker-compose.server.yml config --quiet
docker compose --env-file .env.server -f docker-compose.server.yml up -d
docker compose --env-file .env.server -f docker-compose.server.yml ps -a
```

The `migrate` service must show `Exited (0)`. Backend, worker, and Beat are gated
on migration success, so a failed migration prevents a stale-schema API from
starting.

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

1. Back up PostgreSQL and persistent application files.
2. Load the new image archive.
3. Change `SBOM_ANALYSER_VERSION` in `.env.server`.
4. Validate Compose, then recreate services:

```bash
docker compose --env-file .env.server -f docker-compose.server.yml config --quiet
docker compose --env-file .env.server -f docker-compose.server.yml up -d
docker compose --env-file .env.server -f docker-compose.server.yml ps -a
docker compose --env-file .env.server -f docker-compose.server.yml logs migrate
```

The migration container runs before the new API/worker/scheduler starts.

## 9. Rollback

Application rollback is safe only when the database schema remains compatible
with the previous release. Consult that release's migration notes first. Then
restore the pre-upgrade database backup if required, set
`SBOM_ANALYSER_VERSION` to the previous loaded tag, and run:

```bash
docker compose --env-file .env.server -f docker-compose.server.yml up -d
```

Never run an Alembic downgrade against production without a tested database
restore plan.

## 10. Back up PostgreSQL and persistent files

Create an encrypted backup destination with adequate free space:

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
  --build-arg NEXT_PUBLIC_API_URL="$NEXT_PUBLIC_API_URL" \
  --build-arg NEXT_PUBLIC_HCL_IAM_ISSUER="$NEXT_PUBLIC_HCL_IAM_ISSUER" \
  --build-arg NEXT_PUBLIC_HCL_IAM_CLIENT_ID="$NEXT_PUBLIC_HCL_IAM_CLIENT_ID" \
  --build-arg NEXT_PUBLIC_HCL_IAM_REDIRECT_URI="$NEXT_PUBLIC_HCL_IAM_REDIRECT_URI" \
  --build-arg NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI="$NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI" \
  --build-arg NEXT_PUBLIC_HCL_IAM_SCOPES="$NEXT_PUBLIC_HCL_IAM_SCOPES" \
  --build-arg NEXT_PUBLIC_COMPARE_V1_FALLBACK="$NEXT_PUBLIC_COMPARE_V1_FALLBACK" \
  -f frontend/Dockerfile frontend
```

Do not pass database, IAM private keys, provider tokens, or other secrets as
build arguments.

Export the validated application images for transfer:

```bash
docker save -o sbom-analyser-images-2.0.0.tar \
  sbom-analyser-backend:2.0.0 \
  sbom-analyser-frontend:2.0.0
ls -lh sbom-analyser-images-2.0.0.tar
```

The TAR is ignored by Git and must be transferred through an approved artifact
channel.
