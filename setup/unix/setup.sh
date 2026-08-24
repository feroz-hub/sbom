#!/usr/bin/env bash
# Canonical first-time setup for macOS and Linux.
# Internal implementation scripts remain under scripts/ and are normally
# invoked through this setup/... entry point.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
OS="$(uname -s)"
VENV_PYTHON="${REPO_ROOT}/.venv/bin/python"
BOOTSTRAP_PLATFORM_ADMIN=0
PLATFORM_ADMIN_SUBJECT=""
PLATFORM_ADMIN_ISSUER=""
PLATFORM_ADMIN_CHANGE_REFERENCE=""

red=$'\033[31m'; green=$'\033[32m'; yellow=$'\033[33m'; blue=$'\033[34m'; reset=$'\033[0m'
pass() { printf '%sPASS%s %s\n' "$green" "$reset" "$*"; }
warn() { printf '%sWARN%s %s\n' "$yellow" "$reset" "$*" >&2; }
fail() { printf '%sFAIL%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }
step() { printf '%s==>%s %s\n' "$blue" "$reset" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

dotenv_value_file() {
  local file="$1" wanted="$2"
  [[ -f "$file" ]] || return 0
  awk -F= -v wanted="$wanted" '$1==wanted {sub(/^[^=]*=/, ""); gsub(/"/, ""); gsub(/\047/, ""); print; exit}' "$file" 2>/dev/null |
    sed 's/^["'"'"']//; s/["'"'"']$//' || true
}

normalise_bool() {
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'
}

assert_auth_consistent() {
  local backend frontend
  backend="$(normalise_bool "$(dotenv_value_file "$REPO_ROOT/.env" AUTH_ENABLED)")"
  frontend="$(normalise_bool "$(dotenv_value_file "$REPO_ROOT/frontend/.env.local" NEXT_PUBLIC_AUTH_ENABLED)")"
  [[ -n "$backend" ]] || backend=false
  [[ -n "$frontend" ]] || frontend=false
  [[ "$backend" == true || "$backend" == false ]] || fail "AUTH_ENABLED must be true or false in .env."
  [[ "$frontend" == true || "$frontend" == false ]] || fail "NEXT_PUBLIC_AUTH_ENABLED must be true or false in frontend/.env.local."
  [[ "$backend" == "$frontend" ]] || fail "Authentication configuration is inconsistent: AUTH_ENABLED=$backend, NEXT_PUBLIC_AUTH_ENABLED=$frontend. Update both files explicitly."
  printf '%s\n' "$backend"
}

resolve_repo_path() {
  local value="$1"
  [[ -z "$value" ]] && return 0
  if [[ "$value" = /* ]]; then
    printf '%s\n' "$value"
  else
    printf '%s\n' "$REPO_ROOT/$value"
  fi
}

compose_database_matches() {
  local expected_port
  expected_port="$postgres_port"
  DATABASE_URL="$database_url" EXPECTED_POSTGRES_PORT="$expected_port" \
    "$VENV_PYTHON" - <<'PY'
import os
from sqlalchemy.engine import make_url

try:
    url = make_url(os.environ["DATABASE_URL"])
    expected_port = int(os.environ["EXPECTED_POSTGRES_PORT"])
    matches = (
        url.get_backend_name().startswith("postgresql")
        and (url.host or "localhost") in {"localhost", "127.0.0.1", "::1"}
        and (url.port or 5432) == expected_port
        and (url.database or "") == "sbom_analyser"
        and (url.username or "") == "sbom"
        and (url.password or "") == "sbom"
    )
except Exception:
    matches = False
print("true" if matches else "false")
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bootstrap-platform-admin) BOOTSTRAP_PLATFORM_ADMIN=1 ;;
    --platform-admin-subject|--platform-admin-issuer|--platform-admin-change-reference)
      [[ $# -ge 2 && "$2" != --* ]] || fail "$1 requires a value that is not another option."
      case "$1" in
        --platform-admin-subject) PLATFORM_ADMIN_SUBJECT="$2" ;;
        --platform-admin-issuer) PLATFORM_ADMIN_ISSUER="$2" ;;
        --platform-admin-change-reference) PLATFORM_ADMIN_CHANGE_REFERENCE="$2" ;;
      esac
      shift
      ;;
    -h|--help)
      sed -n '1,18p' "${BASH_SOURCE[0]}"
      printf '%s\n' 'Optional audited grant: --bootstrap-platform-admin --platform-admin-subject SUBJECT --platform-admin-change-reference CHANGE [--platform-admin-issuer ISSUER]'
      exit 0
      ;;
    *) fail "Unknown option: $1" ;;
  esac
  shift
done

case "$OS" in
  Darwin|Linux) : ;;
  *) fail "Unsupported OS '$OS'. Use the PowerShell entry points on Windows." ;;
esac

step "Checking required developer tools"
have git || fail "Git is required. On macOS install with 'brew install git'; on Debian/Ubuntu/Kali use 'sudo apt update && sudo apt install git'."
python_command=""
for candidate in python3.11 python3 python; do
  if have "$candidate" && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
    python_command="$candidate"
    break
  fi
done
[[ -n "$python_command" ]] || fail "Python 3.11 or newer is required. On macOS use 'brew install python@3.11'; on Debian/Ubuntu/Kali use 'sudo apt install python3.11 python3.11-venv python3-pip'."
have node || fail "Node.js is required. On macOS use 'brew install node@20'; on Debian/Ubuntu/Kali install Node.js 20 from NodeSource or your approved package source."
node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' || fail "Node.js 20 or newer is required."
have npm || fail "npm is required; install it with Node.js 20."
pass "Git, Python >=3.11, Node.js >=20, and npm are available."

if [[ ! -f "${REPO_ROOT}/.env" ]]; then
  [[ -f "${REPO_ROOT}/.env.example" ]] || fail "Missing .env.example."
  cp "${REPO_ROOT}/.env.example" "${REPO_ROOT}/.env"
  pass "Created .env from .env.example; existing developer values are never overwritten."
else
  pass "Preserved existing .env."
fi
if [[ ! -f "${REPO_ROOT}/frontend/.env.local" ]]; then
  [[ -f "${REPO_ROOT}/frontend/.env.local.example" ]] || fail "Missing frontend/.env.local.example."
  cp "${REPO_ROOT}/frontend/.env.local.example" "${REPO_ROOT}/frontend/.env.local"
  pass "Created frontend/.env.local from its template."
else
  pass "Preserved existing frontend/.env.local."
fi
auth_enabled="$(assert_auth_consistent)"

compose_available=0
if have docker && docker compose version >/dev/null 2>&1; then compose_available=1; fi
if (( compose_available == 0 )) && ! have psql; then
  if [[ "$OS" == "Darwin" ]]; then
    warn "Docker Compose and psql are unavailable. Install Docker Desktop or run 'brew install libpq' and add its bin directory to PATH; setup will still try the configured Python database driver."
  else
    warn "Docker Compose and psql are unavailable. Install Docker Engine/Compose or run 'sudo apt install postgresql-client'; setup will still try the configured Python database driver."
  fi
fi

step "Reusing existing dependency bootstrap"
[[ -f "${REPO_ROOT}/scripts/bootstrap.sh" ]] || fail "Missing scripts/bootstrap.sh."
bash "${REPO_ROOT}/scripts/bootstrap.sh" --skip-system || fail "Existing Unix dependency bootstrap failed."
[[ -x "$VENV_PYTHON" ]] || fail "Python virtual environment was not created at $REPO_ROOT/.venv."

database_url="$(cd "$REPO_ROOT" && "$VENV_PYTHON" -c 'from dotenv import dotenv_values; print(dotenv_values(".env").get("DATABASE_URL", ""))')"
[[ -n "$database_url" ]] || fail "DATABASE_URL is missing in .env."
postgres_port="$(cd "$REPO_ROOT" && "$VENV_PYTHON" -c 'from dotenv import dotenv_values; print(dotenv_values(".env").get("POSTGRES_PORT", "") or "55439")')"
[[ "$postgres_port" =~ ^[0-9]+$ ]] && (( postgres_port >= 1 && postgres_port <= 65535 )) || fail "POSTGRES_PORT must be a valid TCP port in .env."
database_name="$(DATABASE_URL="$database_url" "$VENV_PYTHON" -c 'from sqlalchemy.engine import make_url; print(make_url(__import__("os").environ["DATABASE_URL"]).database or "")')" || fail "DATABASE_URL is invalid in .env."
[[ -n "$database_name" ]] || fail "DATABASE_URL does not contain a database name."

if (( compose_available == 1 )) && [[ "$(compose_database_matches)" == true ]]; then
  step "Starting the repository PostgreSQL service"
  (cd "$REPO_ROOT" && docker compose up -d postgres) || fail "Docker Compose could not start the configured repository PostgreSQL service."
  pass "PostgreSQL Compose service is running."
else
  pass "Docker Compose was not started because DATABASE_URL points to a non-repository database."
fi

step "Checking database connectivity"
db_connected=0
for ((attempt=1; attempt<=30; attempt++)); do
  if (cd "$REPO_ROOT" && "$VENV_PYTHON" -c 'from app.db import engine; c=engine.connect(); c.close(); engine.dispose()' >/dev/null 2>&1); then
    db_connected=1
    break
  fi
  sleep 1
done
(( db_connected == 1 )) || fail "Database connection failed after 30 seconds. Start PostgreSQL or correct DATABASE_URL in .env."
pass "Database connection is healthy."

step "Applying Alembic migrations"
object_count="$(cd "$REPO_ROOT" && DATABASE_URL="$database_url" "$VENV_PYTHON" - <<'PY'
from sqlalchemy import create_engine
from scripts.bootstrap_fresh_database import existing_application_objects
import os

engine = create_engine(os.environ["DATABASE_URL"])
try:
    with engine.connect() as connection:
        print(len(existing_application_objects(connection)))
finally:
    engine.dispose()
PY
)" || fail "Unable to inspect database objects."
if [[ "$object_count" == "0" && "$database_url" == postgresql* ]]; then
  DATABASE_URL="$database_url" "$VENV_PYTHON" "$REPO_ROOT/scripts/bootstrap_fresh_database.py" \
    --confirm-empty-database "$database_name" || fail "Fresh PostgreSQL bootstrap failed."
else
  (cd "$REPO_ROOT" && "$VENV_PYTHON" -m alembic upgrade head) || fail "Alembic migration failed."
fi
pass "Database schema is at the Alembic head."
active_admin_count="$(cd "$REPO_ROOT" && "$VENV_PYTHON" -c 'from app.db import SessionLocal; from app.models import PlatformUserRole; db=SessionLocal(); print(db.query(PlatformUserRole).filter(PlatformUserRole.status == "ACTIVE").count()); db.close()')" || active_admin_count="unknown"
if [[ "$active_admin_count" == "0" ]]; then
  warn "No active Platform Administrator grant exists. Setup does not grant authority; use scripts/bootstrap_platform_admin.py with an approved change reference if required."
fi

if [[ "$auth_enabled" == "true" ]]; then
  step "Checking authenticated development prerequisites"
  issuer="$(dotenv_value_file "$REPO_ROOT/.env" HCL_IAM_ISSUER)"
  discovery="$(dotenv_value_file "$REPO_ROOT/.env" HCL_IAM_DISCOVERY_URL)"
  [[ -n "$discovery" ]] || discovery="${issuer%/}/.well-known/openid-configuration"
  [[ -n "$issuer" ]] || fail "AUTH_ENABLED=true but HCL_IAM_ISSUER is empty in .env."
  ca_bundle="$(resolve_repo_path "$(dotenv_value_file "$REPO_ROOT/.env" HCL_IAM_CA_BUNDLE)")"
  [[ -z "$ca_bundle" || -f "$ca_bundle" ]] || fail "HCL_IAM_CA_BUNDLE does not exist: $ca_bundle"
  if [[ ! -f "$REPO_ROOT/frontend/certificates/localhost.pem" || ! -f "$REPO_ROOT/frontend/certificates/localhost-key.pem" ]]; then
    have openssl || fail "Authenticated frontend setup needs openssl or mkcert. Install it using your OS package manager."
    (cd "$REPO_ROOT/frontend" && bash scripts/setup-dev-https.sh) || fail "Frontend HTTPS setup failed."
  fi
  if have curl; then
    curl_args=(--fail --silent --show-error --max-time 5)
    [[ -n "$ca_bundle" ]] && curl_args+=(--cacert "$ca_bundle")
    if curl "${curl_args[@]}" "$discovery" >/dev/null; then
      pass "HCL IAM discovery endpoint is reachable."
    else
      warn "HCL IAM is external and not reachable. Start Security Framework separately and verify $discovery."
    fi
  else
    warn "curl is unavailable; HCL IAM reachability was not checked."
  fi
  [[ -f "$REPO_ROOT/frontend/certificates/localhost.pem" && -f "$REPO_ROOT/frontend/certificates/localhost-key.pem" ]] || fail "Authenticated frontend HTTPS requires both localhost.pem and localhost-key.pem."
else
  warn "AUTH_ENABLED=false; HCL IAM is disabled for this local setup."
fi

if (( BOOTSTRAP_PLATFORM_ADMIN == 1 )); then
  [[ "$auth_enabled" == "true" ]] || fail "Platform Administrator bootstrap requires AUTH_ENABLED=true in .env; do not override application auth mode."
  [[ -n "$PLATFORM_ADMIN_SUBJECT" && -n "$PLATFORM_ADMIN_CHANGE_REFERENCE" ]] || fail "--bootstrap-platform-admin requires --platform-admin-subject and --platform-admin-change-reference."
  admin_args=(--subject "$PLATFORM_ADMIN_SUBJECT" --change-reference "$PLATFORM_ADMIN_CHANGE_REFERENCE" --confirm BOOTSTRAP_PLATFORM_ADMIN)
  [[ -n "$PLATFORM_ADMIN_ISSUER" ]] && admin_args+=(--issuer "$PLATFORM_ADMIN_ISSUER")
  (cd "$REPO_ROOT" && "$VENV_PYTHON" scripts/bootstrap_platform_admin.py "${admin_args[@]}") || fail "Platform Administrator bootstrap failed."
else
  warn "Platform Administrator grants are explicit and were not changed. Use scripts/bootstrap_platform_admin.py only with an approved change reference and an existing local IAM user."
fi
printf '\n%sREADY%s\n' "$green" "$reset"
printf 'Run ./setup/unix/start.sh for the API and integrated frontend/admin UI.\n'
printf 'HCL Security Framework/IAM is external to this repository and is only detected, not started, by this setup.\n'
