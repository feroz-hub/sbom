#!/usr/bin/env bash
# Canonical Unix status entry point; read-only diagnostics.
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
FRONTEND_PORT=3000
status_failed=0
red=$'\033[31m'; green=$'\033[32m'; yellow=$'\033[33m'; reset=$'\033[0m'
pass() { printf '%sPASS%s %s\n' "$green" "$reset" "$*"; }
warn() { printf '%sWARN%s %s\n' "$yellow" "$reset" "$*" >&2; }
fail_line() { status_failed=1; printf '%sFAIL%s %s\n' "$red" "$reset" "$*"; }
unknown_line() { printf '%sUNKNOWN%s %s\n' "$yellow" "$reset" "$*"; }
dotenv_value_file() {
  local file="$1" wanted="$2"
  [[ -f "$file" ]] || return 0
  awk -F= -v wanted="$wanted" '$1==wanted {sub(/^[^=]*=/, ""); gsub(/"/, ""); gsub(/\047/, ""); print; exit}' "$file" 2>/dev/null |
    sed 's/^["'"'"']//; s/["'"'"']$//' || true
}
normalise_bool() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
resolve_repo_path() {
  local value="$1"
  [[ -z "$value" ]] && return 0
  if [[ "$value" = /* ]]; then printf '%s\n' "$value"; else printf '%s\n' "$REPO_ROOT/$value"; fi
}
port_status() {
  local port="$1" name="$2"
  if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    pass "$name port $port is listening"
  elif ! command -v lsof >/dev/null 2>&1 && command -v ss >/dev/null 2>&1 && ss -ltn "sport = :$port" | tail -n +2 | grep -q .; then
    pass "$name port $port is listening"
  elif ! command -v lsof >/dev/null 2>&1 && ! command -v ss >/dev/null 2>&1; then
    unknown_line "$name port $port could not be checked (install lsof or iproute2/ss)"
    status_failed=1
  else
    fail_line "$name port $port is not listening"
  fi
}
url_status() {
  local url="$1" name="$2" required="$3" insecure="$4" ca_bundle="$5"
  local curl_args=(--fail --silent --show-error --max-time 5)
  [[ "$insecure" == true ]] && curl_args+=(-k)
  [[ -n "$ca_bundle" ]] && curl_args+=(--cacert "$ca_bundle")
  if command -v curl >/dev/null 2>&1 && curl "${curl_args[@]}" "$url" >/dev/null 2>&1; then
    pass "$name $url"
  elif ! command -v curl >/dev/null 2>&1; then
    unknown_line "$name could not be checked (curl is unavailable): $url"
    [[ "$required" == true ]] && status_failed=1
  elif [[ "$required" == true ]]; then
    fail_line "$name unavailable: $url"
  else
    warn "$name unreachable: $url"
  fi
}
printf '\nSBOM Analyser Status\n====================\n'
[[ -f "$REPO_ROOT/.env" ]] && pass '.env present' || fail_line '.env missing'
[[ -f "$REPO_ROOT/frontend/.env.local" ]] && pass 'frontend/.env.local present' || fail_line 'frontend/.env.local missing'
if [[ -x "$VENV_PYTHON" && -f "$REPO_ROOT/.env" ]] && (cd "$REPO_ROOT" && "$VENV_PYTHON" -c 'from app.db import engine; c=engine.connect(); c.close(); engine.dispose()' >/dev/null 2>&1); then
  pass 'database reachable'
else
  fail_line 'database unavailable or .venv missing'
fi

backend_auth="$(normalise_bool "$(dotenv_value_file "$REPO_ROOT/.env" AUTH_ENABLED)")"
frontend_auth="$(normalise_bool "$(dotenv_value_file "$REPO_ROOT/frontend/.env.local" NEXT_PUBLIC_AUTH_ENABLED)")"
[[ "$backend_auth" == true || "$backend_auth" == false ]] || fail_line 'AUTH_ENABLED must be true or false'
[[ "$frontend_auth" == true || "$frontend_auth" == false ]] || fail_line 'NEXT_PUBLIC_AUTH_ENABLED must be true or false'
if [[ "$backend_auth" != "$frontend_auth" ]]; then
  fail_line "authentication configuration is inconsistent: AUTH_ENABLED=$backend_auth, NEXT_PUBLIC_AUTH_ENABLED=$frontend_auth"
fi

port="$(dotenv_value_file "$REPO_ROOT/.env" PORT)"
[[ -n "$port" ]] || port=8000
if [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; then
  backend_url="http://localhost:$port"
  url_status "$backend_url/health" Backend true false ""
  port_status "$port" Backend
else
  fail_line "invalid backend PORT: $port"
fi
if [[ "$frontend_auth" == true ]]; then
  frontend_url=https://localhost:$FRONTEND_PORT
  url_status "$frontend_url" Frontend/admin true true ""
else
  frontend_url=http://localhost:$FRONTEND_PORT
  url_status "$frontend_url" Frontend/admin true false ""
fi
port_status "$FRONTEND_PORT" Frontend

if [[ "$backend_auth" == true ]]; then
  issuer="$(dotenv_value_file "$REPO_ROOT/.env" HCL_IAM_ISSUER)"
  discovery="$(dotenv_value_file "$REPO_ROOT/.env" HCL_IAM_DISCOVERY_URL)"
  if [[ -z "$discovery" ]]; then
    discovery="$(printf '%s' "$issuer" | sed 's:/*$::')/.well-known/openid-configuration"
  fi
  ca_bundle="$(resolve_repo_path "$(dotenv_value_file "$REPO_ROOT/.env" HCL_IAM_CA_BUNDLE)")"
  [[ -n "$issuer" ]] || fail_line 'AUTH_ENABLED=true but HCL_IAM_ISSUER is empty'
  if [[ -n "$ca_bundle" && ! -f "$ca_bundle" ]]; then
    fail_line "HCL_IAM_CA_BUNDLE does not exist: $ca_bundle"
  fi
  [[ -n "$discovery" ]] && url_status "$discovery" 'IAM (external)' false false "$ca_bundle"
else
  warn 'IAM disabled for local development'
fi
printf 'INFO Admin      integrated into the same Next.js frontend; no separate SBOM Admin process\n'
printf 'INFO HCL IAM    external to this repository; not started by setup scripts\n'
exit "$status_failed"
