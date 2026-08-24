#!/usr/bin/env bash
# Canonical daily Unix startup. Only the run recorded in .sbom-dev/state.tsv
# can be stopped by setup/unix/stop.sh.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
umask 077
VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
STATE_DIR="$REPO_ROOT/.sbom-dev"
STATE_FILE="$STATE_DIR/state.tsv"
LOG_DIR="$STATE_DIR/logs"
FRONTEND_ROOT="$REPO_ROOT/frontend"
FRONTEND_PORT=3000
red=$'\033[31m'; green=$'\033[32m'; yellow=$'\033[33m'; reset=$'\033[0m'
fail() { printf '%sFAIL%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }
pass() { printf '%sPASS%s %s\n' "$green" "$reset" "$*"; }
dotenv_value_file() {
  local file="$1" wanted="$2"
  [[ -f "$file" ]] || return 0
  awk -F= -v wanted="$wanted" '$1==wanted {sub(/^[^=]*=/, ""); gsub(/"/, ""); gsub(/\047/, ""); print; exit}' "$file" 2>/dev/null |
    sed 's/^["'"'"']//; s/["'"'"']$//' || true
}
normalise_bool() { printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'; }
port_busy() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v ss >/dev/null 2>&1; then
    ss -ltn "sport = :$port" | tail -n +2 | grep -q .
  else
    return 1
  fi
}
process_start_time() { ps -o lstart= -p "$1" 2>/dev/null | sed 's/^ *//'; }
process_comm() { ps -o comm= -p "$1" 2>/dev/null | sed 's/^ *//; s/ *$//'; }
process_pgid() { ps -o pgid= -p "$1" 2>/dev/null | tr -d ' '; }
process_command() { ps -o args= -p "$1" 2>/dev/null | sed 's/^ *//'; }
pid_alive() { [[ "$1" =~ ^[1-9][0-9]*$ ]] && kill -0 "$1" >/dev/null 2>&1; }
identity_matches() {
  local pid="$1" start="$2" comm="$3" marker="$4"
  pid_alive "$pid" || return 1
  [[ "$(process_start_time "$pid")" == "$start" ]] || return 1
  [[ "$(process_comm "$pid")" == "$comm" ]] || return 1
  [[ "$(process_command "$pid")" == *"$marker"* ]] || return 1
}
record_process() {
  local run_id="$1" name="$2" pid="$3" marker="$4" start comm pgid command
  sleep 0.2
  start="$(process_start_time "$pid")"
  comm="$(process_comm "$pid")"
  pgid="$(process_pgid "$pid")"
  command="$(process_command "$pid")"
  [[ -n "$start" && -n "$comm" && "$pgid" =~ ^[1-9][0-9]*$ && "$command" == *"$marker"* ]] || fail "Unable to validate the $name process identity after launch."
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$run_id" "$name" "$pid" "$start" "$comm" "$pgid" "$marker"
}
cleanup_candidate() {
  local pid="$1" marker="$2" start comm pgid
  pid_alive "$pid" || return 0
  start="$(process_start_time "$pid")"
  comm="$(process_comm "$pid")"
  pgid="$(process_pgid "$pid")"
  [[ -n "$start" && -n "$comm" && "$pgid" =~ ^[1-9][0-9]*$ ]] || return 0
  terminate_record "$pid" "$start" "$comm" "$pgid" "$marker"
}
send_tree_signal() {
  local pid="$1" signal="$2" child
  if command -v pgrep >/dev/null 2>&1; then
    while read -r child; do
      [[ -n "$child" ]] && send_tree_signal "$child" "$signal"
    done < <(pgrep -P "$pid" 2>/dev/null || true)
  fi
  kill "-$signal" "$pid" 2>/dev/null || true
}
terminate_record() {
  local pid="$1" start="$2" comm="$3" pgid="$4" marker="$5" current_pgid
  identity_matches "$pid" "$start" "$comm" "$marker" || return 0
  current_pgid="$(process_pgid "$$")"
  if [[ "$pgid" == "$pid" && "$pgid" != "$current_pgid" ]]; then
    kill -TERM -- "-$pgid" 2>/dev/null || true
    for ((waited=0; waited<10; waited++)); do
      pid_alive "$pid" || return 0
      sleep 1
    done
    identity_matches "$pid" "$start" "$comm" "$marker" && kill -KILL -- "-$pgid" 2>/dev/null || true
  else
    send_tree_signal "$pid" TERM
    for ((waited=0; waited<10; waited++)); do
      pid_alive "$pid" || return 0
      sleep 1
    done
    identity_matches "$pid" "$start" "$comm" "$marker" && send_tree_signal "$pid" KILL
  fi
}
cleanup_records() {
  local run_id name pid start comm pgid marker
  while IFS=$'\t' read -r run_id name pid start comm pgid marker; do
    [[ -n "$pid" ]] || continue
    terminate_record "$pid" "$start" "$comm" "$pgid" "$marker"
  done
  rm -f "$STATE_FILE"
}
compose_database_matches() {
  local database_url="$1" expected_port
  expected_port="$(dotenv_value_file "$REPO_ROOT/.env" POSTGRES_PORT)"
  [[ -n "$expected_port" ]] || expected_port=55439
  DATABASE_URL="$database_url" EXPECTED_POSTGRES_PORT="$expected_port" \
    "$VENV_PYTHON" - <<'PY'
import os
from sqlalchemy.engine import make_url
try:
    url = make_url(os.environ["DATABASE_URL"])
    match = (
        url.get_backend_name().startswith("postgresql")
        and (url.host or "localhost") in {"localhost", "127.0.0.1", "::1"}
        and (url.port or 5432) == int(os.environ["EXPECTED_POSTGRES_PORT"])
        and (url.database or "") == "sbom_analyser"
        and (url.username or "") == "sbom"
        and (url.password or "") == "sbom"
    )
except Exception:
    match = False
print("true" if match else "false")
PY
}

[[ -x "$VENV_PYTHON" ]] || fail "Missing .venv. Run ./setup/unix/setup.sh first."
[[ -f "$REPO_ROOT/.env" ]] || fail "Missing .env. Run ./setup/unix/setup.sh first."
[[ -f "$FRONTEND_ROOT/.env.local" ]] || fail "Missing frontend/.env.local. Run ./setup/unix/setup.sh first."
backend_auth="$(normalise_bool "$(dotenv_value_file "$REPO_ROOT/.env" AUTH_ENABLED)")"
frontend_auth="$(normalise_bool "$(dotenv_value_file "$FRONTEND_ROOT/.env.local" NEXT_PUBLIC_AUTH_ENABLED)")"
[[ "$backend_auth" == true || "$backend_auth" == false ]] || fail "AUTH_ENABLED must be true or false in .env."
[[ "$frontend_auth" == true || "$frontend_auth" == false ]] || fail "NEXT_PUBLIC_AUTH_ENABLED must be true or false in frontend/.env.local."
[[ "$backend_auth" == "$frontend_auth" ]] || fail "Authentication configuration is inconsistent: AUTH_ENABLED=$backend_auth, NEXT_PUBLIC_AUTH_ENABLED=$frontend_auth. Update both files explicitly."

database_url="$(cd "$REPO_ROOT" && "$VENV_PYTHON" -c 'from dotenv import dotenv_values; print(dotenv_values(".env").get("DATABASE_URL", ""))')"
[[ -n "$database_url" ]] || fail "DATABASE_URL is missing from .env."
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 && [[ "$(compose_database_matches "$database_url")" == true ]]; then
  (cd "$REPO_ROOT" && docker compose up -d postgres) || fail "Configured repository PostgreSQL could not be started."
fi
mkdir -p "$STATE_DIR" "$LOG_DIR"
if ! "$VENV_PYTHON" -c 'from app.db import engine; c=engine.connect(); c.close(); engine.dispose()' >"$LOG_DIR/database-check.log" 2>&1; then
  fail "Database is not reachable. See .sbom-dev/logs/database-check.log or run ./setup/unix/status.sh."
fi

host="$(dotenv_value_file "$REPO_ROOT/.env" HOST)"
[[ -n "$host" ]] || host=127.0.0.1
port="$(dotenv_value_file "$REPO_ROOT/.env" PORT)"
[[ -n "$port" ]] || port=8000
[[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] || fail "PORT must be a valid TCP port in .env."
port_busy "$port" && fail "Port $port is already in use. Stop the existing SBOM API first."
port_busy "$FRONTEND_PORT" && fail "Port $FRONTEND_PORT is already in use. Stop the existing SBOM frontend first."

if [[ "$frontend_auth" == true ]]; then
  frontend_command=dev:https
  frontend_url=https://localhost:$FRONTEND_PORT
  [[ -f "$FRONTEND_ROOT/certificates/localhost.pem" && -f "$FRONTEND_ROOT/certificates/localhost-key.pem" ]] || fail "Authenticated mode requires both frontend HTTPS certificate files. Run ./setup/unix/setup.sh."
  frontend_curl_args=(-k)
else
  frontend_command=dev
  frontend_url=http://localhost:$FRONTEND_PORT
  frontend_curl_args=()
fi
backend_url=http://localhost:$port
export NEXT_PUBLIC_API_URL="$backend_url"
export SBOM_API_URL="$backend_url"
if [[ -e "$STATE_FILE" ]]; then
  [[ -f "$STATE_FILE" ]] || fail "Invalid SBOM state path: $STATE_FILE"
  state_lines=0
  while IFS=$'\t' read -r old_run old_name old_pid old_start old_comm old_pgid old_marker extra; do
    state_lines=$((state_lines + 1))
    [[ -z "$extra" && -n "$old_run" && -n "$old_name" && "$old_pid" =~ ^[1-9][0-9]*$ && -n "$old_start" && -n "$old_comm" && "$old_pgid" =~ ^[1-9][0-9]*$ && -n "$old_marker" ]] || fail "Malformed SBOM state. Run setup/unix/stop.sh after reviewing $STATE_FILE."
    if identity_matches "$old_pid" "$old_start" "$old_comm" "$old_marker"; then
      fail "SBOM $old_name is already running (PID $old_pid)."
    fi
  done < "$STATE_FILE"
  (( state_lines > 0 )) || fail "SBOM state is empty or malformed. Run setup/unix/stop.sh after reviewing $STATE_FILE."
  rm -f "$STATE_FILE"
fi

run_id="$(date +%s)-$$-$RANDOM"
if command -v setsid >/dev/null 2>&1; then
  (cd "$REPO_ROOT" && exec setsid "$VENV_PYTHON" -m uvicorn app.main:app --host "$host" --port "$port" --reload >"$LOG_DIR/backend.log" 2>&1) &
else
  (cd "$REPO_ROOT" && exec nohup "$VENV_PYTHON" -m uvicorn app.main:app --host "$host" --port "$port" --reload >"$LOG_DIR/backend.log" 2>&1) &
fi
backend_pid=$!
if command -v setsid >/dev/null 2>&1; then
  (cd "$FRONTEND_ROOT" && exec setsid npm run "$frontend_command" >"$LOG_DIR/frontend.log" 2>&1) &
else
  (cd "$FRONTEND_ROOT" && exec nohup npm run "$frontend_command" >"$LOG_DIR/frontend.log" 2>&1) &
fi
frontend_pid=$!
backend_record="$(record_process "$run_id" backend "$backend_pid" "-m uvicorn app.main:app")" || {
  cleanup_candidate "$backend_pid" "-m uvicorn app.main:app"
  cleanup_candidate "$frontend_pid" "npm run $frontend_command"
  fail "Unable to validate backend process ownership after launch. Inspect $LOG_DIR/backend.log."
}
frontend_record="$(record_process "$run_id" frontend "$frontend_pid" "npm run $frontend_command")" || {
  cleanup_candidate "$frontend_pid" "npm run $frontend_command"
  printf '%s\n' "$backend_record" | cleanup_records
  fail "Unable to validate frontend process ownership after launch. Inspect $LOG_DIR/frontend.log."
}
tmp_state="$STATE_FILE.tmp.$$"
printf '%s\n%s\n' "$backend_record" "$frontend_record" >"$tmp_state"
mv -f "$tmp_state" "$STATE_FILE"

ready=0
for ((attempt=1; attempt<=60; attempt++)); do
  if ! identity_matches "$backend_pid" "$(printf '%s' "$backend_record" | awk -F '\t' '{print $4}')" "$(printf '%s' "$backend_record" | awk -F '\t' '{print $5}')" "-m uvicorn app.main:app"; then
    cleanup_records < "$STATE_FILE"
    fail "Backend exited during startup; inspect $LOG_DIR/backend.log."
  fi
  if ! identity_matches "$frontend_pid" "$(printf '%s' "$frontend_record" | awk -F '\t' '{print $4}')" "$(printf '%s' "$frontend_record" | awk -F '\t' '{print $5}')" "npm run $frontend_command"; then
    cleanup_records < "$STATE_FILE"
    fail "Frontend exited during startup; inspect $LOG_DIR/frontend.log."
  fi
  backend_ready=0
  frontend_ready=0
  if curl --fail --silent --show-error --max-time 2 "$backend_url/health" >/dev/null 2>&1; then backend_ready=1; fi
  if curl --fail --silent --show-error --max-time 2 "${frontend_curl_args[@]}" "$frontend_url" >/dev/null 2>&1; then frontend_ready=1; fi
  if (( backend_ready == 1 && frontend_ready == 1 )); then ready=1; break; fi
  sleep 1
done
if (( ready == 0 )); then
  cleanup_records < "$STATE_FILE"
  fail "SBOM services did not become ready within 60 seconds. Inspect $LOG_DIR/backend.log and $LOG_DIR/frontend.log."
fi

printf '\nSBOM Analyser Startup\n---------------------\n'
if [[ "$backend_auth" == true ]]; then printf 'IAM        : EXTERNAL\n'; else printf 'IAM        : DISABLED\n'; fi
printf 'Database   : READY\nBackend    : READY (%s)\nFrontend   : READY (%s)\n' "$backend_url" "$frontend_url"
printf 'Admin      : integrated in the frontend (same URL)\n'
printf 'HCL IAM    : external dependency; this script does not start Security Framework\n'
