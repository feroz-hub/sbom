#!/usr/bin/env bash
# Canonical Unix stop entry point. It stops only validated process records
# created by setup/unix/start.sh.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
STATE_FILE="$REPO_ROOT/.sbom-dev/state.tsv"
red=$'\033[31m'; green=$'\033[32m'; yellow=$'\033[33m'; reset=$'\033[0m'
pass() { printf '%sPASS%s %s\n' "$green" "$reset" "$*"; }
warn() { printf '%sWARN%s %s\n' "$yellow" "$reset" "$*" >&2; }
fail() { printf '%sFAIL%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }
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

[[ -e "$STATE_FILE" ]] || { printf 'No SBOM processes tracked by setup/unix/start.sh.\n'; exit 0; }
[[ -f "$STATE_FILE" ]] || fail "Invalid SBOM state path: $STATE_FILE"
first_run=""
malformed=0
state_lines=0
while IFS=$'\t' read -r run_id name pid start comm pgid marker extra; do
  state_lines=$((state_lines + 1))
  [[ -z "$extra" && -n "$run_id" && -n "$name" && "$pid" =~ ^[1-9][0-9]*$ && -n "$start" && -n "$comm" && "$pgid" =~ ^[1-9][0-9]*$ && -n "$marker" ]] || { malformed=1; continue; }
  [[ "$name" == backend || "$name" == frontend ]] || { malformed=1; continue; }
  if [[ -z "$first_run" ]]; then first_run="$run_id"; fi
  [[ "$run_id" == "$first_run" ]] || { malformed=1; continue; }
  if identity_matches "$pid" "$start" "$comm" "$marker"; then
    printf 'Stopping validated %s process (PID %s, run %s)\n' "$name" "$pid" "$run_id"
    terminate_record "$pid" "$start" "$comm" "$pgid" "$marker"
  else
    warn "Ignoring stale or mismatched $name record (PID $pid); no process was terminated."
  fi
done < "$STATE_FILE"
if (( malformed == 1 || state_lines == 0 )); then
  fail "Malformed SBOM state was rejected; state was preserved for inspection: $STATE_FILE"
fi
rm -f "$STATE_FILE"
pass "Stopped validated SBOM development processes. PostgreSQL and external HCL IAM were left running."
