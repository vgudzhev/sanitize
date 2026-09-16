#!/usr/bin/env bash
# Local development runner for pi-scrub.
#
# Starts the `sanitize` detection service (with auto-reload) in the background,
# waits until it reports healthy, then prints how to run pi with the extension
# loaded. Ctrl-C stops the service.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SANITIZE_DIR="$ROOT_DIR/sanitize"
EXTENSION_DIR="$ROOT_DIR/extension"
VENV_DIR="$SANITIZE_DIR/.venv"

SANITIZE_HOST="${SANITIZE_HOST:-127.0.0.1}"
SANITIZE_PORT="${SANITIZE_PORT:-7411}"
HEALTH_URL="http://${SANITIZE_HOST}:${SANITIZE_PORT}/v1/health"
HEALTH_RETRIES="${HEALTH_RETRIES:-30}"   # attempts
HEALTH_INTERVAL="${HEALTH_INTERVAL:-1}"  # seconds between attempts

MIN_PY_MAJOR=3
MIN_PY_MINOR=12

SANITIZE_PID=""

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BOLD=""; RESET=""
fi

info()  { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$*"; }
ok()    { printf '%s[ok]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s[warn]%s %s\n' "$YELLOW" "$RESET" "$*"; }
error() { printf '%s[error]%s %s\n' "$RED" "$RESET" "$*" >&2; }
die()   { error "$@"; exit 1; }

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -n "$SANITIZE_PID" ]] && kill -0 "$SANITIZE_PID" 2>/dev/null; then
    printf '\n'
    info "Stopping sanitize (pid $SANITIZE_PID)"
    # uvicorn's --reload supervisor forwards SIGTERM to its worker.
    kill -TERM "$SANITIZE_PID" 2>/dev/null || true
    wait "$SANITIZE_PID" 2>/dev/null || true
    ok "sanitize stopped"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
check_prereqs() {
  info "Checking prerequisites"

  if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    error "sanitize virtualenv not found at $VENV_DIR"
    die "Run the one-time setup first: $SCRIPT_DIR/install.sh"
  fi

  local major minor
  read -r major minor < <("$VENV_DIR/bin/python" -c 'import sys; print(sys.version_info[0], sys.version_info[1])')
  if (( major < MIN_PY_MAJOR || (major == MIN_PY_MAJOR && minor < MIN_PY_MINOR) )); then
    die "Virtualenv Python is ${major}.${minor}; ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ is required. Delete $VENV_DIR and re-run install.sh."
  fi
  ok "Python: $("$VENV_DIR/bin/python" --version 2>&1) (venv)"

  if ! command -v node >/dev/null 2>&1; then
    die "Node.js is required but 'node' was not found on PATH."
  fi
  ok "Node.js: $(node --version)"

  if [[ ! -x "$VENV_DIR/bin/uvicorn" ]]; then
    die "uvicorn not found in $VENV_DIR. Re-run $SCRIPT_DIR/install.sh"
  fi

  if [[ ! -d "$EXTENSION_DIR/node_modules" ]]; then
    warn "extension/node_modules is missing; run $SCRIPT_DIR/install.sh to install extension dependencies."
  fi

  if ! command -v curl >/dev/null 2>&1; then
    die "curl is required for the health check but was not found on PATH."
  fi
}

# ---------------------------------------------------------------------------
# sanitize service
# ---------------------------------------------------------------------------
is_healthy() {
  curl --silent --fail --max-time 2 "$HEALTH_URL" >/dev/null 2>&1
}

start_sanitize() {
  if is_healthy; then
    warn "Something is already answering at $HEALTH_URL; not starting a second sanitize instance."
    warn "Stop it first if you want this script to manage the service."
    return 0
  fi

  info "Starting sanitize on ${SANITIZE_HOST}:${SANITIZE_PORT} (auto-reload enabled)"
  (
    cd "$SANITIZE_DIR"
    exec "$VENV_DIR/bin/uvicorn" sanitize.app:app \
      --host "$SANITIZE_HOST" --port "$SANITIZE_PORT" --reload
  ) &
  SANITIZE_PID=$!
  ok "sanitize started (pid $SANITIZE_PID)"
}

wait_for_health() {
  info "Waiting for $HEALTH_URL"
  local attempt
  for (( attempt = 1; attempt <= HEALTH_RETRIES; attempt++ )); do
    if is_healthy; then
      ok "sanitize is healthy: $(curl --silent --max-time 2 "$HEALTH_URL")"
      return 0
    fi
    if [[ -n "$SANITIZE_PID" ]] && ! kill -0 "$SANITIZE_PID" 2>/dev/null; then
      die "sanitize exited before becoming healthy; see output above."
    fi
    sleep "$HEALTH_INTERVAL"
  done
  die "sanitize did not become healthy after $((HEALTH_RETRIES * HEALTH_INTERVAL))s."
}

# ---------------------------------------------------------------------------
print_instructions() {
  printf '\n%s%s[ready]%s sanitize is running at http://%s:%s%s\n\n' \
    "$BOLD" "$GREEN" "$RESET$BOLD" "$SANITIZE_HOST" "$SANITIZE_PORT" "$RESET"
  cat <<EOF
Run pi with the extension loaded (in another terminal):

  Option A - load directly for this session:
    pi -e "$EXTENSION_DIR/src/index.ts"

  Option B - link once, then start pi as usual:
    mkdir -p ~/.pi/agent/extensions/pi-scrub
    ln -sf "$EXTENSION_DIR/src/index.ts" ~/.pi/agent/extensions/pi-scrub/
    pi

Inside pi:
  /sanitize status         check service health and redaction count
  /sanitize test <text>    try detection on any text

Test detection directly:
  curl -s -X POST http://${SANITIZE_HOST}:${SANITIZE_PORT}/v1/detect \\
    -H 'Content-Type: application/json' \\
    -d '{"text": "key AKIAIOSFODNN7EXAMPLE, email alice@corp.com"}'

Edits under sanitize/ reload automatically. Press Ctrl-C to stop.
EOF
}

main() {
  check_prereqs
  start_sanitize
  wait_for_health
  print_instructions

  if [[ -n "$SANITIZE_PID" ]]; then
    # Block until sanitize exits (or we receive SIGINT/SIGTERM).
    wait "$SANITIZE_PID"
  fi
}

main "$@"
