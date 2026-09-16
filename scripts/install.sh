#!/usr/bin/env bash
# One-time setup for pi-scrub: Python venv for `sanitize`, npm deps for the
# pi extension, then a test run of both to verify the install.
# Safe to re-run; every step is idempotent.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SANITIZE_DIR="$ROOT_DIR/sanitize"
EXTENSION_DIR="$ROOT_DIR/extension"
VENV_DIR="$SANITIZE_DIR/.venv"

MIN_PY_MAJOR=3
MIN_PY_MINOR=12
MIN_NODE_MAJOR=18

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
# Prerequisite checks
# ---------------------------------------------------------------------------
# Find a Python interpreter >= 3.12. Prefers a version-specific binary so a
# system `python3` that is too old does not block the install.
find_python() {
  local candidate major minor
  for candidate in python3.14 python3.13 python3.12 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      read -r major minor < <("$candidate" -c 'import sys; print(sys.version_info[0], sys.version_info[1])' 2>/dev/null) || continue
      if (( major > MIN_PY_MAJOR || (major == MIN_PY_MAJOR && minor >= MIN_PY_MINOR) )); then
        printf '%s' "$candidate"
        return 0
      fi
    fi
  done
  return 1
}

check_prereqs() {
  info "Checking prerequisites"

  if ! PYTHON="$(find_python)"; then
    die "Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ is required but was not found on PATH."
  fi
  ok "Python: $("$PYTHON" --version 2>&1) ($(command -v "$PYTHON"))"

  if ! command -v node >/dev/null 2>&1; then
    die "Node.js ${MIN_NODE_MAJOR}+ is required but 'node' was not found on PATH."
  fi
  local node_version node_major
  node_version="$(node --version)"          # e.g. v22.1.0
  node_major="${node_version#v}"; node_major="${node_major%%.*}"
  if (( node_major < MIN_NODE_MAJOR )); then
    die "Node.js ${MIN_NODE_MAJOR}+ is required, found ${node_version}."
  fi
  ok "Node.js: ${node_version}"

  if ! command -v npm >/dev/null 2>&1; then
    die "npm is required but was not found on PATH."
  fi
  ok "npm: $(npm --version)"
}

# ---------------------------------------------------------------------------
# sanitize (Python)
# ---------------------------------------------------------------------------
setup_sanitize() {
  info "Setting up sanitize (Python) in $SANITIZE_DIR"

  if [[ -x "$VENV_DIR/bin/python" ]]; then
    ok "Virtualenv already exists at $VENV_DIR"
  else
    "$PYTHON" -m venv "$VENV_DIR"
    ok "Created virtualenv at $VENV_DIR"
  fi

  local venv_python="$VENV_DIR/bin/python"
  "$venv_python" -m pip install --quiet --upgrade pip
  # Editable install with dev extras (pytest etc.), as declared in pyproject.toml.
  (cd "$SANITIZE_DIR" && "$venv_python" -m pip install --quiet -e ".[dev]")
  ok "Installed sanitize package and dev dependencies"

  # Presidio's NER recognizers need a spaCy model. Pattern-based detection
  # works without it, so a failure here is a warning rather than an error.
  if "$venv_python" -c 'import spacy, en_core_web_sm' >/dev/null 2>&1; then
    ok "spaCy model en_core_web_sm already installed"
  elif "$venv_python" -m spacy download en_core_web_sm >/dev/null 2>&1; then
    ok "Downloaded spaCy model en_core_web_sm"
  else
    warn "Could not download spaCy model en_core_web_sm; Presidio NER recognizers will be unavailable."
    warn "Retry later with: $venv_python -m spacy download en_core_web_sm"
  fi
}

# ---------------------------------------------------------------------------
# extension (TypeScript)
# ---------------------------------------------------------------------------
setup_extension() {
  info "Setting up extension (Node) in $EXTENSION_DIR"
  (cd "$EXTENSION_DIR" && npm install --no-audit --no-fund)
  ok "Installed extension dependencies"
}

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
run_tests() {
  info "Running sanitize tests"
  if [[ -d "$SANITIZE_DIR/tests" ]]; then
    (cd "$SANITIZE_DIR" && "$VENV_DIR/bin/python" -m pytest tests/ -x -q)
    ok "sanitize tests passed"
  else
    warn "No sanitize/tests directory found; skipping Python tests"
  fi

  info "Running extension tests"
  (cd "$EXTENSION_DIR" && npm test --silent)
  ok "extension tests passed"
}

# ---------------------------------------------------------------------------
main() {
  check_prereqs
  setup_sanitize
  setup_extension
  run_tests

  printf '\n%s%s[success]%s pi-scrub is installed.%s\n\n' "$BOLD" "$GREEN" "$RESET$BOLD" "$RESET"
  cat <<EOF
Next steps:

  1. Start the detection service and follow the on-screen pi instructions:
       $SCRIPT_DIR/dev.sh

  2. Or link the extension into pi manually (one time):
       mkdir -p ~/.pi/agent/extensions/pi-scrub
       ln -sf "$EXTENSION_DIR/src/index.ts" ~/.pi/agent/extensions/pi-scrub/

  3. Optional: enable GLiNER for person/org/address detection:
       $VENV_DIR/bin/pip install -e "$SANITIZE_DIR[gliner]"

Docs: $ROOT_DIR/docs/quickstart.md
EOF
}

main "$@"
