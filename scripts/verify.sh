#!/usr/bin/env bash
# Run everything CI would run, locally.
#
# Usage:
#   ./scripts/verify.sh              # full check
#   ./scripts/verify.sh --fast       # tests only, no install
#
# Exit code 0 means every gate passed.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || exit 1

BOLD=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD="$(printf '\033[1m')"; RED="$(printf '\033[31m')"
  GREEN="$(printf '\033[32m')"; YELLOW="$(printf '\033[33m')"
  CYAN="$(printf '\033[36m')"; RESET="$(printf '\033[0m')"
fi

FAILED=0
declare -a RESULTS=()

step() { printf '\n%s==>%s %s\n' "$CYAN" "$RESET" "$*"; }
pass() { printf '  %sPASS%s %s\n' "$GREEN" "$RESET" "$*"; RESULTS+=("PASS  $*"); }
fail() { printf '  %sFAIL%s %s\n' "$RED" "$RESET" "$*"; RESULTS+=("FAIL  $*"); FAILED=$((FAILED+1)); }
skip() { printf '  %sSKIP%s %s\n' "$YELLOW" "$RESET" "$*"; RESULTS+=("SKIP  $*"); }

FAST=0
for arg in "$@"; do
  case "$arg" in
    --fast) FAST=1 ;;
    -h|--help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- python ----
step "Locating Python"
PYTHON=""
# Prefer the project venv so a `./install.sh --venv` setup is reused.
for candidate in "$REPO_ROOT/.venv/bin/python" "$REPO_ROOT/.venv/Scripts/python.exe" python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
      PYTHON="$candidate"; break
    fi
  fi
done
if [ -z "$PYTHON" ]; then
  fail "Python 3.8+ not found"
  printf '\n%sAborting: cannot run any checks.%s\n' "$RED" "$RESET"
  exit 1
fi
pass "python: $("$PYTHON" --version 2>&1)"

# ----------------------------------------------------------- dependencies ----
if [ "$FAST" -eq 0 ]; then
  step "Installing test dependencies"
  if "$PYTHON" -m pip install -q -e ".[dev]" 2>/dev/null; then
    pass "pip install -e .[dev]"
  else
    # Fall back to the minimum needed to run the suite.
    if "$PYTHON" -m pip install -q dnspython pytest 2>/dev/null; then
      pass "pip install dnspython pytest (editable install unavailable)"
    else
      fail "could not install test dependencies"
    fi
  fi
else
  step "Installing test dependencies"
  skip "--fast requested"
fi

# ------------------------------------------------------------------ tests ----
step "Running the test suite"
if "$PYTHON" -m pytest -q 2>&1 | tail -3; then
  pass "pytest"
else
  fail "pytest"
fi

# -------------------------------------------------------------------- CLI ----
step "Verifying the CLI entrypoint"
if "$PYTHON" -m fullrecon --version >/dev/null 2>&1; then
  pass "fullrecon --version"
else
  fail "fullrecon --version"
fi

if "$PYTHON" -m fullrecon --list-modules >/dev/null 2>&1; then
  pass "fullrecon --list-modules"
else
  fail "fullrecon --list-modules"
fi

# Every module must import; a syntax error in an unreferenced module would
# otherwise only surface at scan time.
step "Importing every module"
if "$PYTHON" - <<'PYEOF'
import importlib
import pathlib
import sys

failed = []
for path in sorted(pathlib.Path("fullrecon").rglob("*.py")):
    if path.name == "__init__.py":
        continue
    name = ".".join(path.with_suffix("").parts)
    try:
        importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001
        failed.append(f"{name}: {type(exc).__name__}: {exc}")

for entry in failed:
    print(f"  import failed: {entry}", file=sys.stderr)
raise SystemExit(1 if failed else 0)
PYEOF
then
  pass "all modules import"
else
  fail "module import errors"
fi

# ------------------------------------------------------------------- YAML ----
step "Validating the CI workflow (if present)"
if [ -f .github/workflows/tests.yml ]; then
  if "$PYTHON" -c "import yaml,sys; yaml.safe_load(open('.github/workflows/tests.yml',encoding='utf-8'))" 2>/dev/null; then
    pass ".github/workflows/tests.yml parses"
  elif "$PYTHON" -c "import yaml" 2>/dev/null; then
    fail ".github/workflows/tests.yml is invalid YAML"
  else
    skip "pyyaml not installed - cannot validate workflow YAML"
  fi
else
  skip "no workflow file"
fi

# ------------------------------------------------------------------ scope ----
step "Checking scope enforcement still blocks third parties"
if "$PYTHON" - <<'PYEOF'
from fullrecon.core.scope import Scope
scope = Scope("example.com", out_of_scope=["dev.example.com"])
checks = [
    ("example.com", True),
    ("a.example.com", True),
    ("evil.com", False),
    ("example.com.evil.com", False),
    ("dev.example.com", False),
]
bad = [(h, want, scope.allows_host(h).allowed) for h, want in checks
       if scope.allows_host(h).allowed is not want]
for host, want, got in bad:
    print(f"  scope regression: {host} expected {want} got {got}")
raise SystemExit(1 if bad else 0)
PYEOF
then
  pass "scope guard behaviour"
else
  fail "scope guard regression"
fi

# ---------------------------------------------------------------- summary ----
printf '\n%s\n' "${BOLD}────────────────────────────────────────────────${RESET}"
for line in "${RESULTS[@]}"; do
  case "$line" in
    PASS*) printf ' %s%s%s\n' "$GREEN" "$line" "$RESET" ;;
    FAIL*) printf ' %s%s%s\n' "$RED" "$line" "$RESET" ;;
    *)     printf ' %s%s%s\n' "$YELLOW" "$line" "$RESET" ;;
  esac
done
printf '%s\n' "${BOLD}────────────────────────────────────────────────${RESET}"

if [ "$FAILED" -eq 0 ]; then
  printf '\n%s%sAll checks passed.%s\n\n' "$BOLD" "$GREEN" "$RESET"
  exit 0
fi

printf '\n%s%s%d check(s) failed.%s\n\n' "$BOLD" "$RED" "$FAILED" "$RESET"
exit 1
