#!/usr/bin/env bash
# FullRecon installer for Kali / Ubuntu / Debian / other Linux distributions.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh              # user install (pipx or pip --user)
#   sudo ./install.sh         # system-wide install into /usr/local/bin
#   ./install.sh --venv       # install into ./.venv next to the source
#
# The script is idempotent: re-running it upgrades the existing install.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

BOLD=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD="$(printf '\033[1m')"; RED="$(printf '\033[31m')"
  GREEN="$(printf '\033[32m')"; YELLOW="$(printf '\033[33m')"
  CYAN="$(printf '\033[36m')"; RESET="$(printf '\033[0m')"
fi

info()  { printf '%s[*]%s %s\n' "$CYAN" "$RESET" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; }
fail()  { printf '%s[x]%s %s\n' "$RED" "$RESET" "$*"; }
die()   { fail "$*"; exit 1; }

MODE="user"
for arg in "$@"; do
  case "$arg" in
    --venv)     MODE="venv" ;;
    --user)     MODE="user" ;;
    --system)   MODE="system" ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "unknown option: $arg" ;;
  esac
done

if [ "$(id -u)" -eq 0 ] && [ "$MODE" = "user" ]; then
  MODE="system"
fi

printf '%s\n' "${BOLD}${CYAN}"
cat <<'BANNER'
  ______      _ _ ____
 |  ____|    | | |  _ \
 | |__ _   _ | | | |_) |___  ___ ___  _ __
 |  __| | | || | |  _ < _ \/ __/ _ \| '_ \
 | |  | |_| || | | |_) |  __/ (_| (_) | | | |
 |_|   \__,_|_|_|____/ \___|\___\___/|_| |_|
BANNER
printf '%s\n' "${RESET}"
info "installer mode: $MODE"

# ---------------------------------------------------------------- Python ----
info "checking Python..."
PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
      PYTHON="$candidate"
      break
    fi
  fi
done

if [ -z "$PYTHON" ]; then
  warn "Python 3.8+ not found."
  if command -v apt-get >/dev/null 2>&1; then
    info "attempting: apt-get install -y python3 python3-pip python3-venv"
    SUDO=""
    [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
    $SUDO apt-get update -qq && $SUDO apt-get install -y python3 python3-pip python3-venv || true
    PYTHON="$(command -v python3 || true)"
  fi
fi
[ -n "$PYTHON" ] || die "Python 3.8+ is required. Install it and re-run this script."
ok "python: $($PYTHON --version 2>&1) ($(command -v "$PYTHON"))"

if ! "$PYTHON" -c 'import venv' 2>/dev/null; then
  warn "python3-venv module missing"
  if command -v apt-get >/dev/null 2>&1; then
    SUDO=""
    [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
    $SUDO apt-get install -y python3-venv || true
  fi
fi

# ------------------------------------------------------------------ pip ----
info "checking pip..."
PIP_OK=0
if "$PYTHON" -m pip --version >/dev/null 2>&1; then
  PIP_OK=1
else
  warn "system pip missing for $PYTHON - trying ensurepip"
  # ensurepip ships with CPython and works without network access.
  if "$PYTHON" -m ensurepip --upgrade >/dev/null 2>&1 && "$PYTHON" -m pip --version >/dev/null 2>&1; then
    PIP_OK=1
  fi
fi

if [ "$PIP_OK" -eq 0 ] && [ "$MODE" != "venv" ]; then
  warn "attempting to install python3-pip with apt-get"
  if command -v apt-get >/dev/null 2>&1; then
    SUDO=""
    [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-pip >/dev/null 2>&1 || true
  fi
  if "$PYTHON" -m pip --version >/dev/null 2>&1; then
    PIP_OK=1
  fi
fi

if [ "$PIP_OK" -eq 0 ] && [ "$MODE" = "venv" ]; then
  info "venv mode: pip will be bootstrapped inside the virtual environment"
fi

if [ "$PIP_OK" -eq 0 ] && [ "$MODE" != "venv" ]; then
  die "pip is required. Install it with: sudo apt-get install -y python3-pip"
fi

if [ "$PIP_OK" -eq 1 ]; then
  ok "pip: $("$PYTHON" -m pip --version 2>&1 | cut -d' ' -f1-2)"
fi

# ------------------------------------------------------------ install ----
PIP_ARGS=(--upgrade --quiet)

case "$MODE" in
  venv)
    info "creating virtual environment at ./.venv"
    rm -rf .venv
    if ! "$PYTHON" -m venv .venv >/tmp/fullrecon-venv.log 2>&1; then
      warn "venv creation failed - installing python3-venv"
      if command -v apt-get >/dev/null 2>&1; then
        SUDO=""
        [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
        VENV_PKG="python3-venv"
        # Try the version-specific package first (Debian/Ubuntu name it that way).
        VER_PKG="$("$PYTHON" -c 'import sys; print(f"python3.{sys.version_info.minor}-venv")' 2>/dev/null || true)"
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
        if [ -n "$VER_PKG" ]; then
          $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$VER_PKG" >/dev/null 2>&1 || true
        fi
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$VENV_PKG" >/dev/null 2>&1 || true
      fi
      rm -rf .venv
      if ! "$PYTHON" -m venv .venv >/tmp/fullrecon-venv.log 2>&1; then
        fail "could not create a virtual environment"
        sed 's/^/    /' /tmp/fullrecon-venv.log 2>/dev/null | head -10
        printf '\n    Install the venv package, then re-run:\n'
        printf '      sudo apt-get install -y python3-venv\n'
        printf '    Or use a user install instead:\n'
        printf '      ./install.sh --user\n\n'
        exit 1
      fi
    fi
    VENV_PY=".venv/bin/python"
    [ -x "$VENV_PY" ] || VENV_PY=".venv/Scripts/python.exe"
    [ -x "$VENV_PY" ] || die "virtual environment python not found"
    info "installing FullRecon into ./.venv"
    "$VENV_PY" -m pip install "${PIP_ARGS[@]}" -e . || die "pip install failed"
    BIN_DIR="$SCRIPT_DIR/.venv/bin"
    ok "installed into $SCRIPT_DIR/.venv"
    ;;
  system)
    info "installing FullRecon system-wide"
    "$PYTHON" -m pip install "${PIP_ARGS[@]}" --break-system-packages . 2>/dev/null \
      || "$PYTHON" -m pip install "${PIP_ARGS[@]}" . \
      || die "pip install failed"
    BIN_DIR="$("$PYTHON" -c 'import sysconfig; print(sysconfig.get_path("scripts"))')"
    ok "installed for $PYTHON"
    ;;
  *)
    if command -v pipx >/dev/null 2>&1; then
      info "installing with pipx"
      pipx install --force . || die "pipx install failed"
      BIN_DIR="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || echo "$HOME/.local/bin")"
    else
      info "installing with pip --user"
      "$PYTHON" -m pip install "${PIP_ARGS[@]}" --user . \
        || "$PYTHON" -m pip install "${PIP_ARGS[@]}" --break-system-packages --user . \
        || die "pip install failed"
      BIN_DIR="$("$PYTHON" -m site --user-base)/bin"
    fi
    ok "installed for the current user"
    ;;
esac

# ---------------------------------------------------------- PATH check ----
FULLRECON_BIN=""
for candidate in "$BIN_DIR/fullrecon" "$BIN_DIR/fullrecon.exe"; do
  [ -x "$candidate" ] && FULLRECON_BIN="$candidate" && break
done

if [ -z "$FULLRECON_BIN" ]; then
  FULLRECON_BIN="$(command -v fullrecon 2>/dev/null || true)"
fi
[ -n "$FULLRECON_BIN" ] || die "install completed but the 'fullrecon' command was not found in $BIN_DIR"
ok "command: $FULLRECON_BIN"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    warn "$BIN_DIR is not on your PATH."
    printf '    add this to ~/.bashrc or ~/.zshrc:\n\n      export PATH="%s:$PATH"\n\n' "$BIN_DIR"
    ;;
esac

# ------------------------------------------------------------ verify ----
info "verifying installation..."
if "$FULLRECON_BIN" --version >/dev/null 2>&1; then
  ok "verified: $("$FULLRECON_BIN" --version 2>&1)"
else
  die "'fullrecon --version' failed. Check the output above."
fi

if "$FULLRECON_BIN" --list-modules >/dev/null 2>&1; then
  ok "all modules load correctly"
else
  warn "module import check failed - run 'fullrecon --list-modules' for details"
fi

# ------------------------------------------------- optional external tools ----
info "checking optional external tools"
OPTIONAL_MISSING=()
for tool in nmap subfinder jq curl; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool found"
  else
    OPTIONAL_MISSING+=("$tool")
  fi
done

if [ ${#OPTIONAL_MISSING[@]} -gt 0 ]; then
  warn "optional tools not installed: ${OPTIONAL_MISSING[*]}"
  printf '    FullRecon works without them, but these improve results:\n'
  printf '      sudo apt-get install -y nmap curl jq\n'
  printf '      go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n'
  printf '    nmap adds service/version detection; jq/curl help with manual workflows.\n'
fi

printf '\n%s\n' "${BOLD}${GREEN}FullRecon installed successfully.${RESET}"
printf 'Run your first scan:\n\n  %sfullrecon -d example.com%s\n\n' "$BOLD" "$RESET"
printf '%sOnly scan systems you own or have explicit written permission to test.%s\n\n' "$YELLOW" "$RESET"
