#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# SBOM Analyzer — local-machine bootstrap (macOS + Linux)
#
# Installs the two prerequisites the project needs to run locally:
#   • Python 3.11
#   • Node.js 20
#
# Then creates the backend venv, installs Python deps, installs frontend
# deps, and copies the .env / .env.local templates if they are missing.
#
# Usage:
#   ./scripts/bootstrap.sh                 # auto-detect + install everything
#   ./scripts/bootstrap.sh --skip-system   # skip system pkg install, only
#                                          # set up venv + npm deps
#   ./scripts/bootstrap.sh --help
#
# Idempotent: safe to re-run. Every install step checks first; nothing is
# reinstalled if it already meets the required minimum version.
#
# Supported package managers (auto-detected):
#   macOS:      Homebrew  (installed automatically if missing)
#   Debian/Ubuntu/Mint:     apt-get
#   Fedora/RHEL/CentOS/Rocky/Alma:  dnf  (or yum)
#   Arch/Manjaro:           pacman
#   openSUSE:               zypper
#   Alpine:                 apk
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

readonly REQUIRED_PYTHON_MAJOR=3
readonly REQUIRED_PYTHON_MINOR=11
readonly REQUIRED_NODE_MAJOR=20

# Resolve repo root assuming the script lives in <repo>/scripts/.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"

SKIP_SYSTEM=0
for arg in "$@"; do
  case "$arg" in
    --skip-system) SKIP_SYSTEM=1 ;;
    -h|--help)
      sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown flag: $arg" >&2
      exit 2
      ;;
  esac
done

# ── helpers ───────────────────────────────────────────────────────────────────

c_red()    { printf '\033[31m%s\033[0m' "$*"; }
c_green()  { printf '\033[32m%s\033[0m' "$*"; }
c_yellow() { printf '\033[33m%s\033[0m' "$*"; }
c_blue()   { printf '\033[34m%s\033[0m' "$*"; }

log()   { printf '%s %s\n' "$(c_blue '==>')" "$*"; }
ok()    { printf '%s %s\n' "$(c_green '✓')"  "$*"; }
warn()  { printf '%s %s\n' "$(c_yellow '!')" "$*" >&2; }
die()   { printf '%s %s\n' "$(c_red '✗')"    "$*" >&2; exit 1; }

have()  { command -v "$1" > /dev/null 2>&1; }

# Returns 0 if installed python meets >=3.11.
python_ok() {
  local cmd="$1"
  have "$cmd" || return 1
  "$cmd" -c "import sys; sys.exit(0 if sys.version_info >= (${REQUIRED_PYTHON_MAJOR}, ${REQUIRED_PYTHON_MINOR}) else 1)" 2> /dev/null
}

# Returns 0 if installed node meets >=20.
node_ok() {
  have node || return 1
  local major
  major="$(node -e 'process.stdout.write(String(process.versions.node.split(".")[0]))')"
  [[ "$major" =~ ^[0-9]+$ ]] && (( major >= REQUIRED_NODE_MAJOR ))
}

# Detect platform and package manager.
OS=""           # mac | linux
PM=""           # brew | apt | dnf | yum | pacman | zypper | apk
SUDO=""         # "" | "sudo"

detect_platform() {
  case "$(uname -s)" in
    Darwin) OS="mac" ;;
    Linux)  OS="linux" ;;
    *)      die "Unsupported OS: $(uname -s). Use the PowerShell script on Windows." ;;
  esac

  if [[ "$OS" == "mac" ]]; then
    PM="brew"
    return
  fi

  # Linux package manager probe — order matters: prefer dnf over yum.
  for candidate in apt-get dnf yum pacman zypper apk; do
    if have "$candidate"; then
      case "$candidate" in
        apt-get) PM="apt" ;;
        *)       PM="$candidate" ;;
      esac
      break
    fi
  done
  [[ -n "$PM" ]] || die "No supported package manager found (apt/dnf/yum/pacman/zypper/apk)."

  # sudo only if not already root.
  if [[ "$(id -u)" -ne 0 ]]; then
    have sudo || die "sudo is required to install system packages on Linux."
    SUDO="sudo"
  fi
}

# ── installers ────────────────────────────────────────────────────────────────

ensure_homebrew() {
  if have brew; then
    ok "Homebrew present"
    return
  fi
  log "Installing Homebrew (non-interactive)"
  NONINTERACTIVE=1 /bin/bash -c \
    "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  # Add brew to PATH for this shell (Apple Silicon vs Intel).
  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
  have brew || die "Homebrew install failed."
}

install_python_mac() {
  log "Installing Python ${REQUIRED_PYTHON_MAJOR}.${REQUIRED_PYTHON_MINOR} via Homebrew"
  brew install "python@${REQUIRED_PYTHON_MAJOR}.${REQUIRED_PYTHON_MINOR}"
}

install_node_mac() {
  log "Installing Node ${REQUIRED_NODE_MAJOR} via Homebrew"
  brew install "node@${REQUIRED_NODE_MAJOR}"
  # node@20 is keg-only — expose it for this shell.
  if brew --prefix "node@${REQUIRED_NODE_MAJOR}" > /dev/null 2>&1; then
    local prefix
    prefix="$(brew --prefix "node@${REQUIRED_NODE_MAJOR}")"
    export PATH="${prefix}/bin:${PATH}"
  fi
}

install_python_linux() {
  log "Installing Python ${REQUIRED_PYTHON_MAJOR}.${REQUIRED_PYTHON_MINOR} via $PM"
  case "$PM" in
    apt)
      $SUDO apt-get update -y
      # python3.11 ships on Ubuntu 22.04+, Debian 12+. Older Debian/Ubuntu
      # need the deadsnakes PPA, which we only add if the package isn't
      # already in the repos.
      if ! apt-cache show python3.11 > /dev/null 2>&1; then
        $SUDO apt-get install -y software-properties-common
        $SUDO add-apt-repository -y ppa:deadsnakes/ppa
        $SUDO apt-get update -y
      fi
      $SUDO apt-get install -y \
        python3.11 python3.11-venv python3.11-dev python3-pip \
        build-essential libxml2-dev libxslt1-dev libssl-dev libffi-dev libpq-dev
      ;;
    dnf|yum)
      $SUDO "$PM" install -y \
        python3.11 python3.11-devel python3-pip \
        gcc gcc-c++ make libxml2-devel libxslt-devel openssl-devel libffi-devel libpq-devel
      ;;
    pacman)
      # Arch ships current Python; 3.11 may need AUR. Use system python if
      # it already satisfies >=3.11.
      if python_ok python3; then
        ok "system python3 already meets >=3.11"
      else
        $SUDO pacman -Sy --noconfirm python python-pip
      fi
      $SUDO pacman -S --noconfirm --needed base-devel libxml2 libxslt openssl libffi postgresql-libs
      ;;
    zypper)
      $SUDO zypper install -y \
        python311 python311-devel python311-pip \
        gcc gcc-c++ make libxml2-devel libxslt-devel libopenssl-devel libffi-devel postgresql-devel
      ;;
    apk)
      $SUDO apk add --no-cache \
        python3 python3-dev py3-pip \
        build-base libxml2-dev libxslt-dev openssl-dev libffi-dev postgresql-dev
      ;;
  esac
}

install_node_linux() {
  log "Installing Node ${REQUIRED_NODE_MAJOR} via $PM (NodeSource where applicable)"
  case "$PM" in
    apt)
      # Official NodeSource setup script for v20.x.
      if ! have curl; then $SUDO apt-get install -y curl; fi
      curl -fsSL "https://deb.nodesource.com/setup_${REQUIRED_NODE_MAJOR}.x" | $SUDO -E bash -
      $SUDO apt-get install -y nodejs
      ;;
    dnf|yum)
      if ! have curl; then $SUDO "$PM" install -y curl; fi
      curl -fsSL "https://rpm.nodesource.com/setup_${REQUIRED_NODE_MAJOR}.x" | $SUDO -E bash -
      $SUDO "$PM" install -y nodejs
      ;;
    pacman)
      $SUDO pacman -Sy --noconfirm nodejs npm
      ;;
    zypper)
      $SUDO zypper install -y nodejs20 npm20 || $SUDO zypper install -y nodejs npm
      ;;
    apk)
      $SUDO apk add --no-cache "nodejs~=${REQUIRED_NODE_MAJOR}" npm || $SUDO apk add --no-cache nodejs npm
      ;;
  esac
}

# Pick the best available python3.11 binary, in priority order.
pick_python() {
  for candidate in \
    "python${REQUIRED_PYTHON_MAJOR}.${REQUIRED_PYTHON_MINOR}" \
    "python${REQUIRED_PYTHON_MAJOR}" \
    python; do
    if python_ok "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

# ── steps ─────────────────────────────────────────────────────────────────────

step_install_system_deps() {
  if (( SKIP_SYSTEM == 1 )); then
    log "--skip-system: not touching system packages"
    return
  fi

  detect_platform
  log "Detected: OS=$OS  PM=$PM"

  if [[ "$OS" == "mac" ]]; then
    ensure_homebrew
    if python_ok "python${REQUIRED_PYTHON_MAJOR}.${REQUIRED_PYTHON_MINOR}"; then
      ok "Python ${REQUIRED_PYTHON_MAJOR}.${REQUIRED_PYTHON_MINOR} already installed"
    else
      install_python_mac
    fi
    if node_ok; then
      ok "Node $(node -v) already installed"
    else
      install_node_mac
    fi
  else
    if pick_python > /dev/null; then
      ok "Python $($(pick_python) -V) already installed"
    else
      install_python_linux
    fi
    if node_ok; then
      ok "Node $(node -v) already installed"
    else
      install_node_linux
    fi
  fi
}

step_setup_backend() {
  local py
  py="$(pick_python)" || die "Python ${REQUIRED_PYTHON_MAJOR}.${REQUIRED_PYTHON_MINOR}+ not on PATH after install — start a new shell and re-run."

  log "Creating venv at ${REPO_ROOT}/.venv using ${py}"
  if [[ ! -d "${REPO_ROOT}/.venv" ]]; then
    "$py" -m venv "${REPO_ROOT}/.venv"
  else
    ok "venv already exists"
  fi

  log "Upgrading pip + installing backend deps"
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.venv/bin/activate"
  python -m pip install --upgrade pip
  python -m pip install -r "${REPO_ROOT}/requirements.txt"
  deactivate

  if [[ ! -f "${REPO_ROOT}/.env" && -f "${REPO_ROOT}/.env.example" ]]; then
    cp "${REPO_ROOT}/.env.example" "${REPO_ROOT}/.env"
    ok "Copied .env.example → .env  (edit it before running in production)"
  fi
}

step_setup_frontend() {
  if [[ ! -d "${REPO_ROOT}/frontend" ]]; then
    warn "frontend/ not found — skipping npm install"
    return
  fi
  have npm || die "npm is not on PATH. Restart your shell and re-run."

  log "Installing frontend deps (npm ci)"
  (cd "${REPO_ROOT}/frontend" && npm ci)

  if [[ ! -f "${REPO_ROOT}/frontend/.env.local" && -f "${REPO_ROOT}/frontend/.env.local.example" ]]; then
    cp "${REPO_ROOT}/frontend/.env.local.example" "${REPO_ROOT}/frontend/.env.local"
    ok "Copied frontend/.env.local.example → frontend/.env.local"
  fi
}

# ── main ──────────────────────────────────────────────────────────────────────

step_install_system_deps
step_setup_backend
step_setup_frontend

cat <<EOF

$(c_green '═══════════════════════════════════════════════════════════════════════')
  Bootstrap complete.

  Start the backend:
    source .venv/bin/activate
    python run.py                      # → http://localhost:8000

  Start the frontend (in another terminal):
    cd frontend && npm run dev         # → http://localhost:3000
$(c_green '═══════════════════════════════════════════════════════════════════════')
EOF
