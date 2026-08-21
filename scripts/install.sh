#!/bin/bash
#
# Install the Proxmox Redfish daemon.
#
# Installs the package with pip into a virtual environment, writes a systemd
# unit that runs the installed console script, and leaves a configuration
# file for the operator to fill in. Nothing is started until the operator
# has done that.
#
# This replaces an existing installation rather than upgrading it. There is
# no in-place upgrade from releases before the daemon was split into
# modules; back the old directory up and install fresh.

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/proxmox-redfish}"
REPO_URL="${REPO_URL:-https://github.com/v1k0d3n/proxmox-redfish.git}"
VERSION="${VERSION:-}"
SERVICE_NAME="proxmox-redfish"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
ASSUME_YES="${ASSUME_YES:-0}"
SKIP_SERVICE="${SKIP_SERVICE:-0}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
status()  { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARNING]${NC} $1"; }
fail()    { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

usage() {
    cat <<USAGE
Usage: $0 [options]

  --version <ref>    Git tag, branch or commit to install (default: repository default branch)
  --install-dir <d>  Where to install (default: /opt/proxmox-redfish)
  --repo <url>       Repository to install from
  --skip-service     Install the package only; do not write a systemd unit
  --yes              Do not prompt
  -h, --help         Show this message

Environment variables of the same name may be used instead: INSTALL_DIR,
REPO_URL, VERSION, ASSUME_YES, SKIP_SERVICE.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --repo) REPO_URL="$2"; shift 2 ;;
        --skip-service) SKIP_SERVICE=1; shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown option: $1 (try --help)" ;;
    esac
done

confirm() {
    [[ "$ASSUME_YES" == "1" ]] && return 0
    read -r -p "$1 (y/N): " -n 1 reply; echo
    [[ "$reply" =~ ^[Yy]$ ]]
}

check_root() {
    [[ $EUID -eq 0 ]] || fail "This script must be run as root"
}

check_dependencies() {
    status "Checking dependencies..."
    command -v python3 >/dev/null || fail "python3 is not installed"
    command -v openssl >/dev/null || fail "openssl is not installed"
    command -v git     >/dev/null || fail "git is not installed (pip needs it to fetch the repository)"

    # The package requires 3.10 or newer.
    python3 - <<'PY' || fail "Python 3.10 or newer is required"
import sys
sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY
    python3 -c "import venv" 2>/dev/null || fail "the python3 venv module is missing (install python3-venv)"
    success "Dependencies satisfied"
}

prepare_directory() {
    if [[ -e "$INSTALL_DIR" ]]; then
        warn "$INSTALL_DIR already exists."
        warn "This installs over it. Existing configuration under config/ is kept;"
        warn "back the directory up first if you need to return to it."
        confirm "Continue?" || { status "Cancelled"; exit 0; }
    fi
    mkdir -p "$INSTALL_DIR/config/ssl"
    success "Installation directory ready: $INSTALL_DIR"
}

create_venv() {
    status "Creating virtual environment..."
    # Proxmox does not carry these libraries system-wide, so the daemon always
    # runs from its own environment.
    python3 -m venv "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
    success "Virtual environment created"
}

install_package() {
    local target="git+${REPO_URL}"
    [[ -n "$VERSION" ]] && target="${target}@${VERSION}"

    status "Installing from ${target}..."
    "$INSTALL_DIR/venv/bin/pip" install --quiet "$target"

    local entrypoint="$INSTALL_DIR/venv/bin/proxmox-redfish"
    [[ -x "$entrypoint" ]] || fail "Install finished but $entrypoint is missing"
    success "Installed $("$INSTALL_DIR/venv/bin/pip" show proxmox-redfish | awk '/^Version:/{print $2}')"
}

generate_ssl_cert() {
    local cert="$INSTALL_DIR/config/ssl/server.crt"
    local key="$INSTALL_DIR/config/ssl/server.key"

    if [[ -f "$cert" || -f "$key" ]]; then
        warn "SSL certificate already present"
        confirm "Regenerate it?" || { status "Keeping the existing certificate"; return; }
    fi

    status "Generating a self-signed certificate..."
    openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
        -keyout "$key" -out "$cert" -subj "/CN=$(hostname -f 2>/dev/null || hostname)" 2>/dev/null
    chmod 600 "$key"; chmod 644 "$cert"
    success "Certificate written to $cert"
}

create_config() {
    local env_file="$INSTALL_DIR/config/params.env"

    if [[ -f "$env_file" ]]; then
        warn "Keeping existing configuration: $env_file"
        return
    fi

    status "Writing configuration template..."
    # Values are literal. systemd reads this file directly and does not run
    # commands, so a $(...) written here would be taken as the value itself.
    cat > "$env_file" <<CONFIG
# Address of the Proxmox API. Use the address, not a command.
#   hostname -I | awk '{print \$1}'
PROXMOX_HOST=CHANGE-ME
PROXMOX_API_PORT=8006

# Restrict the daemon to one node. Leave unset to manage a whole cluster
# (experimental). Find the name with: hostname
PROXMOX_NODE=

# Storage that ISO images are uploaded to. Must be file-backed; a shared
# storage is required if guests run on more than one node.
PROXMOX_ISO_STORAGE=local

# No Proxmox account is configured here. Each request is served using the
# credentials of the Redfish caller, so those accounts need privileges in
# Proxmox. See "Proxmox Permissions" in the administrator guide.

# Listening address and port.
REDFISH_PORT=8000
REDFISH_HOST=

# TLS is used when both of these are set.
SSL_CERT_FILE=$INSTALL_DIR/config/ssl/server.crt
SSL_KEY_FILE=$INSTALL_DIR/config/ssl/server.key

# Logging. DEBUG is safe to use: credentials are redacted from the logs.
REDFISH_LOG_LEVEL=INFO
REDFISH_LOGGING_ENABLED=true
CONFIG
    chmod 600 "$env_file"
    success "Configuration template written to $env_file"
}

setup_service() {
    status "Writing systemd unit..."
    # Generated here rather than copied from the package: the unit has to
    # carry paths that are only known at install time.
    cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=Proxmox Redfish Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=$INSTALL_DIR/config/params.env
ExecStart=$INSTALL_DIR/venv/bin/proxmox-redfish
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    success "Unit written to $UNIT_PATH"
}

next_steps() {
    echo
    success "Installation complete."
    echo
    status "Before starting the daemon:"
    echo "  1. Set PROXMOX_HOST in $INSTALL_DIR/config/params.env"
    echo "  2. Grant Proxmox privileges to the accounts that will call the"
    echo "     Redfish API. Callers act as themselves, so an account with no"
    echo "     privileges can authenticate and will then be refused everything."
    echo "     See \"Proxmox Permissions\" in the administrator guide."
    echo
    status "Then:"
    echo "  systemctl enable --now $SERVICE_NAME"
    echo "  systemctl status $SERVICE_NAME"
    echo "  journalctl -u $SERVICE_NAME -f"
}

main() {
    echo "=========================================="
    echo " Proxmox Redfish Daemon installer"
    echo "=========================================="
    echo
    check_root
    check_dependencies
    prepare_directory
    create_venv
    install_package
    generate_ssl_cert
    create_config
    [[ "$SKIP_SERVICE" == "1" ]] || setup_service
    next_steps
}

main "$@"
