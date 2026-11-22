#!/usr/bin/env bash
# ZerTrus Installation Script
# Installs ZerTrus Zero Trust Network Controller on Raspberry Pi
set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/zertrus"
CONFIG_DIR="/etc/zertrus"
DATA_DIR="/var/lib/zertrus"
LOG_DIR="/var/log/zertrus"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# --- Pre-flight checks ---

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       ZerTrus Installer v1.0                 ║${NC}"
echo -e "${GREEN}║   Zero Trust Network Controller for RPi      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# Check root
if [[ "$EUID" -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)."
    exit 1
fi

# Check Debian-based system
if ! command -v apt &>/dev/null; then
    log_error "This script requires a Debian-based system (apt not found)."
    exit 1
fi

# Check architecture (Raspberry Pi = aarch64 or armv7l)
ARCH=$(uname -m)
if [[ "$ARCH" != "aarch64" && "$ARCH" != "armv7l" && "$ARCH" != "armv6l" ]]; then
    log_warn "Architecture '$ARCH' detected — this is designed for Raspberry Pi (ARM)."
    log_warn "Proceeding anyway, but some features may not work as expected."
fi

log_info "System checks passed."

# --- Step 1: Install system dependencies ---

log_info "Installing system dependencies..."
apt update -y
apt install -y \
    python3-pip \
    python3-venv \
    nftables \
    dnsmasq \
    libnetfilter-queue-dev \
    build-essential

log_ok "System dependencies installed."

# --- Step 2: Create directory structure ---

log_info "Creating directory structure..."

mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"

log_ok "Directories created:"
log_ok "  Install:  $INSTALL_DIR"
log_ok "  Config:   $CONFIG_DIR"
log_ok "  Data:     $DATA_DIR"
log_ok "  Logs:     $LOG_DIR"

# --- Step 3: Copy project files ---

log_info "Copying project files to $INSTALL_DIR..."

# Copy source code
cp -r "$PROJECT_DIR/src" "$INSTALL_DIR/"
cp -r "$PROJECT_DIR/web" "$INSTALL_DIR/"
cp "$PROJECT_DIR/requirements.txt" "$INSTALL_DIR/"
cp -r "$PROJECT_DIR/setup" "$INSTALL_DIR/"

log_ok "Project files copied."

# --- Step 4: Create Python virtual environment ---

log_info "Creating Python virtual environment..."

python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

log_info "Installing Python dependencies..."
pip install --upgrade pip
pip install -r "$INSTALL_DIR/requirements.txt"

deactivate
log_ok "Python environment ready."

# --- Step 5: Install configuration ---

log_info "Installing configuration..."

if [[ -f "$CONFIG_DIR/config.json" ]]; then
    log_warn "Existing config found at $CONFIG_DIR/config.json — backing up."
    cp "$CONFIG_DIR/config.json" "$CONFIG_DIR/config.json.bak.$(date +%s)"
fi

cp "$PROJECT_DIR/config.json" "$CONFIG_DIR/config.json"
chmod 600 "$CONFIG_DIR/config.json"

log_ok "Configuration installed at $CONFIG_DIR/config.json"

# --- Step 6: Install systemd service ---

log_info "Installing systemd service..."

# Update ExecStart to use the venv python
sed "s|/usr/bin/python3|$INSTALL_DIR/venv/bin/python3|" \
    "$PROJECT_DIR/zertrus.service" > /etc/systemd/system/zertrus.service

systemctl daemon-reload
log_ok "Systemd service installed."

# --- Step 7: Run network setup ---

log_info "Running network setup..."

chmod +x "$PROJECT_DIR/setup/network_setup.sh"
bash "$PROJECT_DIR/setup/network_setup.sh"

log_ok "Network setup complete."

# --- Step 8: Enable and start the service ---

log_info "Enabling and starting ZerTrus service..."

systemctl enable zertrus.service
systemctl start zertrus.service

# Give it a moment to start
sleep 2

if systemctl is-active --quiet zertrus.service; then
    log_ok "ZerTrus service is running!"
else
    log_warn "ZerTrus service may not have started correctly."
    log_warn "Check status with: systemctl status zertrus.service"
    log_warn "Check logs with:   journalctl -u zertrus.service -f"
fi

# --- Summary ---

PI_IP=$(grep -oP '"pi_lan_ip"\s*:\s*"\K[^"]+' "$CONFIG_DIR/config.json" 2>/dev/null || echo "192.168.50.1")
WEB_PORT=$(grep -oP '"web_port"\s*:\s*\K[0-9]+' "$CONFIG_DIR/config.json" 2>/dev/null || echo "8443")

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       ZerTrus Installation Complete!         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BLUE}Web Panel:${NC}    http://${PI_IP}:${WEB_PORT}"
echo -e "  ${BLUE}Username:${NC}     admin"
echo -e "  ${BLUE}Password:${NC}     zertrus"
echo ""
echo -e "  ${YELLOW}⚠  Change the default password in $CONFIG_DIR/config.json${NC}"
echo -e "  ${YELLOW}⚠  Change web_secret_key in $CONFIG_DIR/config.json${NC}"
echo ""
echo -e "  ${BLUE}Service:${NC}      systemctl status zertrus"
echo -e "  ${BLUE}Logs:${NC}         journalctl -u zertrus -f"
echo -e "  ${BLUE}Config:${NC}       $CONFIG_DIR/config.json"
echo ""
echo -e "  Connect clients to the ${GREEN}eth0${NC} network (192.168.50.0/24)."
echo -e "  All traffic will be inspected by ZerTrus."
echo ""
