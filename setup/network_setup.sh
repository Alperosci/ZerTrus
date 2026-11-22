#!/usr/bin/env bash
# ZerTrus Network Setup Script
# Configures the Raspberry Pi as a Zero Trust network gateway.
set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[NET]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[NET]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[NET]${NC}  $*"; }
log_error() { echo -e "${RED}[NET]${NC}  $*"; }

# --- Configuration (env vars > arguments > defaults) ---

LAN_IF="${LAN_IF:-${1:-eth0}}"
WAN_IF="${WAN_IF:-${2:-wlan0}}"
LAN_SUBNET="${LAN_SUBNET:-${3:-192.168.50.0/24}}"
PI_IP="${PI_IP:-${4:-192.168.50.1}}"

# Derive DHCP range from subnet
SUBNET_PREFIX="${LAN_SUBNET%.*}"
DHCP_START="${SUBNET_PREFIX}.100"
DHCP_END="${SUBNET_PREFIX}.200"
NETMASK="255.255.255.0"

echo ""
log_info "=== ZerTrus Network Setup ==="
log_info "LAN interface:  $LAN_IF"
log_info "WAN interface:  $WAN_IF"
log_info "LAN subnet:     $LAN_SUBNET"
log_info "Pi LAN IP:      $PI_IP"
log_info "DHCP range:     $DHCP_START - $DHCP_END"
echo ""

# --- Step 1: Enable IP Forwarding ---

log_info "Enabling IP forwarding..."

sysctl -w net.ipv4.ip_forward=1

# Persist across reboots
cat > /etc/sysctl.d/99-zertrus.conf <<EOF
# ZerTrus: Enable IP forwarding for gateway mode
net.ipv4.ip_forward = 1
EOF

sysctl --system >/dev/null 2>&1
log_ok "IP forwarding enabled and persisted."

# --- Step 2: Configure LAN Interface Static IP ---

log_info "Configuring static IP on $LAN_IF..."

# Method 1: dhcpcd (traditional Raspberry Pi OS)
if [[ -f /etc/dhcpcd.conf ]]; then
    # Remove any existing ZerTrus config block
    sed -i '/# ZerTrus LAN config/,/# End ZerTrus LAN config/d' /etc/dhcpcd.conf

    cat >> /etc/dhcpcd.conf <<EOF

# ZerTrus LAN config
interface $LAN_IF
static ip_address=${PI_IP}/24
nogateway
# End ZerTrus LAN config
EOF
    log_ok "Static IP configured via dhcpcd.conf"

    # Apply immediately if dhcpcd is running
    if systemctl is-active --quiet dhcpcd; then
        systemctl restart dhcpcd || true
    fi

# Method 2: NetworkManager (newer Raspberry Pi OS / Bookworm)
elif command -v nmcli &>/dev/null; then
    # Check if connection exists
    if nmcli -t -f NAME con show | grep -q "zertrus-lan"; then
        nmcli con delete "zertrus-lan" >/dev/null 2>&1 || true
    fi

    nmcli con add type ethernet \
        con-name "zertrus-lan" \
        ifname "$LAN_IF" \
        ipv4.method manual \
        ipv4.addresses "${PI_IP}/24" \
        ipv4.never-default yes \
        connection.autoconnect yes

    nmcli con up "zertrus-lan" || true
    log_ok "Static IP configured via NetworkManager"
else
    log_warn "Neither dhcpcd nor NetworkManager found."
    log_warn "Manually configure $LAN_IF with IP $PI_IP/24."
fi

# --- Step 3: Configure nftables ---

log_info "Configuring nftables firewall rules..."

cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet zertrus {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established
        ct state established,related accept

        # Allow SSH (so we don't lock ourselves out!)
        tcp dport 22 accept

        # Allow web panel
        tcp dport 8443 accept

        # Allow DHCP server
        udp dport 67 accept

        # Allow DNS to Pi
        udp dport 53 accept
        tcp dport 53 accept

        # Allow ICMP
        icmp type { echo-request, echo-reply } accept

        # Log and drop everything else
        log prefix "ZerTrus-INPUT-DROP: " drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;

        # Allow established/related
        ct state established,related accept

        # Queue NEW connections for ZerTrus inspection
        ct state new queue num 1

        # Drop invalid
        ct state invalid drop
    }

    chain postrouting {
        type nat hook postrouting priority 100;

        # NAT for outbound traffic
        oifname "$WAN_IF" masquerade
    }
}
EOF

log_ok "nftables rules written to /etc/nftables.conf"

# Apply rules
systemctl enable nftables
systemctl restart nftables

log_ok "nftables rules applied."

# --- Step 4: Configure dnsmasq ---

log_info "Configuring dnsmasq DHCP/DNS server..."

# Backup existing config
if [[ -f /etc/dnsmasq.conf ]]; then
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak.$(date +%s)
fi

cat > /etc/dnsmasq.conf <<EOF
# ZerTrus dnsmasq configuration
# DHCP server on LAN interface

interface=$LAN_IF
dhcp-range=${DHCP_START},${DHCP_END},${NETMASK},24h
dhcp-option=option:router,${PI_IP}
dhcp-option=option:dns-server,${PI_IP}

# Upstream DNS servers
server=8.8.8.8
server=1.1.1.1

# Log DNS queries for visibility
log-queries

# Don't read /etc/resolv.conf
no-resolv

# Don't forward queries without a domain
domain-needed
bogus-priv

# Set the DHCP server to authoritative mode
dhcp-authoritative
EOF

log_ok "dnsmasq configured."

# Enable and restart dnsmasq
systemctl enable dnsmasq
systemctl restart dnsmasq

log_ok "dnsmasq running."

# --- Step 5: Verify setup ---

log_info "Verifying network setup..."

# Check IP forwarding
FWD=$(cat /proc/sys/net/ipv4/ip_forward)
if [[ "$FWD" == "1" ]]; then
    log_ok "IP forwarding is enabled."
else
    log_error "IP forwarding is NOT enabled!"
fi

# Check nftables
if nft list ruleset | grep -q "zertrus"; then
    log_ok "nftables rules loaded (zertrus table found)."
else
    log_error "nftables rules NOT loaded!"
fi

# Check dnsmasq
if systemctl is-active --quiet dnsmasq; then
    log_ok "dnsmasq is running."
else
    log_error "dnsmasq is NOT running!"
fi

echo ""
log_ok "=== Network setup complete ==="
log_info "LAN clients on $LAN_IF will get DHCP from $DHCP_START-$DHCP_END"
log_info "Gateway: $PI_IP | DNS: $PI_IP"
log_info "Outbound traffic NAT'd via $WAN_IF"
echo ""
