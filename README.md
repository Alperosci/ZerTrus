# ZerTrus — Zero Trust Network Controller for Raspberry Pi

> **Every connection is guilty until proven innocent.**

ZerTrus turns a Raspberry Pi into a Zero Trust network gateway that intercepts, inspects, and controls all traffic flowing through it. No device on your network gets internet access unless you explicitly approve it — per destination, per port, per protocol.

---

## How It Works

Traditional firewalls default to **allow** — everything gets through unless you block it. ZerTrus flips that model:

1. **Default Deny** — All outbound connections are dropped by default.
2. **Inspect** — DNS queries and TLS SNI headers are parsed to identify *where* traffic is going (domain-level visibility, not just IP).
3. **Queue** — Unknown connections appear in a web dashboard as pending approval requests.
4. **Approve/Deny** — The admin reviews each request and allows or blocks it, with optional time limits.
5. **Learn** — Approved rules persist, so the next connection to the same destination goes through automatically.

---

## Architecture

```
                        ┌─────────────────────────────────────┐
                        │          Raspberry Pi               │
                        │                                     │
 ┌──────────┐    eth0   │   ┌──────────┐     ┌────────────┐  │   wlan0    ┌──────────┐
 │  Client   │◄────────►│   │  dnsmasq │     │  ZerTrus   │  │◄──────────►│ Internet │
 │  Devices  │  (LAN)   │   │ DHCP/DNS │     │  Service   │  │   (WAN)    │  Router  │
 └──────────┘           │   └──────────┘     │            │  │            └──────────┘
                        │                     │ ┌────────┐ │  │
                        │   ┌──────────┐     │ │ Rule   │ │  │
                        │   │ nftables │────►│ │ Engine │ │  │
                        │   │ NFQUEUE  │     │ ├────────┤ │  │
                        │   └──────────┘     │ │DNS/SNI │ │  │
                        │                     │ │Parser  │ │  │
                        │   ┌──────────┐     │ ├────────┤ │  │
                        │   │  Flask   │◄───►│ │SQLite  │ │  │
                        │   │ Web UI   │     │ │  DB    │ │  │
                        │   │ :8443    │     │ └────────┘ │  │
                        │   └──────────┘     └────────────┘  │
                        └─────────────────────────────────────┘

Traffic Flow:
  Client → eth0 → nftables FORWARD → NFQUEUE 1 → ZerTrus Interceptor
       → Rule check → ACCEPT (if allowed) → NAT → wlan0 → Internet
                     → DROP   (if denied/unknown) → Pending Request → Web UI
```

---

## Features

- **Zero Trust by Default** — All unknown connections are dropped and queued for review.
- **DNS Inspection** — Intercepts DNS queries/responses to map IPs to domain names.
- **TLS SNI Extraction** — Reads Server Name Indication from TLS ClientHello to identify HTTPS destinations.
- **Real-time Web Dashboard** — Dark-themed control panel with SSE live updates.
- **Flexible Rules** — Allow or deny by source IP, destination IP/domain, port, and protocol.
- **Time-limited Rules** — Approve access for 1 hour, 24 hours, 7 days, or permanently.
- **DHCP Server** — Built-in DHCP via dnsmasq for LAN clients.
- **NAT Gateway** — Transparent NAT so clients use the Pi as their default gateway.
- **Lightweight** — Pure Python with manual DNS/TLS parsing (no Scapy dependency).
- **Systemd Integration** — Runs as a managed service with automatic restart.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Hardware** | Raspberry Pi 3B+ or newer (4 recommended) |
| **OS** | Raspberry Pi OS Bookworm (Debian 12) or later |
| **Network** | Two network interfaces — typically `eth0` (LAN) + `wlan0` (WAN) |
| **Access** | SSH or physical terminal access with root/sudo |

> [!IMPORTANT]
> The Raspberry Pi must have **two network interfaces**: one for the LAN (clients connect here) and one for the WAN (connects to your existing router/internet). A USB-to-Ethernet adapter works if your Pi has only one Ethernet port.

---

## Quick Start

```bash
# 1. Clone or copy the project to your Raspberry Pi
git clone https://github.com/your-repo/zertrus.git
cd zertrus

# 2. Run the installer (as root)
sudo bash setup/install.sh

# 3. Connect a client device to the Pi's eth0 network

# 4. Open the web panel
#    http://192.168.50.1:8443
#    Username: admin | Password: zertrus

# 5. Watch connections appear — approve or deny them!
```

---

## Detailed Setup Guide

### Network Topology

```
Your existing network:         ZerTrus network:
┌──────────┐                   ┌──────────────┐          ┌────────┐
│  Modem/  │◄── wlan0 ───────►│  Raspberry   │◄─ eth0 ──►│ Client │
│  Router  │   (gets DHCP)     │     Pi       │  (LAN)    │ Device │
│ Internet │                   │  ZerTrus     │           └────────┘
└──────────┘                   └──────────────┘
                                192.168.50.1
```

The Pi connects to your existing router via WiFi (`wlan0`) and serves a new, isolated LAN on `eth0` (192.168.50.0/24). All client traffic must flow through the Pi, where ZerTrus inspects it.

### Step 1: Prepare Your Raspberry Pi

1. Flash **Raspberry Pi OS Bookworm** (Lite or Desktop).
2. Enable SSH: `sudo raspi-config` → Interface Options → SSH.
3. Connect the Pi's **wlan0** to your existing WiFi network.
4. Connect an Ethernet cable from the Pi's **eth0** to a switch or directly to a client.

### Step 2: Install ZerTrus

```bash
# Copy the project to the Pi
scp -r zertrus/ pi@<pi-ip>:~/zertrus

# SSH into the Pi
ssh pi@<pi-ip>

# Run the installer
cd ~/zertrus
sudo bash setup/install.sh
```

The installer will:
- Install system packages (`nftables`, `dnsmasq`, `libnetfilter-queue-dev`, etc.)
- Create a Python virtual environment with dependencies
- Configure network interfaces, firewall rules, and DHCP
- Install and start the ZerTrus systemd service

### Step 3: Connect Clients

1. Connect a device to the Pi's `eth0` network (via switch or direct cable).
2. The device will receive an IP via DHCP (192.168.50.100–200).
3. The device's default gateway and DNS will be set to the Pi (192.168.50.1).

### Step 4: Manage Traffic

1. Open **http://192.168.50.1:8443** in a browser.
2. Log in with the default credentials (`admin` / `zertrus`).
3. As the client tries to access websites, pending requests will appear.
4. **Approve** to allow, **Deny** to block.

---

## Usage Guide

### Web Panel

The web panel is served on port **8443** and provides three main views:

#### Dashboard (`/`)
- Overview cards showing total rules, pending requests, and traffic stats.
- Real-time updates via Server-Sent Events (SSE).

#### Pending Requests (`/pending`)
- Lists all intercepted connections awaiting approval.
- Each entry shows: source IP, destination IP, resolved domain, port, protocol, and packet count.
- **Approve** opens a modal to set duration (1 hour, 24 hours, 7 days, or permanent) and add a description.
- **Deny** creates a deny rule to actively reject future connections to that destination.

#### Rules (`/rules`)
- Lists all active allow/deny rules.
- Shows hit counts and expiration status.
- **Delete** removes a rule (traffic to that destination will be blocked again).
- **Add Rule** form for creating manual rules.

### CLI Usage

```bash
# Check service status
sudo systemctl status zertrus

# View live logs
sudo journalctl -u zertrus -f

# Restart the service
sudo systemctl restart zertrus

# Stop the service
sudo systemctl stop zertrus

# View nftables rules
sudo nft list ruleset

# View DHCP leases
cat /var/lib/misc/dnsmasq.leases
```

---

## Configuration Reference

The configuration file is located at `/etc/zertrus/config.json`.

| Key | Type | Default | Description |
|---|---|---|---|
| `nfqueue_num` | int | `1` | NFQUEUE number for packet interception |
| `web_host` | string | `"0.0.0.0"` | Web panel bind address |
| `web_port` | int | `8443` | Web panel port |
| `web_secret_key` | string | `"CHANGE_ME_IN_PRODUCTION"` | Flask session secret key — **change this!** |
| `db_path` | string | `"/var/lib/zertrus/zertrus.db"` | SQLite database file path |
| `log_path` | string | `"/var/log/zertrus/zertrus.log"` | Log file path |
| `log_level` | string | `"INFO"` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `default_action` | string | `"drop"` | Action for unknown traffic (`drop`) |
| `dns_intercept` | bool | `true` | Enable DNS query/response interception |
| `sni_extraction` | bool | `true` | Enable TLS SNI extraction from ClientHello |
| `request_timeout_seconds` | int | `300` | Seconds before pending requests expire |
| `lan_interface` | string | `"eth0"` | LAN-side network interface |
| `wan_interface` | string | `"wlan0"` | WAN-side network interface (internet uplink) |
| `lan_subnet` | string | `"192.168.50.0/24"` | LAN subnet CIDR |
| `pi_lan_ip` | string | `"192.168.50.1"` | Pi's static IP on the LAN |
| `auto_allow_established` | bool | `true` | Auto-allow established/related connections |
| `auto_allow_dhcp` | bool | `true` | Auto-allow DHCP traffic |
| `auto_allow_dns_to_pi` | bool | `true` | Auto-allow DNS queries to the Pi |
| `web_username` | string | `"admin"` | Web panel login username |
| `web_password` | string | `"zertrus"` | Web panel login password — **change this!** |

---

## API Reference

All API endpoints are prefixed with the web panel URL (default: `http://192.168.50.1:8443`).

### Pages

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard page |
| `GET` | `/pending` | Pending requests page |
| `GET` | `/rules` | Rules management page |

### Pending Requests API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/pending` | List all pending requests (JSON) |
| `POST` | `/api/pending/<id>/approve` | Approve a pending request |
| `POST` | `/api/pending/<id>/deny` | Deny a pending request |
| `DELETE` | `/api/pending/<id>` | Dismiss a pending request |

**Approve request body:**
```json
{
    "action": "allow",
    "duration": "permanent",
    "duration_minutes": null,
    "description": "Allow access to example.com"
}
```

Duration options: `"1h"`, `"24h"`, `"7d"`, `"permanent"`, or set `duration_minutes` for custom.

### Rules API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/rules` | List all active rules (JSON) |
| `DELETE` | `/api/rules/<id>` | Delete a rule |

### System API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/stats` | System statistics (JSON) |
| `GET` | `/api/events` | Server-Sent Events stream for real-time updates |

---

## Security Considerations

> [!WARNING]
> ZerTrus provides **visibility and control** at the network layer, but it is not a complete security solution. Understand these limitations before deploying.

### DNS Leak Risks

ZerTrus relies on intercepting DNS queries to map IP addresses to domain names. This can be bypassed:

- **DNS over HTTPS (DoH)** — Browsers like Firefox and Chrome can send DNS queries over HTTPS to resolvers like `dns.mozilla.org` or `dns.google`, bypassing the Pi's DNS entirely. Mitigation: Block known DoH endpoints, or block all HTTPS to known DoH IPs.
- **DNS over TLS (DoT)** — Similar to DoH but on port 853. Mitigation: Block TCP port 853 in nftables.
- **Hardcoded DNS** — Some apps use hardcoded DNS servers (e.g., `8.8.8.8`). The nftables rules queue these for inspection, but the domain won't be visible via SNI if the app doesn't use TLS.

### QUIC / HTTP/3 (UDP)

QUIC runs over UDP port 443. The current nftables rules queue TCP connections but may not fully handle QUIC. Consider blocking UDP port 443 to force fallback to TCP/TLS:

```bash
# Add to nftables forward chain:
udp dport 443 drop
```

### IPv6 Traffic

ZerTrus currently handles **IPv4 only**. If IPv6 is enabled on client devices, traffic may bypass the Pi entirely. Mitigation:

```bash
# Disable IPv6 on the LAN interface
sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
# Or add to /etc/sysctl.d/99-zertrus.conf:
net.ipv6.conf.all.disable_ipv6 = 1
```

### TLS 1.3 Encrypted Client Hello (ECH)

TLS 1.3 introduced Encrypted Client Hello (ECH), which encrypts the SNI field. When ECH is in use, ZerTrus **cannot extract the destination domain** from the TLS handshake. This is an emerging standard; as adoption grows, SNI-based inspection will become less effective. The DNS-based mapping will still work if DNS is not also encrypted.

### Performance Impact

- **Throughput**: NFQUEUE adds latency to every new connection (established connections bypass it). Expect ~10-15% throughput reduction on a Raspberry Pi 4.
- **Connection setup time**: New connections are delayed by the time it takes to process them through the Python handler.
- **CPU**: DNS/SNI parsing is lightweight, but high connection rates (100+ new connections/second) may saturate a Pi 3B+.

### Single Point of Failure

The Pi is a single point of failure. If the ZerTrus service crashes:
- The `Restart=on-failure` systemd directive will restart it automatically.
- During restart, **no new connections will be established** (they queue in NFQUEUE and time out if the service doesn't come back quickly).
- Consider a hardware watchdog timer for the Pi itself.

### Production Hardening Recommendations

1. **Change default credentials** — Update `web_username`, `web_password`, and `web_secret_key` in `/etc/zertrus/config.json`.
2. **Enable HTTPS** — Put a reverse proxy (nginx/caddy) in front of the web panel with a self-signed or Let's Encrypt certificate.
3. **Restrict web panel access** — Bind to `127.0.0.1` and access via SSH tunnel, or restrict by source IP in nftables.
4. **Regular backups** — Back up `/var/lib/zertrus/zertrus.db` and `/etc/zertrus/config.json`.
5. **Monitor logs** — Set up log rotation for `/var/log/zertrus/` and monitor for anomalies.
6. **Block IPv6** — Disable IPv6 to prevent bypass.
7. **Block QUIC** — Drop UDP port 443 to force HTTP/2 over TCP.
8. **Block DoH/DoT** — Maintain a blocklist of known DoH/DoT resolver IPs.
9. **Keep software updated** — Regularly update Raspberry Pi OS and ZerTrus dependencies.

---

## Troubleshooting

### ZerTrus service won't start

```bash
# Check service status and logs
sudo systemctl status zertrus
sudo journalctl -u zertrus -e --no-pager

# Common issues:
# - NFQUEUE not available: ensure nftables is running
sudo systemctl status nftables

# - Python module not found: check the venv
/opt/zertrus/venv/bin/python3 -c "import netfilterqueue; print('OK')"
```

### Clients can't get an IP address

```bash
# Check dnsmasq is running
sudo systemctl status dnsmasq

# Check eth0 has the correct IP
ip addr show eth0

# Check DHCP leases
cat /var/lib/misc/dnsmasq.leases
```

### Clients get IP but no internet

```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward
# Should be 1

# Check nftables rules are loaded
sudo nft list ruleset | grep zertrus

# Check the Pi itself has internet
ping -c 3 8.8.8.8

# Check ZerTrus service is running and processing packets
sudo journalctl -u zertrus -f
# Try accessing a website from the client and watch for log entries
```

### Web panel not accessible

```bash
# Check the service is running
sudo systemctl status zertrus

# Check the port is open
ss -tlnp | grep 8443

# Check nftables allows port 8443
sudo nft list chain inet zertrus input | grep 8443

# Try from the Pi itself
curl http://localhost:8443
```

### All traffic is being blocked

```bash
# Check the nftables NFQUEUE rule is working
sudo nft list chain inet zertrus forward

# Check ZerTrus logs for packet processing
sudo journalctl -u zertrus -f

# Verify the NFQUEUE binding
cat /proc/net/netfilter/nfnetlink_queue
```

### DNS resolution not working for clients

```bash
# Check dnsmasq is handling DNS
dig @192.168.50.1 google.com

# Check upstream DNS from the Pi
dig @8.8.8.8 google.com

# Check dnsmasq logs
sudo journalctl -u dnsmasq -f
```

---

## Project Structure

```
zertrus/
├── src/
│   ├── __init__.py          # Package init
│   ├── config.py            # Configuration loader
│   ├── models.py            # Data models (Rule, PendingRequest, DnsEntry)
│   ├── database.py          # SQLite database layer (thread-safe)
│   ├── dns_sni.py           # DNS query/response & TLS SNI parsers
│   ├── rule_engine.py       # Rule matching engine (in-memory + DB)
│   ├── interceptor.py       # NFQUEUE packet interceptor
│   └── main.py              # Application entry point
├── web/
│   ├── __init__.py          # Package init
│   ├── app.py               # Flask web application
│   ├── templates/
│   │   ├── base.html        # Base layout (dark theme, navbar)
│   │   ├── dashboard.html   # Stats dashboard
│   │   ├── pending.html     # Pending requests view
│   │   └── rules.html       # Rules management view
│   └── static/
│       └── style.css        # Custom styles
├── setup/
│   ├── install.sh           # Main installation script
│   └── network_setup.sh     # Network configuration script
├── config.json              # Default configuration
├── requirements.txt         # Python dependencies
├── zertrus.service          # Systemd unit file
└── README.md                # This file
```

---

## License

MIT License

Copyright (c) 2026 ZerTrus Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
