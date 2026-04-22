# AstraLink v2 (Rust + React + Auto-SSL)

Production-oriented VPN control plane stack:
- Rust protocol core/server/client
- Rust API panel (`axum + sqlite`)
- React-based panel UI
- Automatic HTTPS certificates with Caddy
- One-command installer with domain prompts

## Stack

1. `astralink-core`  
Protocol primitives, handshake, framing.

2. `astralink-server`  
QUIC + TLS1.3 transport server for AstraLink clients.
- hot-reloads users from runtime config without restarting process

3. `astralink-client`  
Local SOCKS5 bridge for user devices.

4. `astralink-panel`  
API + React admin UI:
- one admin login
- domain settings
- automated customer key issuing
- tokenized subscription links
- JSON export + JSON download for client import
- light and dark themes
- hardened security headers and secure cookies
- login brute-force protection and audit log

5. `Caddy`  
Reverse proxy + automatic Let's Encrypt TLS for panel/subscription domains.

## One-Command Install (Recommended)

Run on a fresh Ubuntu/Debian server:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/IlyaMakeev0/AstraLink/main/scripts/install.sh)
```

Installer will ask:
- panel domain
- subscription domain
- optional priority subscription subdomain
- Let's Encrypt email
- admin password
- whether to enable fragmentation/jitter transport profile

Then it automatically:
1. installs dependencies (`git/curl/build-essential/pkg-config/caddy`)
2. installs Rust toolchain (if missing)
3. clones/updates repo in `/opt/astralink/src`
4. builds release binaries
5. creates systemd services
6. generates QUIC transport cert (`transport.crt/key`) for client pinning/CA trust
7. configures Caddy with HTTPS for domains
8. bootstraps admin user

## Access

- Panel URL: `https://<panel-domain>`
- Admin username: `admin` (default)
- Admin password: value entered during install

## Customer Provisioning Flow

In panel:
1. Open `Domains & Routing` and verify domain settings.
2. Use `Automated Key Issuing`:
   - enter customer label
   - choose duration (days)
   - choose profile
3. Send one of:
   - subscription URI link
   - JSON URL
   - downloadable JSON config

Generated public endpoints are tokenized:
- `/s/<token>?format=astralink-uri`
- `/s/<token>?format=singbox-socks`
- `/s/<token>?format=singbox-socks-download`

## Services

```bash
sudo systemctl status astralink-server astralink-panel caddy
```

Logs:

```bash
sudo journalctl -u astralink-server -f
sudo journalctl -u astralink-panel -f
sudo journalctl -u caddy -f
```

## Ports

- `80/tcp` (HTTP, ACME challenge + redirect/proxy)
- `443/tcp` (HTTPS panel/subscriptions)
- `8443/tcp` (AstraLink QUIC transport, configurable)

## QUIC Client Config Template

`config/client.example.json`

```json
{
  "server_host": "your-subscription-domain.com",
  "server_port": 8443,
  "server_name": "your-subscription-domain.com",
  "username": "replace_with_username",
  "psk": "replace_with_psk",
  "local_socks_host": "127.0.0.1",
  "local_socks_port": 1080,
  "ca_cert_path": "transport.crt",
  "quic_alpn": "astralink/2"
}
```

Client must trust the generated `transport.crt`.

## Fragmentation / Stealth Profile

Both server and client support optional traffic shaping:
- random chunk fragmentation
- small inter-chunk jitter delay
- optional hello fragmentation (client)

Configure in JSON under `shaping`.

## Local build (dev)

```bash
cargo build --release -p astralink-server -p astralink-client -p astralink-panel
```

## Security Notes

Before high-scale commercial usage, complete:
1. external cryptography audit
2. replay-defense and token-rotation hardening
3. integration/load tests and abuse controls
4. anti-DDoS edge protection (WAF + rate limits + geo policy)
