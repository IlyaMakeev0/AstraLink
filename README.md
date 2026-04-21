# AstraLink Rust Stack

Rust-first implementation of:
- `astralink-server` (tunnel server)
- `astralink-client` (local SOCKS5 bridge client)
- `astralink-panel` (full web panel: auth, users, inbounds, subscriptions)

## Architecture

1. `astralink-core`  
Protocol primitives: handshake, frame format, encryption/MAC framing, control frame IDs.

2. `astralink-server`  
Accepts AstraLink sessions, authenticates users (`username + psk`), multiplexes streams, forwards TCP targets.

3. `astralink-client`  
Connects to server and exposes local SOCKS5 (`127.0.0.1:1080` by default) for apps/system proxy.

4. `astralink-panel`  
Rust panel (`axum + sqlite`) with:
- admin bootstrap/login
- users CRUD
- inbounds CRUD
- subscription links:
  - `astralink-uri`
  - `singbox-socks` bridge profile
- runtime sync into server config and optional service restart

## Repository Layout

- `Cargo.toml` (workspace)
- `crates/astralink-core/`
- `crates/astralink-server/`
- `crates/astralink-client/`
- `crates/astralink-panel/`
- `config/server.example.json`
- `config/client.example.json`
- `scripts/deploy.sh`

## Important Notes

1. Current transport is TCP-based tunnel framing (MVP for stability and deployment simplicity).  
2. For production-grade censorship resistance, add QUIC/UDP transport and external security audit.  
3. Custom protocol will not be imported natively by most third-party VPN apps until dedicated core plugin is built.

## Local Build (Dev Machine)

```bash
cargo build --release -p astralink-server -p astralink-client -p astralink-panel
```

## Quick Linux Install (Recommended)

From repository root:

```bash
chmod +x scripts/deploy.sh
sudo PUBLIC_HOST=YOUR_SERVER_IP ADMIN_PASSWORD='StrongPassword123' bash scripts/deploy.sh
```

What script does:
1. Installs Rust toolchain (if missing).
2. Builds release binaries.
3. Installs binaries to:
   - `/opt/astralink/bin/astralink-server`
   - `/opt/astralink/bin/astralink-client`
   - `/opt/astralink/bin/astralink-panel`
4. Creates service files:
   - `astralink-server.service`
   - `astralink-panel.service`
5. Starts and enables services.
6. Optionally bootstraps admin (if `ADMIN_PASSWORD` set).

## Services

Check status:

```bash
sudo systemctl status astralink-server astralink-panel
```

Logs:

```bash
sudo journalctl -u astralink-server -f
sudo journalctl -u astralink-panel -f
```

## Panel First Login

Panel URL:

```text
http://SERVER_IP:2096
```

If you did not pass `ADMIN_PASSWORD` in deploy:

```bash
curl -X POST "http://127.0.0.1:2096/api/bootstrap" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"StrongPassword123"}'
```

Then login from web UI and create users/inbounds.

## Client Connection

Prepare client config from template:

```json
{
  "server_host": "YOUR_SERVER_IP",
  "server_port": 8443,
  "username": "demo",
  "psk": "replace_with_long_random_psk",
  "local_socks_host": "127.0.0.1",
  "local_socks_port": 1080
}
```

Run client:

```bash
./astralink-client --config client.json
```

Now local SOCKS5 is available on `127.0.0.1:1080`.

## How to Use With Popular Apps

### What works now
1. Any app that can use local/system SOCKS5 proxy:
   - point app/system proxy to `127.0.0.1:1080`
2. Apps that can import a sing-box JSON bridge profile:
   - use `/api/subscription/<uuid>?format=singbox-socks`

### What needs future work
1. Direct native `astralink://` import in apps like v2rayTun/HApp/Throne usually needs plugin/core support.
2. To remove bridge mode, implement a native outbound plugin for sing-box/Xray.

## API Summary

Public/admin endpoints:
- `POST /api/bootstrap`
- `POST /api/auth/login`
- `GET /api/users`
- `POST /api/users`
- `PATCH /api/users/:id`
- `DELETE /api/users/:id`
- `GET /api/inbounds`
- `POST /api/inbounds`
- `PATCH /api/inbounds/:id`
- `GET /api/subscription/:uuid?format=astralink-uri`
- `GET /api/subscription/:uuid?format=singbox-socks`

## Production Hardening TODO

1. Replace custom framing crypto with audited AEAD transport stack on QUIC/TLS1.3.
2. Add replay protection window and stronger key schedule/rotation.
3. Add rate limits and abuse controls.
4. Add integration tests, fuzzing, and benchmark suite.
5. Add multi-inbound runtime and zero-downtime config reload.

## Tested State in This Workspace

This workspace currently does not have Rust toolchain preinstalled, so full `cargo build` was not executed here.  
Code and deployment pipeline are prepared for Linux host where `deploy.sh` installs Rust automatically.

