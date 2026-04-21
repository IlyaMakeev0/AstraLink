#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/astralink"
BIN_DIR="$APP_DIR/bin"
CFG_DIR="$APP_DIR/config"
DATA_DIR="$APP_DIR/data"
SYSTEMD_DIR="/etc/systemd/system"

SERVER_PORT="${SERVER_PORT:-8443}"
PANEL_PORT="${PANEL_PORT:-2096}"
PUBLIC_HOST="${PUBLIC_HOST:-}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/deploy.sh"
  exit 1
fi

ensure_tool() {
  if command -v "$1" >/dev/null 2>&1; then
    return
  fi
  echo "Missing required command: $1"
  exit 1
}

ensure_rust() {
  if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    return
  fi
  echo "Rust toolchain not found. Installing rustup..."
  ensure_tool curl
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  export PATH="$HOME/.cargo/bin:$PATH"
  if [[ -d /root/.cargo/bin ]]; then
    export PATH="/root/.cargo/bin:$PATH"
  fi
  ensure_tool cargo
  ensure_tool rustc
}

ensure_rust
ensure_tool systemctl

mkdir -p "$APP_DIR" "$BIN_DIR" "$CFG_DIR" "$DATA_DIR"

echo "Building release binaries..."
cd "$ROOT_DIR"
cargo build --release -p astralink-server -p astralink-client -p astralink-panel

install -m 0755 "target/release/astralink-server" "$BIN_DIR/astralink-server"
install -m 0755 "target/release/astralink-client" "$BIN_DIR/astralink-client"
install -m 0755 "target/release/astralink-panel" "$BIN_DIR/astralink-panel"

if [[ ! -f "$CFG_DIR/server.json" ]]; then
  cp "$ROOT_DIR/config/server.example.json" "$CFG_DIR/server.json"
fi

if [[ ! -f "$CFG_DIR/client.example.json" ]]; then
  cp "$ROOT_DIR/config/client.example.json" "$CFG_DIR/client.example.json"
fi

cat > "$SYSTEMD_DIR/astralink-server.service" <<EOF
[Unit]
Description=AstraLink Rust Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$BIN_DIR/astralink-server --config $CFG_DIR/server.json
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

cat > "$SYSTEMD_DIR/astralink-panel.service" <<EOF
[Unit]
Description=AstraLink Rust Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$BIN_DIR/astralink-panel --host 0.0.0.0 --port $PANEL_PORT --db $DATA_DIR/panel.db --runtime-server-config $CFG_DIR/server.json --restart-service astralink-server --public-host ${PUBLIC_HOST:-127.0.0.1} --public-port $SERVER_PORT
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now astralink-server
systemctl enable --now astralink-panel

echo "Services started:"
echo "  astralink-server on TCP:$SERVER_PORT"
echo "  astralink-panel  on TCP:$PANEL_PORT"
echo
echo "Check:"
echo "  systemctl status astralink-server astralink-panel"

if [[ -n "$ADMIN_PASSWORD" ]]; then
  echo "Bootstrapping admin user..."
  curl -sS -X POST "http://127.0.0.1:$PANEL_PORT/api/bootstrap" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}" >/dev/null || true
  echo "Bootstrap request sent."
else
  cat <<EOF
Admin bootstrap command:
curl -X POST "http://127.0.0.1:$PANEL_PORT/api/bootstrap" \\
  -H "Content-Type: application/json" \\
  -d '{"username":"$ADMIN_USER","password":"StrongPassword123"}'
EOF
fi

