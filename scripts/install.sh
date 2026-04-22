#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/install.sh"
  exit 1
fi

APP_DIR="/opt/astralink"
SRC_DIR="$APP_DIR/src"
BIN_DIR="$APP_DIR/bin"
CFG_DIR="$APP_DIR/config"
DATA_DIR="$APP_DIR/data"
SYSTEMD_DIR="/etc/systemd/system"

REPO_URL="${REPO_URL:-https://github.com/IlyaMakeev0/AstraLink.git}"
BRANCH="${BRANCH:-main}"
SERVER_PORT="${SERVER_PORT:-8443}"
PANEL_PORT_LOCAL="${PANEL_PORT_LOCAL:-2096}"
ADMIN_USER="${ADMIN_USER:-admin}"

prompt_if_empty() {
  local var_name="$1"
  local prompt="$2"
  local secret="${3:-0}"
  local current="${!var_name:-}"
  if [[ -n "$current" ]]; then
    return
  fi
  if [[ "$secret" == "1" ]]; then
    read -r -s -p "$prompt: " value
    echo
  else
    read -r -p "$prompt: " value
  fi
  eval "$var_name=\"\$value\""
}

install_base_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y git curl ca-certificates build-essential pkg-config ufw caddy openssl
}

ensure_rust() {
  if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    return
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
}

prompt_if_empty PANEL_DOMAIN "Enter panel domain (example: panel.example.com)"
prompt_if_empty SUBSCRIPTION_DOMAIN "Enter subscription domain (example: sub.example.com)"
prompt_if_empty SUBSCRIPTION_SUB_DOMAIN "Enter priority subscription subdomain (example: api.sub.example.com, optional)"
prompt_if_empty ACME_EMAIL "Enter email for SSL (Let's Encrypt)"
prompt_if_empty ADMIN_PASSWORD "Enter admin password (min 8 chars)" 1
prompt_if_empty ENABLE_FRAGMENTATION "Enable fragmentation/jitter profile for transport? (y/N)"

if [[ -z "${PANEL_DOMAIN}" || -z "${SUBSCRIPTION_DOMAIN}" || -z "${ACME_EMAIL}" || -z "${ADMIN_PASSWORD}" ]]; then
  echo "Required values are missing."
  exit 1
fi

ENABLE_FRAGMENTATION="${ENABLE_FRAGMENTATION:-N}"
ENABLE_FRAGMENTATION="$(echo "$ENABLE_FRAGMENTATION" | tr '[:upper:]' '[:lower:]')"
if [[ "$ENABLE_FRAGMENTATION" == "y" || "$ENABLE_FRAGMENTATION" == "yes" || "$ENABLE_FRAGMENTATION" == "1" || "$ENABLE_FRAGMENTATION" == "true" ]]; then
  SHAPING_ENABLED=true
else
  SHAPING_ENABLED=false
fi

mkdir -p "$APP_DIR" "$BIN_DIR" "$CFG_DIR" "$DATA_DIR"
install_base_packages
ensure_rust
export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

if [[ ! -d "$SRC_DIR/.git" ]]; then
  git clone --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
else
  git -C "$SRC_DIR" fetch --all --prune
  git -C "$SRC_DIR" checkout "$BRANCH"
  git -C "$SRC_DIR" pull --ff-only
fi

cd "$SRC_DIR"
echo "Building AstraLink binaries..."
cargo build --release -p astralink-server -p astralink-client -p astralink-panel

install -m 0755 "$SRC_DIR/target/release/astralink-server" "$BIN_DIR/astralink-server"
install -m 0755 "$SRC_DIR/target/release/astralink-client" "$BIN_DIR/astralink-client"
install -m 0755 "$SRC_DIR/target/release/astralink-panel" "$BIN_DIR/astralink-panel"

if [[ ! -f "$CFG_DIR/server.json" ]]; then
  cp "$SRC_DIR/config/server.example.json" "$CFG_DIR/server.json"
fi
if [[ ! -f "$CFG_DIR/client.example.json" ]]; then
  cp "$SRC_DIR/config/client.example.json" "$CFG_DIR/client.example.json"
fi

if [[ ! -f "$CFG_DIR/transport.crt" || ! -f "$CFG_DIR/transport.key" ]]; then
  echo "Generating QUIC transport certificate..."
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$CFG_DIR/transport.key" \
    -out "$CFG_DIR/transport.crt" \
    -subj "/CN=$SUBSCRIPTION_DOMAIN" \
    -days 3650 >/dev/null 2>&1
fi

python3 - <<PY
import json, pathlib
cfg_path = pathlib.Path(r"$CFG_DIR/server.json")
if cfg_path.exists():
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        data = {}
else:
    data = {}
data.setdefault("users", {})
data["listen_host"] = "0.0.0.0"
data["listen_port"] = int("$SERVER_PORT")
data["quic_cert_path"] = "config/transport.crt"
data["quic_key_path"] = "config/transport.key"
data["quic_alpn"] = "astralink/2"
shaping_enabled = "${SHAPING_ENABLED}".lower() in ("1", "true", "yes", "y")
data["shaping"] = {
    "enabled": shaping_enabled,
    "min_chunk": 256,
    "max_chunk": 1400,
    "max_delay_ms": 8
}
cfg_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
PY

cat > "$CFG_DIR/client.example.json" <<EOF
{
  "server_host": "$SUBSCRIPTION_DOMAIN",
  "server_port": $SERVER_PORT,
  "server_name": "$SUBSCRIPTION_DOMAIN",
  "username": "replace_with_username",
  "psk": "replace_with_psk",
  "local_socks_host": "127.0.0.1",
  "local_socks_port": 1080,
  "ca_cert_path": "transport.crt",
  "quic_alpn": "astralink/2",
  "shaping": {
    "enabled": $SHAPING_ENABLED,
    "min_chunk": 256,
    "max_chunk": 1400,
    "max_delay_ms": 8,
    "fragment_hello": true
  }
}
EOF

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
Description=AstraLink React Panel API
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$BIN_DIR/astralink-panel --host 127.0.0.1 --port $PANEL_PORT_LOCAL --db $DATA_DIR/panel.db --runtime-server-config $CFG_DIR/server.json --restart-service astralink-server --public-host $SUBSCRIPTION_DOMAIN --public-port $SERVER_PORT --panel-domain $PANEL_DOMAIN --subscription-domain $SUBSCRIPTION_DOMAIN
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

if [[ -n "$SUBSCRIPTION_SUB_DOMAIN" ]]; then
  sed -i "s#--subscription-domain $SUBSCRIPTION_DOMAIN#--subscription-domain $SUBSCRIPTION_DOMAIN --subscription-sub-domain $SUBSCRIPTION_SUB_DOMAIN#g" "$SYSTEMD_DIR/astralink-panel.service"
fi

cat > /etc/caddy/Caddyfile <<EOF
{
  email $ACME_EMAIL
}

$PANEL_DOMAIN {
  encode gzip
  reverse_proxy 127.0.0.1:$PANEL_PORT_LOCAL
}

$SUBSCRIPTION_DOMAIN {
  encode gzip
  reverse_proxy 127.0.0.1:$PANEL_PORT_LOCAL
}
EOF

if [[ -n "$SUBSCRIPTION_SUB_DOMAIN" ]]; then
  cat >> /etc/caddy/Caddyfile <<EOF

$SUBSCRIPTION_SUB_DOMAIN {
  encode gzip
  reverse_proxy 127.0.0.1:$PANEL_PORT_LOCAL
}
EOF
fi

systemctl daemon-reload
systemctl enable --now astralink-server
systemctl enable --now astralink-panel
systemctl enable --now caddy
systemctl restart caddy

ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw allow "$SERVER_PORT/tcp" || true

sleep 2
curl -sS -X POST "http://127.0.0.1:$PANEL_PORT_LOCAL/api/bootstrap" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}" >/dev/null || true

echo
echo "AstraLink installation completed."
echo "Panel URL: https://$PANEL_DOMAIN"
echo "Admin login: $ADMIN_USER"
echo "Server transport port: $SERVER_PORT/tcp"
echo
echo "System status:"
systemctl --no-pager --full status astralink-server astralink-panel caddy | sed -n '1,60p'
