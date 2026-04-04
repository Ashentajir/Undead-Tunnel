#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-undead-tunnel}"
PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
APP_USER="${APP_USER:-${SUDO_USER:-$USER}}"
APP_HOME="$(eval echo "~${APP_USER}")"
CONFIG_DIR="${CONFIG_DIR:-/etc/undead-tunnel}"
CONFIG_PATH="${CONFIG_PATH:-$CONFIG_DIR/server.json}"
DOMAIN="${DOMAIN:-t.example.com}"
DOMAIN_ALIASES="${DOMAIN_ALIASES:-}"
DOMAINS_FILE="${DOMAINS_FILE:-}"
LISTEN_HOST="${LISTEN_HOST:-0.0.0.0}"
LISTEN_PORT="${LISTEN_PORT:-53}"
UPSTREAM_HOST="${UPSTREAM_HOST:-127.0.0.1}"
UPSTREAM_PORT="${UPSTREAM_PORT:-80}"
UPSTREAM_PROTO="${UPSTREAM_PROTO:-tcp}"
UPLOAD_MTU="${UPLOAD_MTU:-220}"
DOWNLOAD_MTU="${DOWNLOAD_MTU:-512}"
QUERY_SIZE="${QUERY_SIZE:-220}"
MAX_SESSIONS="${MAX_SESSIONS:-100}"
QUERY_TYPES="${QUERY_TYPES:-NS,TXT,CNAME,MX,SRV}"

if [[ $EUID -ne 0 ]]; then
  echo "[deploy] run as root (sudo)" >&2
  exit 1
fi

if ! id "$APP_USER" >/dev/null 2>&1; then
  echo "[deploy] user not found: $APP_USER" >&2
  exit 1
fi

echo "[deploy] project: $PROJECT_DIR"
echo "[deploy] app user: $APP_USER"
echo "[deploy] service: $SERVICE_NAME"

sudo -u "$APP_USER" bash "$PROJECT_DIR/install_linux.sh"

LAUNCHER="$APP_HOME/.local/bin/undead-server"
if [[ ! -x "$LAUNCHER" ]]; then
  echo "[deploy] launcher missing: $LAUNCHER" >&2
  exit 1
fi

mkdir -p "$CONFIG_DIR"

export CONFIG_PATH DOMAIN DOMAIN_ALIASES DOMAINS_FILE LISTEN_HOST LISTEN_PORT
export UPSTREAM_HOST UPSTREAM_PORT UPSTREAM_PROTO UPLOAD_MTU DOWNLOAD_MTU
export QUERY_SIZE MAX_SESSIONS QUERY_TYPES

python3 - <<'PY'
import json, os

aliases_raw = os.environ.get("DOMAIN_ALIASES", "").strip()
aliases = [x.strip() for x in aliases_raw.split(",") if x.strip()] if aliases_raw else []

cfg = {
    "server": {
        "domain": os.environ["DOMAIN"],
        "domain_alias": aliases,
        "domains_file": os.environ.get("DOMAINS_FILE", ""),
        "listen_host": os.environ["LISTEN_HOST"],
        "listen_port": int(os.environ["LISTEN_PORT"]),
        "upstream_host": os.environ["UPSTREAM_HOST"],
        "upstream_port": int(os.environ["UPSTREAM_PORT"]),
        "upstream_proto": os.environ["UPSTREAM_PROTO"],
        "upload_mtu": int(os.environ["UPLOAD_MTU"]),
        "download_mtu": int(os.environ["DOWNLOAD_MTU"]),
        "query_size": int(os.environ["QUERY_SIZE"]),
        "max_sessions": int(os.environ["MAX_SESSIONS"]),
        "query_types": os.environ["QUERY_TYPES"],
        "setup": False,
        "setup_output": "undead_client_import.json",
    }
}

with open(os.environ["CONFIG_PATH"], "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
print(f"[deploy] wrote config: {os.environ['CONFIG_PATH']}")
PY

SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Undead Tunnel DNS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${PROJECT_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart=${LAUNCHER} --config ${CONFIG_PATH}
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

echo "[deploy] service installed: ${SERVICE_NAME}"
echo "[deploy] status:"
systemctl --no-pager --full status "${SERVICE_NAME}.service" | sed -n '1,20p'
