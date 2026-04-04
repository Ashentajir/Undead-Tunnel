#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VENV_DIR="$ROOT_DIR/.venv"

printf "[install] project: %s\n" "$ROOT_DIR"
printf "[install] python:  %s\n" "$PYTHON_BIN"
printf "[install] bin dir: %s\n" "$INSTALL_DIR"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[install] python3 not found" >&2
  exit 1
fi

"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null

mkdir -p "$INSTALL_DIR"

cat > "$INSTALL_DIR/undead-client" <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python" "$ROOT_DIR/undead_cli.py" client "\$@"
EOF

cat > "$INSTALL_DIR/undead-server" <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python" "$ROOT_DIR/undead_cli.py" server "\$@"
EOF

chmod +x "$INSTALL_DIR/undead-client" "$INSTALL_DIR/undead-server"

printf "\n[install] done.\n"
printf "[install] commands:\n"
printf "  undead-server --domain t.example.com --upstream-host 127.0.0.1 --upstream-port 8080\n"
printf "  undead-client --domain t.example.com --resolver 1.1.1.1 --proxy-mode socks --proxy-port 1080\n"

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
  printf "\n[install] add this to your shell profile:\n"
  printf "export PATH=\"$INSTALL_DIR:\$PATH\"\n"
fi
