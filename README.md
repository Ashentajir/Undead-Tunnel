# Undead Tunnel

A lightweight DNS/NTP tunneling project with:

- DNS and NTP client/server pairs
- Shared transport core (`tunnel_core.py`)
- Resolver pooling and parallel send paths
- Optional local proxy mode on client side
- Simple unified CLI and Linux installer

<img width="612" height="1280" alt="project-diagram" src="https://github.com/user-attachments/assets/2e6d69e4-dc71-47d3-90fe-8230d706a110" />

---

## Project Files

- `tunnel_core.py` — shared encode/decode pipeline used by DNS/NTP
- `dns_tunnel_client.py` — DNS tunnel client
- `dns_tunnel_server.py` — DNS tunnel server
- `ntp_tunnel_client.py` — NTP tunnel client
- `ntp_tunnel_server.py` — NTP tunnel server
- `undead_cli.py` — simple launcher for client/server
- `install_linux.sh` — Linux setup helper
- `undead_client_config.json` — editable client config template
- `undead_server_config.json` — editable server config template

---

## Core Design Notes

### `tunnel_core.py`

- Uses a 32-bit block transport path for label-safe tunneling.
- Includes framing/deframing to preserve original payload boundaries.
- Adds optional compression when beneficial before transport packing.
- Adds authenticated encryption layer (via shared key env support).

### `dns_tunnel_client.py`

- Splits payload across covert DNS record types.
- Keeps vital chunks prioritized on `NS`.
- Supports resolver lists, channels, duplication, and parallel sends.
- Supports separate upload/download MTU and query-size limits.
- Supports local proxy mode (`socks` or `http`).

### `dns_tunnel_server.py`

- Listens on both UDP and TCP DNS paths.
- Enforces query/label/MTU safety limits.
- Handles session assembly and reply chunking.
- Supports configurable query types and session bounds.

---

## Simple CLI (`undead_cli.py`)

Run server:

```bash
python3 undead_cli.py server --domain t.example.com --upstream-host 127.0.0.1 --upstream-port 8080
```

Add multiple domains on server:

```bash
python3 undead_cli.py server --domain t.example.com --domain-alias a.example.com --domain-alias b.example.com
```

Or load domains from file (one domain per line):

```bash
python3 undead_cli.py server --domain t.example.com --domains-file domains.txt
```

Run client (SOCKS proxy):

```bash
python3 undead_cli.py client --domain t.example.com --resolver 1.1.1.1 --proxy-mode socks --proxy-port 1080
```

CLI behavior:

- Prints launch command and final status (`success` or `failed`).
- Prints proxy endpoint in proxy mode.

---

## Server Setup Export (Key + Client Import Config)

Generate setup from server side:

```bash
python3 undead_cli.py server --setup --setup-output undead_client_import.json --domain t.example.com
```

Use generated import config on client:

```bash
python3 undead_cli.py client --import-config undead_client_import.json --resolver 1.1.1.1
```

Optional key override:

```bash
python3 undead_cli.py client --shared-key <hex_or_text_key> ...
```

---

## Easy Settings Management (JSON)

You can edit settings (MTU, query size, resolvers, proxy, etc.) without touching code.

Use provided templates:

- `undead_client_config.json`
- `undead_server_config.json`

Run with config:

```bash
python3 undead_cli.py client --config undead_client_config.json
python3 undead_cli.py server --config undead_server_config.json
```

Print effective config (without running):

```bash
python3 undead_cli.py client --config undead_client_config.json --print-config
python3 undead_cli.py server --config undead_server_config.json --print-config
```

Write current flags into a config file:

```bash
python3 undead_cli.py client --upload-mtu 220 --query-size 220 --write-config my_client.json
python3 undead_cli.py server --upload-mtu 220 --query-size 220 --write-config my_server.json
```

---

## Linux Install

Install helper:

```bash
bash install_linux.sh
```

What it does:

- Creates `.venv`
- Installs launchers into `$HOME/.local/bin` (or `INSTALL_DIR`):
  - `undead-client`
  - `undead-server`

Then use:

```bash
undead-server --domain t.example.com --upstream-host 127.0.0.1 --upstream-port 8080
undead-client --domain t.example.com --resolver 1.1.1.1 --proxy-mode socks --proxy-port 1080
```

### Full server deployment (systemd)

Use deploy helper:

```bash
sudo bash deploy_server_linux.sh
```

Useful environment overrides:

```bash
sudo APP_USER=ubuntu DOMAIN=t.example.com DOMAIN_ALIASES="a.example.com,b.example.com" \
UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=8080 bash deploy_server_linux.sh
```

This script:

- installs launchers for the target user
- writes server config to `/etc/undead-tunnel/server.json`
- creates `systemd` service (`undead-tunnel.service` by default)
- enables and starts the service

---

## Notes

- Keep DNS query size conservative for stability on public resolvers.
- Compression helps only for compressible payloads.
- Proxy mode is intended for local app integration through the tunnel runtime.
