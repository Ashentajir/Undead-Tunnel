#!/usr/bin/env python3
import argparse
import json
import os
import secrets
import subprocess
import sys
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.abspath(__file__))
CLIENT_SCRIPT = os.path.join(ROOT, "dns_tunnel_client.py")
SERVER_SCRIPT = os.path.join(ROOT, "dns_tunnel_server.py")

CLIENT_DEFAULTS: Dict[str, Any] = {
    "domain": "t.example.com",
    "resolver": [],
    "resolvers_file": "",
    "upload_mtu": 220,
    "download_mtu": 512,
    "query_size": 220,
    "parallel_resolvers": 20,
    "channels": 8,
    "duplication": 1,
    "setup_duplication": 2,
    "query_timeout": 2.0,
    "check_transport": False,
    "proxy_mode": "socks",
    "proxy_host": "127.0.0.1",
    "proxy_port": 1080,
    "data": "GET / HTTP/1.1\\r\\nHost: test\\r\\n\\r\\n",
    "shared_key": "",
    "import_config": "",
}

SERVER_DEFAULTS: Dict[str, Any] = {
    "domain": "t.example.com",
    "domain_alias": [],
    "domains_file": "",
    "listen_host": "0.0.0.0",
    "listen_port": 53,
    "upstream_host": "127.0.0.1",
    "upstream_port": 80,
    "upstream_proto": "tcp",
    "upload_mtu": 220,
    "download_mtu": 512,
    "query_size": 220,
    "max_sessions": 100,
    "query_types": "NS,TXT,CNAME,MX,SRV",
    "setup": False,
    "setup_output": "undead_client_import.json",
    "shared_key": "",
}


def _run(script: str, args: List[str], dry_run: bool, env_extra: Optional[Dict[str, str]] = None) -> int:
    cmd = [sys.executable, script] + args
    print("[undead]", " ".join(cmd))
    if dry_run:
        print("[undead] dry-run: command not started")
        return 0
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)

    print("[undead] launching...")
    rc = subprocess.call(cmd, env=env)
    if rc == 0:
        print("[undead] status: success")
    else:
        print(f"[undead] status: failed (exit={rc})")
    return rc


def _load_import(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _load_json_config(path: str) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[undead] config load error: {e}")
        return {}


def _apply_json_config(args: argparse.Namespace, mode: str, defaults: Dict[str, Any]):
    cfg = _load_json_config(getattr(args, "config", ""))
    if not cfg:
        return

    section = cfg.get(mode, cfg)
    if not isinstance(section, dict):
        return

    for key, value in section.items():
        if not hasattr(args, key):
            continue
        if key == "extra":
            continue

        current = getattr(args, key)
        default = defaults.get(key)
        if current == default:
            setattr(args, key, value)


def _effective_client_config(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "domain": args.domain,
        "resolver": args.resolver,
        "resolvers_file": args.resolvers_file,
        "upload_mtu": args.upload_mtu,
        "download_mtu": args.download_mtu,
        "query_size": args.query_size,
        "parallel_resolvers": args.parallel_resolvers,
        "channels": args.channels,
        "duplication": args.duplication,
        "setup_duplication": args.setup_duplication,
        "query_timeout": args.query_timeout,
        "check_transport": args.check_transport,
        "proxy_mode": args.proxy_mode,
        "proxy_host": args.proxy_host,
        "proxy_port": args.proxy_port,
        "data": args.data,
        "import_config": args.import_config,
    }


def _effective_server_config(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "domain": args.domain,
        "domain_alias": args.domain_alias,
        "domains_file": args.domains_file,
        "listen_host": args.listen_host,
        "listen_port": args.listen_port,
        "upstream_host": args.upstream_host,
        "upstream_port": args.upstream_port,
        "upstream_proto": args.upstream_proto,
        "upload_mtu": args.upload_mtu,
        "download_mtu": args.download_mtu,
        "query_size": args.query_size,
        "max_sessions": args.max_sessions,
        "query_types": args.query_types,
        "setup": args.setup,
        "setup_output": args.setup_output,
    }


def _handle_config_io(args: argparse.Namespace, mode: str, effective_cfg: Dict[str, Any]) -> int:
    if getattr(args, "print_config", False):
        print(json.dumps({mode: effective_cfg}, indent=2))
        if not getattr(args, "write_config", ""):
            return 0

    write_path = getattr(args, "write_config", "")
    if write_path:
        with open(write_path, "w", encoding="utf-8") as f:
            json.dump({mode: effective_cfg}, f, indent=2)
        print(f"[undead] wrote config: {write_path}")
        return 0
    return -1


def _apply_import_to_client(args: argparse.Namespace) -> Dict[str, Any]:
    if not args.import_config:
        return {}
    cfg = _load_import(args.import_config)
    if not cfg:
        return {}

    client_cfg = cfg.get("client", {}) if isinstance(cfg.get("client", {}), dict) else {}
    key = str(cfg.get("shared_key", "")).strip()

    if args.domain == "t.example.com" and client_cfg.get("domain"):
        args.domain = str(client_cfg.get("domain"))
    if args.upload_mtu == 220 and client_cfg.get("upload_mtu") is not None:
        args.upload_mtu = int(client_cfg.get("upload_mtu"))
    if args.download_mtu == 512 and client_cfg.get("download_mtu") is not None:
        args.download_mtu = int(client_cfg.get("download_mtu"))
    if args.query_size == 220 and client_cfg.get("query_size") is not None:
        args.query_size = int(client_cfg.get("query_size"))
    if args.parallel_resolvers == 20 and client_cfg.get("parallel_resolvers") is not None:
        args.parallel_resolvers = int(client_cfg.get("parallel_resolvers"))
    if args.channels == 8 and client_cfg.get("channels") is not None:
        args.channels = int(client_cfg.get("channels"))
    if args.duplication == 1 and client_cfg.get("duplication") is not None:
        args.duplication = int(client_cfg.get("duplication"))
    if args.setup_duplication == 2 and client_cfg.get("setup_duplication") is not None:
        args.setup_duplication = int(client_cfg.get("setup_duplication"))
    if args.proxy_mode == "socks" and client_cfg.get("proxy_mode"):
        args.proxy_mode = str(client_cfg.get("proxy_mode"))
    if args.proxy_host == "127.0.0.1" and client_cfg.get("proxy_host"):
        args.proxy_host = str(client_cfg.get("proxy_host"))
    if args.proxy_port == 1080 and client_cfg.get("proxy_port") is not None:
        args.proxy_port = int(client_cfg.get("proxy_port"))

    if not args.resolver and isinstance(client_cfg.get("resolvers"), list):
        args.resolver = [str(x) for x in client_cfg.get("resolvers") if str(x).strip()]
    if not args.resolvers_file and client_cfg.get("resolvers_file"):
        args.resolvers_file = str(client_cfg.get("resolvers_file"))

    return {"UNDEAD_SHARED_KEY": key} if key else {}


def _build_server_setup_config(args: argparse.Namespace, shared_key: str) -> Dict[str, Any]:
    return {
        "version": 1,
        "shared_key": shared_key,
        "client": {
            "domain": args.domain,
            "upload_mtu": args.upload_mtu,
            "download_mtu": args.download_mtu,
            "query_size": args.query_size,
            "parallel_resolvers": 20,
            "channels": 8,
            "duplication": 1,
            "setup_duplication": 2,
            "proxy_mode": "socks",
            "proxy_host": "127.0.0.1",
            "proxy_port": 1080,
            "resolvers": [],
        },
        "server": {
            "domain": args.domain,
            "domain_alias": args.domain_alias,
            "domains_file": args.domains_file,
            "listen_host": args.listen_host,
            "listen_port": args.listen_port,
            "upstream_host": args.upstream_host,
            "upstream_port": args.upstream_port,
            "upstream_proto": args.upstream_proto,
            "upload_mtu": args.upload_mtu,
            "download_mtu": args.download_mtu,
            "query_size": args.query_size,
        },
    }


def _client_cmd(args: argparse.Namespace) -> int:
    _apply_json_config(args, "client", CLIENT_DEFAULTS)

    env_extra: Dict[str, str] = {}
    env_extra.update(_apply_import_to_client(args))
    if args.shared_key:
        env_extra["UNDEAD_SHARED_KEY"] = args.shared_key

    effective_cfg = _effective_client_config(args)
    cfg_io = _handle_config_io(args, "client", effective_cfg)
    if cfg_io == 0:
        return 0

    cmd: List[str] = [
        "--domain", args.domain,
        "--upload-mtu", str(args.upload_mtu),
        "--download-mtu", str(args.download_mtu),
        "--query-size", str(args.query_size),
        "--parallel-resolvers", str(args.parallel_resolvers),
        "--channels", str(args.channels),
        "--duplication", str(args.duplication),
        "--setup-duplication", str(args.setup_duplication),
        "--query-timeout", str(args.query_timeout),
    ]

    if args.resolvers_file:
        cmd += ["--resolvers-file", args.resolvers_file]
    for resolver in args.resolver:
        cmd += ["--resolver", resolver]

    if args.proxy_mode != "none":
        cmd += [
            "--proxy-mode", args.proxy_mode,
            "--proxy-host", args.proxy_host,
            "--proxy-port", str(args.proxy_port),
        ]
        scheme = "socks5" if args.proxy_mode == "socks" else "http"
        print(f"[undead] proxy endpoint: {scheme}://{args.proxy_host}:{args.proxy_port}")
    else:
        cmd += ["--data", args.data]

    if args.check_transport:
        cmd.append("--check-transport")

    cmd += args.extra
    return _run(CLIENT_SCRIPT, cmd, args.dry_run, env_extra=env_extra)


def _server_cmd(args: argparse.Namespace) -> int:
    _apply_json_config(args, "server", SERVER_DEFAULTS)

    env_extra: Dict[str, str] = {}
    shared_key = args.shared_key.strip() if args.shared_key else ""

    effective_cfg = _effective_server_config(args)
    cfg_io = _handle_config_io(args, "server", effective_cfg)
    if cfg_io == 0:
        return 0

    if args.setup:
        if not shared_key:
            shared_key = secrets.token_hex(16)
        cfg = _build_server_setup_config(args, shared_key)
        with open(args.setup_output, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        print(f"[undead] setup key: {shared_key}")
        print(f"[undead] client import config: {args.setup_output}")

    if shared_key:
        env_extra["UNDEAD_SHARED_KEY"] = shared_key

    cmd: List[str] = [
        "--domain", args.domain,
        "--listen-host", args.listen_host,
        "--listen-port", str(args.listen_port),
        "--upstream-host", args.upstream_host,
        "--upstream-port", str(args.upstream_port),
        "--upstream-proto", args.upstream_proto,
        "--upload-mtu", str(args.upload_mtu),
        "--download-mtu", str(args.download_mtu),
        "--query-size", str(args.query_size),
        "--max-sessions", str(args.max_sessions),
    ]

    for alias in args.domain_alias:
        cmd += ["--domain-alias", alias]
    if args.domains_file:
        cmd += ["--domains-file", args.domains_file]

    if args.query_types:
        cmd += ["--query-types", args.query_types]

    cmd += args.extra
    return _run(SERVER_SCRIPT, cmd, args.dry_run, env_extra=env_extra)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Undead Tunnel simple CLI")
    sub = parser.add_subparsers(dest="mode", required=True)

    client = sub.add_parser("client", help="Run DNS tunnel client")
    client.add_argument("--config", default="", help="Path to JSON config file")
    client.add_argument("--print-config", action="store_true", help="Print effective client config")
    client.add_argument("--write-config", default="", help="Write effective client config JSON and exit")
    client.add_argument("--domain", default="t.example.com")
    client.add_argument("--import-config", default="", help="Import JSON file generated by server --setup")
    client.add_argument("--shared-key", default="", help="Shared key (overrides import config key)")
    client.add_argument("--resolver", action="append", default=[], help="Resolver host[:port], repeatable")
    client.add_argument("--resolvers-file", default="")
    client.add_argument("--upload-mtu", type=int, default=220)
    client.add_argument("--download-mtu", type=int, default=512)
    client.add_argument("--query-size", type=int, default=220)
    client.add_argument("--parallel-resolvers", type=int, default=20)
    client.add_argument("--channels", type=int, default=8)
    client.add_argument("--duplication", type=int, default=1)
    client.add_argument("--setup-duplication", type=int, default=2)
    client.add_argument("--query-timeout", type=float, default=2.0)
    client.add_argument("--check-transport", action="store_true")
    client.add_argument("--proxy-mode", choices=["none", "http", "socks"], default="socks")
    client.add_argument("--proxy-host", default="127.0.0.1")
    client.add_argument("--proxy-port", type=int, default=1080)
    client.add_argument("--data", default="GET / HTTP/1.1\\r\\nHost: test\\r\\n\\r\\n")
    client.add_argument("--dry-run", action="store_true")
    client.add_argument("extra", nargs=argparse.REMAINDER, help="Extra args forwarded to dns_tunnel_client.py")
    client.set_defaults(func=_client_cmd)

    server = sub.add_parser("server", help="Run DNS tunnel server")
    server.add_argument("--config", default="", help="Path to JSON config file")
    server.add_argument("--print-config", action="store_true", help="Print effective server config")
    server.add_argument("--write-config", default="", help="Write effective server config JSON and exit")
    server.add_argument("--domain", default="t.example.com")
    server.add_argument("--domain-alias", action="append", default=[], help="Additional tunnel domain, repeatable")
    server.add_argument("--domains-file", default="", help="File with one domain per line")
    server.add_argument("--setup", action="store_true", help="Generate shared key + client import config before launch")
    server.add_argument("--setup-output", default="undead_client_import.json", help="Where to write generated client import config")
    server.add_argument("--shared-key", default="", help="Shared key (if omitted with --setup, a random key is generated)")
    server.add_argument("--listen-host", default="0.0.0.0")
    server.add_argument("--listen-port", type=int, default=53)
    server.add_argument("--upstream-host", default="127.0.0.1")
    server.add_argument("--upstream-port", type=int, default=80)
    server.add_argument("--upstream-proto", choices=["tcp", "udp"], default="tcp")
    server.add_argument("--upload-mtu", type=int, default=220)
    server.add_argument("--download-mtu", type=int, default=512)
    server.add_argument("--query-size", type=int, default=220)
    server.add_argument("--max-sessions", type=int, default=100)
    server.add_argument("--query-types", default="NS,TXT,CNAME,MX,SRV")
    server.add_argument("--dry-run", action="store_true")
    server.add_argument("extra", nargs=argparse.REMAINDER, help="Extra args forwarded to dns_tunnel_server.py")
    server.set_defaults(func=_server_cmd)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
