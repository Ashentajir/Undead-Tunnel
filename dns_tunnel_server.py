#!/usr/bin/env python3
"""
DNS tunnel — server

Architecture
────────────
• Listens on both UDP/53 and TCP/53 simultaneously.
• Handles up to 100 concurrent client sessions.
• NS queries carry vital payload (session header + primary data chunks).
  TXT/CNAME/MX/SRV carry supporting shards.
• Decoy A/AAAA queries get plausible NXDOMAIN responses.
• On session completion: forwards reassembled payload to upstream TCP or UDP.
• Reply is 32-bit encoded and embedded as NS RDATA in the reply-<sid> response.
• Per-response send delay: 30–80 ms to look like a real authoritative server.
"""

import os, sys, time, random, struct, socket, threading, hashlib, base64, secrets, argparse
from dataclasses  import dataclass, field
from typing       import Dict, List, Optional, Tuple
from tunnel_core  import (
    derive_key_stream, encode_payload, decode_labels,
    b32enc, b32dec, frame, deframe,
)

# ─── config ──────────────────────────────────────────────────────────────────
TUNNEL_DOMAIN       = "t.example.com"
TUNNEL_DOMAINS      = [TUNNEL_DOMAIN]
LISTEN_HOST         = "0.0.0.0"
LISTEN_PORT         = 53
UPSTREAM_HOST       = "127.0.0.1"
UPSTREAM_PORT       = 80
UPSTREAM_PROTO      = "tcp"         # "tcp" or "udp"
SESSION_TTL_S       = 60.0
REPLY_DELAY_MS_MIN  = 30            # ms delay before sending each response
REPLY_DELAY_MS_MAX  = 80
REASSEMBLE_WAIT_S   = 0.5           # wait this long for straggler chunks
MAX_SESSIONS        = 100
UPLOAD_MTU          = 512
DOWNLOAD_MTU        = 512
ALLOWED_COVERT_QTYPES = {2, 16, 5, 15, 33}
MAX_QUERY_BYTES     = 220
MAX_QNAME_SIZE      = 253
MAX_LABEL_SIZE      = 48


# ─── record types ────────────────────────────────────────────────────────────
class RType:
    NS    = 2
    CNAME = 5
    MX    = 15
    TXT   = 16
    SRV   = 33
    A     = 1
    AAAA  = 28
    NAMES = {2:"NS",5:"CNAME",15:"MX",16:"TXT",33:"SRV",1:"A",28:"AAAA"}


def parse_qtypes(csv: str) -> set:
    mapping = {
        "NS": RType.NS,
        "TXT": RType.TXT,
        "CNAME": RType.CNAME,
        "MX": RType.MX,
        "SRV": RType.SRV,
        "A": RType.A,
        "AAAA": RType.AAAA,
    }
    out = set()
    for raw in csv.split(","):
        t = raw.strip().upper()
        if t in mapping:
            out.add(mapping[t])
    return out


def load_domains_file(path: str) -> List[str]:
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                out.append(value)
    except Exception as e:
        print(f"[SRV] domains file read error: {e}")
    return out


def _match_tunnel_domain(qname: str) -> Optional[Tuple[str, str]]:
    for domain in TUNNEL_DOMAINS:
        suffix = f".{domain}"
        if qname.endswith(suffix):
            return qname[: -len(suffix)], domain
    return None


# ─── DNS wire format helpers ─────────────────────────────────────────────────

def _encode_name(name: str) -> bytes:
    out = b""
    for part in name.rstrip(".").split("."):
        enc = part.encode()
        out += bytes([len(enc)]) + enc
    return out + b"\x00"

def parse_qname(data: bytes, offset: int) -> Tuple[str, int]:
    parts, visited = [], set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            sub, _ = parse_qname(data, ptr)
            parts.append(sub)
            offset += 2
            break
        offset += 1
        parts.append(data[offset : offset + length].decode(errors="replace"))
        offset += length
    return ".".join(parts), offset

def parse_question(data: bytes) -> Optional[Tuple[str, int, int]]:
    try:
        qname, off = parse_qname(data, 12)
        qtype, qclass = struct.unpack_from("!HH", data, off)
        return qname, qtype, qclass
    except Exception:
        return None

def get_txid(data: bytes) -> int:
    return struct.unpack_from("!H", data, 0)[0] if len(data) >= 2 else 0


# ─── response builders ────────────────────────────────────────────────────────

def _question_section(qname: str, qtype: int) -> bytes:
    return _encode_name(qname) + struct.pack("!HH", qtype, 1)

def build_nxdomain(query: bytes) -> bytes:
    """NXDOMAIN — used for decoys and unrecognised queries."""
    txid = get_txid(query)
    # flags: QR=1 AA=1 RCODE=3(NXDOMAIN)
    flags = struct.pack("!H", 0x8403)
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    res = parse_question(query)
    if res is None:
        return struct.pack("!H", txid) + flags + counts
    qname, qtype, _ = res
    q = _question_section(qname, qtype)
    return struct.pack("!H", txid) + flags + counts + q

def build_ns_response(query: bytes, ns_names: List[str], ttl: int = 1) -> bytes:
    """
    Build a DNS response with NS records in the answer section.
    Each ns_name becomes one NS RDATA entry.
    Used for both covert data delivery and reply transport.
    """
    txid = get_txid(query)
    res  = parse_question(query)
    if res is None:
        return build_nxdomain(query)
    qname, qtype, _ = res

    flags  = struct.pack("!H", 0x8400)   # QR=1 AA=1 RCODE=0
    counts = struct.pack("!HHHH", 1, len(ns_names), 0, 0)
    q_sec  = _question_section(qname, qtype)

    answers = b""
    for ns in ns_names:
        name_ptr = struct.pack("!H", 0xC00C)   # ptr to question QNAME
        ns_enc   = _encode_name(ns)
        ans_meta = struct.pack("!HHIH", RType.NS, 1, ttl, len(ns_enc))
        answers += name_ptr + ans_meta + ns_enc

    return struct.pack("!H", txid) + flags + counts + q_sec + answers

def build_txt_response(query: bytes, txt_strings: List[bytes], ttl: int = 1) -> bytes:
    """Build a DNS TXT response — used for shard acknowledgement."""
    txid = get_txid(query)
    res  = parse_question(query)
    if res is None:
        return build_nxdomain(query)
    qname, qtype, _ = res

    flags  = struct.pack("!H", 0x8400)
    counts = struct.pack("!HHHH", 1, len(txt_strings), 0, 0)
    q_sec  = _question_section(qname, qtype)

    answers = b""
    for txt in txt_strings:
        name_ptr = struct.pack("!H", 0xC00C)
        rdata    = bytes([len(txt)]) + txt
        ans_meta = struct.pack("!HHIH", RType.TXT, 1, ttl, len(rdata))
        answers += name_ptr + ans_meta + rdata

    return struct.pack("!H", txid) + flags + counts + q_sec + answers


# ─── covert query parser ──────────────────────────────────────────────────────

def parse_covert_label(qname: str) -> Optional[Tuple[str, int, int, str]]:
    """
    Parse a covert query name of the form:
      <b32label>-<sid8hex><seq3hex><total3hex>.<tunnel_domain>

    Returns (sid_hex, seq, total, b32_label) or None if not a covert query.
    """
    matched = _match_tunnel_domain(qname)
    if not matched:
        return None
    first, _ = matched

    # format: <label>-<sid8><seq3><total3>
    # meta is always 8+3+3 = 14 hex chars at the end after the last '-'
    dash = first.rfind("-")
    if dash < 0:
        return None
    label = first[:dash]
    meta  = first[dash + 1:]
    if len(label) > MAX_LABEL_SIZE:
        return None
    if len(meta) != 14:
        return None
    try:
        sid_hex = meta[:8]
        seq     = int(meta[8:11],  16)
        total   = int(meta[11:14], 16)
        bytes.fromhex(sid_hex)                # validate hex
        return sid_hex, seq, total, label
    except Exception:
        return None

def is_reply_query(qname: str) -> Optional[Tuple[str, str]]:
    """Return (sid_hex, matched_domain) if this is a reply-poll query, else None."""
    matched = _match_tunnel_domain(qname)
    if not matched:
        return None
    label, matched_domain = matched
    if label.startswith("reply-") and len(label) > 6:
        return label[6:], matched_domain
    return None


# ─── session state ────────────────────────────────────────────────────────────

@dataclass
class ServerSession:
    session_id:   bytes
    total:        int
    key_stream:   bytes          = field(init=False)
    chunks:       Dict[int, str] = field(default_factory=dict)  # seq → b32label
    created_at:   float          = field(default_factory=time.time)
    last_chunk:   float          = field(default_factory=time.time)
    complete:     bool           = False
    reply_labels: List[str]      = field(default_factory=list)
    reply_total:  int            = 0
    block_offset: int            = 0     # mirrors client's block_offset for RX key sync

    def __post_init__(self):
        self.key_stream = derive_key_stream(self.session_id, 8192)

    def add_chunk(self, seq: int, label: str):
        if seq not in self.chunks:
            self.chunks[seq]  = label
            self.last_chunk   = time.time()

    def all_arrived(self) -> bool:
        return len(self.chunks) >= self.total

    def reassemble_and_decode(self) -> Optional[bytes]:
        """32-bit decode the collected labels → original payload bytes."""
        if not self.chunks:
            return None
        ordered = [self.chunks[k] for k in sorted(self.chunks.keys())]
        return decode_labels(ordered, self.key_stream, self.block_offset)

    def encode_reply(self, reply_data: bytes) -> None:
        """32-bit encode reply for TX back to client via NS RDATA."""
        # advance block_offset past the rx labels so TX key doesn't overlap
        n_rx = len(self.chunks)
        labels = encode_payload(reply_data, self.key_stream, n_rx)
        self.reply_labels = labels
        self.reply_total  = len(labels)
        self.block_offset = n_rx + len(labels)

    def expired(self) -> bool:
        return (time.time() - self.created_at) > SESSION_TTL_S


_sessions: Dict[str, ServerSession] = {}
_lock     = threading.Lock()

def get_session(sid_hex: str, total: int) -> ServerSession:
    with _lock:
        if sid_hex not in _sessions:
            if len(_sessions) >= MAX_SESSIONS:
                # evict the oldest
                oldest = min(_sessions.items(), key=lambda kv: kv[1].created_at)[0]
                del _sessions[oldest]
            try:
                sid_bytes = bytes.fromhex(sid_hex)
            except ValueError:
                sid_bytes = sid_hex.encode()
            _sessions[sid_hex] = ServerSession(session_id=sid_bytes, total=total)
        return _sessions[sid_hex]

def cleanup_sessions():
    while True:
        time.sleep(15)
        with _lock:
            expired = [k for k, v in _sessions.items() if v.expired()]
            for k in expired:
                print(f"[SRV] Expiring session {k}")
                del _sessions[k]


# ─── upstream forwarding ─────────────────────────────────────────────────────

def forward_tcp(payload: bytes) -> bytes:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8.0)
        s.connect((UPSTREAM_HOST, UPSTREAM_PORT))
        s.sendall(payload)
        resp = b""
        while True:
            d = s.recv(8192)
            if not d:
                break
            resp += d
        s.close()
        return resp
    except Exception as e:
        print(f"[SRV] TCP upstream error: {e}")
        return b""

def forward_udp(payload: bytes) -> bytes:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4.0)
        s.sendto(payload, (UPSTREAM_HOST, UPSTREAM_PORT))
        resp, _ = s.recvfrom(65535)
        s.close()
        return resp
    except Exception as e:
        print(f"[SRV] UDP upstream error: {e}")
        return b""

def forward(payload: bytes) -> bytes:
    return forward_tcp(payload) if UPSTREAM_PROTO == "tcp" else forward_udp(payload)


# ─── request handler ──────────────────────────────────────────────────────────

def _ms_delay():
    """Apply a realistic authoritative-server response delay."""
    time.sleep(random.uniform(REPLY_DELAY_MS_MIN, REPLY_DELAY_MS_MAX) / 1000.0)

def handle_query(query: bytes) -> bytes:
    """
    Process one DNS query and return the response bytes.
    Called by both UDP and TCP handlers.
    """
    if len(query) > min(MAX_QUERY_BYTES, UPLOAD_MTU):
        return build_nxdomain(query)

    result = parse_question(query)
    if result is None:
        return build_nxdomain(query)

    qname, qtype, _ = result
    if len(qname) > MAX_QNAME_SIZE:
        return build_nxdomain(query)

    # ── Reply poll? ──
    sid_info = is_reply_query(qname)
    if sid_info:
        sid_hex, sid_domain = sid_info
        with _lock:
            sess = _sessions.get(sid_hex)
        _ms_delay()
        if sess and sess.reply_labels:
            # Serve reply chunks as NS RDATA
            # Format: <b32label>-<seq3hex><total3hex>.<tunnel_domain>
            ns_names = []
            for seq, lbl in enumerate(sess.reply_labels):
                meta = f"{seq:03x}{sess.reply_total:03x}"
                ns_names.append(f"{lbl}-{meta}.{sid_domain}")
            return build_ns_response(query, ns_names)
        return build_nxdomain(query)

    # ── Covert payload? ──
    parsed = parse_covert_label(qname)
    if parsed:
        if qtype not in ALLOWED_COVERT_QTYPES:
            _ms_delay()
            return build_nxdomain(query)

        sid_hex, seq, total, label = parsed
        rtype_name = RType.NAMES.get(qtype, f"TYPE{qtype}")
        print(f"[SRV] covert {rtype_name} sid={sid_hex} seq={seq}/{total}")

        sess = get_session(sid_hex, total)
        sess.add_chunk(seq, label)

        # Attempt reassemble if all chunks are in, or a short wait has passed
        if sess.all_arrived() and not sess.complete:
            _try_complete(sess, sid_hex)

        _ms_delay()
        # Always return NXDOMAIN — never distinguish covert from normal
        return build_nxdomain(query)

    # ── Decoy / unknown ──
    _ms_delay()
    return build_nxdomain(query)


def _try_complete(sess: ServerSession, sid_hex: str):
    """Reassemble + forward + encode reply (called under normal flow)."""
    with _lock:
        if sess.complete:
            return
        sess.complete = True

    payload = sess.reassemble_and_decode()
    if payload is None:
        return

    print(f"[SRV] session {sid_hex} complete — {len(payload)} B → upstream")
    reply = forward(payload)
    if not reply:
        reply = b"OK"

    sess.encode_reply(reply)
    print(f"[SRV] reply encoded — {len(sess.reply_labels)} labels")


# ─── UDP server ───────────────────────────────────────────────────────────────

class UDPHandler(threading.Thread):
    def __init__(self, sock: socket.socket, data: bytes, addr: tuple):
        super().__init__(daemon=True)
        self.sock = sock
        self.data = data
        self.addr = addr

    def run(self):
        resp = handle_query(self.data)
        # If response > UDP MTU, set TC flag and truncate.
        if len(resp) > DOWNLOAD_MTU:
            if len(resp) >= 4:
                flags = struct.unpack_from("!H", resp, 2)[0] | 0x0200  # TC=1
                resp = resp[:2] + struct.pack("!H", flags) + resp[4:DOWNLOAD_MTU]
        try:
            self.sock.sendto(resp, self.addr)
        except Exception:
            pass

def run_udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    print(f"[SRV] UDP/53 listening on {LISTEN_HOST}:{LISTEN_PORT}")
    recv_limit = max(512, min(MAX_QUERY_BYTES, UPLOAD_MTU))
    while True:
        try:
            data, addr = s.recvfrom(recv_limit)
            UDPHandler(s, data, addr).start()
        except Exception as e:
            print(f"[SRV] UDP recv error: {e}")


# ─── TCP server ───────────────────────────────────────────────────────────────

class TCPClientHandler(threading.Thread):
    def __init__(self, conn: socket.socket, addr: tuple):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr

    def run(self):
        try:
            self.conn.settimeout(10.0)
            while True:
                # DNS over TCP: 2-byte length prefix
                raw_len = self._recv_exact(2)
                if not raw_len:
                    break
                msg_len = struct.unpack("!H", raw_len)[0]
                if msg_len == 0:
                    break
                query = self._recv_exact(msg_len)
                if not query:
                    break
                resp = handle_query(query)
                framed = struct.pack("!H", len(resp)) + resp
                self.conn.sendall(framed)
        except Exception:
            pass
        finally:
            try:
                self.conn.close()
            except Exception:
                pass

    def _recv_exact(self, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.conn.recv(n - len(buf))
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

def run_tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(128)
    print(f"[SRV] TCP/53 listening on {LISTEN_HOST}:{LISTEN_PORT}")
    while True:
        try:
            conn, addr = s.accept()
            TCPClientHandler(conn, addr).start()
        except Exception as e:
            print(f"[SRV] TCP accept error: {e}")


# ─── straggler checker ────────────────────────────────────────────────────────

def straggler_checker():
    """
    Background thread: if a session hasn't received a new chunk in
    REASSEMBLE_WAIT_S seconds but is not yet complete, attempt reassembly
    with whatever chunks arrived (handles packet loss gracefully).
    """
    while True:
        time.sleep(0.25)
        now = time.time()
        with _lock:
            pending = [
                (k, v) for k, v in _sessions.items()
                if not v.complete and v.chunks
                   and (now - v.last_chunk) > REASSEMBLE_WAIT_S
            ]
        for sid_hex, sess in pending:
            print(f"[SRV] Straggler reassemble for {sid_hex} "
                  f"({len(sess.chunks)}/{sess.total} chunks)")
            _try_complete(sess, sid_hex)


# ─── entry point ─────────────────────────────────────────────────────────────

def main():
    global TUNNEL_DOMAIN, TUNNEL_DOMAINS, LISTEN_HOST, LISTEN_PORT, UPSTREAM_HOST, UPSTREAM_PORT
    global UPSTREAM_PROTO, SESSION_TTL_S, REPLY_DELAY_MS_MIN, REPLY_DELAY_MS_MAX
    global REASSEMBLE_WAIT_S, MAX_SESSIONS, UPLOAD_MTU, DOWNLOAD_MTU, ALLOWED_COVERT_QTYPES
    global MAX_QUERY_BYTES, MAX_QNAME_SIZE, MAX_LABEL_SIZE

    parser = argparse.ArgumentParser(description="DNS tunnel server")
    parser.add_argument("--domain", default=TUNNEL_DOMAIN, help="Tunnel domain")
    parser.add_argument("--domain-alias", action="append", default=[], help="Additional tunnel domain, repeatable")
    parser.add_argument("--domains-file", default="", help="File with one domain per line")
    parser.add_argument("--listen-host", default=LISTEN_HOST, help="Bind host")
    parser.add_argument("--listen-port", type=int, default=LISTEN_PORT, help="Bind port")
    parser.add_argument("--upstream-host", default=UPSTREAM_HOST, help="Upstream host")
    parser.add_argument("--upstream-port", type=int, default=UPSTREAM_PORT, help="Upstream port")
    parser.add_argument("--upstream-proto", choices=["tcp", "udp"], default=UPSTREAM_PROTO, help="Upstream protocol")
    parser.add_argument("--session-ttl", type=float, default=SESSION_TTL_S, help="Session TTL seconds")
    parser.add_argument("--max-sessions", type=int, default=MAX_SESSIONS, help="Max concurrent sessions")
    parser.add_argument("--reassemble-wait", type=float, default=REASSEMBLE_WAIT_S, help="Straggler reassembly wait seconds")
    parser.add_argument("--reply-delay-min", type=int, default=REPLY_DELAY_MS_MIN, help="Reply min delay ms")
    parser.add_argument("--reply-delay-max", type=int, default=REPLY_DELAY_MS_MAX, help="Reply max delay ms")
    parser.add_argument("--mtu", type=int, default=None, help="Set both upload and download MTU")
    parser.add_argument("--upload-mtu", type=int, default=UPLOAD_MTU, help="Server upload MTU (incoming query path)")
    parser.add_argument("--download-mtu", type=int, default=DOWNLOAD_MTU, help="Server download MTU (UDP response path)")
    parser.add_argument("--max-query-bytes", type=int, default=MAX_QUERY_BYTES, help="Maximum incoming DNS query packet size")
    parser.add_argument("--max-qname-size", type=int, default=MAX_QNAME_SIZE, help="Maximum DNS qname length")
    parser.add_argument("--query-size", type=int, default=MAX_QUERY_BYTES, help="Maximum incoming DNS query packet size")
    parser.add_argument("--max-label-size", type=int, default=MAX_LABEL_SIZE, help="Maximum covert label chars accepted")
    parser.add_argument("--query-types", default="NS,TXT,CNAME,MX,SRV", help="Allowed covert query types CSV")
    args = parser.parse_args()

    TUNNEL_DOMAIN = args.domain.strip()
    domain_list = [TUNNEL_DOMAIN]
    for d in args.domain_alias:
        value = d.strip()
        if value:
            domain_list.append(value)
    if args.domains_file:
        domain_list.extend(load_domains_file(args.domains_file))
    dedup: List[str] = []
    seen = set()
    for d in domain_list:
        if d and d not in seen:
            dedup.append(d)
            seen.add(d)
    TUNNEL_DOMAINS = dedup if dedup else [TUNNEL_DOMAIN]
    LISTEN_HOST = args.listen_host
    LISTEN_PORT = args.listen_port
    UPSTREAM_HOST = args.upstream_host
    UPSTREAM_PORT = args.upstream_port
    UPSTREAM_PROTO = args.upstream_proto
    SESSION_TTL_S = max(5.0, args.session_ttl)
    MAX_SESSIONS = min(max(1, args.max_sessions), 100)
    REASSEMBLE_WAIT_S = max(0.05, args.reassemble_wait)
    REPLY_DELAY_MS_MIN = max(0, args.reply_delay_min)
    REPLY_DELAY_MS_MAX = max(REPLY_DELAY_MS_MIN, args.reply_delay_max)
    if args.mtu is not None:
        UPLOAD_MTU = max(128, args.mtu)
        DOWNLOAD_MTU = max(128, args.mtu)
    else:
        UPLOAD_MTU = max(128, args.upload_mtu)
        DOWNLOAD_MTU = max(128, args.download_mtu)
    MAX_QUERY_BYTES = min(max(80, args.max_query_bytes), 512)
    MAX_QNAME_SIZE = min(max(64, args.max_qname_size), 253)
    MAX_QUERY_BYTES = min(MAX_QUERY_BYTES, min(max(80, args.query_size), 512))
    MAX_LABEL_SIZE = min(max(7, args.max_label_size), 63)
    ALLOWED_COVERT_QTYPES = parse_qtypes(args.query_types)
    if not ALLOWED_COVERT_QTYPES:
        ALLOWED_COVERT_QTYPES = {RType.NS, RType.TXT, RType.CNAME, RType.MX, RType.SRV}

    threading.Thread(target=cleanup_sessions,  daemon=True).start()
    threading.Thread(target=straggler_checker, daemon=True).start()

    # Start UDP and TCP servers in separate threads
    udp_thread = threading.Thread(target=run_udp_server, daemon=False)
    tcp_thread = threading.Thread(target=run_tcp_server, daemon=False)
    udp_thread.start()
    tcp_thread.start()

    print(f"[SRV] Upstream: {UPSTREAM_PROTO}://{UPSTREAM_HOST}:{UPSTREAM_PORT}")
    print(f"[SRV] Domains: {', '.join(TUNNEL_DOMAINS)}")
    print(f"[SRV] Max sessions: {MAX_SESSIONS}  TTL: {SESSION_TTL_S}s")
    print(f"[SRV] MTU up={UPLOAD_MTU} down={DOWNLOAD_MTU}  Allowed covert qtypes: {[RType.NAMES.get(t, t) for t in sorted(ALLOWED_COVERT_QTYPES)]}")
    print(f"[SRV] query limits: bytes={MAX_QUERY_BYTES} qname={MAX_QNAME_SIZE} label={MAX_LABEL_SIZE}")
    udp_thread.join()
    tcp_thread.join()

if __name__ == "__main__":
    main()
