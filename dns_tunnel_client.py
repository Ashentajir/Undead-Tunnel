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

import os, sys, time, random, struct, socket, threading, secrets, hashlib, base64, argparse
import concurrent.futures as cf
import socketserver
from dataclasses     import dataclass, field
from typing          import Callable, Dict, List, Optional, Tuple
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
UPLOAD_MTU         = 512    # max DNS query bytes over UDP before TCP fallback
DOWNLOAD_MTU       = 512    # max UDP DNS response bytes accepted client-side
QUERY_TIMEOUT_S    = 2.0
JITTER_MEAN_S      = 1.2    # seconds mean inter-burst delay (Gaussian)
JITTER_STD_S       = 0.4
SESSION_TIMEOUT_S  = 30.0
PARALLEL_RESOLVERS = 20
POLL_FANOUT        = 3
QUERY_MAX_BYTES    = 220
MAX_QNAME_SIZE     = 253
CHANNEL_COUNT      = 8
PROXY_BUFFER_SIZE  = 4096
PROXY_IO_TIMEOUT_S = 2.0
PACKET_DUPLICATION_COUNT = 1
SETUP_PACKET_DUPLICATION_COUNT = 2
RESOLVER_COOLDOWN_S = 20.0


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


COVERT_QUERY_TYPES = [RType.NS, RType.TXT, RType.CNAME, RType.MX, RType.SRV]


# ─── resolver pool ──────────────────────────────────────────────────────────

@dataclass
class Resolver:
    host:     str
    port:     int   = 53
    failures: int   = 0
    last_ok:  float = field(default_factory=time.time)
    disabled_until: float = 0.0

    @property
    def weight(self) -> float:
        """Higher failures → lower weight → used less."""
        return max(0.05, 1.0 / (1 + self.failures))

    def mark_ok(self):
        self.failures = max(0, self.failures - 1)
        self.last_ok  = time.time()
        self.disabled_until = 0.0

    def mark_fail(self):
        self.failures = min(self.failures + 1, 10)
        if self.failures >= 3:
            self.disabled_until = time.time() + RESOLVER_COOLDOWN_S

    def is_healthy(self) -> bool:
        return time.time() >= self.disabled_until


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
            pool = [r for r in self._pool if r.is_healthy()]
            if not pool:
                pool = self._pool
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

    def snapshot(self) -> List[Resolver]:
        with self._lock:
            return list(self._pool)


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

def _send_udp(pkt: bytes, resolver: Resolver, timeout: float = 2.0, recv_limit: int = 2048) -> Optional[bytes]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (resolver.host, resolver.port))
        resp, _ = s.recvfrom(max(512, recv_limit))
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
    upload_mtu: Optional[int] = None,
    download_mtu: Optional[int] = None,
    query_size: Optional[int] = None,
    query_timeout_s: Optional[float] = None,
    resolver_override: Optional[Resolver] = None,
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
    res  = resolver_override or pool.pick()

    # mandatory ms-range jitter before every send
    delay_ms = random.uniform(SEND_DELAY_MS_MIN, SEND_DELAY_MS_MAX)
    time.sleep(delay_ms / 1000.0)

    effective_upload_mtu = upload_mtu if upload_mtu is not None else UPLOAD_MTU
    effective_download_mtu = download_mtu if download_mtu is not None else DOWNLOAD_MTU
    effective_qsize = query_size if query_size is not None else QUERY_MAX_BYTES
    timeout_s = query_timeout_s if query_timeout_s is not None else QUERY_TIMEOUT_S

    if len(pkt) > effective_qsize:
        return None

    use_tcp = force_tcp or len(pkt) > effective_upload_mtu

    if not use_tcp:
        resp = _send_udp(pkt, res, timeout=timeout_s, recv_limit=effective_download_mtu)
        if resp is None:
            res.mark_fail()
            # retry once on a different resolver
            res2 = pool.pick()
            resp = _send_udp(pkt, res2, timeout=timeout_s, recv_limit=effective_download_mtu)
            if resp:
                res2.mark_ok()
        elif is_tc(resp):
            use_tcp = True   # server says it was truncated → retry via TCP

        if resp is not None and len(resp) > effective_download_mtu:
            resp = None
            res.mark_fail()

    if use_tcp:
        resp = _send_tcp(pkt, res, timeout=max(3.0, timeout_s * 2))
        if resp is None:
            res.mark_fail()
            res2 = pool.pick()
            resp = _send_tcp(pkt, res2, timeout=max(3.0, timeout_s * 2))
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
    chunk = label
    qname = f"{chunk}-{meta}.{TUNNEL_DOMAIN}"
    first, rest = qname.split(".", 1)
    if len(first) > 63:
        first = first[:63]
    qname = f"{first}.{rest}"
    if len(qname) > MAX_QNAME_SIZE:
        qname = qname[:MAX_QNAME_SIZE].rstrip(".")
    return qname


def build_channels(pool: ResolverPool, channels: int) -> List[Resolver]:
    resolvers = pool.snapshot()
    if not resolvers:
        return []
    random.shuffle(resolvers)
    channel_count = min(max(1, channels), 100)
    return [resolvers[i % len(resolvers)] for i in range(channel_count)]


# ─── NS reply builder (client-side) ──────────────────────────────────────────

def build_ns_query(qname: str, txid: int) -> bytes:
    """Build an NS query — this is what clients send to get vital reply data."""
    return build_query(qname, RType.NS, txid)


# ─── SEND: data → DNS burst ──────────────────────────────────────────────────

def send_payload(
    data: bytes,
    pool: ResolverPool,
    session: Optional[TunnelSession] = None,
    parallel_resolvers: Optional[int] = None,
    upload_mtu: Optional[int] = None,
    download_mtu: Optional[int] = None,
    query_size: Optional[int] = None,
    query_timeout_s: Optional[float] = None,
    query_types: Optional[List[int]] = None,
    channels: Optional[int] = None,
    packet_duplication_count: Optional[int] = None,
    setup_duplication_count: Optional[int] = None,
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

    # Assign labels across all enabled covert headers, with NS carrying vital priority.
    active_types = query_types[:] if query_types else COVERT_QUERY_TYPES[:]
    if not active_types:
        active_types = [RType.NS]

    ordered_types = list(dict.fromkeys(active_types))
    type_plan: List[int] = []
    if RType.NS in ordered_types:
        other_types = [t for t in ordered_types if t != RType.NS]
        vital_ns = min(n, max(1, (n * 3) // 5))
        type_plan.extend([RType.NS] * vital_ns)
        remain = n - vital_ns

        # ensure every other header type carries data when enough chunks exist
        for t in other_types:
            if remain <= 0:
                break
            type_plan.append(t)
            remain -= 1

        idx = 0
        while remain > 0:
            if other_types:
                type_plan.append(other_types[idx % len(other_types)])
                idx += 1
            else:
                type_plan.append(RType.NS)
            remain -= 1
    else:
        for i in range(n):
            type_plan.append(ordered_types[i % len(ordered_types)])

    covert_queries: List[Tuple[str, int, bool]] = []
    vital_ns = 0
    for t in type_plan:
        if t == RType.NS:
            vital_ns += 1
        else:
            break

    for seq, lbl in enumerate(labels):
        rtype = type_plan[seq]
        qname = _covert_qname(sid, seq, total, lbl, rtype)
        is_vital = (rtype == RType.NS and seq < vital_ns)
        covert_queries.append((qname, rtype, is_vital))

    # Decoy queries (A/AAAA) — blend with real traffic
    n_decoys = max(2, int(n * DECOY_RATIO))
    decoys   = [(_decoy_qname(), random.choice(RType.DECOY)) for _ in range(n_decoys)]

    # Interleave: covert + decoys, then shuffle (but keep first NS query first
    # so the server can establish the session before shards arrive)
    first_ns  = covert_queries[:1]
    rest_q    = covert_queries[1:] + [(q, t, False) for q, t in decoys]
    random.shuffle(rest_q)
    all_q     = first_ns + rest_q

    channel_resolvers = build_channels(pool, channels or CHANNEL_COUNT)
    workers = min(max(1, parallel_resolvers or PARALLEL_RESOLVERS), 100, max(1, len(pool)))

    first_qname, first_qtype, first_vital = all_q[0]
    first_resolver = channel_resolvers[0] if channel_resolvers else None
    setup_dup = max(1, setup_duplication_count or SETUP_PACKET_DUPLICATION_COUNT)
    normal_dup = max(1, packet_duplication_count or PACKET_DUPLICATION_COUNT)

    first_count = setup_dup if first_vital else normal_dup
    for _ in range(first_count):
        send_query(
            first_qname,
            first_qtype,
            pool,
            upload_mtu=upload_mtu,
            download_mtu=download_mtu,
            query_size=query_size,
            query_timeout_s=query_timeout_s,
            resolver_override=first_resolver,
        )

    remaining = all_q[1:]
    if remaining:
        scheduled: List[Tuple[str, int, Optional[Resolver]]] = []
        for idx, (qname, qtype, is_vital) in enumerate(remaining):
            resolver = None
            if channel_resolvers:
                resolver = channel_resolvers[idx % len(channel_resolvers)]
            dup = setup_dup if is_vital else normal_dup
            for _ in range(dup):
                scheduled.append((qname, qtype, resolver))

        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [
                ex.submit(send_query, qname, qtype, pool, False, upload_mtu, download_mtu, query_size, query_timeout_s, resolver)
                for qname, qtype, resolver in scheduled
            ]
            for fut in cf.as_completed(futures):
                _ = fut.result()

    return session


# ─── RECEIVE: poll for reply ─────────────────────────────────────────────────

def receive_reply(
    session: TunnelSession,
    pool: ResolverPool,
    expected_labels: int = 0,
    upload_mtu: Optional[int] = None,
    download_mtu: Optional[int] = None,
    query_size: Optional[int] = None,
    query_timeout_s: Optional[float] = None,
    poll_fanout: Optional[int] = None,
    channels: Optional[int] = None,
    packet_duplication_count: Optional[int] = None,
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
        time.sleep(RECV_POLL_DELAY_MS / 1000.0)

        fanout = min(max(1, poll_fanout or POLL_FANOUT), 100, max(1, len(pool)))
        fanout = fanout * max(1, packet_duplication_count or PACKET_DUPLICATION_COUNT)
        channel_resolvers = build_channels(pool, channels or CHANNEL_COUNT)
        if fanout == 1:
            chosen = channel_resolvers[attempt % len(channel_resolvers)] if channel_resolvers else None
            responses = [send_query(reply_qname, RType.NS, pool, upload_mtu=upload_mtu, download_mtu=download_mtu, query_size=query_size, query_timeout_s=query_timeout_s, resolver_override=chosen)]
        else:
            with cf.ThreadPoolExecutor(max_workers=fanout) as ex:
                futures = [
                    ex.submit(
                        send_query,
                        reply_qname,
                        RType.NS,
                        pool,
                        False,
                        upload_mtu,
                        download_mtu,
                        query_size,
                        query_timeout_s,
                        channel_resolvers[i % len(channel_resolvers)] if channel_resolvers else None,
                    )
                    for i in range(fanout)
                ]
                responses = [f.result() for f in cf.as_completed(futures)]

        for resp in responses:
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


def parse_resolver_entry(value: str) -> Optional[Tuple[str, int]]:
    value = value.strip()
    if not value or value.startswith("#"):
        return None
    host = value
    port = 53
    if ":" in value:
        host, p = value.rsplit(":", 1)
        try:
            port = int(p)
        except ValueError:
            port = 53
    host = host.strip()
    if not host:
        return None
    return host, port


def load_resolvers_file(path: str) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                entry = parse_resolver_entry(line)
                if entry:
                    out.append(entry)
    except Exception as e:
        print(f"[DNS] resolver file read error: {e}")
    return out


def check_transport_support(pool: ResolverPool, timeout_s: float = 1.5, probes: int = 6) -> Tuple[bool, bool]:
    test_qname = f"chk-{secrets.token_hex(2)}.{TUNNEL_DOMAIN}"
    pkt = build_query(test_qname, RType.A, random.randint(1, 0xFFFF))
    udp_ok = False
    tcp_ok = False
    resolvers = pool.snapshot()[:max(1, min(probes, len(pool)))]
    for resolver in resolvers:
        if not udp_ok:
            udp_ok = _send_udp(pkt, resolver, timeout=timeout_s) is not None
        if not tcp_ok:
            tcp_ok = _send_tcp(pkt, resolver, timeout=max(2.0, timeout_s * 2)) is not None
        if udp_ok and tcp_ok:
            break
    return udp_ok, tcp_ok


def tunnel_roundtrip(
    payload: bytes,
    pool: ResolverPool,
    parallel_resolvers: int,
    upload_mtu: int,
    download_mtu: int,
    query_size: int,
    query_timeout_s: float,
    query_types: List[int],
    poll_fanout: int,
    channels: int,
    packet_duplication_count: int,
    setup_duplication_count: int,
) -> bytes:
    session = TunnelSession()
    send_payload(
        payload,
        pool,
        session,
        parallel_resolvers=parallel_resolvers,
        upload_mtu=upload_mtu,
        download_mtu=download_mtu,
        query_size=query_size,
        query_timeout_s=query_timeout_s,
        query_types=query_types,
        channels=channels,
        packet_duplication_count=packet_duplication_count,
        setup_duplication_count=setup_duplication_count,
    )
    reply = receive_reply(
        session,
        pool,
        upload_mtu=upload_mtu,
        download_mtu=download_mtu,
        query_size=query_size,
        query_timeout_s=query_timeout_s,
        poll_fanout=poll_fanout,
        channels=channels,
        packet_duplication_count=packet_duplication_count,
    )
    return reply or b""


def run_http_proxy(listen_host: str, listen_port: int, roundtrip: Callable[[bytes], bytes], buffer_size: int, timeout_s: float):
    class _HTTPProxyHandler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(timeout_s)
            data = b""
            try:
                while True:
                    chunk = self.request.recv(buffer_size)
                    if not chunk:
                        break
                    data += chunk
                    if len(chunk) < buffer_size:
                        break
            except Exception:
                pass

            if not data:
                return

            reply = roundtrip(data)
            if reply:
                try:
                    self.request.sendall(reply)
                except Exception:
                    return

    class _Srv(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    server = _Srv((listen_host, listen_port), _HTTPProxyHandler)
    print(f"[DNS] HTTP proxy listening on {listen_host}:{listen_port}")
    server.serve_forever()


def run_socks_proxy(listen_host: str, listen_port: int, roundtrip: Callable[[bytes], bytes], buffer_size: int, timeout_s: float):
    class _SOCKSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(timeout_s)
            try:
                hello = self.request.recv(2)
                if len(hello) < 2 or hello[0] != 0x05:
                    return
                n_methods = hello[1]
                if n_methods:
                    _ = self.request.recv(n_methods)
                self.request.sendall(b"\x05\x00")

                req = self.request.recv(buffer_size)
                if len(req) < 7 or req[0] != 0x05:
                    return
                self.request.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

                while True:
                    chunk = self.request.recv(buffer_size)
                    if not chunk:
                        break
                    reply = roundtrip(chunk)
                    if reply:
                        self.request.sendall(reply)
            except Exception:
                return

    class _Srv(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    server = _Srv((listen_host, listen_port), _SOCKSHandler)
    print(f"[DNS] SOCKS5 proxy listening on {listen_host}:{listen_port}")
    server.serve_forever()


# ─── demo / entry point ──────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS tunnel client")
    parser.add_argument("--domain", default=TUNNEL_DOMAIN, help="Tunnel domain")
    parser.add_argument("--resolver", action="append", default=[], help="Resolver as host[:port], repeatable (max 100)")
    parser.add_argument("--resolvers-file", default="", help="File containing resolvers host[:port], one per line")
    parser.add_argument("--parallel-resolvers", type=int, default=PARALLEL_RESOLVERS, help="Parallel queries across resolver pool (1-100)")
    parser.add_argument("--channels", type=int, default=CHANNEL_COUNT, help="Number of resolver channels for load-splitting (1-100)")
    parser.add_argument("--poll-fanout", type=int, default=POLL_FANOUT, help="Parallel reply polls per attempt (1-100)")
    parser.add_argument("--mtu", type=int, default=None, help="Set both upload and download MTU")
    parser.add_argument("--upload-mtu", type=int, default=UPLOAD_MTU, help="Client upload MTU (query send path)")
    parser.add_argument("--download-mtu", type=int, default=DOWNLOAD_MTU, help="Client download MTU (response receive path)")
    parser.add_argument("--query-size", type=int, default=QUERY_MAX_BYTES, help="Max DNS query packet size in bytes")
    parser.add_argument("--max-qname-size", type=int, default=MAX_QNAME_SIZE, help="Max DNS query name length")
    parser.add_argument("--query-timeout", type=float, default=QUERY_TIMEOUT_S, help="Per-query timeout seconds")
    parser.add_argument("--query-types", default="NS,TXT,CNAME,MX,SRV", help="Covert query types CSV")
    parser.add_argument("--check-transport", action="store_true", help="Check UDP and TCP DNS transport support before sending")
    parser.add_argument("--proxy-mode", choices=["none", "http", "socks"], default="none", help="Run local proxy after startup")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="Local proxy bind host")
    parser.add_argument("--proxy-port", type=int, default=8080, help="Local proxy bind port")
    parser.add_argument("--proxy-buffer", type=int, default=PROXY_BUFFER_SIZE, help="Proxy socket read buffer")
    parser.add_argument("--proxy-timeout", type=float, default=PROXY_IO_TIMEOUT_S, help="Proxy I/O timeout seconds")
    parser.add_argument("--duplication", type=int, default=PACKET_DUPLICATION_COUNT, help="Normal packet duplication count")
    parser.add_argument("--setup-duplication", type=int, default=SETUP_PACKET_DUPLICATION_COUNT, help="Duplication for vital NS/setup packets")
    parser.add_argument("--resolver-cooldown", type=float, default=RESOLVER_COOLDOWN_S, help="Seconds to temporarily disable failing resolvers")
    parser.add_argument("--poll-delay-ms", type=int, default=RECV_POLL_DELAY_MS, help="Reply poll delay in milliseconds")
    parser.add_argument("--max-polls", type=int, default=RECV_MAX_POLLS, help="Maximum reply polls")
    parser.add_argument("--send-delay-min", type=int, default=SEND_DELAY_MS_MIN, help="Min send delay in ms")
    parser.add_argument("--send-delay-max", type=int, default=SEND_DELAY_MS_MAX, help="Max send delay in ms")
    parser.add_argument("--decoy-ratio", type=float, default=DECOY_RATIO, help="Decoy query ratio")
    parser.add_argument("--data", default="GET /secret HTTP/1.1\\r\\nHost: internal.lan\\r\\nX-Auth: token123\\r\\n\\r\\n", help="Payload string to send")
    args = parser.parse_args()

    TUNNEL_DOMAIN = args.domain
    if args.mtu is not None:
        UPLOAD_MTU = max(128, args.mtu)
        DOWNLOAD_MTU = max(128, args.mtu)
    else:
        UPLOAD_MTU = max(128, args.upload_mtu)
        DOWNLOAD_MTU = max(128, args.download_mtu)
    QUERY_TIMEOUT_S = max(0.2, args.query_timeout)
    PARALLEL_RESOLVERS = min(max(1, args.parallel_resolvers), 100)
    CHANNEL_COUNT = min(max(1, args.channels), 100)
    POLL_FANOUT = min(max(1, args.poll_fanout), 100)
    QUERY_MAX_BYTES = min(max(80, args.query_size), 512)
    MAX_QNAME_SIZE = min(max(64, args.max_qname_size), 253)
    RECV_POLL_DELAY_MS = max(1, args.poll_delay_ms)
    RECV_MAX_POLLS = max(1, args.max_polls)
    SEND_DELAY_MS_MIN = max(0, args.send_delay_min)
    SEND_DELAY_MS_MAX = max(SEND_DELAY_MS_MIN, args.send_delay_max)
    DECOY_RATIO = max(0.0, min(3.0, args.decoy_ratio))
    PROXY_BUFFER_SIZE = max(512, args.proxy_buffer)
    PROXY_IO_TIMEOUT_S = max(0.2, args.proxy_timeout)
    PACKET_DUPLICATION_COUNT = min(max(1, args.duplication), 8)
    SETUP_PACKET_DUPLICATION_COUNT = min(max(1, args.setup_duplication), 8)
    RESOLVER_COOLDOWN_S = max(1.0, args.resolver_cooldown)

    type_map = {
        "NS": RType.NS, "TXT": RType.TXT, "CNAME": RType.CNAME,
        "MX": RType.MX, "SRV": RType.SRV, "A": RType.A, "AAAA": RType.AAAA,
    }
    parsed_types = []
    for t in [x.strip().upper() for x in args.query_types.split(",") if x.strip()]:
        if t in type_map:
            parsed_types.append(type_map[t])
    COVERT_QUERY_TYPES = parsed_types if parsed_types else [RType.NS, RType.TXT, RType.CNAME, RType.MX, RType.SRV]

    resolvers: List[Tuple[str, int]] = DEFAULT_RESOLVERS[:]
    if args.resolvers_file:
        resolvers.extend(load_resolvers_file(args.resolvers_file))
    for item in args.resolver:
        parsed = parse_resolver_entry(item)
        if parsed:
            resolvers.append(parsed)
    resolvers = resolvers[:100]

    pool = ResolverPool(resolvers)
    print(f"[DNS] Resolver pool: {len(pool)} resolvers (parallel={PARALLEL_RESOLVERS}, channels={CHANNEL_COUNT}, poll_fanout={POLL_FANOUT})")
    print(f"[DNS] duplication normal={PACKET_DUPLICATION_COUNT} setup={SETUP_PACKET_DUPLICATION_COUNT} resolver_cooldown={RESOLVER_COOLDOWN_S:.1f}s")
    print(f"[DNS] MTU up={UPLOAD_MTU} down={DOWNLOAD_MTU} query_max={QUERY_MAX_BYTES} qname_max={MAX_QNAME_SIZE} timeout={QUERY_TIMEOUT_S:.2f}s types={[RType.NAMES.get(t, t) for t in COVERT_QUERY_TYPES]}")

    if args.check_transport:
        udp_ok, tcp_ok = check_transport_support(pool, QUERY_TIMEOUT_S)
        print(f"[DNS] transport support: udp={udp_ok} tcp={tcp_ok}")

    data = args.data.encode()

    roundtrip = lambda payload: tunnel_roundtrip(
        payload,
        pool,
        PARALLEL_RESOLVERS,
        UPLOAD_MTU,
        DOWNLOAD_MTU,
        QUERY_MAX_BYTES,
        QUERY_TIMEOUT_S,
        COVERT_QUERY_TYPES,
        POLL_FANOUT,
        CHANNEL_COUNT,
        PACKET_DUPLICATION_COUNT,
        SETUP_PACKET_DUPLICATION_COUNT,
    )

    if args.proxy_mode != "none":
        print(f"[DNS] proxy startup: mode={args.proxy_mode} bind={args.proxy_host}:{args.proxy_port}")
        if args.proxy_mode == "http":
            run_http_proxy(args.proxy_host, args.proxy_port, roundtrip, PROXY_BUFFER_SIZE, PROXY_IO_TIMEOUT_S)
        else:
            run_socks_proxy(args.proxy_host, args.proxy_port, roundtrip, PROXY_BUFFER_SIZE, PROXY_IO_TIMEOUT_S)
    else:
        sess = TunnelSession()
        print(f"\n[DNS] Sending {len(data)} bytes — session {sess.sid_hex}")
        sess = send_payload(
            data,
            pool,
            sess,
            parallel_resolvers=PARALLEL_RESOLVERS,
            upload_mtu=UPLOAD_MTU,
            download_mtu=DOWNLOAD_MTU,
            query_size=QUERY_MAX_BYTES,
            query_timeout_s=QUERY_TIMEOUT_S,
            query_types=COVERT_QUERY_TYPES,
            channels=CHANNEL_COUNT,
            packet_duplication_count=PACKET_DUPLICATION_COUNT,
            setup_duplication_count=SETUP_PACKET_DUPLICATION_COUNT,
        )
        print(f"[DNS] TX burst complete, block_offset={sess.block_offset}")
        print("[DNS] Polling for reply...")
        reply = receive_reply(
            sess,
            pool,
            upload_mtu=UPLOAD_MTU,
            download_mtu=DOWNLOAD_MTU,
            query_size=QUERY_MAX_BYTES,
            query_timeout_s=QUERY_TIMEOUT_S,
            poll_fanout=POLL_FANOUT,
            channels=CHANNEL_COUNT,
            packet_duplication_count=PACKET_DUPLICATION_COUNT,
        )
        if reply:
            print(f"[DNS] RX reply: {len(reply)} bytes — {reply[:80]!r}")
        else:
            print("[DNS] No reply (server not running — expected in standalone demo)")
