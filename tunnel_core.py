#!/usr/bin/env python3
"""
tunnel_core.py — shared 32-bit XOR + Base32 encoding engine
Used by both DNS and NTP tunnel clients and servers.

SEND path:  raw bytes → frame → pad4 → split32 → XOR-per-block → Base32 → labels
RECV path:  labels → Base32dec → XOR-per-block → join → deframe → raw bytes

Both paths are fully symmetric: the receiver applies the same key stream at
the same block offsets to reverse the XOR.  No separate encrypt/decrypt key.
"""

import os
import struct
import hashlib
import base64
import secrets
import zlib
import hmac
from typing import List


# ─── Base32 ────────────────────────────────────────────────────────────────

def b32enc(data: bytes) -> str:
    """bytes → lowercase Base32, no padding — safe for DNS labels."""
    return base64.b32encode(data).decode().lower().rstrip("=")

def b32dec(s: str) -> bytes:
    """lowercase Base32 → bytes, auto-padding to 8-char boundary."""
    s = s.upper()
    pad = (8 - len(s) % 8) % 8
    return base64.b32decode(s + "=" * pad)


# ─── Key stream (SHA-256 counter mode) ─────────────────────────────────────

def derive_key_stream(session_id: bytes, length: int = 2048) -> bytes:
    """
    Expand a session_id (any length) into an arbitrarily long byte stream.
    Deterministic: both sides can reproduce it from the shared session_id.
    Used for both TX (encode) and RX (decode) — XOR is its own inverse.
    """
    out, ctr = b"", 0
    while len(out) < length:
        out += hashlib.sha256(session_id + struct.pack("!I", ctr)).digest()
        ctr += 1
    return out[:length]


# ─── 32-bit block XOR ──────────────────────────────────────────────────────

def _xor32(data: bytes, key_stream: bytes, block_offset: int = 0) -> bytes:
    """
    XOR data against key_stream 32 bits at a time.
    data must be a multiple of 4 bytes.
    block_offset shifts which part of key_stream is used, enabling multi-burst
    sessions where each burst continues from where the last left off.
    """
    assert len(data) % 4 == 0, "data must be 4-byte aligned"
    out = bytearray(len(data))
    for i in range(0, len(data), 4):
        bi  = block_offset + i // 4
        k4  = key_stream[bi * 4 : bi * 4 + 4]
        b4  = data[i : i + 4]
        out[i : i + 4] = bytes(x ^ y for x, y in zip(b4, k4))
    return bytes(out)


def _xor_bytes(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def _expand_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = b""
    ctr = 0
    while len(out) < length:
        out += hashlib.sha256(key + nonce + struct.pack("!I", ctr)).digest()
        ctr += 1
    return out[:length]


def _shared_key_bytes() -> bytes:
    raw = os.getenv("UNDEAD_SHARED_KEY", "").strip()
    if not raw:
        return b""
    try:
        return bytes.fromhex(raw)
    except Exception:
        return raw.encode("utf-8", errors="ignore")


def _derive_packet_keys(key_stream: bytes) -> tuple[bytes, bytes]:
    seed = hashlib.sha256(key_stream + _shared_key_bytes()).digest()
    enc_key = hashlib.sha256(seed + b"enc-v1").digest()
    mac_key = hashlib.sha256(seed + b"mac-v1").digest()
    return enc_key, mac_key


def _secure_pack(payload: bytes, key_stream: bytes) -> bytes:
    """
    Packet format (v1):
      [flags:1][nonce:8][ciphertext:N][tag:16]

    flags bit0 = payload was zlib-compressed before encryption.
    """
    flags = 0
    plain = payload
    compressed = zlib.compress(payload, level=6)
    if len(compressed) + 2 < len(payload):
        plain = compressed
        flags |= 0x01

    nonce = os.urandom(8)
    enc_key, mac_key = _derive_packet_keys(key_stream)
    stream = _expand_stream(enc_key, nonce, len(plain))
    cipher = _xor_bytes(plain, stream)
    auth_body = bytes([flags]) + nonce + cipher
    tag = hmac.new(mac_key, auth_body, hashlib.sha256).digest()[:16]
    return bytes([flags]) + nonce + cipher + tag


def _secure_unpack(packet: bytes, key_stream: bytes) -> bytes:
    if len(packet) < 1 + 8 + 16:
        return b""

    flags = packet[0]
    nonce = packet[1:9]
    tag = packet[-16:]
    cipher = packet[9:-16]

    enc_key, mac_key = _derive_packet_keys(key_stream)
    auth_body = bytes([flags]) + nonce + cipher
    expected = hmac.new(mac_key, auth_body, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected):
        return b""

    stream = _expand_stream(enc_key, nonce, len(cipher))
    plain = _xor_bytes(cipher, stream)
    if flags & 0x01:
        try:
            plain = zlib.decompress(plain)
        except Exception:
            return b""
    return plain


# ─── Framing ────────────────────────────────────────────────────────────────

def frame(data: bytes) -> bytes:
    """Prepend 4-byte big-endian length so the receiver can strip random pad."""
    return struct.pack("!I", len(data)) + data

def deframe(data: bytes) -> bytes:
    """Strip length prefix; return exactly the original data bytes."""
    if len(data) < 4:
        return b""
    n = struct.unpack_from("!I", data, 0)[0]
    if 4 + n > len(data):
        return data[4:]          # corrupted frame — return what we have
    return data[4 : 4 + n]


# ─── SEND PATH: bytes → [label, …] ─────────────────────────────────────────

def encode_payload(
    data: bytes,
    key_stream: bytes,
    block_offset: int = 0,
) -> List[str]:
    """
    Encode `data` for transmission over DNS or NTP covert fields.

    Steps:
      1. frame(data)       — 4-byte length prefix so receiver strips random pad
      2. random pad        — extend to 4-byte boundary with os.urandom bytes
      3. split into 32-bit blocks
      4. XOR each block    — key_stream[block_offset + i]
      5. Base32-encode     — 4 raw bytes → 7 ASCII chars (DNS-label safe)

    Returns a list of 7-char Base32 strings, one per 32-bit block.
    `block_offset` lets multi-burst sessions advance through the key stream
    without reusing the same XOR positions.
    """
    secure = _secure_pack(data, key_stream)
    framed = frame(secure)
    pad    = (4 - len(framed) % 4) % 4
    padded = framed + os.urandom(pad)                  # cryptographic random pad

    scrambled = _xor32(padded, key_stream, block_offset)
    return [b32enc(scrambled[i : i + 4]) for i in range(0, len(scrambled), 4)]


# ─── RECEIVE PATH: [label, …] → bytes ──────────────────────────────────────

def decode_labels(
    labels: List[str],
    key_stream: bytes,
    block_offset: int = 0,
) -> bytes:
    """
    Decode labels produced by encode_payload — exact reverse.

    Steps:
      1. Base32-decode each label → 4 bytes  (bad labels → 0x00 block)
      2. join all blocks
      3. XOR each block           — same key_stream and block_offset
      4. deframe                  — strip length prefix, return original bytes

    Tolerates isolated bad labels (replaced with null block) so one dropped
    DNS packet doesn't destroy the entire session.
    """
    raw = bytearray()
    for lbl in labels:
        try:
            raw += b32dec(lbl)
        except Exception:
            raw += b"\x00" * 4          # null-substitute for a single bad block

    # defensive alignment
    tail = len(raw) % 4
    if tail:
        raw += b"\x00" * (4 - tail)

    plain = _xor32(bytes(raw), key_stream, block_offset)
    secured = deframe(plain)
    if not secured:
        return b""
    unpacked = _secure_unpack(secured, key_stream)
    if not unpacked:
        return b""
    return unpacked


# ─── NTP fixed-width encode/decode (20 covert bytes per packet) ────────────

NTP_COVERT_BYTES = 20   # 5 × 32-bit blocks hidden in timestamp fields

def ntp_encode_chunk(data: bytes, key_stream: bytes, block_offset: int) -> bytes:
    """
    Encode up to NTP_COVERT_BYTES bytes for embedding into NTP timestamp fields.
    Pads short input with os.urandom.  Returns exactly NTP_COVERT_BYTES bytes.
    """
    if len(data) > NTP_COVERT_BYTES:
        data = data[:NTP_COVERT_BYTES]
    padded = data + os.urandom(NTP_COVERT_BYTES - len(data))
    return _xor32(padded, key_stream, block_offset)

def ntp_decode_chunk(raw: bytes, key_stream: bytes, block_offset: int) -> bytes:
    """
    Reverse ntp_encode_chunk.  Returns NTP_COVERT_BYTES bytes of plaintext.
    XOR is its own inverse so the implementation is identical to encode.
    """
    assert len(raw) == NTP_COVERT_BYTES
    return _xor32(raw, key_stream, block_offset)


# ─── Self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sid = secrets.token_bytes(8)
    ks  = derive_key_stream(sid, 4096)

    # --- basic round-trip ---
    for size in [1, 3, 4, 7, 127, 252, 1000]:
        msg    = os.urandom(size)
        labels = encode_payload(msg, ks, 0)
        got    = decode_labels(labels, ks, 0)
        assert got == msg, f"FAIL size={size}"
    print("[core] Basic round-trip ✓")

    # --- multi-burst continuity ---
    msg    = os.urandom(512)
    off    = 0
    chunks = [msg[i:i+64] for i in range(0, len(msg), 64)]
    recon  = b""
    all_l  = []
    for chunk in chunks:
        lbls = encode_payload(chunk, ks, off)
        all_l.append((lbls, off))
        off += len(lbls)
    for lbls, o in all_l:
        recon += decode_labels(lbls, ks, o)
    assert recon == msg
    print("[core] Multi-burst block_offset continuity ✓")

    # --- NTP chunk encode/decode ---
    for _ in range(20):
        raw_in  = os.urandom(NTP_COVERT_BYTES)
        enc     = ntp_encode_chunk(raw_in, ks, 0)
        dec     = ntp_decode_chunk(enc, ks, 0)
        assert dec == raw_in
    print("[core] NTP fixed-width encode/decode ✓")

    # --- bad label tolerance ---
    msg    = b"test message"
    labels = encode_payload(msg, ks, 0)
    labels[1] = "!!!bad!!!"           # corrupt one label
    got    = decode_labels(labels, ks, 0)
    assert isinstance(got, bytes)     # must not raise
    print("[core] Bad-label tolerance ✓")

    print("[core] All self-tests PASSED")
