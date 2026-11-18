"""Cryptography layer.

* Pre-shared master key (32 bytes) is loaded on every node before deployment.
* Two per-node keys are derived with HKDF-SHA256:
    - a seal key   (info = "node:<id>")  used for AES-256-GCM message encryption
    - a header key (info = "hdr:<id>")   used for HMAC-SHA256 packet-header authentication
  Domain separation means the two keys are independent even though both come from
  the same master key.
* Messages are sealed with AES-256-GCM. Nonce = msg_id (unique per sender, strictly
  increasing under a lock, optionally persisted across restarts).
  AAD = sender_id || msg_id, so a packet cannot be re-attributed to another node.
* Every packet (DATA fragment and ACK) carries a truncated HMAC-SHA256 over its own
  20-byte header (+ the ciphertext for DATA), so no header field -- sender, msg_id,
  fragment index/count, type -- can be modified without detection.
* The plaintext carries a timestamp, giving a freshness window against delayed replays.
"""
import hmac as hmac_lib
import os
import struct
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32
SALT = b"securecomm-v1"
TAG_LEN = 16  # truncated HMAC-SHA256 tag size (128 bits)


class AuthError(Exception):
    """Tag mismatch: tampered data or wrong key."""


class StaleError(Exception):
    """Timestamp outside freshness window."""


def generate_master_key(path: str, force: bool = False) -> None:
    if os.path.exists(path) and not force:
        raise FileExistsError(
            f"{path} already exists; use --force to overwrite (overwriting invalidates "
            "every node that still holds the old key)")
    with open(path, "wb") as f:
        f.write(os.urandom(KEY_LEN))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_master_key(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            key = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(
            f"master key not found at {path!r} -- generate it first with: "
            f"python cli.py keygen --out {path}")
    if len(key) != KEY_LEN:
        raise ValueError("master key must be 32 bytes")
    return key


def derive_node_key(master: bytes, node_id: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=SALT,
                info=b"node:" + struct.pack("!I", node_id)).derive(master)


def derive_header_key(master: bytes, node_id: int) -> bytes:
    """Independent key for packet-header authentication (domain separated from the seal key)."""
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=SALT,
                info=b"hdr:" + struct.pack("!I", node_id)).derive(master)


def _aad(sender_id: int, msg_id: int) -> bytes:
    return struct.pack("!IQ", sender_id, msg_id)


def _nonce(msg_id: int) -> bytes:
    return struct.pack("!4xQ", msg_id)


def encrypt_message(key: bytes, sender_id: int, msg_id: int, plaintext: bytes,
                    timestamp: float = None) -> bytes:
    ts = time.time() if timestamp is None else timestamp
    body = struct.pack("!d", ts) + plaintext
    return AESGCM(key).encrypt(_nonce(msg_id), body, _aad(sender_id, msg_id))


def decrypt_message(key: bytes, sender_id: int, msg_id: int, blob: bytes,
                    max_age: float = 30.0) -> bytes:
    try:
        body = AESGCM(key).decrypt(_nonce(msg_id), blob, _aad(sender_id, msg_id))
    except InvalidTag:
        raise AuthError("authentication failed")
    if len(body) < 8:
        raise AuthError("malformed body")
    (ts,) = struct.unpack("!d", body[:8])
    if abs(time.time() - ts) > max_age:
        raise StaleError("message outside freshness window")
    return body[8:]


def header_tag(key: bytes, data: bytes) -> bytes:
    """Truncated HMAC-SHA256 over a packet header (+ ciphertext for DATA fragments)."""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()[:TAG_LEN]


def verify_header_tag(key: bytes, data: bytes, tag: bytes) -> bool:
    if len(tag) != TAG_LEN:
        return False
    return hmac_lib.compare_digest(header_tag(key, data), tag)
