"""Cryptography layer.

* Pre-shared master key (32 bytes) is loaded on every node before deployment.
* A per-node key is derived with HKDF-SHA256 (info = node id).
* Messages are sealed with AES-256-GCM. Nonce = msg_id (unique per sender, time-seeded).
  AAD = sender_id || msg_id, so a packet cannot be re-attributed to another node.
* The plaintext carries a timestamp, giving a freshness window against delayed replays.
* ACKs are authenticated with a truncated HMAC-SHA256 under the acknowledger's node key.
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


class AuthError(Exception):
    """Tag mismatch: tampered data or wrong key."""


class StaleError(Exception):
    """Timestamp outside freshness window."""


def generate_master_key(path: str) -> None:
    with open(path, "wb") as f:
        f.write(os.urandom(KEY_LEN))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_master_key(path: str) -> bytes:
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != KEY_LEN:
        raise ValueError("master key must be 32 bytes")
    return key


def derive_node_key(master: bytes, node_id: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=SALT,
                info=b"node:" + struct.pack("!I", node_id)).derive(master)


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


def ack_tag(key: bytes, header: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(header)
    return h.finalize()[:16]


def verify_ack_tag(key: bytes, header: bytes, tag: bytes) -> bool:
    return hmac_lib.compare_digest(ack_tag(key, header), tag)
