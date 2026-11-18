"""Packet format and fragmentation.

Header (20 bytes, network byte order):
    magic(2) | version(1) | type(1) | sender_id(4) | msg_id(8) | frag_idx(2) | frag_total(2)

Payload rules (enforced by unpack):
    DATA: ciphertext fragment (>= 1 byte) || header_tag (TAG_LEN bytes)
    ACK:  header_tag (TAG_LEN bytes) exactly
Every packet therefore carries an HMAC-SHA256 over its own header, so no header
field can be altered without detection.
"""
import struct
from dataclasses import dataclass

from .crypto import TAG_LEN

MAGIC = b"SM"
VERSION = 1
T_DATA = 1
T_ACK = 2
HDR = struct.Struct("!2sBBIQHH")
HDR_SIZE = HDR.size
MAX_FRAGMENTS = 2048


class ProtocolError(Exception):
    pass


@dataclass
class Packet:
    ptype: int
    sender_id: int
    msg_id: int
    frag_idx: int
    frag_total: int
    payload: bytes = b""


def header_bytes(p: Packet) -> bytes:
    return HDR.pack(MAGIC, VERSION, p.ptype, p.sender_id, p.msg_id, p.frag_idx, p.frag_total)


def pack(p: Packet) -> bytes:
    return header_bytes(p) + p.payload


def unpack(data: bytes) -> Packet:
    if len(data) < HDR_SIZE:
        raise ProtocolError("too short")
    magic, ver, ptype, sid, mid, idx, total = HDR.unpack_from(data)
    if magic != MAGIC or ver != VERSION:
        raise ProtocolError("bad magic/version")
    if ptype not in (T_DATA, T_ACK):
        raise ProtocolError("bad type")
    if total < 1 or total > MAX_FRAGMENTS or idx >= total:
        raise ProtocolError("bad fragment fields")
    payload = data[HDR_SIZE:]
    if ptype == T_ACK:
        if len(payload) != TAG_LEN:
            raise ProtocolError("bad ack tag length")
        if idx != 0 or total != 1:
            raise ProtocolError("bad ack fragment fields")
    elif len(payload) <= TAG_LEN:
        raise ProtocolError("fragment carries no ciphertext")
    return Packet(ptype, sid, mid, idx, total, payload)


def split_tag(payload: bytes) -> tuple:
    """Split a DATA payload into (ciphertext fragment, header tag)."""
    return payload[:-TAG_LEN], payload[-TAG_LEN:]


def join_tag(body: bytes, tag: bytes) -> bytes:
    """Attach a header tag to a DATA payload."""
    return body + tag


def fragment(blob: bytes, size: int) -> list:
    if size < 1:
        raise ValueError("fragment size must be >= 1")
    parts = [blob[i:i + size] for i in range(0, len(blob), size)] or [b""]
    if len(parts) > MAX_FRAGMENTS:
        raise ValueError("message too large")
    return parts
