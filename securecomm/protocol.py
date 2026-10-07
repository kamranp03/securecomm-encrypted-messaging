"""Packet format and fragmentation.

Header (20 bytes, network byte order):
    magic(2) | version(1) | type(1) | sender_id(4) | msg_id(8) | frag_idx(2) | frag_total(2)
"""
import struct
from dataclasses import dataclass

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
    return Packet(ptype, sid, mid, idx, total, data[HDR_SIZE:])


def fragment(blob: bytes, size: int) -> list:
    if size < 1:
        raise ValueError("fragment size must be >= 1")
    parts = [blob[i:i + size] for i in range(0, len(blob), size)] or [b""]
    if len(parts) > MAX_FRAGMENTS:
        raise ValueError("message too large")
    return parts
