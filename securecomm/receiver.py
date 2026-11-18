"""Shared receiver-side pipeline.

Both the UDP `Node` and the web demo drive this exact code, so the two can never
drift apart: whatever the admin dashboard shows is what a real receiver does.

Checks performed, in order (any failure = packet discarded):

    1. parse / validate the 20-byte header
    2. sender is an authorised peer            (unknown_sender)
    3. HMAC-SHA256 over the header verifies    (bad_header)   -- no header field
       (sender, msg_id, frag_idx/total, type) can be altered silently
    4. replay protection: msg_id not seen before and not older than the
       reorder window                          (replay_blocked / retransmit_acked)
    5. reassembly of all fragments             (malformed / overflow)
    6. AES-256-GCM authentication + freshness  (auth_failed / stale)
    7. deliver + build an authenticated ACK

Retransmissions of an already-delivered message are recognised (same source
address) and re-ACKed instead of being counted as an attack.
"""
import collections
import json
import logging
import os
import threading
import time

from . import crypto, protocol
from .protocol import Packet, T_ACK

log = logging.getLogger("securecomm")

REORDER_WINDOW = 512   # how far behind the newest message an older valid one may arrive
SEEN_CAPACITY = 1024   # delivered-id window; must stay strictly larger than REORDER_WINDOW
MAX_PENDING = 64       # concurrent partial messages
REASSEMBLY_TTL = 30.0  # seconds before a partial message is forgotten
STATE_VERSION = 1


class Outcome:
    """Result of feeding one packet into the pipeline.

    ok      -- True when a message was freshly delivered (or an ACK verified)
    reason  -- 'delivered', 'pending', or a drop reason (see stats keys)
    ack     -- Packet to transmit back (delivery receipt), or None
    plain   -- plaintext when ok and the packet was DATA
    """
    __slots__ = ("ok", "reason", "detail", "ack", "plain", "pkt")

    def __init__(self, ok, reason, detail="", ack=None, plain=None, pkt=None):
        self.ok = ok
        self.reason = reason
        self.detail = detail
        self.ack = ack
        self.plain = plain
        self.pkt = pkt

    def __repr__(self):
        return f"<Outcome ok={self.ok} reason={self.reason!r}>"


def hx(b, n=64):
    h = b.hex()
    return h if len(h) <= n * 2 else h[:n * 2] + "..."


def _addr_str(addr):
    return None if addr is None else f"{addr[0]}:{addr[1]}"


class _SenderState:
    """Replay-protection state for one remote sender."""

    def __init__(self):
        self.highest = 0
        self.seen = set()          # msg_ids already delivered
        self.order = collections.deque()
        self.addrs = {}            # msg_id -> source address of the original delivery

    def record(self, msg_id, addr=None):
        self.highest = max(self.highest, msg_id)
        self.seen.add(msg_id)
        self.order.append(msg_id)
        a = _addr_str(addr)
        if a is not None:
            self.addrs[msg_id] = a
        while len(self.order) > SEEN_CAPACITY:
            old = self.order.popleft()
            self.seen.discard(old)
            self.addrs.pop(old, None)

    def dump(self):
        return {"highest": self.highest, "seen": list(self.order),
                "addrs": dict(self.addrs)}

    def load(self, d):
        self.highest = int(d.get("highest", 0))
        self.order = collections.deque(int(x) for x in d.get("seen", ()))
        self.seen = set(self.order)
        self.addrs = {int(k): v for k, v in d.get("addrs", {}).items()}


class ReceiverState:
    """Authorisation, replay protection, reassembly and AEAD opening."""

    def __init__(self, master, peers=None, local_id=None, max_age=30.0,
                 stats=None, reorder_window=REORDER_WINDOW):
        self.master = master
        self.peers = set(peers) if peers is not None else None
        self.local_id = local_id          # node id used when signing ACKs
        self.max_age = max_age
        self.reorder_window = reorder_window
        self.stats = stats if stats is not None else collections.Counter()
        self._seal = {}
        self._hdr = {}
        self._reasm = {}
        self._senders = {}
        self._lock = threading.Lock()

    # ---------- keys ----------
    def seal_key(self, node_id):
        if node_id not in self._seal:
            self._seal[node_id] = crypto.derive_node_key(self.master, node_id)
        return self._seal[node_id]

    def header_key(self, node_id):
        if node_id not in self._hdr:
            self._hdr[node_id] = crypto.derive_header_key(self.master, node_id)
        return self._hdr[node_id]

    # ---------- persistence ----------
    def dump_state(self):
        with self._lock:
            return {str(s): st.dump() for s, st in self._senders.items()}

    def load_state(self, data):
        with self._lock:
            for s, d in (data or {}).items():
                try:
                    sid = int(s)
                except (TypeError, ValueError):
                    continue
                st = self._senders.setdefault(sid, _SenderState())
                st.load(d)

    def reset(self):
        """Forget all replay state and partial messages (admin 'clear log')."""
        with self._lock:
            self._senders.clear()
            self._reasm.clear()
            self.stats.clear()

    # ---------- helpers ----------
    @staticmethod
    def _step(trace, name, status, detail):
        if trace is not None:
            trace.append((name, status, detail))

    def _drop(self, reason, detail):
        self.stats[reason] += 1
        log.warning("DROP [%s] %s", reason, detail)
        return Outcome(False, reason, detail)

    def _build_ack(self, msg_id):
        if self.local_id is None:
            return None
        pkt = Packet(T_ACK, self.local_id, msg_id, 0, 1)
        pkt.payload = crypto.header_tag(self.header_key(self.local_id),
                                        protocol.header_bytes(pkt))
        return pkt

    # ---------- pipeline ----------
    def ingest_raw(self, data, addr=None, trace=None):
        """Parse one raw datagram and run it through the pipeline."""
        try:
            pkt = protocol.unpack(data)
        except protocol.ProtocolError as e:
            self._step(trace, "Parse header", "fail", f"Malformed packet: {e}")
            return self._drop("malformed", str(e))
        return self.ingest(pkt, addr, trace)

    def ingest(self, pkt, addr=None, trace=None):
        with self._lock:
            out = self._run(pkt, addr, trace)
        out.pkt = pkt
        return out

    def _run(self, pkt, addr, trace):
        s, m = pkt.sender_id, pkt.msg_id

        # 1. authorised sender
        if self.peers is not None and s not in self.peers:
            self._step(trace, "Sender check", "fail",
                       f"Node {s} is NOT an authorised peer -> packet discarded")
            return self._drop("unknown_sender", f"node {s} is not authorised")

        # 2. header authentication (applies to DATA fragments and ACKs alike)
        hdr = protocol.header_bytes(pkt)
        if pkt.ptype == T_ACK:
            if not crypto.verify_header_tag(self.header_key(s), hdr, pkt.payload):
                self._step(trace, "Header HMAC", "fail",
                           "Delivery receipt is not authentic -> DISCARDED")
                return self._drop("bad_ack", f"from node {s}")
            return Outcome(True, "ack_ok", "ack tag verified")

        ct, tag = protocol.split_tag(pkt.payload)
        if not crypto.verify_header_tag(self.header_key(s), hdr, tag):
            self._step(trace, "Header HMAC", "fail",
                       "HMAC-SHA256 over the 20-byte header does not verify -> "
                       "a header field (sender, msg_id, fragment index/count, type) "
                       "was modified -> DISCARDED")
            return self._drop("bad_header",
                              f"header authentication failed for msg {m} from node {s}")

        # 3. replay protection
        st = self._senders.get(s)
        if st is None:
            st = self._senders[s] = _SenderState()

        if m in st.seen:
            if addr is not None and st.addrs.get(m) == _addr_str(addr):
                # same source as the original delivery: a lost-ACK retransmission
                self.stats["retransmit_acked"] += 1
                log.info("retransmit of msg %s from node %s (already delivered) -> re-ACK",
                         m, s)
                self._step(trace, "Replay check", "ok",
                           f"msg_id {m} already delivered, same source -> "
                           "idempotent re-ACK (not an attack)")
                return Outcome(False, "retransmit_acked",
                               "retransmission of an already-delivered message",
                               ack=self._build_ack(m))
            self._step(trace, "Replay check", "fail",
                       f"msg_id {m} already seen (highest={st.highest}) -> REPLAY BLOCKED")
            return self._drop("replay_blocked",
                              f"duplicate msg {m} from node {s}")

        if st.highest - m > self.reorder_window:
            self._step(trace, "Replay check", "fail",
                       f"msg_id {m} is older than the replay window "
                       f"(highest={st.highest}) -> REPLAY BLOCKED")
            return self._drop("replay_blocked",
                              f"old msg {m} < {st.highest} from node {s}")

        # 4. reassembly
        key = (s, m)
        buf = self._reasm.get(key)
        if buf is None:
            if len(self._reasm) >= MAX_PENDING:
                self._purge()
                if len(self._reasm) >= MAX_PENDING:
                    return self._drop("overflow", "too many partial messages")
            buf = {"total": pkt.frag_total, "frags": {}, "ts": time.time()}
            self._reasm[key] = buf
        elif buf["total"] != pkt.frag_total:
            return self._drop("malformed", "fragment count mismatch")

        buf["frags"][pkt.frag_idx] = ct
        if len(buf["frags"]) < buf["total"]:
            return Outcome(False, "pending", "waiting for remaining fragments")

        # 5. every fragment present -> open the AEAD seal
        blob = b"".join(buf["frags"][i] for i in range(buf["total"]))
        del self._reasm[key]

        self._step(trace, "Parse header", "ok",
                   f"magic=SM v1, sender={s}, msg_id={m}, {buf['total']} fragment(s)")
        self._step(trace, "Sender check", "ok", f"Node {s} is an authorised peer")
        self._step(trace, "Header HMAC", "ok",
                   "HMAC-SHA256 verified on every fragment: no header field was modified")
        self._step(trace, "Replay check", "ok",
                   f"msg_id {m} is new (counter within window, not seen before)")
        self._step(trace, "Reassemble", "ok",
                   f"{buf['total']} fragments -> {len(blob)} byte ciphertext\n{hx(blob)}")

        try:
            plain = crypto.decrypt_message(self.seal_key(s), s, m, blob, self.max_age)
        except crypto.StaleError:
            self._step(trace, "Freshness", "fail",
                       f"Timestamp outside {self.max_age:.0f}s window -> DISCARDED")
            return self._drop("stale", f"msg {m} from node {s} outside freshness window")
        except crypto.AuthError:
            self._step(trace, "AES-GCM verify", "fail",
                       "GCM auth tag mismatch -> data tampered or wrong key -> DISCARDED")
            return self._drop("auth_failed",
                              f"msg {m} from node {s} failed authentication")

        self._step(trace, "AES-GCM verify", "ok",
                   "Auth tag valid -> integrity + authenticity confirmed")
        self._step(trace, "Freshness", "ok",
                   f"Timestamp within {self.max_age:.0f}s window")

        st.record(m, addr)
        self.stats["delivered"] += 1
        ack = self._build_ack(m)
        tag_hex = ack.payload.hex() if ack is not None else "n/a"
        self._step(trace, "Decrypt + ACK", "ok",
                   f'Plaintext: "{plain.decode(errors="replace")}"\n'
                   f"HMAC ACK sent: {tag_hex}")
        return Outcome(True, "delivered", "delivered", ack=ack, plain=plain)

    def _purge(self):
        now = time.time()
        for k in [k for k, v in self._reasm.items() if now - v["ts"] > REASSEMBLY_TTL]:
            del self._reasm[k]


def load_state_file(path):
    """Read a persisted replay/id state file; returns {} when absent or corrupt."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
            return {}
        return data
    except (OSError, ValueError):
        return {}


def save_state_file(path, data):
    """Atomic write so a crash mid-save cannot corrupt the state file."""
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except OSError:
        pass
