"""A secure node: sends sealed, fragmented messages and receives/verifies them over UDP."""
import collections
import logging
import queue
import random
import socket
import threading
import time

from . import crypto, protocol
from .protocol import Packet, T_ACK, T_DATA

log = logging.getLogger("securecomm")


class _SenderState:
    """Replay-protection state for one remote sender."""

    def __init__(self):
        self.highest = 0
        self.seen = set()
        self.order = collections.deque()

    def record(self, msg_id):
        self.highest = max(self.highest, msg_id)
        self.seen.add(msg_id)
        self.order.append(msg_id)
        if len(self.order) > 1024:
            self.seen.discard(self.order.popleft())


class Node:
    MAX_PENDING = 64
    REASSEMBLY_TTL = 30.0

    def __init__(self, node_id, master_key, host="127.0.0.1", port=0, peers=None,
                 frag_size=400, loss_rate=0.0, max_age=30.0):
        self.node_id = node_id
        self.master = master_key
        self.peers = set(peers) if peers is not None else None  # None = any holder of the key
        self.frag_size = frag_size
        self.loss_rate = loss_rate          # simulated radio loss on transmit (for testing)
        self.max_age = max_age

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]

        self.inbox = queue.Queue()
        self.stats = collections.Counter()
        self._keys = {}
        self._acks = {}
        self._ack_lock = threading.Lock()
        self._reasm = {}
        self._state = {}
        self._next_id = time.time_ns() // 1000   # time-seeded: stays monotonic across restarts
        self._running = False
        self._thread = None

    # ---------- lifecycle ----------
    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        self.sock.close()

    # ---------- helpers ----------
    def _key_for(self, node_id):
        if node_id not in self._keys:
            self._keys[node_id] = crypto.derive_node_key(self.master, node_id)
        return self._keys[node_id]

    def _tx(self, data, addr):
        if self.loss_rate and random.random() < self.loss_rate:
            self.stats["sim_tx_dropped"] += 1
            return
        try:
            self.sock.sendto(data, addr)
        except OSError:
            pass

    def _drop(self, reason, detail):
        self.stats[reason] += 1
        log.warning("DROP [%s] %s", reason, detail)

    def recv(self, timeout=None):
        """Returns (sender_id, plaintext_bytes) or None on timeout."""
        try:
            return self.inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    # ---------- sending ----------
    def send(self, dest_addr, dest_id, data: bytes, retries=5, timeout=1.0) -> bool:
        self._next_id += 1
        msg_id = self._next_id
        blob = crypto.encrypt_message(self._key_for(self.node_id), self.node_id, msg_id, data)
        parts = protocol.fragment(blob, self.frag_size)
        total = len(parts)
        ev = threading.Event()
        with self._ack_lock:
            self._acks[(dest_id, msg_id)] = ev
        try:
            for attempt in range(retries + 1):
                if attempt:
                    self.stats["retransmits"] += 1
                for i, part in enumerate(parts):
                    pkt = Packet(T_DATA, self.node_id, msg_id, i, total, part)
                    self._tx(protocol.pack(pkt), dest_addr)
                if ev.wait(timeout):
                    self.stats["sent_ok"] += 1
                    return True
            self.stats["send_failed"] += 1
            return False
        finally:
            with self._ack_lock:
                self._acks.pop((dest_id, msg_id), None)

    def _send_ack(self, to_sender, msg_id, addr):
        hdr = Packet(T_ACK, self.node_id, msg_id, 0, 1)
        tag = crypto.ack_tag(self._key_for(self.node_id), protocol.header_bytes(hdr))
        hdr.payload = tag
        self._tx(protocol.pack(hdr), addr)

    # ---------- receiving ----------
    def _rx_loop(self):
        while self._running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                pkt = protocol.unpack(data)
            except protocol.ProtocolError as e:
                self._drop("malformed", str(e))
                continue
            if pkt.ptype == T_DATA:
                self._handle_data(pkt, addr)
            else:
                self._handle_ack(pkt)

    def _handle_ack(self, pkt):
        hdr = protocol.header_bytes(Packet(T_ACK, pkt.sender_id, pkt.msg_id, 0, 1))
        if not crypto.verify_ack_tag(self._key_for(pkt.sender_id), hdr, pkt.payload):
            self._drop("bad_ack", f"from node {pkt.sender_id}")
            return
        with self._ack_lock:
            ev = self._acks.get((pkt.sender_id, pkt.msg_id))
        if ev:
            ev.set()

    def _purge(self):
        now = time.time()
        for k in [k for k, v in self._reasm.items() if now - v["ts"] > self.REASSEMBLY_TTL]:
            del self._reasm[k]

    def _handle_data(self, pkt, addr):
        s, m = pkt.sender_id, pkt.msg_id
        if self.peers is not None and s not in self.peers:
            self._drop("unknown_sender", f"node {s} is not authorised")
            return

        st = self._state.setdefault(s, _SenderState())
        if m in st.seen:                       # already delivered
            self._drop("replay_blocked", f"duplicate msg {m} from node {s}")
            self._send_ack(s, m, addr)         # idempotent re-ACK in case our ACK was lost
            return
        if m < st.highest:
            self._drop("replay_blocked", f"old msg {m} < {st.highest} from node {s}")
            return

        key = (s, m)
        buf = self._reasm.get(key)
        if buf is None:
            if len(self._reasm) >= self.MAX_PENDING:
                self._purge()
                if len(self._reasm) >= self.MAX_PENDING:
                    self._drop("overflow", "too many partial messages")
                    return
            buf = {"total": pkt.frag_total, "frags": {}, "ts": time.time()}
            self._reasm[key] = buf
        elif buf["total"] != pkt.frag_total:
            self._drop("malformed", "fragment count mismatch")
            return

        buf["frags"][pkt.frag_idx] = pkt.payload
        if len(buf["frags"]) < buf["total"]:
            return

        blob = b"".join(buf["frags"][i] for i in range(buf["total"]))
        del self._reasm[key]
        try:
            plain = crypto.decrypt_message(self._key_for(s), s, m, blob, self.max_age)
        except crypto.StaleError:
            self._drop("stale", f"msg {m} from node {s} outside freshness window")
            return
        except crypto.AuthError:
            self._drop("auth_failed", f"msg {m} from node {s} failed authentication")
            return

        st.record(m)
        self.stats["delivered"] += 1
        self.inbox.put((s, plain))
        self._send_ack(s, m, addr)
