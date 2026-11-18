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
from .receiver import (MAX_PENDING, REASSEMBLY_TTL, REORDER_WINDOW,  # noqa: F401
                       STATE_VERSION, ReceiverState, load_state_file,
                       save_state_file)

log = logging.getLogger("securecomm")


class Node:
    def __init__(self, node_id, master_key, host="127.0.0.1", port=0, peers=None,
                 frag_size=400, loss_rate=0.0, max_age=30.0, state_file=None,
                 reorder_window=None):
        self.node_id = node_id
        self.master = master_key
        self.peers = set(peers) if peers is not None else None  # None = any holder of the key
        self.frag_size = frag_size
        self.loss_rate = loss_rate          # simulated radio loss on transmit (for testing)
        self.max_age = max_age
        self.state_file = state_file        # persist msg_id high-water + replay state (optional)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]

        self.inbox = queue.Queue()
        self.stats = collections.Counter()
        rx_kw = {} if reorder_window is None else {"reorder_window": reorder_window}
        self.rx = ReceiverState(master_key, peers=self.peers, local_id=node_id,
                                max_age=max_age, stats=self.stats, **rx_kw)
        self._acks = {}
        self._ack_lock = threading.Lock()
        self._id_lock = threading.Lock()     # guards _next_id (and state saving)
        self._next_id = time.time_ns() // 1000   # time-seeded: stays monotonic across restarts
        self._running = False
        self._thread = None
        self._load_state()

    # ---------- lifecycle ----------
    def start(self):
        if self._running:
            return self
        self._running = True
        self._thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._running = False
        t, self._thread = self._thread, None
        if t and t is not threading.current_thread():
            t.join(timeout=1)
        try:
            self.sock.close()
        except OSError:
            pass

    # ---------- state persistence ----------
    def _load_state(self):
        if not self.state_file:
            return
        data = load_state_file(self.state_file)
        if not data:
            return
        if data.get("node_id") not in (None, self.node_id):
            log.warning("state file %s belongs to node %s, ignoring it",
                        self.state_file, data.get("node_id"))
            return
        # msg ids must never repeat for this node id (AES-GCM nonce uniqueness)
        self._next_id = max(self._next_id, int(data.get("next_id", 0)) + 1)
        self.rx.load_state(data.get("senders", {}))

    def _save_state(self):
        """Called with _id_lock held; rx.dump_state() takes its own lock."""
        if not self.state_file:
            return
        save_state_file(self.state_file, {
            "version": STATE_VERSION,
            "node_id": self.node_id,
            "next_id": self._next_id,
            "senders": self.rx.dump_state(),
        })

    # ---------- helpers ----------
    def _alloc_id(self):
        """Allocate a fresh msg_id; unique per node id across threads and restarts."""
        with self._id_lock:
            self._next_id += 1
            self._save_state()
            return self._next_id

    def _tx(self, data, addr):
        if self.loss_rate and random.random() < self.loss_rate:
            self.stats["sim_tx_dropped"] += 1
            return
        try:
            self.sock.sendto(data, addr)
        except OSError:
            self.stats["tx_error"] += 1

    def recv(self, timeout=None):
        """Returns (sender_id, plaintext_bytes) or None on timeout."""
        try:
            return self.inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    # ---------- sending ----------
    def send(self, dest_addr, dest_id, data: bytes, retries=5, timeout=1.0) -> bool:
        msg_id = self._alloc_id()
        blob = crypto.encrypt_message(self.rx.seal_key(self.node_id), self.node_id,
                                      msg_id, data)
        parts = protocol.fragment(blob, self.frag_size)
        total = len(parts)
        hdr_key = self.rx.header_key(self.node_id)
        ev = threading.Event()
        with self._ack_lock:
            self._acks[(dest_id, msg_id)] = ev
        try:
            for attempt in range(retries + 1):
                if attempt:
                    self.stats["retransmits"] += 1
                for i, part in enumerate(parts):
                    pkt = Packet(T_DATA, self.node_id, msg_id, i, total)
                    tag = crypto.header_tag(hdr_key, protocol.header_bytes(pkt))
                    pkt.payload = protocol.join_tag(part, tag)
                    self._tx(protocol.pack(pkt), dest_addr)
                if ev.wait(timeout):
                    self.stats["sent_ok"] += 1
                    return True
            self.stats["send_failed"] += 1
            return False
        finally:
            with self._ack_lock:
                self._acks.pop((dest_id, msg_id), None)

    # ---------- receiving ----------
    def _rx_loop(self):
        while self._running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            out = self.rx.ingest_raw(data, addr)
            if out.ok and out.reason == "delivered":
                self._save_state()
                self.inbox.put((out.pkt.sender_id, out.plain))
            elif out.ok and out.reason == "ack_ok":
                with self._ack_lock:
                    ev = self._acks.get((out.pkt.sender_id, out.pkt.msg_id))
                if ev:
                    ev.set()
            if out.ack is not None:
                # delivery receipt (or idempotent re-ACK for a lost ACK)
                self._tx(protocol.pack(out.ack), addr)
