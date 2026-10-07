import os
import sys
import socket
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from securecomm import Node, crypto  # noqa: E402

MASTER = os.urandom(32)


class Tests(unittest.TestCase):
    def tearDown(self):
        for n in getattr(self, "nodes", []):
            n.stop()

    def mk(self, **kw):
        rx = Node(2, MASTER, **kw).start()
        tx = Node(1, MASTER, frag_size=200).start()
        self.nodes = [tx, rx]
        return tx, rx, ("127.0.0.1", rx.port)

    def test_roundtrip(self):
        tx, rx, addr = self.mk()
        self.assertTrue(tx.send(addr, 2, b"hello defence"))
        self.assertEqual(rx.recv(1), (1, b"hello defence"))

    def test_fragmentation_large_message(self):
        tx, rx, addr = self.mk()
        msg = os.urandom(5000)
        self.assertTrue(tx.send(addr, 2, msg))
        self.assertEqual(rx.recv(1)[1], msg)

    def test_packet_loss_recovers(self):
        tx, rx, addr = self.mk()
        tx.loss_rate = rx.loss_rate = 0.3
        msg = os.urandom(1500)
        self.assertTrue(tx.send(addr, 2, msg, retries=30, timeout=0.15))
        self.assertEqual(rx.recv(1)[1], msg)
        self.assertEqual(rx.stats["delivered"], 1)

    def test_replay_rejected(self):
        tx, rx, addr = self.mk()
        captured = []
        orig = tx._tx
        tx._tx = lambda d, a: (captured.append(d), orig(d, a))
        self.assertTrue(tx.send(addr, 2, b"order: move at dawn"))
        self.assertIsNotNone(rx.recv(1))
        attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for d in captured:
            attacker.sendto(d, addr)
        time.sleep(0.5)
        self.assertIsNone(rx.recv(0.2))
        self.assertGreaterEqual(rx.stats["replay_blocked"], 1)
        self.assertEqual(rx.stats["delivered"], 1)

    def test_tamper_rejected(self):
        tx, rx, addr = self.mk()
        orig = tx._tx

        def evil(d, a):
            b = bytearray(d)
            b[-1] ^= 0xFF
            orig(bytes(b), a)

        tx._tx = evil
        self.assertFalse(tx.send(addr, 2, b"secret", retries=1, timeout=0.3))
        self.assertIsNone(rx.recv(0.2))
        self.assertGreaterEqual(rx.stats["auth_failed"], 1)

    def test_unknown_node_rejected(self):
        tx, rx, addr = self.mk(peers=[7])
        self.assertFalse(tx.send(addr, 2, b"hi", retries=1, timeout=0.3))
        self.assertGreaterEqual(rx.stats["unknown_sender"], 1)

    def test_wrong_key_rejected(self):
        rx = Node(2, MASTER, peers=[1]).start()
        rogue = Node(1, os.urandom(32)).start()
        self.nodes = [rx, rogue]
        self.assertFalse(rogue.send(("127.0.0.1", rx.port), 2, b"fake", retries=1, timeout=0.3))
        self.assertGreaterEqual(rx.stats["auth_failed"], 1)
        self.assertIsNone(rx.recv(0.2))

    def test_stale_message_rejected(self):
        key = crypto.derive_node_key(MASTER, 1)
        blob = crypto.encrypt_message(key, 1, 5, b"old", timestamp=time.time() - 120)
        with self.assertRaises(crypto.StaleError):
            crypto.decrypt_message(key, 1, 5, blob, max_age=30)

    def test_ciphertext_hides_plaintext(self):
        key = crypto.derive_node_key(MASTER, 1)
        blob = crypto.encrypt_message(key, 1, 9, b"TOP SECRET COORDINATES")
        self.assertNotIn(b"SECRET", blob)

    def test_sender_cannot_be_spoofed_via_aad(self):
        key = crypto.derive_node_key(MASTER, 1)
        blob = crypto.encrypt_message(key, 1, 11, b"x")
        with self.assertRaises(crypto.AuthError):
            crypto.decrypt_message(key, 3, 11, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
