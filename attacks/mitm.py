#!/usr/bin/env python3
"""UDP man-in-the-middle for demonstrating attacks. Put it between sender and receiver.

  python attacks/mitm.py --listen 9001 --forward 127.0.0.1:9000 --mode sniff|replay|tamper|corrupt-header|drop
Then point the sender at port 9001.
"""
import argparse
import os
import random
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from securecomm.protocol import HDR_SIZE, T_DATA  # noqa: E402


def say(*args):
    print(*args, flush=True)


def main():
    ap = argparse.ArgumentParser(description="SecureComm attack proxy")
    ap.add_argument("--listen", type=int, default=9001)
    ap.add_argument("--forward", default="127.0.0.1:9000")
    ap.add_argument("--mode", choices=["sniff", "replay", "tamper", "corrupt-header", "drop"],
                    default="sniff")
    ap.add_argument("--delay", type=float, default=2.0, help="replay delay in seconds")
    ap.add_argument("--rate", type=float, default=0.5,
                    help="probability of dropping a DATA packet (mode=drop)")
    a = ap.parse_args()

    fhost, fport = a.forward.rsplit(":", 1)
    fwd = (fhost, int(fport))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", a.listen))
    client = None
    say(f"[mitm] mode={a.mode} listening :{a.listen} -> {a.forward}")

    def replay_later(data):
        time.sleep(a.delay)
        sock.sendto(data, fwd)
        say(f"[mitm] REPLAYED {len(data)} bytes")

    while True:
        data, addr = sock.recvfrom(65535)
        if addr[0] == fwd[0] and addr[1] == fwd[1]:
            if client:
                sock.sendto(data, client)
            continue
        client = addr
        # a DATA packet always carries a ciphertext fragment + a 16-byte header tag
        is_data = len(data) > HDR_SIZE + 16 and data[3] == T_DATA
        body = data[HDR_SIZE:]

        if a.mode == "sniff":
            say(f"[mitm] captured {len(data)} B  hdr={data[:HDR_SIZE].hex()}")
            say(f"       payload hex : {body[:48].hex()}...")
            say("       as text     : "
                + body[:48].decode("latin-1").encode("ascii", "replace").decode())
        elif a.mode == "tamper" and is_data:
            b = bytearray(data)
            b[HDR_SIZE] ^= 0x01                 # flip one bit of the ciphertext
            data = bytes(b)
            say("[mitm] flipped 1 bit in the ciphertext")
        elif a.mode == "corrupt-header" and is_data:
            b = bytearray(data)
            b[18] ^= 0x01                       # flip a bit in frag_total (header field)
            data = bytes(b)
            say("[mitm] flipped 1 bit in frag_total -- the header HMAC must catch this")
        elif a.mode == "drop" and is_data and random.random() < a.rate:
            say(f"[mitm] DROPPED {len(data)} B on the floor (loss rate {a.rate})")
            continue
        elif a.mode == "replay" and is_data:
            threading.Thread(target=replay_later, args=(data,), daemon=True).start()
            say(f"[mitm] captured {len(data)} B, will replay in {a.delay}s")

        sock.sendto(data, fwd)


if __name__ == "__main__":
    main()
