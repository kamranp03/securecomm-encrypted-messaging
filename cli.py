#!/usr/bin/env python3
"""Command line interface.

  python cli.py keygen --out master.key
  python cli.py receive --id 2 --port 9000 --key master.key --peers 1
  python cli.py send --id 1 --to 127.0.0.1:9000 --dest-id 2 --key master.key "hello"
"""
import argparse
import logging
import sys
import time

from securecomm import Node, generate_master_key, load_master_key


def parse_addr(s):
    host, port = s.rsplit(":", 1)
    return host, int(port)


def main():
    ap = argparse.ArgumentParser(description="Secure offline message transmission")
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen")
    k.add_argument("--out", default="master.key")

    r = sub.add_parser("receive")
    r.add_argument("--id", type=int, required=True)
    r.add_argument("--host", default="0.0.0.0")
    r.add_argument("--port", type=int, default=9000)
    r.add_argument("--key", default="master.key")
    r.add_argument("--peers", type=int, nargs="*", default=None, help="allowed sender ids")

    s = sub.add_parser("send")
    s.add_argument("--id", type=int, required=True)
    s.add_argument("--to", required=True, help="host:port of receiver")
    s.add_argument("--dest-id", type=int, required=True)
    s.add_argument("--key", default="master.key")
    s.add_argument("--frag-size", type=int, default=400)
    s.add_argument("--loss", type=float, default=0.0, help="simulated packet loss 0-1")
    s.add_argument("--retries", type=int, default=5)
    s.add_argument("message", nargs="?", help="omit for interactive mode")

    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

    if a.cmd == "keygen":
        generate_master_key(a.out)
        print(f"Master key written to {a.out}. Copy it to every trusted node offline (USB).")
        return

    master = load_master_key(a.key)

    if a.cmd == "receive":
        node = Node(a.id, master, host=a.host, port=a.port, peers=a.peers).start()
        print(f"[node {a.id}] listening on {a.host}:{node.port}  (Ctrl+C to stop)")
        try:
            while True:
                m = node.recv(timeout=0.5)
                if m:
                    sid, data = m
                    print(f"[{time.strftime('%H:%M:%S')}] from node {sid}: {data.decode(errors='replace')}")
        except KeyboardInterrupt:
            print("\nstats:", dict(node.stats))
        return

    node = Node(a.id, master, host="0.0.0.0", frag_size=a.frag_size, loss_rate=a.loss).start()
    dest = parse_addr(a.to)


    def push(text):
        t0 = time.time()
        ok = node.send(dest, a.dest_id, text.encode(), retries=a.retries)
        dt = (time.time() - t0) * 1000
        print(f"{'delivered' if ok else 'FAILED'} in {dt:.0f} ms  retransmits={node.stats['retransmits']}")
        return ok

    if a.message:
        sys.exit(0 if push(a.message) else 1)
    print("Interactive mode. Type a message, Enter to send, Ctrl+C to quit.")
    try:
        for line in sys.stdin:
            if line.strip():
                push(line.rstrip("\n"))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
