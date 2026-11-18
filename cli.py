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

STATE_PREFIX = "node-state-"
STATS_INTERVAL = 10.0   # seconds between status lines in receive mode


def parse_addr(s):
    host, port = s.rsplit(":", 1)
    return host, int(port)


def state_path(a):
    """Persist msg_id / replay state unless explicitly disabled."""
    if a.no_state:
        return None
    return a.state or f"{STATE_PREFIX}{a.id}.json"


def load_key(path):
    try:
        return load_master_key(path)
    except (FileNotFoundError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description="Secure offline message transmission")
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen")
    k.add_argument("--out", default="master.key")
    k.add_argument("--force", action="store_true",
                   help="overwrite an existing key (invalidates every deployed node)")

    r = sub.add_parser("receive")
    r.add_argument("--id", type=int, required=True)
    r.add_argument("--host", default="0.0.0.0")
    r.add_argument("--port", type=int, default=9000)
    r.add_argument("--key", default="master.key")
    r.add_argument("--peers", type=int, nargs="*", default=None, help="allowed sender ids")
    r.add_argument("--loss", type=float, default=0.0,
                   help="simulated packet loss 0-1 on transmitted ACKs")
    r.add_argument("--state", default=None,
                   help=f"replay-state file (default: {STATE_PREFIX}<id>.json)")
    r.add_argument("--no-state", action="store_true",
                   help="do not persist replay state (a restart then accepts replays "
                        "inside the freshness window)")

    s = sub.add_parser("send")
    s.add_argument("--id", type=int, required=True)
    s.add_argument("--to", required=True, help="host:port of receiver")
    s.add_argument("--dest-id", type=int, required=True)
    s.add_argument("--key", default="master.key")
    s.add_argument("--frag-size", type=int, default=400)
    s.add_argument("--loss", type=float, default=0.0, help="simulated packet loss 0-1")
    s.add_argument("--retries", type=int, default=5)
    s.add_argument("--state", default=None,
                   help=f"msg-id state file (default: {STATE_PREFIX}<id>.json)")
    s.add_argument("--no-state", action="store_true",
                   help="do not persist the msg-id counter")
    s.add_argument("message", nargs="?", help="omit for interactive mode")

    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

    if a.cmd == "keygen":
        try:
            generate_master_key(a.out, force=a.force)
        except FileExistsError as e:
            print(f"refusing to overwrite: {e}\nRe-run with --force only if every node "
                  "will receive the new key.", file=sys.stderr)
            sys.exit(2)
        print(f"Master key written to {a.out}. Copy it to every trusted node offline (USB).")
        return

    if a.cmd == "receive" and a.peers is not None and not a.peers:
        print("error: --peers given without any id (use e.g. --peers 1, or omit --peers "
              "to accept any holder of the key)", file=sys.stderr)
        sys.exit(2)

    master = load_key(a.key)
    state = state_path(a)

    if a.cmd == "receive":
        node = Node(a.id, master, host=a.host, port=a.port, peers=a.peers,
                    loss_rate=a.loss, state_file=state).start()
        print(f"[node {a.id}] listening on {a.host}:{node.port}  (Ctrl+C to stop)"
              + ("" if state is None else f"\nreplay state: {state}"), flush=True)
        last_stats = time.time()
        last_seen = dict(node.stats)
        try:
            while True:
                m = node.recv(timeout=0.5)
                if m:
                    sid, data = m
                    print(f"[{time.strftime('%H:%M:%S')}] from node {sid}: "
                          f"{data.decode(errors='replace')}", flush=True)
                elif time.time() - last_stats >= STATS_INTERVAL:
                    now = dict(node.stats)
                    if now != last_seen:
                        print(f"stats: {now}", flush=True)
                        last_seen = now
                    last_stats = time.time()
        except KeyboardInterrupt:
            pass
        finally:
            print("stats:", dict(node.stats), flush=True)
            node.stop()
        return

    node = Node(a.id, master, host="0.0.0.0", frag_size=a.frag_size,
                loss_rate=a.loss, state_file=state).start()
    dest = parse_addr(a.to)
    try:

        def push(text):
            t0 = time.time()
            ok = node.send(dest, a.dest_id, text.encode(), retries=a.retries)
            dt = (time.time() - t0) * 1000
            print(f"{'delivered' if ok else 'FAILED'} in {dt:.0f} ms  "
                  f"retransmits={node.stats['retransmits']}", flush=True)
            return ok

        if a.message:
            sys.exit(0 if push(a.message) else 1)
        print("Interactive mode. Type a message, Enter to send, Ctrl+C to quit.", flush=True)
        try:
            for line in sys.stdin:
                if line.strip():
                    push(line.rstrip("\n"))
        except KeyboardInterrupt:
            pass
    finally:
        node.stop()


if __name__ == "__main__":
    main()
