"""Web UI: Sender / Receiver / Admin views on top of the real securecomm crypto + protocol.

Run:  python web/app.py   then open http://127.0.0.1:5000
      (binds to 127.0.0.1 by default; use --host 0.0.0.0 to expose it on the LAN)
"""
import collections
import os
import sys
import threading
import time

from flask import Flask, jsonify, redirect, request, send_from_directory, session

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from securecomm import crypto, protocol  # noqa: E402
from securecomm.protocol import Packet, T_DATA  # noqa: E402
from securecomm.receiver import ReceiverState  # noqa: E402

app = Flask(__name__, static_folder=os.path.join(ROOT, "web"), static_url_path="")
app.secret_key = os.environ.get("SECURECOMM_SECRET") or os.urandom(24)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",   # blocks cross-site POSTs (CSRF) in modern browsers
    SESSION_COOKIE_SECURE=False,        # demo runs over plain HTTP on localhost
)

MASTER = crypto.load_master_key(os.path.join(ROOT, "master.key"))
SENDER_ID, RECEIVER_ID = 1, 2
PEERS = {SENDER_ID}
FRAG_SIZE = 24
MAX_MESSAGE = 4096          # bytes of plaintext accepted by the demo UI
ATTACKS = ("none", "sniff", "tamper", "replay", "rogue", "wrongkey")
HISTORY = 500               # bounded per-role history so a long demo cannot grow forever

# Demo credentials; override with environment variables for anything non-local.
USERS = {
    "sender": {"password": os.environ.get("SECURECOMM_SENDER_PASSWORD", "sender123"),
               "role": "sender", "name": "Node 1 - Field Unit Alpha", "node": 1},
    "receiver": {"password": os.environ.get("SECURECOMM_RECEIVER_PASSWORD", "receiver123"),
                 "role": "receiver", "name": "Node 2 - Command Base", "node": 2},
    "admin": {"password": os.environ.get("SECURECOMM_ADMIN_PASSWORD", "admin123"),
              "role": "admin", "name": "Network Administrator", "node": None},
}

lock = threading.Lock()
inbox, sent, transmissions = (collections.deque(maxlen=HISTORY),
                              collections.deque(maxlen=HISTORY),
                              collections.deque(maxlen=HISTORY))
totals = {"inbox": 0, "sent": 0, "transmissions": 0}
stats = {"delivered": 0, "dropped": 0}
# The receiver side of the demo runs the *same* pipeline a real Node runs.
rx = ReceiverState(MASTER, peers=PEERS, local_id=RECEIVER_ID, max_age=30.0)
next_id = [time.time_ns() // 1000]

# Brute-force protection for the demo login (per username + client address).
LOGIN_WINDOW, LOGIN_MAX = 300.0, 5
_attempts = {}


def _attempt_key():
    return f"{request.remote_addr}:{(request.get_json(silent=True) or {}).get('username', '')}"


def _login_blocked(key):
    count, start = _attempts.get(key, (0, 0.0))
    return count >= LOGIN_MAX and (time.time() - start) <= LOGIN_WINDOW


def _login_failed(key):
    now = time.time()
    count, start = _attempts.get(key, (0, now))
    if now - start > LOGIN_WINDOW:
        count, start = 0, now
    _attempts[key] = (count + 1, start)



def hx(b, n=64):
    h = b.hex()
    return h if len(h) <= n * 2 else h[:n * 2] + "..."


def receive(raw_packets, steps):
    """Receiver side: the exact pipeline a real Node runs (shared code, no drift).

    Returns (ok, reason, plaintext). Trace steps are appended to `steps`.
    """
    outcome = None
    for raw in raw_packets:
        outcome = rx.ingest_raw(raw, addr=None, trace=steps)
        if outcome.reason != "pending":
            break
    if outcome is None:
        steps.append(("Parse header", "fail", "No packets supplied"))
        return False, "malformed", None
    if outcome.reason == "pending":
        steps.append(("Reassemble", "fail", "Not all fragments arrived"))
        return False, "malformed", None
    if outcome.ok:
        return True, "delivered", outcome.plain
    return False, outcome.reason, None


def need(*roles):
    u = USERS.get(session.get("user"))
    return u if u and u["role"] in roles else None


@app.post("/api/login")
def api_login():
    d = request.get_json(silent=True) or {}
    user = (d.get("username") or "").strip().lower()
    key = f"{request.remote_addr}:{user}"
    if _login_blocked(key):
        return jsonify(error="Too many attempts; wait a few minutes and try again"), 429
    u = USERS.get(user)
    if not u or u["password"] != d.get("password") or u["role"] != d.get("role"):
        _login_failed(key)
        return jsonify(error="Invalid credentials for the selected role"), 401
    _attempts.pop(key, None)
    session["user"] = user
    return jsonify(ok=True, redirect="/" + u["role"])


@app.get("/api/me")
def api_me():
    u = USERS.get(session.get("user"))
    if not u:
        return jsonify(error="unauthorised"), 401
    return jsonify(user=session["user"], role=u["role"], name=u["name"], node=u["node"],
                   key_fp=crypto.derive_node_key(MASTER, u["node"] or 0)[:8].hex())


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.post("/api/send")
def api_send():
    if not need("sender"):
        return jsonify(error="unauthorised"), 401
    d = request.get_json(silent=True) or {}
    text = (d.get("message") or "").strip()
    attack = d.get("attack", "none")
    if attack not in ATTACKS:
        return jsonify(error=f"unknown attack {attack!r}; choose one of {', '.join(ATTACKS)}"), 400
    if not text:
        return jsonify(error="empty message"), 400
    size = len(text.encode())
    if size > MAX_MESSAGE:
        return jsonify(error=f"message too large: {size} B (limit {MAX_MESSAGE} B)"), 413
    with lock:
        next_id[0] += 1
        msg_id = next_id[0]
        sender_id = 9 if attack == "rogue" else SENDER_ID
        master = os.urandom(32) if attack == "wrongkey" else MASTER
        key = crypto.derive_node_key(master, sender_id)
        hdr_key = crypto.derive_header_key(master, sender_id)
        ts = time.time()
        blob = crypto.encrypt_message(key, sender_id, msg_id, text.encode(), ts)
        parts = protocol.fragment(blob, FRAG_SIZE)
        raw = []
        for i, p in enumerate(parts):
            pkt = Packet(T_DATA, sender_id, msg_id, i, len(parts))
            pkt.payload = protocol.join_tag(
                p, crypto.header_tag(hdr_key, protocol.header_bytes(pkt)))
            raw.append(protocol.pack(pkt))

        pkt_info = []
        for i, r in enumerate(raw):
            pkt_info.append({"idx": i, "magic": "SM", "ver": 1, "type": "DATA", "sender": sender_id,
                             "msg_id": msg_id, "frag": f"{i + 1}/{len(raw)}", "len": len(r),
                             "header": r[:20].hex(), "payload": r[20:].hex()})
        totals["transmissions"] += 1
        tx = {"id": totals["transmissions"], "packets": pkt_info, "time": time.strftime("%H:%M:%S"),
              "message": text, "attack": attack, "msg_id": msg_id,
              "sender_steps": [], "channel": [], "runs": []}
        ss = tx["sender_steps"]
        ss.append(("Plaintext", "ok", f"\"{text}\" ({len(text.encode())} bytes)"))
        ss.append(("Key derivation (HKDF-SHA256)",
                   "warn" if attack in ("rogue", "wrongkey") else "ok",
                   f"seal_key  = HKDF(master, 'node:{sender_id}')\n{hx(key, 8)}...\n"
                   f"header_key = HKDF(master, 'hdr:{sender_id}')\n{hx(hdr_key, 8)}..."
                   + ("\n(attacker uses a DIFFERENT master key)" if attack == "wrongkey" else "")
                   + ("\n(attacker claims to be node 9)" if attack == "rogue" else "")))
        ss.append(("AES-256-GCM encrypt", "ok",
                   f"nonce = {crypto._nonce(msg_id).hex()}\nAAD = sender||msg_id = {crypto._aad(sender_id, msg_id).hex()}\n"
                   f"ciphertext+tag ({len(blob)} B) = {hx(blob)}\nauth tag = {blob[-16:].hex()}"))
        ss.append(("Fragment + header", "ok",
                   f"{len(parts)} packet(s) of <= {FRAG_SIZE} B, 20-byte header each\n"
                   "every packet is sealed with HMAC-SHA256(header, header_key):\n"
                   + "\n".join(f"pkt{i}: {hx(r[:20])} | {hx(r[20:], 12)}" for i, r in enumerate(raw))))

        ch = tx["channel"]
        if attack == "none":
            ch.append(("Wireless channel", "ok", "Packets transmitted over UDP link"))
        elif attack == "sniff":
            ch.append(("Attacker SNIFFS", "warn",
                       "Eavesdropper captured packets. Payload is ciphertext only:\n"
                       + "\n".join(hx(r[20:], 24) for r in raw) + "\n-> cannot read the message"))
        elif attack == "tamper":
            victim = bytearray(raw[0])
            victim[protocol.HDR_SIZE] ^= 0x01       # flip one bit of the ciphertext
            raw[0] = bytes(victim)
            ch.append(("Attacker TAMPERS", "warn",
                       f"Flipped 1 bit in the ciphertext of pkt0 (header left intact)\n"
                       f"new pkt0: {hx(raw[0][20:], 24)}"))
        elif attack == "replay":
            ch.append(("Attacker REPLAYS", "warn", "Attacker recorded the packets and will re-send them after delivery"))
        elif attack == "rogue":
            ch.append(("Rogue node", "warn", "Packets come from node 9 (not in trusted peer list)"))
        elif attack == "wrongkey":
            ch.append(("Fake key", "warn", "Packets sealed with an attacker-generated master key"))

        runs = [("Original transmission", raw)]
        if attack == "replay":
            runs.append(("Replayed copy (attacker)", list(raw)))
        for label, pkts in runs:
            steps = []
            ok, reason, plain = receive(pkts, steps)
            tx["runs"].append({"label": label, "ok": ok, "reason": reason, "steps": steps})
            if ok:
                stats["delivered"] += 1
                totals["inbox"] += 1
                inbox.append({"time": tx["time"], "from": sender_id, "message": plain.decode(errors="replace"),
                              "msg_id": msg_id})
            else:
                stats["dropped"] += 1
                totals["inbox"] += 1
                inbox.append({"time": tx["time"], "from": sender_id, "dropped": True, "reason": reason,
                              "msg_id": msg_id})
        delivered = any(r["ok"] for r in tx["runs"])
        totals["sent"] += 1
        sent.append({"time": tx["time"], "message": text, "attack": attack,
                     "status": "delivered" if delivered else tx["runs"][0]["reason"]})
        transmissions.append(tx)
    return jsonify(ok=True, delivered=delivered, tx=tx)


@app.get("/api/state")
def api_state():
    u = need("sender", "receiver", "admin")
    if not u:
        return jsonify(error="unauthorised"), 401
    with lock:
        # role-scoped: each dashboard only receives the data it is meant to see
        out = {"stats": dict(stats), "inbox": [], "sent": [], "transmissions": [],
               "inbox_total": totals["inbox"], "sent_total": totals["sent"],
               "tx_total": totals["transmissions"]}
        if u["role"] == "admin":
            out.update(inbox=list(inbox), sent=list(sent), transmissions=list(transmissions))
        elif u["role"] == "sender":
            out["sent"] = list(sent)
        else:
            out["inbox"] = list(inbox)
        return jsonify(**out)


@app.post("/api/reset")
def api_reset():
    if not need("admin"):
        return jsonify(error="unauthorised"), 401
    with lock:
        inbox.clear(); sent.clear(); transmissions.clear(); rx.reset()
        stats.update(delivered=0, dropped=0)
        totals.update(inbox=0, sent=0, transmissions=0)
        _attempts.clear()
    return jsonify(ok=True)


@app.get("/")
def home():
    u = USERS.get(session.get("user"))
    return redirect("/" + u["role"] if u else "/login")


@app.get("/login")
def login_page():
    return send_from_directory(app.static_folder, "login.html")


@app.get("/sender")
@app.get("/receiver")
def chat_page():
    if not need(request.path[1:]):
        return redirect("/login")
    return send_from_directory(app.static_folder, "chat.html")


@app.get("/admin")
def admin_page():
    if not need("admin"):
        return redirect("/login")
    return send_from_directory(app.static_folder, "admin.html")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="SecureComm web demo")
    ap.add_argument("--host", default=os.environ.get("SECURECOMM_HOST", "127.0.0.1"),
                    help="bind address (default: 127.0.0.1; use 0.0.0.0 for LAN demos)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("SECURECOMM_PORT", "5000")))
    ap.add_argument("--debug", action="store_true", help="Flask debug mode (never in production)")
    a = ap.parse_args()

    if a.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: bound to {a.host} -- anyone on this network can reach the demo "
              "with the published demo passwords. Set SECURECOMM_*_PASSWORD first, "
              "or keep it on 127.0.0.1.")
    if any(u["password"] in ("sender123", "receiver123", "admin123") for u in USERS.values()):
        print("NOTE: running with the published demo credentials (see README).")
    app.run(host=a.host, port=a.port, debug=a.debug, threaded=True)
