"""Web UI: Sender / Receiver / Admin views on top of the real securecomm crypto + protocol.

Run:  python web/app.py   then open http://127.0.0.1:5000
"""
import os
import sys
import threading
import time

from flask import Flask, jsonify, redirect, request, send_from_directory, session

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from securecomm import crypto, protocol  # noqa: E402
from securecomm.node import _SenderState  # noqa: E402
from securecomm.protocol import Packet, T_ACK, T_DATA  # noqa: E402

app = Flask(__name__, static_folder=os.path.join(ROOT, "web"), static_url_path="")
app.secret_key = os.urandom(24)

USERS = {
    "sender": {"password": "sender123", "role": "sender", "name": "Node 1 - Field Unit Alpha", "node": 1},
    "receiver": {"password": "receiver123", "role": "receiver", "name": "Node 2 - Command Base", "node": 2},
    "admin": {"password": "admin123", "role": "admin", "name": "Network Administrator", "node": None},
}

MASTER = crypto.load_master_key(os.path.join(ROOT, "master.key"))
SENDER_ID, RECEIVER_ID = 1, 2
PEERS = {SENDER_ID}
FRAG_SIZE = 24

lock = threading.Lock()
inbox, sent, transmissions = [], [], []
stats = {"delivered": 0, "dropped": 0}
rx_state = {}
next_id = [time.time_ns() // 1000]


def hx(b, n=64):
    h = b.hex()
    return h if len(h) <= n * 2 else h[:n * 2] + "..."


def receive(raw_packets, steps):
    """Receiver side: same checks as Node._handle_data. Returns (ok, reason, plaintext)."""
    buf = None
    for raw in raw_packets:
        try:
            pkt = protocol.unpack(raw)
        except protocol.ProtocolError as e:
            steps.append(("Parse header", "fail", f"Malformed packet: {e}"))
            return False, "malformed", None
        s, m = pkt.sender_id, pkt.msg_id
        if s not in PEERS:
            steps.append(("Sender check", "fail", f"Node {s} is NOT an authorised peer -> packet discarded"))
            return False, "unknown_sender", None
        st = rx_state.setdefault(s, _SenderState())
        if m in st.seen or m < st.highest:
            steps.append(("Replay check", "fail", f"msg_id {m} already seen (highest={st.highest}) -> REPLAY BLOCKED"))
            return False, "replay_blocked", None
        if buf is None:
            buf = {"total": pkt.frag_total, "frags": {}, "s": s, "m": m}
        buf["frags"][pkt.frag_idx] = pkt.payload

    steps.append(("Parse header", "ok", f"magic=SM v1, sender={buf['s']}, msg_id={buf['m']}, {buf['total']} fragment(s)"))
    steps.append(("Sender check", "ok", f"Node {buf['s']} is an authorised peer"))
    steps.append(("Replay check", "ok", f"msg_id {buf['m']} is new (counter strictly increasing)"))
    blob = b"".join(buf["frags"][i] for i in range(buf["total"]))
    steps.append(("Reassemble", "ok", f"{buf['total']} fragments -> {len(blob)} byte ciphertext\n{hx(blob)}"))
    try:
        plain = crypto.decrypt_message(crypto.derive_node_key(MASTER, buf["s"]), buf["s"], buf["m"], blob)
    except crypto.AuthError:
        steps.append(("AES-GCM verify", "fail", "GCM auth tag mismatch -> data tampered or wrong key -> DISCARDED"))
        return False, "auth_failed", None
    except crypto.StaleError:
        steps.append(("Freshness", "fail", "Timestamp outside 30s window -> DISCARDED"))
        return False, "stale", None
    steps.append(("AES-GCM verify", "ok", "Auth tag valid -> integrity + authenticity confirmed"))
    steps.append(("Freshness", "ok", "Timestamp within 30s window"))
    rx_state[buf["s"]].record(buf["m"])
    ack = Packet(T_ACK, RECEIVER_ID, buf["m"], 0, 1)
    tag = crypto.ack_tag(crypto.derive_node_key(MASTER, RECEIVER_ID), protocol.header_bytes(ack))
    steps.append(("Decrypt + ACK", "ok", f"Plaintext: \"{plain.decode(errors='replace')}\"\nHMAC ACK sent: {tag.hex()}"))
    return True, "delivered", plain


def need(*roles):
    u = USERS.get(session.get("user"))
    return u if u and u["role"] in roles else None


@app.post("/api/login")
def api_login():
    d = request.get_json(force=True)
    u = USERS.get((d.get("username") or "").strip().lower())
    if not u or u["password"] != d.get("password") or u["role"] != d.get("role"):
        return jsonify(error="Invalid credentials for the selected role"), 401
    session["user"] = d["username"].strip().lower()
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
    d = request.get_json(force=True)
    text = (d.get("message") or "").strip()
    attack = d.get("attack", "none")
    if not text:
        return jsonify(error="empty message"), 400
    with lock:
        next_id[0] += 1
        msg_id = next_id[0]
        sender_id = 9 if attack == "rogue" else SENDER_ID
        master = os.urandom(32) if attack == "wrongkey" else MASTER
        key = crypto.derive_node_key(master, sender_id)
        ts = time.time()
        blob = crypto.encrypt_message(key, sender_id, msg_id, text.encode(), ts)
        parts = protocol.fragment(blob, FRAG_SIZE)
        raw = [protocol.pack(Packet(T_DATA, sender_id, msg_id, i, len(parts), p)) for i, p in enumerate(parts)]

        pkt_info = []
        for i, r in enumerate(raw):
            pkt_info.append({"idx": i, "magic": "SM", "ver": 1, "type": "DATA", "sender": sender_id,
                             "msg_id": msg_id, "frag": f"{i + 1}/{len(raw)}", "len": len(r),
                             "header": r[:20].hex(), "payload": r[20:].hex()})
        tx = {"id": len(transmissions) + 1, "packets": pkt_info, "time": time.strftime("%H:%M:%S"), "message": text,
              "attack": attack, "msg_id": msg_id, "sender_steps": [], "channel": [], "runs": []}
        ss = tx["sender_steps"]
        ss.append(("Plaintext", "ok", f"\"{text}\" ({len(text.encode())} bytes)"))
        ss.append(("Key derivation (HKDF-SHA256)",
                   "warn" if attack in ("rogue", "wrongkey") else "ok",
                   f"node_key = HKDF(master, 'node:{sender_id}')\n{hx(key, 8)}..."
                   + ("\n(attacker uses a DIFFERENT master key)" if attack == "wrongkey" else "")
                   + ("\n(attacker claims to be node 9)" if attack == "rogue" else "")))
        ss.append(("AES-256-GCM encrypt", "ok",
                   f"nonce = {crypto._nonce(msg_id).hex()}\nAAD = sender||msg_id = {crypto._aad(sender_id, msg_id).hex()}\n"
                   f"ciphertext+tag ({len(blob)} B) = {hx(blob)}\nauth tag = {blob[-16:].hex()}"))
        ss.append(("Fragment + header", "ok",
                   f"{len(parts)} packet(s) of <= {FRAG_SIZE} B, 20-byte header each\n"
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
            victim[-1] ^= 0x01
            raw[0] = bytes(victim)
            ch.append(("Attacker TAMPERS", "warn", f"Flipped 1 bit in last byte of pkt0 payload\nnew pkt0: {hx(raw[0][20:], 24)}"))
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
                inbox.append({"time": tx["time"], "from": sender_id, "message": plain.decode(errors="replace"),
                              "msg_id": msg_id})
            else:
                stats["dropped"] += 1
                inbox.append({"time": tx["time"], "from": sender_id, "dropped": True, "reason": reason,
                              "msg_id": msg_id})
        delivered = any(r["ok"] for r in tx["runs"])
        sent.append({"time": tx["time"], "message": text, "attack": attack,
                     "status": "delivered" if delivered else tx["runs"][0]["reason"]})
        transmissions.append(tx)
    return jsonify(ok=True, delivered=delivered, tx=tx)


@app.get("/api/state")
def api_state():
    if not need("sender", "receiver", "admin"):
        return jsonify(error="unauthorised"), 401
    with lock:
        return jsonify(inbox=inbox, sent=sent, transmissions=transmissions, stats=stats)


@app.post("/api/reset")
def api_reset():
    if not need("admin"):
        return jsonify(error="unauthorised"), 401
    with lock:
        inbox.clear(); sent.clear(); transmissions.clear(); rx_state.clear()
        stats.update(delivered=0, dropped=0)
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
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
