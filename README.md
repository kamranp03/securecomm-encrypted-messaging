# Secure Offline Wireless Message Transmission (software-only)

Encrypted, authenticated, replay-protected messaging between nodes over a local
network with **no internet**. Runs on any Wi-Fi hotspot / LAN / loopback.

## Features
- AES-256-GCM encryption (confidentiality + integrity)
- Pre-shared master key, two domain-separated per-node keys via HKDF-SHA256
  (a *seal key* for encryption, an independent *header key* for packet authentication)
- Per-packet HMAC-SHA256 over the 20-byte header — sender, msg_id, fragment
  index/count and type cannot be altered silently
- Sender authentication (wrong key or unknown node ID is dropped)
- Replay protection (message counter + duplicate set + reorder window + 30 s freshness)
- Persisted replay state, so a restart cannot reopen a replay window
- Fragmentation, authenticated ACKs, retransmission, packet-loss simulation
- Attack lab: 5 MITM modes (`attacks/mitm.py`) plus 6 link simulations in the web UI
- 11 automated tests
- Web UI with login: Sender, Receiver and Admin dashboards (live packet-path visualisation)

See **[notes.md](notes.md)** for a full explanation of every link-simulation type
and exactly which defence stops it.

## Setup
```
pip install -r requirements.txt
python cli.py keygen --out master.key      # copy this file to every trusted node offline
```
`master.key` is secret and is not stored in git, so generate it once after cloning.
Re-running `keygen` on an existing file refuses to overwrite it; pass `--force` if you
really mean to rotate the key (this invalidates every node still holding the old one).

## Web UI
```
python web/app.py                 # binds to 127.0.0.1:5000
python web/app.py --host 0.0.0.0  # opt in to LAN exposure for two-machine demos
```
Open http://127.0.0.1:5000 and sign in:

| Role | Username | Password | What you get |
|---|---|---|---|
| Sender (Node 1) | `sender` | `sender123` | Chat screen with a link-simulation menu (normal, sniff, tamper, replay, rogue node, forged key) |
| Receiver (Node 2) | `receiver` | `receiver123` | Inbox of verified messages, and notices for discarded ones with the reason |
| Admin | `admin` | `admin123` | Traffic monitor: animated packet path, step-by-step crypto trace, hex packet inspector |

A browser keeps one login at a time, so open each role in a separate browser or an incognito window.

Credentials default to the values above but can be overridden without editing code:

```
SECURECOMM_SENDER_PASSWORD / SECURECOMM_RECEIVER_PASSWORD / SECURECOMM_ADMIN_PASSWORD
SECURECOMM_SECRET          # Flask session signing key
SECURECOMM_HOST / SECURECOMM_PORT
```

The web UI uses the real `securecomm` crypto, packet and receiver code — the receiver
side runs the *same* `ReceiverState` pipeline a real node runs, so what the admin
dashboard shows is what a real receiver does. The attacker is simulated inside the server.

Login is rate-limited (5 attempts per 300 s per user + address), session cookies are
`HttpOnly` + `SameSite=Strict`, and each dashboard only receives the data its role is
meant to see.

## Run (two terminals)
```bash
# Terminal 1 - receiver (node 2, accepts only node 1)
python cli.py receive --id 2 --port 9000 --key master.key --peers 1

# Terminal 2 - sender (node 1)
python cli.py send --id 1 --to 127.0.0.1:9000 --dest-id 2 --key master.key "Move to grid 42 at 0600"
```
For two machines, use the receiver's Wi-Fi IP in `--to`.

Both sides persist replay/message-id state to `node-state-<id>.json` (gitignored) so a
restart cannot reuse a nonce or reopen a replay window. Use `--state <path>` to relocate
it, or `--no-state` to disable persistence — note that `--no-state` on the receiver makes
a restart accept replays again.

## Demo the attacks (three terminals)
Receiver stays on 9000. Start the attacker proxy, then send through port 9001.
```bash
python attacks/mitm.py --listen 9001 --forward 127.0.0.1:9000 --mode sniff            # payload is unreadable
python attacks/mitm.py --listen 9001 --forward 127.0.0.1:9000 --mode tamper           # GCM tag fails -> rejected
python attacks/mitm.py --listen 9001 --forward 127.0.0.1:9000 --mode corrupt-header   # header HMAC fails -> rejected
python attacks/mitm.py --listen 9001 --forward 127.0.0.1:9000 --mode replay           # replay is blocked
python attacks/mitm.py --listen 9001 --forward 127.0.0.1:9000 --mode drop --rate 0.5  # link loss, retransmit recovers
python cli.py send --id 1 --to 127.0.0.1:9001 --dest-id 2 --key master.key "test"
```
Rogue node: `--id 9` is rejected as `unknown_sender`; a different `master.key` fails
authentication (`bad_header`).
Packet loss: add `--loss 0.3` to `send`, or use mitm `--mode drop`.
Wireshark: capture on the loopback/Wi-Fi interface with filter `udp.port == 9000`.

## Tests
```bash
python -m unittest discover -s tests -v
```

## Design notes / limitations (mention in your report)
- Master key is shared, so any key holder could impersonate another node. Fix: Ed25519 signatures per node.
- The receiver accepts a message up to 512 ids behind the newest (a reorder window), so
  it is not a strict "strictly increasing" check; this still bounds replayed traffic.
- No forward secrecy. Fix: X25519 ephemeral key exchange.
- UDP is used to mimic a lossy wireless link; reliability is built into the protocol.
- The web demo binds to loopback and uses demo credentials; treat it as a teaching tool,
  not a production service.
