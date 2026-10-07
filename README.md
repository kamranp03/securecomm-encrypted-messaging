# Secure Offline Wireless Message Transmission (software-only)

Encrypted, authenticated, replay-protected messaging between nodes over a local
network with **no internet**. Runs on any Wi-Fi hotspot / LAN / loopback.

## Features
- AES-256-GCM encryption (confidentiality + integrity)
- Pre-shared master key, per-node keys via HKDF-SHA256
- Sender authentication (wrong key or unknown node ID is dropped)
- Replay protection (message counter + duplicate set + timestamp freshness window)
- Fragmentation, authenticated ACKs, retransmission, packet-loss simulation
- Attack lab: sniff, tamper, replay (`attacks/mitm.py`)
- 10 automated tests

## Setup
```
pip install -r requirements.txt
python cli.py keygen --out master.key      # copy this file to every trusted node offline
```

## Run (two terminals)
```
# Terminal 1 - receiver (node 2, accepts only node 1)
python cli.py receive --id 2 --port 9000 --key master.key --peers 1

# Terminal 2 - sender (node 1)
python cli.py send --id 1 --to 127.0.0.1:9000 --dest-id 2 --key master.key "Move to grid 42 at 0600"
```
For two machines, use the receiver's Wi-Fi IP in `--to`.

## Demo the attacks (three terminals)
Receiver stays on 9000. Start the attacker proxy, then send through port 9001.
```
python attacks/mitm.py --listen 9001 --forward 127.0.0.1:9000 --mode sniff    # payload is unreadable
python attacks/mitm.py --listen 9001 --forward 127.0.0.1:9000 --mode replay   # replay is blocked
python attacks/mitm.py --listen 9001 --forward 127.0.0.1:9000 --mode tamper   # tampering is rejected
python cli.py send --id 1 --to 127.0.0.1:9001 --dest-id 2 --key master.key "test"
```
Rogue node: `--id 9` is rejected as unknown_sender; a different `master.key` fails authentication.
Packet loss: add `--loss 0.3` to `send`.
Wireshark: capture on the loopback/Wi-Fi interface with filter `udp.port == 9000`.

## Tests
```
python -m unittest discover -s tests -v
```

## Design notes / limitations (mention in your report)
- Master key is shared, so any key holder could impersonate another node. Fix: Ed25519 signatures per node.
- Receiver enforces strictly increasing message IDs per sender (stop-and-wait sender).
- No forward secrecy. Fix: X25519 ephemeral key exchange.
- UDP is used to mimic a lossy wireless link; reliability is built into the protocol.
