# SecureComm — Secure Offline Message Transmission

> Sending encrypted messages between trusted devices over a local network (no internet), so attackers can't read, change, replay or fake them.

---

## 1. Problem

Wireless networks (Wi-Fi, hotspots) are easy to attack:

- Anyone nearby can **capture** packets and read them
- A man-in-the-middle can **change** a message
- An old message can be **sent again** (replay)
- A fake device can **pretend** to be a trusted one

## 2. Our Solution

Every message is **encrypted and sealed** before it leaves the sender.
The receiver **checks everything** and **discards** any message that fails a check.

```
Sender (Node 1)                        Channel                     Receiver (Node 2)
Plaintext -> Key (HKDF) -> Encrypt -> Packets  ->  UDP link  ->  Sender check -> Replay check -> Verify + Decrypt -> Deliver + ACK
                          AES-256-GCM                                                         (any failure = DISCARD)
```

---

## 3. Tech Stack

| Part | Technology |
|---|---|
| Language | Python 3.11 |
| Encryption | AES-256-GCM (`cryptography` library) |
| Key derivation | HKDF-SHA256 (separate key per node) |
| Delivery receipt | HMAC-SHA256 signed ACK |
| Transport | UDP sockets, custom 20-byte header, fragmentation |
| Web app | Flask + HTML / CSS / JavaScript |
| Testing | Python `unittest`, Wireshark |

---

## 4. Attacks We Handle

| Attack | How it happens | What stops it | Result |
|---|---|---|---|
| **Sniffing** | Attacker captures packets with Wireshark | AES-256 encryption | Attacker sees only random bytes |
| **Tampering (MITM)** | Attacker changes bytes in the packet | GCM authentication tag | Discarded |
| **Replay** | Attacker re-sends an old valid packet | Message ID counter + 30 s timestamp | Discarded |
| **Rogue node** | Unknown device pretends to be a node | Trusted peer list | Discarded |
| **Forged key** | Attacker uses their own key | Shared master key + HKDF | Discarded |

**Rule:** only a **genuine, unmodified, first-time** message from a **trusted node** is delivered.

---

## 5. Packet Format (20-byte header)

```
| magic "SM" (2) | version (1) | type (1) | sender_id (4) | msg_id (8) | frag_idx (2) | frag_total (2) | encrypted payload ... |
```

---

## 6. Web Application

| Role | Login | What they see |
|---|---|---|
| **Sender** | `sender / sender123` | Chat screen, type a message, choose a link condition (normal or an attack) |
| **Receiver** | `receiver / receiver123` | Inbox: verified messages, or red "Packet discarded" notices with the reason |
| **Admin** | `admin / admin123` | Live traffic monitor: animated packet path, step-by-step trace, hex packet inspector |

**Run:**
```
pip install -r requirements.txt flask
python web/app.py
```
Open `http://127.0.0.1:5000`. Use a separate browser window (or incognito) for each role.

---

## 7. Live Demo Flow

1. **Normal link** → message delivered, ACK verified
2. **Sniff** → delivered, admin shows the attacker saw only ciphertext
3. **Modify packet** → tag check fails, discarded
4. **Replay** → original delivered, copy blocked
5. **Rogue node 9** → rejected as untrusted sender
6. **Forged key** → tag check fails, discarded

---

## 8. Team Contribution

| Member | Module |
|---|---|
| Member 1 | Cryptography: AES-GCM, HKDF, HMAC ACK |
| Member 2 | Protocol: packet header, fragmentation |
| Member 3 | Networking: UDP nodes, retransmission, replay protection, CLI |
| Member 4 | Security testing: MITM attack script, unit tests, Wireshark |
| Member 5 | Web UI: Flask backend, login, Sender / Receiver / Admin dashboards |

---

## 9. Limitations & Future Scope

- All nodes share one master key → add **Ed25519 digital signatures** per node
- No forward secrecy → add **X25519 key exchange**
- Demo runs on one machine → deploy on real devices over Wi-Fi / LoRa

---

## 10. Conclusion

SecureComm provides **confidentiality** (encryption), **integrity** (GCM tag), **authentication** (trusted keys and peers) and **replay protection** (message counter) for offline wireless messaging, and the admin dashboard shows exactly how each message is protected from sender to receiver.

**Thank you!**
