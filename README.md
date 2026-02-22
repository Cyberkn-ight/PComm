# PComm (prototype)

PComm is a **prototype** as of rn, an onion-relay messenger written in **pure C** with:
- **SQLite** message storage (schema designed to extend to group chats later if I'm not too lazy)
- A dogshit **embedded HTTP server** that serves a barebone **HTML/CSS/JS UI**
- **User identifiers** derived from a Curve25519 (X25519) public key
- **E2E encryption** using X25519 + HKDF-SHA256 + ChaCha20-Poly1305
- **Onion-style forwarding type shit** through relay peers (3 max in this prototype for now)
It is inspired from my good friend [S3](https://github.com/S3NP41-v) [Pcomm project](https://github.com/S3NP41-v/PComm)

>  This is not production-or-daily-use-ready software. It lacks many protections Tor uses (padding schedules, guard policy, congestion control, DoS hardening, directory/dht discovery, rendezvous/intro points, etc and even some more.). Use at your own risk for learning/testing only. It will change in the following weeks.

## Build

Requirements:
- CMake
- SQLite3 development headers
- OpenSSL 3 (libssl/libcrypto)

```bash
mkdir -p build
cmake -S . -B build
cmake --build build -j
```

Binary: `build/pcomm`

## Run

From the project root:

```bash
./build/pcomm \
  --data-dir ./pcomm_data \
  --ui-dir ./ui \
  --relay 0.0.0.0:9001 \
  --http 127.0.0.1:8080 \
  --peers ./peers.txt
```

Open UI:
- http://127.0.0.1:8080/

On first start, PComm generates `./pcomm_data/identity.key` and prints your PComm ID.

## Adding contacts

In the UI, add a contact with:
- `id`: the other node's PComm ID
- `host`: reachable IP/DNS
- `port`: their relay port

Mark **Relay** for nodes you want to use as onion hops.

## Peers file (relays)

`peers.txt` format:

```
# <user_id> <host> <port>
pcomm1_XXXX...  203.0.113.10  9001
pcomm1_YYYY...  203.0.113.11  9001
```

Those entries are inserted as contacts with `is_relay=1`.

## How messages route (prototype)

- Sender encrypts the message for the recipient
- Sender optionally wraps it in onion layers for up to 3 relays (if possible)
- Exit relay connects directly to the recipient and delivers the sealed payload

The recipient decrypts and stores messages in SQLite (hoprfully)

