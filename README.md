# PComm (prototype)

PComm is a **prototype** onion-relay messenger written in **pure C** with:
- **SQLite** storage for chats (schema supports direct + group conversations)
- A minimal embedded **HTTP server** serving a barebone **HTML/CSS/JS UI**
- **User identifiers** derived from an X25519 public key (self-certifying ID)
- **E2E encryption** using X25519 + HKDF-SHA256 + ChaCha20-Poly1305
- **Long-lived circuits** (3 hops) with **stream multiplexing** (Tor-like RELAY BEGIN/DATA/END)
- A Tor-inspired **intro + mailbox** model for messaging **by ID only** (no recipient IP required)
  - users publish a small **descriptor** (intro points) onto a few storage relays
  - storage relays announce themselves in a **BEP-5 DHT** under the user’s descriptor/mailbox infohash
  - senders discover descriptor/mailbox hosts via DHT (`get_peers`) and deliver encrypted messages there
  - recipients poll mailboxes via circuit-routed requests and store messages locally
- A simple **mesh gossip** mechanism (HELLO + peer exchange) so new nodes can quickly learn relays
- Lightweight **cover traffic** (NOOP onions) to make traffic less bursty

> ⚠️ This is not production-ready anonymity software. It is missing many protections a real Tor implementation relies on (guards policy, robust padding, congestion control, DoS hardening, timing-correlation defenses, etc.). Use for learning/testing only.

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

```bash
./build/pcomm \
  --data-dir ./pcomm_data \
  --ui-dir ./ui \
  --relay 0.0.0.0:9001 \
  --advertise 203.0.113.10:9001 \
  --http 127.0.0.1:8080 \
  --peers ./peers.txt
```

- On first start PComm generates `identity.key` in the data dir.
- It prints your PComm ID.
- Open dogshit UI: `http://127.0.0.1:8080/`

### Notes about `--advertise`

If you listen on `0.0.0.0`, you should set `--advertise` to a reachable address.
This is what other nodes will learn through mesh gossip.

## Bootstrapping the mesh

PComm needs *some* initial relay peers to join the network.
Use `--peers peers.txt` as a bootstrap list.

`peers.txt` format:

```
# <user_id> <host> <port>
pcomm1_XXXX...  203.0.113.10  9001
pcomm1_YYYY...  203.0.113.11  9001
```

PComm will:
- insert those entries as relays
- periodically connect to a random relay and request more relays (peer exchange)
- announce its advertised relay address (HELLO)

## Messaging by ID (no recipient IP needed)

You can send to a user just by their ID (yipeee):
- add them to contacts (host/port optional), or just paste their ID into the send box
- the sender encrypts E2E to the recipient public key (derived from the ID)
- the encrypted blob is delivered to the recipient mailbox stored on relays discovered via the BEP-5 DHT (with HSDir-style fallback)

The recipient periodically polls those mailboxes and stores messages locally.

## Group chats (prototype)

- Create a group from the UI by providing a title and member IDs
- PComm sends a group invite message to each member
- Group messages are fanned out: the sender encrypts separately to each member (no sender-key optimization yet or in the forseeable future)

