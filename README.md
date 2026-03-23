# PComm (prototype)

PComm is a **prototype** as of rn, an onion-relay messenger written in pure C (the graph lies shhhhhh) with:
- SQLite message storage (schema designed to extend to group chats later if I'm not too lazy)
- A dogshit embedded HTTP server that serves a barebone HTML/CSS/JS UI
- User identifiers derived from a Curve25519 (X25519) public key
- E2E encryption using X25519 + HKDF-SHA256 + ChaCha20-Poly1305
- Onion-style forwarding type shit through relay peers (3 max in this prototype for now)
- A Tor-ripped-off intro/HSDir mailbox model:
  - users publish a small descriptor (intro points) to HSDirs
  - senders deliver encrypted messages to a recipient mailbox (no recipient IP required)
  - recipients poll mailboxes via onion-routed requests
- A simple mesh gossip mechanism (HELLO + peer exchange) so new nodes can quickly learn relays
- Lightweight cover traffic (NOOP onions) to make traffic less bursty
- Circuit pool (primary + spare) and guard pinning (stored in DB settings)
- End-to-end keepalive using `RELAY_PING/RELAY_PONG` (plus idle timeouts for dedicated circuits)
- Hidden-service registry caps + TTL pruning on relays (intro + rendezvous cookies)
- Relay upstream queue cap (prevents unbounded memory growth)
- Exit policy safety default: relays reject connecting to private/loopback/link-local destinations unless enabled
- DHT node persistence + maintenance (learned nodes are stored in SQLite and periodically refreshed)
- Jittered mesh gossip interval (reduces fingerprintable periodicity)

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
- Open UI: `http://127.0.0.1:8080/`

### Dev / local network helpers

- `--allow-private-addrs` : allow learning/using private/loopback peer addresses (useful for LAN testing)
- `--allow-private-exit`  : allow exit connections to private/loopback destinations (**unsafe**, SSRF risk)

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

You can send to a user just by their ID:
- add them to contacts (host/port optional), or just paste their ID into the send box
- the sender encrypts E2E to the recipient public key (derived from the ID)
- messages are delivered using a Tor-inspired approach:
  - users publish a descriptor (intro points) and mailbox location hints
  - when both are online, PComm attempts rendezvous (intro + rendezvous cookie)
  - otherwise it falls back to mailbox dead-drops stored on relays discovered via the DHT

The recipient periodically polls mailboxes and stores messages locally.

## Group chats (prototype)

- Create a group from the UI by providing a title and member IDs
- PComm sends a group invite message to each member
- Group messages are fanned out: the sender encrypts separately to each member