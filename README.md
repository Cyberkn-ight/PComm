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
- Mailbox deposit rate limits, storage quotas, and expiry
- Exit policy safety default: relays reject connecting to private/loopback/link-local destinations unless enabled
- DHT node persistence + maintenance (learned nodes are stored in SQLite and periodically refreshed)
- Jittered mesh gossip interval (reduces fingerprintable periodicity)

It is inspired from my good friend [S3](https://github.com/S3NP41-v) [Pcomm project](https://github.com/S3NP41-v/PComm)

>  This is not production-or-daily-use-ready software. It lacks many protections Tor uses (padding schedules, guard policy, congestion control, DoS hardening, directory/dht discovery, rendezvous/intro points, etc and even some more.). Use at your own risk for learning/testing only. It will change in the following weeks.

## Build

Requirements:
- CMake
- A C11 compiler and POSIX threads library
- SQLite3 development headers
- OpenSSL 3 (libssl/libcrypto)

```bash
mkdir -p build
cmake -S . -B build
cmake --build build -j
```

Binary: `build/pcomm`

### Windows development tools

Use [MSYS2 UCRT64](https://www.msys2.org/docs/environments/) for the native Windows
compiler and dependencies. Update MSYS2 with `pacman -Syu`, reopening the shell
and repeating the update if requested. Then install these packages in its UCRT64
shell:

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
  mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja \
  mingw-w64-ucrt-x86_64-make mingw-w64-ucrt-x86_64-pkgconf \
  mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-sqlite3 \
  mingw-w64-ucrt-x86_64-winpthreads mingw-w64-ucrt-x86_64-gdb
```

For PowerShell, add the installation's `ucrt64\bin` directory (normally
`C:\msys64\ucrt64\bin`) to your user PATH and restart the terminal. Configure in
a separate directory:

```powershell
cmake -S . -B build-ucrt64 -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-ucrt64
```

Native Windows compilation currently needs source portability work for POSIX
networking headers and socket APIs. Keep each platform/toolchain's build directory
separate. Generated build files are ignored by Git, along with local identities,
message databases, and `peers.txt`; share the example peer file instead.

To build the complete application on Windows using the MSYS POSIX runtime, install
`gcc openssl-devel libsqlite-devel` with `pacman -S --needed` in an MSYS2 shell.
Then use a separate PowerShell session (adjust the installation path if needed):

```powershell
$msysRoot = 'C:\msys64'
$env:Path = "$msysRoot\usr\bin;$msysRoot\ucrt64\bin;$env:Path"
cmake -S . -B build-posix-msys -G Ninja -DCMAKE_SYSTEM_NAME=MSYS `
  "-DCMAKE_C_COMPILER=$msysRoot/usr/bin/gcc.exe" -DCMAKE_BUILD_TYPE=Debug
cmake --build build-posix-msys --target check
```

This changes PATH only for that session. The resulting application depends on the
MSYS runtime; it does not resolve the remaining native Windows networking port.

### Tests

Build and run the unit and regression tests with one target:

```bash
cmake -S . -B build-tests -G Ninja -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-tests --target check
```

`check` builds every test executable before running CTest and reports a failing
exit status if any test fails. Use a separate build directory and
`-DCMAKE_BUILD_TYPE=Release` to test an optimized build; checks remain active with
`NDEBUG`. For a multi-configuration generator, select `--config Debug` or
`--config Release` on the build command. Individual tests can also be rerun with
`ctest --test-dir build-tests --output-on-failure`.

| CTest suite | Coverage |
| --- | --- |
| `crypto` | RFC known-answer vectors, seal/open round trips, authentication failures, and buffer limits. |
| `msg` | Direct/group/legacy messages, independent wire fixtures, UTF-8, field limits, and truncation. |
| `db` | Contact/message/group/settings/descriptor/DHT-node insert, fetch, and update operations. |
| `bencode` | Golden encodings, nested containers, binary strings/keys, integer boundaries, and malformed data. |
| `replay_cache`, `receive_replay` | Replay windows, concurrent delivery, storage failure retries, and equivalent X25519 header encodings. |
| `mailbox_guard`, `mailbox_db` | Rate and storage limits, expiry, concurrent admission, and safe retrieval batches. |
| `proto_limits` | Packet framing, early length rejection, and bounded fragment accumulation. |
| `lifecycle` | Concurrent shutdown wakeups, repeated requests, timeouts, and restart reset. |
| `net_shutdown` (POSIX) | Interrupting accept/read operations, socket ownership, and cleanup. |
| `services_shutdown` (POSIX) | Service restarts, stalled clients and peers, active circuits/rendezvous, and partial startup rollback. |
| `process_shutdown` (POSIX) | Actual SIGINT/SIGTERM exits, startup failure, database integrity, and port reuse. |

The ten portable suites use real OpenSSL and isolated in-memory SQLite databases;
packet I/O in the framing test is simulated. They build with the native Windows
toolchain independently of the application's POSIX networking dependencies.
POSIX builds add three integration suites using loopback peers. Process tests
create temporary identities and SQLite files inside the build directory and
remove their fixtures afterward; they do not use your data directory. No extra
test framework is required. These checks do not replace full multi-node or
cross-platform application testing.

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

SIGINT (Ctrl+C) and SIGTERM request coordinated shutdown. The signal handler only
sets a flag; normal thread context interrupts socket operations and waits, joins
all service and connection workers, then closes SQLite. The same cleanup runs
after a partially failed startup. Service start/stop operations are serialized by
the main controller, and shutdown reset is only valid after every worker joins.
An operating-system hostname lookup already inside synchronous `getaddrinfo` can
still delay shutdown until the resolver returns.

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

Incoming mailbox, rendezvous, and legacy direct deliveries share a bounded cache
of 4,096 SHA-256 hashes of successfully stored nonce/ciphertext/tag tuples.
Equivalent X25519 ephemeral public-key encodings share the same fingerprint, so
changing only that header cannot bypass replay rejection. Repeated envelopes
still in the cache are silently ignored before message or group-invite
side effects. Invalid messages and failed storage attempts do not occupy entries.
The cache stores no plaintext and expires entries 24 hours after acceptance, using
local monotonic time. It is process-local: restarting clears it, and LRU eviction
can shorten the replay window. It does not authenticate sender identity or reject
the same plaintext encrypted into a different envelope.

### Mailbox abuse controls

Each relay applies these limits to mailbox deposits:

- Per accepted socket peer IP: burst of 32 deposits, replenished at one per second.
- Across the relay: burst of 128 deposits, replenished at 20 per second.
- Per mailbox: 100 envelopes and 64 KiB of stored envelope bytes.
- Across mailboxes: 10,000 envelopes and 16 MiB of stored envelope bytes.
- Envelope size: 1 to 3,072 bytes, including encryption and message headers.
- Expiry: 48 hours after the relay receives an envelope. Expired items are pruned
  on reads/writes and by five-second relay maintenance.

The IP limiter survives reconnects and keeps up to 4,096 hashed source keys in
memory. Fully replenished source entries are reused; a full limiter rejects new
sources instead of resetting exhausted budgets. Source addresses are not stored
in SQLite or logged by these controls. Onion-routed deposits share their exit
relay's allowance. These limits also apply during local development.

Malformed, rate-limited, and over-quota deposits are silently rejected and do not
trigger DHT announcements. The existing deposit protocol has no acceptance ACK;
successful socket transmission alone does not establish that a relay stored the
message. Proof of work remains an optional future extension.

Retrieval batches contain at most 3,800 encoded bytes so they fit the current
single-cell RPC response. Only returned rows are removed; remaining rows stay
queued for later polls. Larger pre-existing envelopes are left to expire. The
mailbox sender rejects new envelopes over 3 KiB before constructing a deposit.
This size limit includes group invites and their member lists, so large invites
can exceed it before the UI's 64-member input limit. The current group UI does
not surface every individual delivery failure.
Packet payloads and circuit request/response buffers are separately bounded to
64 KiB plus framing. These are mailbox admission and storage protections;
connection-flood and slow-client defenses require further work.

## Group chats (prototype)

- Create a group from the UI by providing a title and member IDs
- PComm sends a group invite message to each member
- Group messages are fanned out: the sender encrypts separately to each member
