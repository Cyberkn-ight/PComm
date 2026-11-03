#define _POSIX_C_SOURCE 200809L
#include "bencode.h"
#include "config.h"
#include "crypto.h"
#include "db.h"
#include "dht.h"
#include "identity.h"
#include "lifecycle.h"
#include "net.h"
#include "sign.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); ok = 0; goto done; \
} } while (0)

enum { NORMAL, FORGED_SOURCE, INVALID_BINDING, INVALID_SIGNATURE, UNSIGNED_METADATA, REPLAYED_NONCE, UNSIGNED_THEN_VALID };

typedef struct {
    int fd, attacker, started;
    uint16_t port;
    pthread_t thread;
    pcomm_identity_t identity;
    atomic_int running, allow_valid, observed, attacks, failed, mode, relay_override;
} fake_seed_t;

static uint64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) abort();
    return (uint64_t)now.tv_sec*1000+(uint64_t)now.tv_nsec/1000000;
}

static void delay_ms(unsigned milliseconds) {
    struct timespec duration = {milliseconds/1000,(long)(milliseconds%1000)*1000000};
    while (nanosleep(&duration, &duration) && errno == EINTR) {}
}

static int make_identity(pcomm_identity_t *identity) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    size_t priv_len = 32, pub_len = 32;
    int ok = ctx && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1 &&
        EVP_PKEY_get_raw_private_key(key, identity->privkey, &priv_len) == 1 &&
        EVP_PKEY_get_raw_public_key(key, identity->pubkey, &pub_len) == 1 &&
        priv_len == 32 && pub_len == 32 &&
        pcomm_user_id_from_pubkey(identity->pubkey, identity->user_id) == 0;
    EVP_PKEY_free(key); EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int bind_udp(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(address);
    if (fd < 0 || bind(fd, (struct sockaddr *)&address, len) ||
        getsockname(fd, (struct sockaddr *)&address, &len)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    *port = ntohs(address.sin_port);
    return fd;
}

static int set_value(benc_t *dict, const char *name, benc_t *value) {
    if (!value || benc_dict_set(dict, name, value)) { benc_free(value); return -1; }
    return 0;
}

static void proof_bytes(const uint8_t tx[2], const uint8_t nonce[32], const uint8_t id[20],
                           const uint8_t public_key[32], uint16_t port, uint8_t out[98]) {
    memcpy(out, "PCOMM-DHT2", 10); memcpy(out+10, tx, 2); memcpy(out+12, nonce, 32);
    memcpy(out+44, id, 20); memcpy(out+64, public_key, 32);
    out[96] = (uint8_t)(port >> 8); out[97] = (uint8_t)port;
}

static int send_response(fake_seed_t *seed, int fd, const struct sockaddr_in *to,
                           const uint8_t tx[2], const uint8_t nonce[32], int mode, int trailing) {
    uint8_t binding[41], node_id[20], reply_nonce[32], input[98], signature[64], *wire = NULL;
    size_t len = 0;
    memcpy(binding, "pcomm-dht", 9); memcpy(binding+9, seed->identity.pubkey, 32);
    SHA1(binding, sizeof(binding), node_id);
    if (mode == INVALID_BINDING) node_id[0] ^= 1;
    memcpy(reply_nonce, nonce, 32);
    if (mode == REPLAYED_NONCE) memset(reply_nonce, 0xa5, 32);
    uint16_t relay_port = (uint16_t)atomic_load(&seed->relay_override);
    if (!relay_port) relay_port = seed->port;
    proof_bytes(tx, reply_nonce, node_id, seed->identity.pubkey, relay_port, input);
    if (pcomm_sign(seed->identity.privkey, input, sizeof(input), signature)) return -1;
    if (mode == INVALID_SIGNATURE) signature[0] ^= 1;
    benc_t *msg = benc_new_dict(), *response = benc_new_dict();
    int rc = -1;
    if (!msg || !response || set_value(msg, "t", benc_new_str(tx, 2)) ||
        set_value(msg, "y", benc_new_str((const uint8_t *)"r", 1)) ||
        set_value(response, "id", benc_new_str(node_id, 20)) ||
        set_value(response, "pcomm_pub", benc_new_str(seed->identity.pubkey, 32)) ||
        set_value(response, "relay_port", benc_new_int(relay_port)) ||
        set_value(response, "pcomm_nonce", benc_new_str(reply_nonce, 32)) ||
        (mode != UNSIGNED_METADATA && set_value(response, "pcomm_sig", benc_new_str(signature, 64)))) goto done;
    if (set_value(msg, "r", response)) { response = NULL; goto done; }
    response = NULL;
    if (benc_encode(msg, &wire, &len)) goto done;
    if (trailing) {
        uint8_t *longer = realloc(wire, len+1);
        if (!longer) goto done;
        wire = longer; wire[len++] = 'x';
    }
    if (sendto(fd, wire, len, 0, (const struct sockaddr *)to, sizeof(*to)) == (ssize_t)len) rc = 0;
done:
    benc_free(response); benc_free(msg); free(wire);
    return rc;
}

static void *fake_thread(void *arg) {
    fake_seed_t *seed = arg;
    struct sockaddr_in pending_from = {0};
    uint8_t pending_tx[2] = {0}, pending_nonce[32] = {0};
    int pending = 0;
    while (atomic_load(&seed->running)) {
        if (pending && (pending == 2 || atomic_load(&seed->allow_valid))) {
            if (send_response(seed, seed->fd, &pending_from, pending_tx, pending_nonce, NORMAL, 0)) atomic_store(&seed->failed, 1);
            pending = 0;
        }
        struct pollfd ready = {seed->fd, POLLIN, 0};
        int polled = poll(&ready, 1, 20);
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0) { atomic_store(&seed->failed, 1); break; }
        if (!polled) continue;
        uint8_t wire[4096];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t count = recvfrom(seed->fd, wire, sizeof(wire), 0, (struct sockaddr *)&from, &from_len);
        benc_t *msg = NULL;
        size_t used = 0;
        if (count <= 0 || benc_parse(wire, (size_t)count, &msg, &used) || used != (size_t)count) {
            benc_free(msg); atomic_store(&seed->failed, 1); break;
        }
        benc_t *tx = benc_dict_get(msg, "t"), *kind = benc_dict_get(msg, "y"), *a = benc_dict_get(msg, "a");
        benc_t *nonce = a ? benc_dict_get(a, "pcomm_nonce") : NULL;
        if (!tx || tx->t != BENC_STR || tx->slen != 2 || !kind ||
            kind->t != BENC_STR || kind->slen != 1 || kind->s[0] != 'q' ||
            !nonce || nonce->t != BENC_STR || nonce->slen != 32) {
            benc_free(msg); atomic_store(&seed->failed, 1); break;
        }
        pending_from = from;
        memcpy(pending_tx, tx->s, 2);
        memcpy(pending_nonce, nonce->s, 32);
        atomic_fetch_add(&seed->observed, 1);
        int mode = atomic_load(&seed->mode);
        if (!atomic_load(&seed->allow_valid) && mode == FORGED_SOURCE) {
            uint8_t wrong_tx[2] = {(uint8_t)(pending_tx[0]^0x80), pending_tx[1]};
            if (send_response(seed, seed->attacker, &from, pending_tx, pending_nonce, NORMAL, 0) ||
                send_response(seed, seed->fd, &from, wrong_tx, pending_nonce, NORMAL, 0) ||
                send_response(seed, seed->fd, &from, pending_tx, pending_nonce, NORMAL, 1)) atomic_store(&seed->failed, 1);
            atomic_store(&seed->attacks, 1);
            pending = 1;
        } else if (!atomic_load(&seed->allow_valid) && mode == UNSIGNED_THEN_VALID) {
            if (send_response(seed, seed->fd, &from, pending_tx, pending_nonce, UNSIGNED_METADATA, 0)) atomic_store(&seed->failed, 1);
            pending = 2;
        } else if (!atomic_load(&seed->allow_valid)) {
            if (send_response(seed, seed->fd, &from, pending_tx, pending_nonce, mode, 0)) atomic_store(&seed->failed, 1);
            if (mode == REPLAYED_NONCE) pending = 1;
        } else {
            if (send_response(seed, seed->fd, &from, pending_tx, pending_nonce, NORMAL, 0)) atomic_store(&seed->failed, 1);
        }
        benc_free(msg);
    }
    return NULL;
}

static int seed_open(fake_seed_t *seed, int mode) {
    memset(seed, 0, sizeof(*seed));
    seed->fd = seed->attacker = -1;
    atomic_init(&seed->running, 1); atomic_init(&seed->allow_valid, mode == NORMAL);
    atomic_init(&seed->observed, 0); atomic_init(&seed->attacks, 0); atomic_init(&seed->failed, 0);
    atomic_init(&seed->mode, mode); atomic_init(&seed->relay_override, 0);
    uint16_t attacker_port;
    if (make_identity(&seed->identity) || (seed->fd = bind_udp(&seed->port)) < 0 ||
        (seed->attacker = bind_udp(&attacker_port)) < 0 || pthread_create(&seed->thread, NULL, fake_thread, seed)) return -1;
    seed->started = 1;
    return 0;
}

static void seed_close(fake_seed_t *seed) {
    atomic_store(&seed->running, 0);
    if (seed->started) pthread_join(seed->thread, NULL);
    if (seed->fd >= 0) close(seed->fd);
    if (seed->attacker >= 0) close(seed->attacker);
    seed->fd = seed->attacker = -1;
}

static int setup(pcomm_config_t *cfg, pcomm_identity_t *identity, pcomm_db_t *db, const fake_seed_t *seed) {
    pcomm_shutdown_reset();
    pcomm_config_defaults(cfg);
    cfg->allow_private_addrs = true;
    cfg->dht_maint_interval_sec = 4;
    int reservation = bind_udp(&cfg->relay_port);
    if (reservation < 0) return -1;
    close(reservation);
    cfg->advertise_port = cfg->relay_port;
    cfg->bootstrap_count = 1;
    strcpy(cfg->bootstrap[0].host, "localhost");
    cfg->bootstrap[0].port = seed->port;
    return make_identity(identity) == 0 && sqlite3_open_v2(":memory:", &db->db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL) == SQLITE_OK &&
        pcomm_db_init_schema(db) == 0 ? 0 : -1;
}

static int contact_count(pcomm_db_t *db) {
    sqlite3_stmt *st = NULL;
    int result = -1;
    if (sqlite3_prepare_v2(db->db, "SELECT count(*) FROM contacts", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) result = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return result;
}

static int wait_contact(pcomm_db_t *db, unsigned timeout) {
    uint64_t deadline = now_ms()+timeout;
    do {
        if (contact_count(db) > 0) return 0;
        delay_ms(10);
    } while (now_ms() < deadline);
    return -1;
}

static int verify_local_response(const pcomm_config_t *cfg, const pcomm_identity_t *identity, int signed_query) {
    uint16_t port;
    int fd = bind_udp(&port), rc = -1;
    if (fd < 0) return -1;
    struct sockaddr_in to = {0};
    to.sin_family = AF_INET; to.sin_port = htons(cfg->relay_port);
    const char *host = strcmp(cfg->relay_host, "0.0.0.0") ? cfg->relay_host : "127.0.0.1";
    if (inet_pton(AF_INET, host, &to.sin_addr) != 1) { close(fd); return -1; }
    benc_t *query = benc_new_dict(), *args = benc_new_dict(), *response = NULL;
    uint8_t tx[2] = {0x63,0x17}, id[20] = {0x7a}, nonce[32] = {0x23}, *wire = NULL;
    size_t wire_len = 0;
    if (!query || !args || set_value(query, "t", benc_new_str(tx, 2)) ||
        set_value(query, "y", benc_new_str((const uint8_t *)"q", 1)) ||
        set_value(query, "q", benc_new_str((const uint8_t *)"ping", 4)) ||
        set_value(args, "id", benc_new_str(id, 20)) ||
        (signed_query && set_value(args, "pcomm_nonce", benc_new_str(nonce, 32)))) goto done;
    if (set_value(query, "a", args)) { args = NULL; goto done; }
    args = NULL;
    if (benc_encode(query, &wire, &wire_len) ||
        sendto(fd, wire, wire_len, 0, (struct sockaddr *)&to, sizeof(to)) != (ssize_t)wire_len) goto done;
    struct pollfd ready = {fd,POLLIN,0};
    if (poll(&ready, 1, 1000) <= 0) goto done;
    uint8_t bytes[4096];
    ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
    size_t used = 0;
    if (count <= 0 || benc_parse(bytes, (size_t)count, &response, &used) || used != (size_t)count) goto done;
    benc_t *r = benc_dict_get(response, "r"), *pub = r ? benc_dict_get(r, "pcomm_pub") : NULL;
    benc_t *relay_port = r ? benc_dict_get(r, "relay_port") : NULL;
    benc_t *reply_nonce = r ? benc_dict_get(r, "pcomm_nonce") : NULL;
    benc_t *signature = r ? benc_dict_get(r, "pcomm_sig") : NULL;
    benc_t *node_id = r ? benc_dict_get(r, "id") : NULL;
    if (!signed_query) {
        if (node_id && node_id->t == BENC_STR && node_id->slen == 20 && !pub && !relay_port && !reply_nonce && !signature) rc = 0;
    } else if (pub && pub->t == BENC_STR && pub->slen == 32 && memcmp(pub->s, identity->pubkey, 32) == 0 &&
        relay_port && relay_port->t == BENC_INT && relay_port->i == cfg->advertise_port &&
        node_id && node_id->t == BENC_STR && node_id->slen == 20 &&
        reply_nonce && reply_nonce->t == BENC_STR && reply_nonce->slen == 32 && !memcmp(reply_nonce->s, nonce, 32) &&
        signature && signature->t == BENC_STR && signature->slen == 64) {
        uint8_t input[98];
        proof_bytes(tx, nonce, node_id->s, pub->s, (uint16_t)relay_port->i, input);
        if (!pcomm_verify(pub->s, input, sizeof(input), signature->s)) rc = 0;
    }
done:
    free(wire); benc_free(args); benc_free(query); benc_free(response); close(fd);
    return rc;
}

static int test_bootstrap(int mode) {
    fake_seed_t seed = {.fd=-1,.attacker=-1};
    pcomm_config_t cfg;
    pcomm_identity_t identity;
    pcomm_db_t db = {0};
    char host[64]; uint16_t port; uint8_t public_key[32]; int is_relay;
    int ok = 1;
    CHECK(seed_open(&seed, mode) == 0 && setup(&cfg, &identity, &db, &seed) == 0);
    CHECK(contact_count(&db) == 0 && pcomm_dht_start(&cfg, &identity, &db) == 0);
    if (mode != NORMAL) {
        uint64_t deadline = now_ms()+2000;
        while ((mode == FORGED_SOURCE ? !atomic_load(&seed.attacks) : atomic_load(&seed.observed) < 2) && now_ms() < deadline) delay_ms(10);
        CHECK(mode == FORGED_SOURCE ? atomic_load(&seed.attacks) : atomic_load(&seed.observed) >= 2);
        delay_ms(200);
        CHECK(contact_count(&db) == 0);
        atomic_store(&seed.allow_valid, 1);
    }
    CHECK(wait_contact(&db, 6500) == 0 && contact_count(&db) == 1);
    CHECK(pcomm_db_get_contact(&db, seed.identity.user_id, host, sizeof(host), &port, public_key, &is_relay) == 0);
    CHECK(strcmp(host, "127.0.0.1") == 0 && port == seed.port && is_relay == 1 &&
          memcmp(public_key, seed.identity.pubkey, 32) == 0);
    CHECK(verify_local_response(&cfg, &identity, 1) == 0);
    CHECK(verify_local_response(&cfg, &identity, 0) == 0);
    uint64_t started = now_ms();
    pcomm_dht_stop(); pcomm_dht_stop();
    CHECK(now_ms()-started < 1500 && !atomic_load(&seed.failed));
    CHECK(net_tracked_socket_count() == 0);
done:
    pcomm_dht_stop(); seed_close(&seed); pcomm_db_close(&db);
    return ok;
}

static int test_private_bootstrap_policy(void) {
    fake_seed_t seed = {.fd=-1,.attacker=-1};
    pcomm_config_t cfg;
    pcomm_identity_t identity;
    pcomm_db_t db = {0};
    int ok = 1;
    CHECK(seed_open(&seed, NORMAL) == 0 && setup(&cfg, &identity, &db, &seed) == 0);
    cfg.allow_private_addrs = false;
    CHECK(pcomm_dht_start(&cfg, &identity, &db) == 0);
    delay_ms(300);
    CHECK(atomic_load(&seed.observed) == 0 && contact_count(&db) == 0);
    uint64_t started = now_ms();
    pcomm_dht_stop();
    CHECK(now_ms()-started < 1500);
done:
    pcomm_dht_stop(); seed_close(&seed); pcomm_db_close(&db);
    return ok;
}

static int test_fresh_authenticated_relay_resolution(void) {
    fake_seed_t seed = {.fd=-1,.attacker=-1};
    pcomm_config_t cfg;
    pcomm_identity_t identity;
    pcomm_db_t db = {0};
    pcomm_peer_t peer;
    int ok = 1;
    CHECK(seed_open(&seed, NORMAL) == 0 && setup(&cfg, &identity, &db, &seed) == 0);
    cfg.bootstrap_count = 0;
    CHECK(pcomm_dht_start(&cfg, &identity, &db) == 0);
    const int bad_modes[] = {INVALID_SIGNATURE, UNSIGNED_METADATA, REPLAYED_NONCE};
    for (size_t i = 0; i < sizeof(bad_modes)/sizeof(bad_modes[0]); i++) {
        atomic_store(&seed.allow_valid, 0);
        atomic_store(&seed.mode, bad_modes[i]);
        memset(&peer, 0x5a, sizeof(peer));
        CHECK(pcomm_dht_resolve_relay("localhost", seed.port, &peer) == -1);
        CHECK(!peer.user_id[0] && !peer.host[0] && peer.port == 0 && contact_count(&db) == 0);
    }
    atomic_store(&seed.allow_valid, 0);
    atomic_store(&seed.mode, UNSIGNED_THEN_VALID);
    CHECK(pcomm_dht_resolve_relay("127.0.0.1", seed.port, &peer) == 0);
    CHECK(strcmp(peer.user_id, seed.identity.user_id) == 0 && peer.port == seed.port);
    atomic_store(&seed.mode, NORMAL);
    atomic_store(&seed.allow_valid, 1);
    CHECK(pcomm_dht_resolve_relay("localhost", seed.port, &peer) == 0);
    CHECK(strcmp(peer.user_id, seed.identity.user_id) == 0 && strcmp(peer.host, "127.0.0.1") == 0 &&
        peer.port == seed.port && !memcmp(peer.pubkey, seed.identity.pubkey, 32));
    CHECK(contact_count(&db) == 1);
    atomic_store(&seed.relay_override, seed.port == 65535 ? seed.port-1 : seed.port+1);
    CHECK(pcomm_dht_resolve_relay("127.0.0.1", seed.port, &peer) == -1);
    CHECK(!peer.user_id[0] && !peer.host[0] && peer.port == 0);
    CHECK(!atomic_load(&seed.failed));
done:
    pcomm_dht_stop(); seed_close(&seed); pcomm_db_close(&db);
    return ok;
}

static int test_configured_udp_interface(void) {
    fake_seed_t seed = {.fd=-1,.attacker=-1};
    pcomm_config_t cfg;
    pcomm_identity_t identity;
    pcomm_db_t db = {0};
    pcomm_peer_t peer;
    int ok = 1;
    CHECK(seed_open(&seed, NORMAL) == 0 && setup(&cfg, &identity, &db, &seed) == 0);
    cfg.bootstrap_count = 0;
    strcpy(cfg.relay_host, "127.0.0.2");
    CHECK(pcomm_dht_start(&cfg, &identity, &db) == 0);
    CHECK(pcomm_dht_resolve_relay("127.0.0.2", cfg.relay_port, &peer) == 0);
    CHECK(strcmp(peer.host, "127.0.0.2") == 0 && peer.port == cfg.relay_port &&
        !memcmp(peer.pubkey, identity.pubkey, 32) && contact_count(&db) == 0);
    CHECK(verify_local_response(&cfg, &identity, 1) == 0);
done:
    pcomm_dht_stop(); seed_close(&seed); pcomm_db_close(&db);
    return ok;
}

int main(void) {
    alarm(30);
    const char *names[] = {"raw hostname bootstrap discovers relay identity", "response source/transaction/datagram binding", "metadata node-ID binding"};
    unsigned failed = 0;
    for (int mode = NORMAL; mode <= INVALID_BINDING; mode++) {
        int passed = test_bootstrap(mode);
        printf("%s: %s\n", passed ? "PASS" : "FAIL", names[mode]);
        if (!passed) failed++;
    }
    int passed = test_private_bootstrap_policy();
    printf("%s: resolved private bootstrap address policy\n", passed ? "PASS" : "FAIL");
    if (!passed) failed++;
    passed = test_fresh_authenticated_relay_resolution();
    printf("%s: fresh signed relay proof, nonce replay, and port binding\n", passed ? "PASS" : "FAIL");
    if (!passed) failed++;
    passed = test_configured_udp_interface();
    printf("%s: configured UDP bind and signed source identity\n", passed ? "PASS" : "FAIL");
    if (!passed) failed++;
    alarm(0);
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
