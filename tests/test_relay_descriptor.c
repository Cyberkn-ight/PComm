#define _POSIX_C_SOURCE 200809L
#include "config.h"
#include "crypto.h"
#include "db.h"
#include "descriptor.h"
#include "directory.h"
#include "identity.h"
#include "lifecycle.h"
#include "net.h"
#include "proto.h"
#include "relay.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #condition, errno); \
        ok = 0; goto done; \
    } \
} while (0)

enum { PUT_HEADER = 61, MAX_PUT = PUT_HEADER + PCOMM_DESCRIPTOR_MAX_BLOB };

static void put_u32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24); out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8); out[3] = (uint8_t)value;
}

static uint64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) abort();
    return (uint64_t)now.tv_sec*1000u + (uint64_t)now.tv_nsec/1000000u;
}

static int make_identity(pcomm_identity_t *identity) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    size_t private_length = 32, public_length = 32;
    memset(identity, 0, sizeof(*identity));
    int result = context && EVP_PKEY_keygen_init(context) == 1 && EVP_PKEY_keygen(context, &key) == 1 &&
        EVP_PKEY_get_raw_private_key(key, identity->privkey, &private_length) == 1 &&
        EVP_PKEY_get_raw_public_key(key, identity->pubkey, &public_length) == 1 &&
        private_length == 32 && public_length == 32 &&
        pcomm_user_id_from_pubkey(identity->pubkey, identity->user_id) == 0 ? 0 : -1;
    EVP_PKEY_free(key); EVP_PKEY_CTX_free(context);
    return result;
}

static int configure(pcomm_config_t *config) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address = {0};
    socklen_t length = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int result = -1;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) ||
        getsockname(fd, (struct sockaddr *)&address, &length)) goto done;
    pcomm_config_defaults(config);
    snprintf(config->relay_host, sizeof(config->relay_host), "127.0.0.1");
    config->relay_port = ntohs(address.sin_port);
    config->allow_private_addrs = true;
    config->peers_path[0] = '\0';
    result = 0;
done:
    close(fd);
    return result;
}

static int open_database(pcomm_db_t *db) {
    if (sqlite3_open_v2(":memory:", &db->db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) return -1;
    db->replay_cache = pcomm_replay_cache_create(PCOMM_REPLAY_CACHE_CAPACITY, PCOMM_REPLAY_CACHE_TTL_MS);
    return db->replay_cache && sqlite3_exec(db->db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL) == SQLITE_OK &&
        pcomm_db_init_schema(db) == 0 ? 0 : -1;
}

static int wait_eof(int fd) {
    uint64_t deadline = now_ms() + 2000;
    while (now_ms() < deadline) {
        struct pollfd ready = {fd, POLLIN, 0};
        uint64_t current = now_ms();
        if (current >= deadline) return -1;
        int remaining = (int)(deadline - current);
        int result = poll(&ready, 1, remaining);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0 || !(ready.revents & (POLLIN | POLLHUP))) return -1;
        uint8_t byte;
        ssize_t count = recv(fd, &byte, 1, 0);
        if (count < 0 && errno == EINTR) continue;
        return count == 0 ? 0 : -1;
    }
    return -1;
}

static int exchange(const pcomm_config_t *config, const uint8_t *request, uint32_t request_length,
                        uint8_t **response, uint32_t *response_length) {
    int fd = net_connect_tcp("127.0.0.1", config->relay_port);
    int result = -1;
    if (response) *response = NULL;
    if (response_length) *response_length = 0;
    if (fd < 0) return -1;
    struct timeval timeout = {2, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        pcomm_send_packet(fd, PCOMM_MSG_CTRL, NULL, request, request_length)) goto done;
    if (response) {
        pcomm_msg_type_t type;
        uint8_t ephemeral[32];
        if (!response_length || pcomm_recv_packet(fd, &type, ephemeral, response, response_length) ||
            type != PCOMM_MSG_CTRL) goto done;
    }
    result = wait_eof(fd);
done:
    net_close(fd);
    if (result && response) { free(*response); *response = NULL; }
    return result;
}

static uint32_t put_request(uint8_t out[MAX_PUT], const uint8_t infohash[20], const uint8_t key[32],
                                uint32_t expires, const uint8_t *blob, uint32_t length) {
    if (length > PCOMM_DESCRIPTOR_MAX_BLOB) return 0;
    out[0] = PCOMM_CTRL_DESC_PUT;
    memcpy(out + 1, infohash, 20); memcpy(out + 21, key, 32);
    put_u32(out + 53, expires); put_u32(out + 57, length);
    memcpy(out + PUT_HEADER, blob, length);
    return PUT_HEADER + length;
}

static uint32_t unsigned_descriptor(uint8_t out[256], const pcomm_peer_t *intro, uint32_t epoch) {
    size_t user_length = strlen(intro->user_id), host_length = strlen(intro->host);
    out[0] = 1; put_u32(out + 1, epoch); out[5] = 1;
    out[6] = (uint8_t)(user_length >> 8); out[7] = (uint8_t)user_length;
    memcpy(out + 8, intro->user_id, user_length);
    size_t offset = 8 + user_length;
    out[offset++] = (uint8_t)host_length;
    memcpy(out + offset, intro->host, host_length); offset += host_length;
    out[offset++] = (uint8_t)(intro->port >> 8); out[offset++] = (uint8_t)intro->port;
    memcpy(out + offset, intro->pubkey, 32);
    return (uint32_t)(offset + 32);
}

static int stored_equals(pcomm_db_t *db, const uint8_t key[32], const uint8_t *expected, uint32_t expected_length) {
    sqlite3_stmt *statement = NULL;
    int count = -1;
    if (sqlite3_prepare_v2(db->db, "SELECT count(*) FROM descriptors;", -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW) count = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    uint8_t *stored = NULL;
    uint32_t length = 0;
    int fetched = pcomm_db_desc_get(db, key, &stored, &length);
    int result = expected ? count == 1 && fetched == 0 && length == expected_length &&
        memcmp(stored, expected, length) == 0 : count == 0 && fetched == -1;
    free(stored);
    return result;
}

static void stop_relay(void) {
    pcomm_shutdown_request();
    net_shutdown_all();
    pcomm_relay_stop();
}

static int test_descriptor_control(void) {
    pcomm_config_t config;
    pcomm_db_t db = {0};
    pcomm_identity_t relay = {0}, owner = {0}, other = {0}, intro_identity = {0};
    pcomm_peer_t intro = {0};
    uint8_t *blob = NULL, *revision = NULL, *request = NULL, *response = NULL, *fetched = NULL;
    uint32_t blob_length = 0, revision_length = 0, request_length = 0, response_length = 0, fetched_length = 0;
    uint8_t key[32], infohash[20], other_key[32], other_hash[20], nonce[32], wrong[32];
    uint8_t packet[MAX_PUT], invalid[8][MAX_PUT + 1], legacy[256];
    uint32_t invalid_length[8];
    const char *invalid_names[] = {"unsigned", "tampered", "wrong key", "wrong infohash",
        "wrong owner lookup", "outer expiry", "trailing payload", "truncated blob"};
    int ok = 1;
    CHECK(net_tracked_socket_count() == 0);
    pcomm_shutdown_reset();
    CHECK(configure(&config) == 0 && open_database(&db) == 0);
    CHECK(make_identity(&relay) == 0 && make_identity(&owner) == 0 && make_identity(&other) == 0 &&
        make_identity(&intro_identity) == 0);
    memcpy(intro.pubkey, intro_identity.pubkey, 32);
    memcpy(intro.user_id, intro_identity.user_id, sizeof(intro.user_id));
    snprintf(intro.host, sizeof(intro.host), "127.0.0.1");
    intro.port = 15001;
    time_t wall_time = time(NULL);
    CHECK(wall_time >= 0 && (uint64_t)wall_time < UINT32_MAX - 3600u);
    uint32_t now = (uint32_t)wall_time;
    uint32_t issued = now % PCOMM_DESCRIPTOR_EPOCH_SECONDS ? now : now + 1;
    uint32_t older = issued - 1, expires = now + 3600;
    uint32_t epoch = issued / PCOMM_DESCRIPTOR_EPOCH_SECONDS;
    CHECK(pcomm_descriptor_build(&owner, epoch, issued, expires, &intro, 1, &blob, &blob_length) == 0);
    CHECK(pcomm_descriptor_keys(owner.pubkey, epoch, key, infohash) == 0);
    CHECK(pcomm_descriptor_keys(other.pubkey, epoch, other_key, other_hash) == 0);
    uint32_t packet_length = put_request(packet, infohash, key, expires, blob, blob_length);
    CHECK(packet_length > PUT_HEADER && packet_length <= MAX_PUT);
    for (size_t i = 0; i < 8; ++i) {
        memcpy(invalid[i], packet, packet_length);
        invalid_length[i] = packet_length;
    }
    uint32_t legacy_length = unsigned_descriptor(legacy, &intro, epoch);
    invalid_length[0] = put_request(invalid[0], infohash, key, expires, legacy, legacy_length);
    invalid[1][packet_length - 1] ^= 1;
    memcpy(invalid[2] + 21, other_key, 32);
    memcpy(invalid[3] + 1, other_hash, 20);
    memcpy(invalid[4] + 21, other_key, 32); memcpy(invalid[4] + 1, other_hash, 20);
    put_u32(invalid[5] + 53, expires + 1);
    invalid[6][packet_length] = 0x42; invalid_length[6]++;
    put_u32(invalid[7] + 57, blob_length + 1);
    CHECK(pcomm_relay_start(&config, &relay, &db) == 0);
    for (unsigned phase = 0; phase < 2; ++phase) {
        for (size_t i = 0; i < 8; ++i) {
            if (exchange(&config, invalid[i], invalid_length[i], NULL, NULL) ||
                !stored_equals(&db, key, phase ? blob : NULL, phase ? blob_length : 0)) {
                fprintf(stderr, "Rejected PUT failed: %s, phase %u\n", invalid_names[i], phase);
                ok = 0; goto done;
            }
        }
        if (!phase) {
            CHECK(exchange(&config, packet, packet_length, NULL, NULL) == 0);
            CHECK(stored_equals(&db, key, blob, blob_length));
        }
    }

    intro.port++;
    CHECK(pcomm_descriptor_build(&owner, epoch, issued, expires, &intro, 1, &revision, &revision_length) == 0);
    uint32_t revision_packet_length = put_request(packet, infohash, key, expires, revision, revision_length);
    CHECK(exchange(&config, packet, revision_packet_length, NULL, NULL) == 0);
    CHECK(stored_equals(&db, key, blob, blob_length));
    free(revision); revision = NULL;
    CHECK(pcomm_descriptor_build(&owner, epoch, older, expires, &intro, 1, &revision, &revision_length) == 0);
    revision_packet_length = put_request(packet, infohash, key, expires, revision, revision_length);
    CHECK(exchange(&config, packet, revision_packet_length, NULL, NULL) == 0);
    CHECK(stored_equals(&db, key, blob, blob_length));

    CHECK(pcomm_random(nonce, sizeof(nonce)) == 0);
    CHECK(pcomm_directory_request(infohash, key, nonce, &request, &request_length) == 0);
    CHECK(exchange(&config, request, request_length, &response, &response_length) == 0);
    CHECK(pcomm_directory_parse_response(response, response_length, relay.pubkey, nonce, key,
        &fetched, &fetched_length) == 0);
    CHECK(fetched_length == blob_length && memcmp(fetched, blob, blob_length) == 0);
    free(fetched); fetched = NULL;
    CHECK(pcomm_directory_parse_response(response, response_length, other.pubkey, nonce, key,
        &fetched, &fetched_length) == -1);
    memcpy(wrong, nonce, sizeof(wrong)); wrong[0] ^= 1;
    CHECK(pcomm_directory_parse_response(response, response_length, relay.pubkey, wrong, key,
        &fetched, &fetched_length) == -1);
    memcpy(wrong, key, sizeof(wrong)); wrong[0] ^= 1;
    CHECK(pcomm_directory_parse_response(response, response_length, relay.pubkey, nonce, wrong,
        &fetched, &fetched_length) == -1);
    free(response); response = NULL; free(request); request = NULL;
    CHECK(pcomm_random(nonce, sizeof(nonce)) == 0);
    CHECK(pcomm_directory_request(other_hash, other_key, nonce, &request, &request_length) == 0);
    CHECK(exchange(&config, request, request_length, &response, &response_length) == 0);
    CHECK(pcomm_directory_parse_response(response, response_length, relay.pubkey, nonce, other_key,
        &fetched, &fetched_length) == 1);
    CHECK(fetched == NULL && fetched_length == 0);

    legacy[0] = PCOMM_CTRL_DESC_GET;
    memcpy(legacy + 1, infohash, 20); memcpy(legacy + 21, key, 32);
    CHECK(exchange(&config, legacy, 53, NULL, NULL) == 0);
    CHECK(stored_equals(&db, key, blob, blob_length));
    stop_relay();
    CHECK(net_tracked_socket_count() == 0);
    CHECK(sqlite3_next_stmt(db.db, NULL) == NULL);
    CHECK(sqlite3_close(db.db) == SQLITE_OK);
    db.db = NULL;
done:
    stop_relay();
    if (net_tracked_socket_count() != 0) ok = 0;
    free(blob); free(revision); free(request); free(response); free(fetched);
    pcomm_db_close(&db);
    OPENSSL_cleanse(&relay, sizeof(relay)); OPENSSL_cleanse(&owner, sizeof(owner));
    OPENSSL_cleanse(&other, sizeof(other)); OPENSSL_cleanse(&intro_identity, sizeof(intro_identity));
    return ok;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, SIG_DFL);
    alarm(20);
    int passed = test_descriptor_control();
    alarm(0);
    printf("%s: relay descriptor control\n", passed ? "PASS" : "FAIL");
    return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
