#include "cell.h"
#include "circuit.h"
#include "config.h"
#include "crypto.h"
#include "db.h"
#include "dht.h"
#include "hidden.h"
#include "http.h"
#include "identity.h"
#include "lifecycle.h"
#include "mesh.h"
#include "msg.h"
#include "net.h"
#include "proto.h"
#include "ratchet.h"
#include "relay.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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
        ok = 0; \
        goto done; \
    } \
} while (0)

typedef struct {
    int tcp;
    int udp;
    uint16_t port;
} reserved_port_t;

static uint64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static void close_raw(int *fd) {
    if (*fd >= 0) close(*fd);
    *fd = -1;
}

static void close_managed(int *fd) {
    if (*fd >= 0) net_close(*fd);
    *fd = -1;
}

static int bind_loopback(int fd, uint16_t port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    return bind(fd, (const struct sockaddr *)&addr, sizeof(addr));
}

static int reserve_port(reserved_port_t *reserved) {
    reserved->tcp = reserved->udp = -1;
    for (unsigned attempt = 0; attempt < 32; attempt++) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        reserved->tcp = socket(AF_INET, SOCK_STREAM, 0);
        if (reserved->tcp < 0 || bind_loopback(reserved->tcp, 0) != 0 ||
            getsockname(reserved->tcp, (struct sockaddr *)&addr, &addr_len) != 0) goto retry;
        reserved->port = ntohs(addr.sin_port);
        reserved->udp = socket(AF_INET, SOCK_DGRAM, 0);
        if (reserved->udp >= 0 && bind_loopback(reserved->udp, reserved->port) == 0) return 0;
retry:
        close_raw(&reserved->tcp);
        close_raw(&reserved->udp);
    }
    return -1;
}

static void release_port(reserved_port_t *reserved) {
    close_raw(&reserved->tcp);
    close_raw(&reserved->udp);
}

static int ports_are_reusable(const pcomm_config_t *cfg) {
    int tcp = -1, udp = -1, http = -1;
    int yes = 1, rc = -1;
    tcp = socket(AF_INET, SOCK_STREAM, 0);
    udp = socket(AF_INET, SOCK_DGRAM, 0);
    http = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp < 0 || udp < 0 || http < 0) goto done;
    if (setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0 ||
        setsockopt(http, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0) goto done;
    if (bind_loopback(tcp, cfg->relay_port) != 0 ||
        bind_loopback(udp, cfg->relay_port) != 0 ||
        bind_loopback(http, cfg->http_port) != 0) goto done;
    rc = 0;
done:
    close_raw(&tcp);
    close_raw(&udp);
    close_raw(&http);
    return rc;
}

static int config_for_test(pcomm_config_t *cfg, const char *ui_dir) {
    reserved_port_t relay = {-1, -1, 0}, http = {-1, -1, 0};
    int rc = -1;
    pcomm_config_defaults(cfg);
    if (strlen(ui_dir) >= sizeof(cfg->ui_dir)) return -1;
    if (reserve_port(&relay) != 0 || reserve_port(&http) != 0) goto done;
    snprintf(cfg->ui_dir, sizeof(cfg->ui_dir), "%s", ui_dir);
    snprintf(cfg->relay_host, sizeof(cfg->relay_host), "127.0.0.1");
    snprintf(cfg->http_host, sizeof(cfg->http_host), "127.0.0.1");
    snprintf(cfg->advertise_host, sizeof(cfg->advertise_host), "127.0.0.1");
    cfg->relay_port = cfg->advertise_port = relay.port;
    cfg->http_port = http.port;
    cfg->allow_private_addrs = true;
    cfg->allow_private_exit = true;
    rc = 0;
done:
    release_port(&relay);
    release_port(&http);
    return rc;
}

static int make_identity(pcomm_identity_t *identity) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    size_t private_len = sizeof(identity->privkey), public_len = sizeof(identity->pubkey);
    memset(identity, 0, sizeof(*identity));
    int ok = ctx && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1 &&
        EVP_PKEY_get_raw_private_key(key, identity->privkey, &private_len) == 1 &&
        EVP_PKEY_get_raw_public_key(key, identity->pubkey, &public_len) == 1 &&
        private_len == sizeof(identity->privkey) && public_len == sizeof(identity->pubkey) &&
        pcomm_user_id_from_pubkey(identity->pubkey, identity->user_id) == 0;
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int db_open_memory(pcomm_db_t *db) {
    memset(db, 0, sizeof(*db));
    if (sqlite3_open_v2(":memory:", &db->db,
                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                       NULL) != SQLITE_OK) return -1;
    db->replay_cache = pcomm_replay_cache_create(PCOMM_REPLAY_CACHE_CAPACITY, PCOMM_REPLAY_CACHE_TTL_MS);
    if (!db->replay_cache || sqlite3_exec(db->db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL) != SQLITE_OK) return -1;
    return pcomm_db_init_schema(db);
}

static int db_close_checked(pcomm_db_t *db) {
    if (sqlite3_next_stmt(db->db, NULL) != NULL || sqlite3_close(db->db) != SQLITE_OK) return -1;
    db->db = NULL;
    return 0;
}

static int start_all(const pcomm_config_t *cfg, const pcomm_identity_t *identity, pcomm_db_t *db) {
    if (pcomm_relay_start(cfg, identity, db) != 0 ||
        pcomm_http_start(cfg, identity, db) != 0 ||
        pcomm_mesh_start(cfg, identity, db) != 0 ||
        pcomm_dht_start(cfg, identity, db) != 0 ||
        pcomm_circuits_start(cfg, identity, db) != 0 ||
        pcomm_hidden_start(cfg, identity, db) != 0) return -1;
    return 0;
}

static void stop_all(void) {
    pcomm_shutdown_request();
    net_shutdown_all();
    pcomm_dht_request_stop();
    pcomm_hidden_request_stop();
    pcomm_circuits_request_stop();
    pcomm_http_stop();
    pcomm_mesh_stop();
    pcomm_hidden_stop();
    pcomm_circuits_stop();
    pcomm_relay_stop();
    pcomm_dht_stop();
}

static int wait_for_socket_count(size_t minimum, uint32_t timeout_ms) {
    uint64_t deadline = now_ms() + timeout_ms;
    do {
        if (net_tracked_socket_count() >= minimum) return 0;
        poll(NULL, 0, 10);
    } while (now_ms() < deadline);
    return -1;
}

static int wait_readable(int fd) {
    struct pollfd ready = {fd, POLLIN, 0};
    int rc;
    do { rc = poll(&ready, 1, 2000); } while (rc < 0 && errno == EINTR);
    return rc > 0 && (ready.revents & POLLIN) ? 0 : -1;
}

static int send_cell(int fd, uint8_t command, const uint8_t *body, uint16_t body_len) {
    uint8_t *cell = NULL;
    uint32_t cell_len = 0;
    if (pcomm_cell_pack(1, command, 0, body, body_len, &cell, &cell_len) != 0) return -1;
    int rc = pcomm_send_packet(fd, PCOMM_MSG_CELL, NULL, cell, cell_len);
    free(cell);
    return rc;
}

static int send_relay(int fd, const uint8_t key[32], uint8_t command, uint16_t sid,
                       const uint8_t *body, uint16_t body_len) {
    uint8_t *plain = NULL, *wrapped = NULL;
    uint16_t plain_len = 0, wrapped_len = 0;
    int rc = -1;
    if (pcomm_relay_plain_pack(command, sid, body, body_len, &plain, &plain_len) != 0) goto done;
    if (pcomm_relay_wrap_forward((const uint8_t (*)[32])key, 1, 1,
                                 plain, plain_len, &wrapped, &wrapped_len) != 0) goto done;
    rc = send_cell(fd, PCOMM_CELL_RELAY, wrapped, wrapped_len);
done:
    free(plain);
    free(wrapped);
    return rc;
}

static int receive_created(int fd, uint8_t server_public[32]) {
    pcomm_msg_type_t type;
    uint8_t eph[32], *packet = NULL;
    const uint8_t *body;
    uint8_t command, flags;
    uint32_t packet_len = 0, cid;
    uint16_t body_len;
    int rc = -1;
    if (wait_readable(fd) != 0 || pcomm_recv_packet(fd, &type, eph, &packet, &packet_len) != 0 ||
        type != PCOMM_MSG_CELL || pcomm_cell_unpack(packet, packet_len, &cid, &command, &flags, &body, &body_len) != 0 ||
        cid != 1 || command != PCOMM_CELL_CREATED || body_len != 32) goto done;
    memcpy(server_public, body, 32);
    rc = 0;
done:
    free(packet);
    return rc;
}

static int receive_relay_body(int fd, const uint8_t key[32], uint8_t expected, uint16_t expected_sid,
                               const uint8_t *expected_body, uint16_t expected_len) {
    pcomm_msg_type_t type;
    uint8_t eph[32], *packet = NULL, *plain = NULL;
    const uint8_t *body, *relay_body;
    uint8_t command, flags, relay_command;
    uint32_t packet_len = 0, cid;
    uint16_t body_len, plain_len = 0, relay_len, sid;
    int rc = -1;
    if (wait_readable(fd) != 0 || pcomm_recv_packet(fd, &type, eph, &packet, &packet_len) != 0 ||
        type != PCOMM_MSG_CELL || pcomm_cell_unpack(packet, packet_len, &cid, &command, &flags, &body, &body_len) != 0 ||
        cid != 1 || command != PCOMM_CELL_RELAY) goto done;
    if (pcomm_relay_unwrap_backward_all((const uint8_t (*)[32])key, 1, 1, body, body_len,
                                       &plain, &plain_len) != 0 ||
        pcomm_relay_plain_unpack(plain, plain_len, &relay_command, &sid, &relay_body, &relay_len) != 0 ||
        relay_command != expected || sid != expected_sid || relay_len != expected_len ||
        (expected_len > 0 && memcmp(relay_body, expected_body, expected_len) != 0)) goto done;
    rc = 0;
done:
    free(packet);
    free(plain);
    return rc;
}

static int receive_relay(int fd, const uint8_t key[32], uint8_t expected, uint16_t expected_sid) {
    return receive_relay_body(fd, key, expected, expected_sid, NULL, 0);
}

static int create_one_hop(const pcomm_config_t *cfg, int *client_out, uint8_t hop_keys[64]) {
    pcomm_identity_t ephemeral;
    uint8_t server_public[32], shared[32];
    const uint8_t salt[] = "pcomm-circ-v1", info[] = "pcomm-hop-keys";
    struct timeval timeout = {2, 0};
    *client_out = net_connect_tcp("127.0.0.1", cfg->relay_port);
    if (*client_out < 0 || setsockopt(*client_out, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        make_identity(&ephemeral) != 0 || send_cell(*client_out, PCOMM_CELL_CREATE, ephemeral.pubkey, 32) != 0 ||
        receive_created(*client_out, server_public) != 0 ||
        pcomm_x25519_derive(ephemeral.privkey, server_public, shared) != 0 ||
        pcomm_hkdf_sha256(shared, sizeof(shared), salt, sizeof(salt) - 1, info, sizeof(info) - 1,
                          hop_keys, 64) != 0) return -1;
    return 0;
}

static int buffered_relay_stream(const pcomm_config_t *cfg, int *client_out) {
    uint8_t hop_keys[64], begin[13] = {9};
    const uint8_t data[] = "request buffered without RELAY_END";
    if (create_one_hop(cfg, client_out, hop_keys) != 0) return -1;
    memcpy(begin + 1, "127.0.0.1", 9);
    begin[10] = (uint8_t)(cfg->relay_port >> 8);
    begin[11] = (uint8_t)cfg->relay_port;
    begin[12] = 1;
    if (send_relay(*client_out, hop_keys, PCOMM_RELAY_BEGIN, 1, begin, sizeof(begin)) != 0 ||
        receive_relay(*client_out, hop_keys + 32, PCOMM_RELAY_CONNECTED, 1) != 0 ||
        send_relay(*client_out, hop_keys, PCOMM_RELAY_DATA, 1, data, sizeof(data) - 1) != 0 ||
        send_relay(*client_out, hop_keys, PCOMM_RELAY_PING, 0, NULL, 0) != 0 ||
        receive_relay(*client_out, hop_keys + 32, PCOMM_RELAY_PONG, 0) != 0) return -1;
    return 0;
}

static int paired_rendezvous(const pcomm_config_t *cfg, int *client_a, int *client_b) {
    uint8_t keys_a[64], keys_b[64], cookie[20], established[21];
    for (size_t i = 0; i < sizeof(cookie); i++) cookie[i] = (uint8_t)(i * 7u + 1u);
    memcpy(established, cookie, sizeof(cookie));
    established[20] = 1;
    if (create_one_hop(cfg, client_a, keys_a) != 0 ||
        create_one_hop(cfg, client_b, keys_b) != 0 ||
        send_relay(*client_a, keys_a, PCOMM_RELAY_ESTABLISH_RENDEZVOUS, 0,
                    cookie, sizeof(cookie)) != 0 ||
        send_relay(*client_a, keys_a, PCOMM_RELAY_PING, 0, NULL, 0) != 0 ||
        receive_relay(*client_a, keys_a + 32, PCOMM_RELAY_PONG, 0) != 0 ||
        send_relay(*client_b, keys_b, PCOMM_RELAY_RENDEZVOUS1, 0,
                    cookie, sizeof(cookie)) != 0 ||
        receive_relay_body(*client_a, keys_a + 32, PCOMM_RELAY_RENDEZVOUS2, 0,
                            established, sizeof(established)) != 0 ||
        receive_relay_body(*client_b, keys_b + 32, PCOMM_RELAY_RENDEZVOUS2, 0,
                            established, sizeof(established)) != 0) return -1;
    return 0;
}

static int restart_cycle(const pcomm_config_t *cfg, unsigned cycle) {
    pcomm_db_t db = {0};
    pcomm_identity_t identity;
    int http_client = -1, relay_client = -1, rendezvous_client = -1;
    int ok = 1;
    CHECK(net_tracked_socket_count() == 0);
    pcomm_shutdown_reset();
    CHECK(db_open_memory(&db) == 0 && make_identity(&identity) == 0);
    CHECK(start_all(cfg, &identity, &db) == 0);
    if (cycle == 1) {
        const char partial_http[] = "POST /api/send HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx";
        http_client = net_connect_tcp("127.0.0.1", cfg->http_port);
        relay_client = net_connect_tcp("127.0.0.1", cfg->relay_port);
        CHECK(http_client >= 0 && relay_client >= 0);
        CHECK(net_sendall(http_client, partial_http, sizeof(partial_http) - 1) == 0);
        CHECK(net_sendall(relay_client, "PC", 2) == 0);
        CHECK(wait_for_socket_count(6, 2000) == 0);
    } else if (cycle == 2) {
        CHECK(buffered_relay_stream(cfg, &relay_client) == 0);
    } else if (cycle == 3) {
        CHECK(paired_rendezvous(cfg, &relay_client, &rendezvous_client) == 0);
    } else {
        poll(NULL, 0, 50);
    }

    uint64_t started = now_ms();
    stop_all();
    stop_all();
    CHECK(now_ms() - started < 5000u);
    close_managed(&http_client);
    close_managed(&relay_client);
    close_managed(&rendezvous_client);
    CHECK(net_tracked_socket_count() == 0);
    CHECK(ports_are_reusable(cfg) == 0);
    CHECK(db_close_checked(&db) == 0);
done:
    stop_all();
    close_managed(&http_client);
    close_managed(&relay_client);
    close_managed(&rendezvous_client);
    pcomm_db_close(&db);
    return ok;
}

static int test_repeated_start_stop(const char *ui_dir) {
    pcomm_config_t cfg;
    if (config_for_test(&cfg, ui_dir) != 0) return 0;
    for (unsigned cycle = 0; cycle < 4; cycle++) {
        if (!restart_cycle(&cfg, cycle)) return 0;
    }
    return 1;
}

static int observe_blocked_bootstrap(reserved_port_t *fake, int accepted[32], size_t *accepted_count,
                                      int all_protocols) {
    int saw_udp = 0, saw_mesh_query = 0, saw_circuit_create = 0;
    uint64_t deadline = now_ms() + 3000u;
    while (now_ms() < deadline) {
        struct pollfd ready[2] = {{fake->tcp, POLLIN, 0}, {fake->udp, POLLIN, 0}};
        int rc = poll(ready, 2, 20);
        if (rc < 0 && errno != EINTR) return -1;
        if (ready[0].revents & POLLIN) {
            int fd = accept(fake->tcp, NULL, NULL);
            if (fd < 0) return -1;
            if (*accepted_count >= 32) { close(fd); return -1; }
            accepted[(*accepted_count)++] = fd;
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
        }
        if (ready[1].revents & POLLIN) {
            uint8_t datagram[4096];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            ssize_t count = recvfrom(fake->udp, datagram, sizeof(datagram), 0,
                                     (struct sockaddr *)&from, &from_len);
            if (count <= 0 || from.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) return -1;
            saw_udp = 1;
        }
        for (size_t i = 0; i < *accepted_count; i++) {
            uint8_t frame[PCOMM_HDR_LEN + 1];
            ssize_t count = recv(accepted[i], frame, sizeof(frame), MSG_PEEK);
            if (count >= PCOMM_HDR_LEN && memcmp(frame, PCOMM_MAGIC, 4) == 0) {
                if (frame[5] == PCOMM_MSG_CELL) saw_circuit_create = 1;
                if (count > PCOMM_HDR_LEN && frame[5] == PCOMM_MSG_CTRL &&
                    frame[PCOMM_HDR_LEN] == PCOMM_CTRL_PEERS_REQ) saw_mesh_query = 1;
            }
        }
        if (saw_mesh_query && (!all_protocols || (saw_udp && saw_circuit_create))) return 0;
    }
    fprintf(stderr, "bootstrap activity missing: UDP=%d mesh=%d circuit=%d\n",
            saw_udp, saw_mesh_query, saw_circuit_create);
    return -1;
}

static int test_blocked_bootstrap_shutdown(const char *ui_dir) {
    pcomm_config_t cfg;
    pcomm_db_t db = {0};
    pcomm_identity_t identity, peer;
    reserved_port_t fake = {-1, -1, 0};
    int accepted[32];
    size_t accepted_count = 0;
    int ok = 1;
    CHECK(net_tracked_socket_count() == 0);
    pcomm_shutdown_reset();
    CHECK(config_for_test(&cfg, ui_dir) == 0);
    for (unsigned attempt = 0; attempt < 32; attempt++) {
        CHECK(reserve_port(&fake) == 0);
        if (fake.port != cfg.relay_port && fake.port != cfg.http_port) break;
        release_port(&fake);
    }
    CHECK(fake.tcp >= 0 && fake.port != cfg.relay_port && fake.port != cfg.http_port);
    CHECK(listen(fake.tcp, 32) == 0);
    CHECK(db_open_memory(&db) == 0 && make_identity(&identity) == 0 && make_identity(&peer) == 0);
    CHECK(strcmp(identity.user_id, peer.user_id) != 0);
    CHECK(pcomm_db_upsert_contact(&db, peer.user_id, "127.0.0.1", fake.port, peer.pubkey, 1) == 0);
    CHECK(start_all(&cfg, &identity, &db) == 0);
    CHECK(observe_blocked_bootstrap(&fake, accepted, &accepted_count, 1) == 0);
    uint64_t started = now_ms();
    stop_all();
    stop_all();
    CHECK(now_ms() - started < 5000u);
    CHECK(net_tracked_socket_count() == 0);
    CHECK(ports_are_reusable(&cfg) == 0);
    CHECK(db_close_checked(&db) == 0);
done:
    stop_all();
    for (size_t i = 0; i < accepted_count; i++) close_raw(&accepted[i]);
    release_port(&fake);
    pcomm_db_close(&db);
    return ok;
}

static int test_local_mesh_stop_interrupts_peer_read(const char *ui_dir) {
    pcomm_config_t cfg;
    pcomm_db_t db = {0};
    pcomm_identity_t identity, peer;
    reserved_port_t fake = {-1, -1, 0};
    int accepted[32];
    size_t accepted_count = 0;
    int ok = 1;
    CHECK(net_tracked_socket_count() == 0);
    pcomm_shutdown_reset();
    CHECK(config_for_test(&cfg, ui_dir) == 0 && reserve_port(&fake) == 0 && listen(fake.tcp, 32) == 0);
    CHECK(db_open_memory(&db) == 0 && make_identity(&identity) == 0 && make_identity(&peer) == 0);
    CHECK(pcomm_db_upsert_contact(&db, peer.user_id, "127.0.0.1", fake.port, peer.pubkey, 1) == 0);
    CHECK(pcomm_mesh_start(&cfg, &identity, &db) == 0);
    CHECK(observe_blocked_bootstrap(&fake, accepted, &accepted_count, 0) == 0);
    uint64_t started = now_ms();
    pcomm_mesh_stop();
    pcomm_mesh_stop();
    CHECK(now_ms() - started < 2000u);
    CHECK(!pcomm_shutdown_requested());
    CHECK(net_tracked_socket_count() == 0);
    CHECK(db_close_checked(&db) == 0);
done:
    stop_all();
    for (size_t i = 0; i < accepted_count; i++) close_raw(&accepted[i]);
    release_port(&fake);
    pcomm_db_close(&db);
    return ok;
}

static int test_partial_startup_rollback(const char *ui_dir) {
    pcomm_config_t cfg;
    pcomm_db_t db = {0};
    pcomm_identity_t identity;
    int blocker = -1;
    int ok = 1;
    CHECK(net_tracked_socket_count() == 0);
    pcomm_shutdown_reset();
    CHECK(config_for_test(&cfg, ui_dir) == 0);
    blocker = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(blocker >= 0 && bind_loopback(blocker, cfg.http_port) == 0 && listen(blocker, 1) == 0);
    CHECK(db_open_memory(&db) == 0 && make_identity(&identity) == 0);
    CHECK(pcomm_relay_start(&cfg, &identity, &db) == 0);
    CHECK(pcomm_http_start(&cfg, &identity, &db) == -1);
    uint64_t started = now_ms();
    stop_all();
    stop_all();
    CHECK(now_ms() - started < 5000u && net_tracked_socket_count() == 0);
    close_raw(&blocker);
    CHECK(ports_are_reusable(&cfg) == 0);
    CHECK(db_close_checked(&db) == 0);
done:
    stop_all();
    close_raw(&blocker);
    pcomm_db_close(&db);

    if (ok) ok = restart_cycle(&cfg, 0);
    return ok;
}

static sqlite3_int64 queue_test_value(pcomm_db_t *db, const char *sql, const char *peer) {
    sqlite3_stmt *st = NULL;
    sqlite3_int64 value = -1;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (peer) sqlite3_bind_text(st, 1, peer, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) value = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return value;
}

static int queue_test_post(const pcomm_config_t *cfg, const char *path,
                            const char *body, char *response, size_t capacity) {
    int fd = net_connect_tcp("127.0.0.1", cfg->http_port);
    if (fd < 0) return -1;
    struct timeval timeout = {2, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    char request[1024];
    int len = snprintf(request, sizeof(request),
        "POST %s HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %zu\r\n\r\n%s", path, strlen(body), body);
    int status = -1;
    size_t used = 0;
    if (len < 0 || (size_t)len >= sizeof(request) || net_sendall(fd, request, (size_t)len)) goto done;
    while (used < capacity-1) {
        ssize_t count = recv(fd, response+used, capacity-1-used, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto done;
        if (!count) break;
        used += (size_t)count;
    }
    response[used] = '\0';
    if (sscanf(response, "HTTP/%*d.%*d %d", &status) != 1) status = -1;
done:
    response[used] = '\0';
    net_close(fd);
    return status;
}

static int queue_state_is_empty(pcomm_db_t *db) {
    return queue_test_value(db, "SELECT count(*) FROM ratchet_sessions", NULL) == 0 &&
        queue_test_value(db, "SELECT count(*) FROM ratchet_pending", NULL) == 0 &&
        queue_test_value(db, "SELECT count(*) FROM ratchet_outbox", NULL) == 0 &&
        queue_test_value(db, "SELECT count(*) FROM messages", NULL) == 0;
}

static int test_http_reports_ratchet_admission_failure(const char *ui_dir) {
    pcomm_config_t cfg;
    pcomm_db_t db = {0};
    pcomm_identity_t identity, admitted, rejected;
    reserved_port_t unavailable = {-1, -1, 0};
    char body[512], response[4096], *trigger = NULL;
    int ok = 1;
    CHECK(net_tracked_socket_count() == 0);
    pcomm_shutdown_reset();
    CHECK(config_for_test(&cfg, ui_dir) == 0 && db_open_memory(&db) == 0);
    CHECK(make_identity(&identity) == 0 && make_identity(&admitted) == 0 && make_identity(&rejected) == 0);
    CHECK(sqlite3_exec(db.db, "CREATE TRIGGER reject_pending BEFORE INSERT ON ratchet_pending "
                             "BEGIN SELECT RAISE(FAIL, 'queue admission rejected'); END;",
                       NULL, NULL, NULL) == SQLITE_OK);
    CHECK(pcomm_http_start(&cfg, &identity, &db) == 0);

    snprintf(body, sizeof(body), "title=Rejected&members=%s", rejected.user_id);
    CHECK(queue_test_post(&cfg, "/api/create_group", body, response, sizeof(response)) == 503);
    CHECK(strstr(response, "\"ok\":false") && strstr(response, "\"queued\":0,\"failed\":1"));
    CHECK(queue_test_value(&db, "SELECT count(*) FROM conversations WHERE type='group'", NULL) == 1);
    CHECK(queue_state_is_empty(&db));
    sqlite3_int64 rejected_group = queue_test_value(&db,
        "SELECT id FROM conversations WHERE type='group' ORDER BY id DESC LIMIT 1", NULL);
    CHECK(rejected_group > 0);

    snprintf(body, sizeof(body), "conv=%lld&text=rejected-group-history", (long long)rejected_group);
    CHECK(queue_test_post(&cfg, "/api/send_group", body, response, sizeof(response)) == 503);
    CHECK(strstr(response, "\"queued\":0,\"failed\":1") && strstr(response, "\"history_saved\":false"));
    CHECK(queue_state_is_empty(&db));

    snprintf(body, sizeof(body), "to=%s&text=rejected-direct-history", rejected.user_id);
    CHECK(queue_test_post(&cfg, "/api/send", body, response, sizeof(response)) == 500);
    CHECK(strstr(response, "\"ok\":false"));
    CHECK(queue_test_value(&db, "SELECT count(*) FROM conversations WHERE type='direct'", NULL) == 0);
    CHECK(queue_state_is_empty(&db));

    CHECK(reserve_port(&unavailable) == 0);
    CHECK(pcomm_db_upsert_contact(&db, admitted.user_id, "127.0.0.1", unavailable.port, admitted.pubkey, 0) == 0);
    CHECK(pcomm_db_upsert_contact(&db, rejected.user_id, "127.0.0.1", unavailable.port, rejected.pubkey, 0) == 0);
    CHECK(sqlite3_exec(db.db, "DROP TRIGGER reject_pending", NULL, NULL, NULL) == SQLITE_OK);
    trigger = sqlite3_mprintf("CREATE TRIGGER reject_pending BEFORE INSERT ON ratchet_pending "
        "WHEN NEW.peer=%Q BEGIN SELECT RAISE(FAIL, 'one peer rejected'); END;", rejected.user_id);
    CHECK(trigger && sqlite3_exec(db.db, trigger, NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_free(trigger); trigger = NULL;

    snprintf(body, sizeof(body), "title=Partial&members=%s,%s", admitted.user_id, rejected.user_id);
    CHECK(queue_test_post(&cfg, "/api/create_group", body, response, sizeof(response)) == 503);
    CHECK(strstr(response, "\"ok\":false") && strstr(response, "\"queued\":1,\"failed\":1"));
    sqlite3_int64 partial_group = queue_test_value(&db,
        "SELECT id FROM conversations WHERE type='group' ORDER BY id DESC LIMIT 1", NULL);
    CHECK(partial_group > rejected_group);
    CHECK(queue_test_value(&db, "SELECT count(*) FROM ratchet_sessions WHERE peer=?", admitted.user_id) == 1);
    CHECK(queue_test_value(&db, "SELECT count(*) FROM ratchet_sessions WHERE peer=?", rejected.user_id) == 0);
    CHECK(queue_test_value(&db, "SELECT count(*) FROM ratchet_pending", NULL) == 1);
    CHECK(queue_test_value(&db, "SELECT count(*) FROM ratchet_outbox", NULL) == 1);
    CHECK(queue_test_value(&db, "SELECT count(*) FROM messages", NULL) == 0);

    snprintf(body, sizeof(body), "conv=%lld&text=partial-admission-history", (long long)partial_group);
    CHECK(queue_test_post(&cfg, "/api/send_group", body, response, sizeof(response)) == 503);
    CHECK(strstr(response, "\"queued\":1,\"failed\":1") && strstr(response, "\"history_saved\":true"));
    CHECK(queue_test_value(&db, "SELECT count(*) FROM messages WHERE direction=1 AND body='partial-admission-history'", NULL) == 1);
    CHECK(queue_test_value(&db, "SELECT count(*) FROM ratchet_pending WHERE peer=?", admitted.user_id) == 2);
    CHECK(queue_test_value(&db, "SELECT count(*) FROM ratchet_pending WHERE peer=?", rejected.user_id) == 0);
    CHECK(queue_test_value(&db, "SELECT count(*) FROM ratchet_outbox", NULL) == 1);
    pcomm_http_stop();
    CHECK(net_tracked_socket_count() == 0);
    CHECK(db_close_checked(&db) == 0);
done:
    stop_all();
    sqlite3_free(trigger);
    release_port(&unavailable);
    pcomm_db_close(&db);
    return ok;
}

static int local_mailbox_key(const char *recipient, uint32_t epoch, uint8_t key[32]) {
    const char tag[] = "pcomm-mb-v1";
    uint8_t input[160];
    size_t identity_length = strlen(recipient);
    size_t length = sizeof(tag);
    if (length + identity_length + 5 > sizeof(input)) return -1;
    memcpy(input, tag, length);
    memcpy(input + length, recipient, identity_length); length += identity_length;
    input[length++] = 0;
    input[length++] = (uint8_t)(epoch >> 24); input[length++] = (uint8_t)(epoch >> 16);
    input[length++] = (uint8_t)(epoch >> 8); input[length++] = (uint8_t)epoch;
    unsigned digest_length = 0;
    return EVP_Digest(input, length, key, &digest_length, EVP_sha256(), NULL) == 1 && digest_length == 32 ? 0 : -1;
}

static int test_local_mailbox_accepts_ratchet_offer(const char *ui_dir) {
    pcomm_config_t cfg;
    pcomm_db_t recipient_db = {0}, sender_db = {0};
    pcomm_identity_t recipient = {0}, sender = {0};
    pcomm_ratchet_outgoing_t outgoing = {0};
    uint8_t *plain = NULL, *offer = NULL, key[32];
    size_t plain_length = 0, offer_length = 0;
    int received = 0, ok = 1;
    CHECK(net_tracked_socket_count() == 0);
    pcomm_shutdown_reset();
    CHECK(config_for_test(&cfg, ui_dir) == 0);
    cfg.mailbox_poll_base_ms = 800;
    CHECK(db_open_memory(&recipient_db) == 0 && db_open_memory(&sender_db) == 0);
    CHECK(make_identity(&recipient) == 0 && make_identity(&sender) == 0);
    time_t wall_time = time(NULL);
    CHECK(wall_time >= 0 && (uint64_t)wall_time <= UINT32_MAX);
    uint32_t now = (uint32_t)wall_time;
    CHECK(pcomm_msg_pack_direct_text(now, sender.user_id, "local mailbox control", &plain, &plain_length) == 0);
    CHECK(pcomm_ratchet_send(&sender_db, &sender, recipient.user_id, "", plain, plain_length) == 0);
    CHECK(pcomm_ratchet_outbox_next(&sender_db, wall_time, &outgoing) == 1);
    CHECK(strcmp(outgoing.peer, recipient.user_id) == 0 && outgoing.sealed_len <= UINT32_MAX);
    CHECK(pcomm_open_seal(recipient.privkey, outgoing.sealed, outgoing.sealed_len, &offer, &offer_length) == 0);
    CHECK(offer_length > 5 && pcomm_ratchet_is_packet(offer, offer_length) && offer[5] == 1);
    CHECK(queue_test_value(&sender_db, "SELECT count(*) FROM messages WHERE direction=1", NULL) == 1);
    CHECK(queue_test_value(&recipient_db, "SELECT count(*) FROM messages", NULL) == 0);
    CHECK(local_mailbox_key(recipient.user_id, now / (6u*3600u), key) == 0);
    CHECK(pcomm_db_mailbox_put(&recipient_db, key, outgoing.sealed, (uint32_t)outgoing.sealed_len, wall_time) == 0);
    CHECK(queue_test_value(&recipient_db, "SELECT count(*) FROM mailbox_items", NULL) == 1);
    CHECK(pcomm_hidden_start(&cfg, &recipient, &recipient_db) == 0);
    uint64_t deadline = now_ms() + 3000;
    do {
        CHECK(net_tracked_socket_count() == 0);
        if (queue_test_value(&recipient_db, "SELECT count(*) FROM mailbox_items", NULL) == 0 &&
            queue_test_value(&recipient_db,
                "SELECT count(*) FROM ratchet_sessions WHERE peer=? AND context='' AND state=2 AND initiator=0",
                sender.user_id) == 1 &&
            queue_test_value(&recipient_db, "SELECT count(*) FROM ratchet_outbox WHERE peer=? AND kind=2",
                sender.user_id) == 1) {
            received = 1;
            break;
        }
        poll(NULL, 0, 10);
    } while (now_ms() < deadline);
    CHECK(received);
    uint64_t stopping = now_ms();
    pcomm_hidden_request_stop();
    pcomm_hidden_stop();
    CHECK(now_ms() - stopping < 2000 && !pcomm_shutdown_requested());
    CHECK(net_tracked_socket_count() == 0);
    CHECK(queue_test_value(&recipient_db, "SELECT count(*) FROM messages", NULL) == 0);
    CHECK(queue_test_value(&recipient_db, "SELECT count(*) FROM conversations", NULL) == 0);
    CHECK(queue_test_value(&recipient_db, "SELECT count(*) FROM ratchet_pending", NULL) == 0);
    CHECK(queue_test_value(&recipient_db, "SELECT count(*) FROM ratchet_outbox", NULL) == 1);
    CHECK(queue_test_value(&recipient_db, "SELECT count(*) FROM contacts", NULL) == 0);
    CHECK(queue_test_value(&recipient_db, "SELECT count(*) FROM dht_nodes", NULL) == 0);
    CHECK(queue_test_value(&sender_db, "SELECT count(*) FROM messages", NULL) == 1);
    CHECK(queue_test_value(&sender_db, "SELECT count(*) FROM ratchet_pending", NULL) == 1);
    CHECK(queue_test_value(&sender_db, "SELECT count(*) FROM ratchet_outbox WHERE kind=1", NULL) == 1);
    CHECK(db_close_checked(&recipient_db) == 0 && db_close_checked(&sender_db) == 0);
done:
    stop_all();
    if (plain) OPENSSL_cleanse(plain, plain_length);
    if (offer) OPENSSL_cleanse(offer, offer_length);
    free(plain); free(offer);
    pcomm_ratchet_outgoing_free(&outgoing);
    pcomm_db_close(&recipient_db); pcomm_db_close(&sender_db);
    OPENSSL_cleanse(&recipient, sizeof(recipient)); OPENSSL_cleanse(&sender, sizeof(sender));
    return ok;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s UI_DIRECTORY\n", argv[0]);
        return EXIT_FAILURE;
    }
    signal(SIGALRM, SIG_DFL);
    alarm(15);
    const struct {
        const char *name;
        int (*run)(const char *);
    } tests[] = {
        {"same-port idle, stalled-client, stream, and paired-rendezvous restarts", test_repeated_start_stop},
        {"blocked TCP and UDP bootstrap shutdown", test_blocked_bootstrap_shutdown},
        {"local mesh stop interrupts stalled peer read", test_local_mesh_stop_interrupts_peer_read},
        {"partial-startup rollback and reuse", test_partial_startup_rollback},
        {"HTTP ratchet queue admission and partial group failure", test_http_reports_ratchet_admission_failure},
        {"local mailbox accepts ratchet control without discovery", test_local_mailbox_accepts_ratchet_offer},
    };
    size_t failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int passed = tests[i].run(argv[1]);
        printf("%s: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        fflush(stdout);
        if (!passed) failures++;
    }
    alarm(0);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
