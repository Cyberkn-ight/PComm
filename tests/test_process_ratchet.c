#define _POSIX_C_SOURCE 200809L
#include "identity.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { NODES = 4 };
typedef struct {
    char directory[256], peers[300], log[300];
    char host[64];
    pcomm_identity_t identity;
    uint16_t relay_port, http_port;
    int relay_reservation, udp_reservation, http_reservation;
    pid_t child;
} node_t;

static uint64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
    return (uint64_t)now.tv_sec*1000 + (uint64_t)now.tv_nsec/1000000;
}

static void delay_ms(unsigned milliseconds) {
    struct timespec duration = {milliseconds/1000, (long)(milliseconds%1000)*1000000};
    while (nanosleep(&duration, &duration) != 0 && errno == EINTR) {}
}

static unsigned remaining_ms(uint64_t deadline, unsigned limit) {
    uint64_t now = now_ms();
    if (now >= deadline) return 0;
    return deadline-now < limit ? (unsigned)(deadline-now) : limit;
}

static int wait_socket(int fd, short events, uint64_t deadline) {
    unsigned wait;
    while ((wait = remaining_ms(deadline, 50)) != 0) {
        struct pollfd ready = {fd, events, 0};
        int rc = poll(&ready, 1, (int)wait);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) return -1;
        if (rc > 0) return ready.revents & (events | POLLERR | POLLHUP) ? 0 : -1;
    }
    return -1;
}

static void close_slot(int *fd) {
    if (*fd >= 0) close(*fd);
    *fd = -1;
}

static int bound_socket(const char *host, int type, uint16_t requested_port, uint16_t *port) {
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) return -1;
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1) { close(fd); return -1; }
    address.sin_port = htons(requested_port);
    socklen_t len = sizeof(address);
    if (bind(fd, (struct sockaddr *)&address, len) != 0 ||
        (type == SOCK_STREAM && listen(fd, 32) != 0) ||
        getsockname(fd, (struct sockaddr *)&address, &len) != 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(address.sin_port);
    return fd;
}

static int fixture_path(char *out, size_t capacity, const node_t *node, const char *leaf) {
    size_t prefix = strnlen(node->directory, sizeof(node->directory));
    size_t suffix = strlen(leaf);
    if (prefix == sizeof(node->directory) || prefix+1+suffix >= capacity) return -1;
    memcpy(out, node->directory, prefix);
    out[prefix] = '/';
    memcpy(out+prefix+1, leaf, suffix+1);
    return 0;
}

static int prepare_node(node_t *node, const char *root, unsigned index, int bootstrap_only) {
    int written = snprintf(node->directory, sizeof(node->directory), "%s/node-%u", root, index);
    if (written < 0 || (size_t)written >= sizeof(node->directory)) {
        node->directory[0] = '\0';
        return -1;
    }
    if (fixture_path(node->peers, sizeof(node->peers), node, "peers.txt") ||
        fixture_path(node->log, sizeof(node->log), node, "process.log")) return -1;
    snprintf(node->host, sizeof(node->host), "127.0.0.%u", bootstrap_only ? 1 : index+1);
    if (mkdir(node->directory, 0700) != 0 ||
        pcomm_identity_load_or_create(&node->identity, node->directory) != 0) return -1;
    for (unsigned i = 0; i < 32; i++) {
        node->relay_reservation = bound_socket(node->host, SOCK_STREAM, 0, &node->relay_port);
        if (node->relay_reservation < 0) return -1;
        uint16_t udp_port = node->relay_port;
        node->udp_reservation = bound_socket(node->host, SOCK_DGRAM, node->relay_port, &udp_port);
        if (node->udp_reservation >= 0) break;
        close_slot(&node->relay_reservation);
    }
    node->http_reservation = bound_socket("127.0.0.1", SOCK_STREAM, 0, &node->http_port);
    return node->relay_reservation >= 0 && node->udp_reservation >= 0 &&
        node->http_reservation >= 0 ? 0 : -1;
}

static int write_peers(node_t nodes[NODES], unsigned index) {
    FILE *file = fopen(nodes[index].peers, "w");
    if (!file) return -1;
    int ok = 1;
    for (unsigned j = 0; j < NODES; j++) {
        if (j != index && fprintf(file, "%s %s %u\n",
                nodes[j].identity.user_id, nodes[j].host, nodes[j].relay_port) < 0) ok = 0;
    }
    if (fclose(file) != 0) ok = 0;
    return ok ? 0 : -1;
}

static int start_node(node_t *node, const char *binary, const char *ui, const char *bootstrap) {
    char relay[80], http[64];
    snprintf(relay, sizeof(relay), "%s:%u", node->host, node->relay_port);
    snprintf(http, sizeof(http), "127.0.0.1:%u", node->http_port);
    int log = open(node->log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (log < 0) return -1;
    node->child = fork();
    if (node->child == 0) {
        if (dup2(log, STDOUT_FILENO) < 0 || dup2(log, STDERR_FILENO) < 0) _exit(126);
        close(log);
        if (bootstrap) {
            execl(binary, binary, "--data-dir", node->directory, "--ui-dir", ui,
                  "--relay", relay, "--advertise", relay, "--http", http,
                  "--peers", node->peers, "--allow-private-addrs", "--allow-private-exit",
                  "--bootstrap", bootstrap, (char *)NULL);
        } else {
            execl(binary, binary, "--data-dir", node->directory, "--ui-dir", ui,
                  "--relay", relay, "--advertise", relay, "--http", http,
                  "--peers", node->peers, "--allow-private-addrs", "--allow-private-exit",
                  (char *)NULL);
        }
        _exit(127);
    }
    close(log);
    return node->child > 0 ? 0 : -1;
}

static int http_request(uint16_t port, const char *method, const char *path,
                         const char *body, unsigned timeout_ms,
                         char *response, size_t capacity) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    uint64_t deadline = now_ms()+timeout_ms;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) { close(fd); return -1; }
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (errno != EINPROGRESS || wait_socket(fd, POLLOUT, deadline)) { close(fd); return -1; }
        int error = 0;
        socklen_t error_len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error) { close(fd); return -1; }
    }
    char request[2048];
    size_t body_len = body ? strlen(body) : 0;
    int request_len = snprintf(request, sizeof(request),
        "%s %s HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %zu\r\n\r\n%s", method, path, body_len, body ? body : "");
    if (request_len < 0 || (size_t)request_len >= sizeof(request)) { close(fd); return -1; }
    size_t sent = 0, received = 0;
    while (sent < (size_t)request_len) {
        ssize_t n = send(fd, request+sent, (size_t)request_len-sent, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
            wait_socket(fd, POLLOUT, deadline) == 0) continue;
        if (n <= 0) { close(fd); return -1; }
        sent += (size_t)n;
    }
    int rc = -1;
    while (received < capacity-1 && now_ms() < deadline) {
        if (wait_socket(fd, POLLIN, deadline)) break;
        ssize_t n = recv(fd, response+received, capacity-1-received, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n < 0) break;
        if (!n) { rc = 0; break; }
        received += (size_t)n;
    }
    response[received] = '\0';
    close(fd);
    return rc == 0 && strstr(response, " 200 ") ? 0 : -1;
}

static int ready_node(node_t *node) {
    char response[2048], expected[128];
    snprintf(expected, sizeof(expected), "\"id\":\"%s\"", node->identity.user_id);
    return http_request(node->http_port, "GET", "/api/me", NULL, 500,
                         response, sizeof(response)) == 0 && strstr(response, expected) ? 0 : -1;
}

static int post_message(node_t *from, node_t *to, const char *text, unsigned timeout_ms) {
    char body[256], response[2048] = {0};
    snprintf(body, sizeof(body), "to=%s&text=%s", to->identity.user_id, text);
    if (http_request(from->http_port, "POST", "/api/send", body, timeout_ms,
                     response, sizeof(response)) != 0 || !strstr(response, "\"ok\":true")) {
        fprintf(stderr, "POST /api/send response: %s\n", response);
        return -1;
    }
    return 0;
}

static int open_readonly(node_t *node, sqlite3 **out) {
    char path[300];
    *out = NULL;
    if (fixture_path(path, sizeof(path), node, "pcomm.sqlite")) return -1;
    if (sqlite3_open_v2(path, out, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (*out) sqlite3_close(*out);
        *out = NULL;
        return -1;
    }
    sqlite3_busy_timeout(*out, 50);
    return 0;
}

static int scalar(sqlite3 *db, const char *sql, const char *first, const char *second) {
    sqlite3_stmt *st = NULL;
    int value = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (first) sqlite3_bind_text(st, 1, first, -1, SQLITE_TRANSIENT);
    if (second) sqlite3_bind_text(st, 2, second, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) value = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return value;
}

static int peer_file_absent(const node_t *node) {
    return access(node->peers, F_OK) != 0 && errno == ENOENT;
}

static int known_contact(sqlite3 *db, const node_t *peer) {
    sqlite3_stmt *st = NULL;
    int ok = sqlite3_prepare_v2(db, "SELECT count(*) FROM contacts WHERE user_id=? AND host=? "
        "AND port=? AND pubkey=? AND is_relay=1", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_bind_text(st, 1, peer->identity.user_id, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_text(st, 2, peer->host, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int(st, 3, peer->relay_port) == SQLITE_OK &&
        sqlite3_bind_blob(st, 4, peer->identity.pubkey, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 1;
    sqlite3_finalize(st);
    return ok;
}

static int bootstrap_contacts_ready(node_t nodes[NODES]) {
    for (unsigned i = 0; i < NODES; i++) {
        if (!peer_file_absent(&nodes[i])) return 0;
        sqlite3 *db = NULL;
        if (open_readonly(&nodes[i], &db)) return 0;
        int ready = 1;
        for (unsigned j = 0; j < NODES; j++) {
            if (i != j && !known_contact(db, &nodes[j])) { ready = 0; break; }
        }
        sqlite3_close(db);
        if (!ready) return 0;
    }
    return 1;
}

static int descriptor_count(node_t *node, const uint8_t owner[32], int trusted) {
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    if (open_readonly(node, &db)) return -1;
    const char *sql = trusted ? "SELECT count(*) FROM descriptor_trust WHERE owner=?" :
        "SELECT count(*) FROM descriptors WHERE substr(blob,5,32)=?";
    int count = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_bind_blob(st, 1, owner, 32, SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st); sqlite3_close(db);
    return count;
}

static unsigned descriptor_replica_count(node_t nodes[NODES], unsigned owner) {
    unsigned replicas = 0;
    for (unsigned i = 0; i < NODES; i++) {
        if (descriptor_count(&nodes[i], nodes[owner].identity.pubkey, 0) > 0) replicas++;
    }
    return replicas;
}

static int descriptor_replicas_ready(node_t nodes[NODES], unsigned owner) {
    return descriptor_replica_count(nodes, owner) >= 2;
}

static int open_writable(node_t *node, int create, sqlite3 **out) {
    char path[300];
    *out = NULL;
    if (fixture_path(path, sizeof(path), node, "pcomm.sqlite")) return -1;
    int flags = SQLITE_OPEN_READWRITE | (create ? SQLITE_OPEN_CREATE : 0);
    if (sqlite3_open_v2(path, out, flags, NULL) != SQLITE_OK) {
        if (*out) sqlite3_close(*out);
        *out = NULL;
        return -1;
    }
    sqlite3_busy_timeout(*out, 1000);
    return 0;
}

static int block_descriptor_storage(node_t *node, const uint8_t owner[32]) {
    sqlite3 *db = NULL;
    if (open_writable(node, 1, &db)) return -1;
    static const char digits[] = "0123456789abcdef";
    char owner_hex[65], sql[768];
    for (size_t i = 0; i < 32; i++) {
        owner_hex[2*i] = digits[owner[i] >> 4];
        owner_hex[2*i+1] = digits[owner[i] & 15];
    }
    owner_hex[64] = '\0';
    int length = snprintf(sql, sizeof(sql),
        "CREATE TABLE descriptors(dkey BLOB PRIMARY KEY,ts_unix INTEGER NOT NULL,"
        "expires_unix INTEGER NOT NULL,blob BLOB NOT NULL);"
        "CREATE TABLE publication_attempts(count INTEGER NOT NULL);"
        "INSERT INTO publication_attempts VALUES(0);"
        "CREATE TRIGGER block_owner_publication BEFORE INSERT ON descriptors "
        "WHEN substr(NEW.blob,5,32)=X'%s' BEGIN "
        "UPDATE publication_attempts SET count=count+1; SELECT RAISE(IGNORE); END;", owner_hex);
    int result = length > 0 && (size_t)length < sizeof(sql) &&
        sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
    if (sqlite3_close(db) != SQLITE_OK) result = -1;
    return result;
}

static int publication_block_observed(node_t *node) {
    sqlite3 *db = NULL;
    if (open_readonly(node, &db)) return 0;
    int attempts = scalar(db, "SELECT count FROM publication_attempts", NULL, NULL);
    sqlite3_close(db);
    return attempts > 0;
}

static int unblock_descriptor_storage(node_t *node) {
    sqlite3 *db = NULL;
    if (open_writable(node, 0, &db)) return -1;
    int result = sqlite3_exec(db, "DROP TRIGGER block_owner_publication;", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
    if (sqlite3_close(db) != SQLITE_OK) result = -1;
    return result;
}

static int received_count(node_t *to, node_t *from, const char *text) {
    sqlite3 *db = NULL;
    if (open_readonly(to, &db)) return -1;
    int value = scalar(db, "SELECT count(*) FROM messages WHERE direction=0 AND sender_user_id=? AND body=?",
                       from->identity.user_id, text);
    sqlite3_close(db);
    return value;
}

static int settled(node_t *node, node_t *peer, const char *incoming, const char *outgoing) {
    sqlite3 *db = NULL;
    if (open_readonly(node, &db)) return 0;
    int ok = scalar(db, "SELECT count(*) FROM messages WHERE direction=0 AND sender_user_id=? AND body=?",
                      peer->identity.user_id, incoming) == 1 &&
        scalar(db, "SELECT count(*) FROM messages WHERE direction=1 AND sender_user_id=? AND body=?",
                 node->identity.user_id, outgoing) == 1 &&
        scalar(db, "SELECT count(*) FROM ratchet_sessions WHERE peer=? AND context='' AND state=3 "
                   "AND private_eph IS NULL AND send_n=1 AND recv_n=1", peer->identity.user_id, NULL) == 1 &&
        scalar(db, "SELECT count(*) FROM ratchet_pending", NULL, NULL) == 0 &&
        scalar(db, "SELECT count(*) FROM ratchet_outbox", NULL, NULL) == 0 &&
        scalar(db, "SELECT count(*) FROM ratchet_received", NULL, NULL) == 1;
    sqlite3_close(db);
    return ok;
}

static void print_diagnostics(node_t nodes[NODES]) {
    for (unsigned i = 0; i < NODES; i++) {
        fprintf(stderr, "Node %u: %s\n", i, nodes[i].identity.user_id);
        sqlite3 *db = NULL;
        if (!open_readonly(&nodes[i], &db)) {
            fprintf(stderr, " contacts=%d dht_nodes=%d messages=%d sessions=%d pending=%d outbox=%d mailbox=%d descriptors=%d trusted=%d\n",
                scalar(db, "SELECT count(*) FROM contacts", NULL, NULL),
                scalar(db, "SELECT count(*) FROM dht_nodes", NULL, NULL),
                scalar(db, "SELECT count(*) FROM messages", NULL, NULL),
                scalar(db, "SELECT count(*) FROM ratchet_sessions", NULL, NULL),
                scalar(db, "SELECT count(*) FROM ratchet_pending", NULL, NULL),
                scalar(db, "SELECT count(*) FROM ratchet_outbox", NULL, NULL),
                scalar(db, "SELECT count(*) FROM mailbox_items", NULL, NULL),
                scalar(db, "SELECT count(*) FROM descriptors", NULL, NULL),
                scalar(db, "SELECT count(*) FROM descriptor_trust", NULL, NULL));
            sqlite3_stmt *detail = NULL;
            if (sqlite3_prepare_v2(db, "SELECT state,initiator,send_n,recv_n FROM ratchet_sessions", -1, &detail, NULL) == SQLITE_OK) {
                while (sqlite3_step(detail) == SQLITE_ROW) fprintf(stderr, " ratchet state=%d initiator=%d send=%lld recv=%lld\n",
                    sqlite3_column_int(detail, 0), sqlite3_column_int(detail, 1),
                    (long long)sqlite3_column_int64(detail, 2), (long long)sqlite3_column_int64(detail, 3));
            }
            sqlite3_finalize(detail); detail = NULL;
            if (sqlite3_prepare_v2(db, "SELECT kind,n,next_attempt FROM ratchet_outbox", -1, &detail, NULL) == SQLITE_OK) {
                while (sqlite3_step(detail) == SQLITE_ROW) fprintf(stderr, " outbox kind=%d n=%lld next=%lld\n",
                    sqlite3_column_int(detail, 0), (long long)sqlite3_column_int64(detail, 1),
                    (long long)sqlite3_column_int64(detail, 2));
            }
            sqlite3_finalize(detail);
            sqlite3_close(db);
        }
        FILE *file = nodes[i].log[0] ? fopen(nodes[i].log, "r") : NULL;
        if (file) {
            char line[512];
            while (fgets(line, sizeof(line), file)) fputs(line, stderr);
            fclose(file);
        }
    }
}

static int stop_nodes(node_t nodes[NODES]) {
    int ok = 1;
    for (unsigned i = 0; i < NODES; i++) {
        if (nodes[i].child > 0 && kill(nodes[i].child, SIGTERM) != 0) ok = 0;
    }
    uint64_t deadline = now_ms()+5000;
    for (unsigned i = 0; i < NODES; i++) {
        if (nodes[i].child <= 0) continue;
        int status = 0, reaped = 0;
        do {
            pid_t result = waitpid(nodes[i].child, &status, WNOHANG);
            if (result == nodes[i].child) { reaped = 1; break; }
            if (result < 0 && errno != EINTR) break;
            delay_ms(10);
        } while (now_ms() < deadline);
        if (!reaped) {
            fprintf(stderr, "Node %u did not exit within the shared shutdown deadline\n", i);
            ok = 0;
            (void)kill(nodes[i].child, SIGKILL);
            while (waitpid(nodes[i].child, &status, 0) < 0 && errno == EINTR) {}
        } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Node %u exited with status %d, signal %d\n", i,
                WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                WIFSIGNALED(status) ? WTERMSIG(status) : 0);
            ok = 0;
        }
        nodes[i].child = -1;
    }
    return ok;
}

static void cleanup_node(node_t *node) {
    static const char *files[] = {"identity.key", "pcomm.sqlite", "pcomm.sqlite-journal",
        "pcomm.sqlite-wal", "pcomm.sqlite-shm", "peers.txt", "process.log"};
    close_slot(&node->relay_reservation);
    close_slot(&node->udp_reservation);
    close_slot(&node->http_reservation);
    if (!node->directory[0]) return;
    char path[300];
    for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); i++) {
        if (fixture_path(path, sizeof(path), node, files[i])) {
            fputs("Invalid ratchet fixture path\n", stderr);
            return;
        }
        if (unlink(path) != 0 && errno != ENOENT) perror("unlink ratchet fixture");
    }
    if (rmdir(node->directory) != 0 && errno != ENOENT) perror("remove ratchet node fixture");
}

int main(int argc, char **argv) {
    int bootstrap_only = argc == 4 && strcmp(argv[3], "--bootstrap-only") == 0;
    if (argc != 3 && !bootstrap_only) {
        fputs("usage: test_process_ratchet PCOMM_BINARY UI_DIRECTORY [--bootstrap-only]\n", stderr);
        return EXIT_FAILURE;
    }
    signal(SIGPIPE, SIG_IGN);
    node_t nodes[NODES] = {0};
    for (unsigned i = 0; i < NODES; i++) {
        nodes[i].relay_reservation = nodes[i].udp_reservation = nodes[i].http_reservation = -1;
        nodes[i].child = -1;
    }
    char directory[] = "process-ratchet-XXXXXX";
    if (!mkdtemp(directory)) return EXIT_FAILURE;
    int ok = 0;
    const char *stage = "prepare fixtures";
    uint64_t deadline = now_ms()+80000;
    for (unsigned i = 0; i < NODES; i++) if (prepare_node(&nodes[i], directory, i, bootstrap_only)) goto done;
    for (unsigned i = 0; i < NODES; i++) {
        if (bootstrap_only ? !peer_file_absent(&nodes[i]) : write_peers(nodes, i)) goto done;
    }
    if (!bootstrap_only) {
        stage = "prepare blocked directory storage";
        if (block_descriptor_storage(&nodes[0], nodes[1].identity.pubkey) ||
            block_descriptor_storage(&nodes[2], nodes[1].identity.pubkey)) goto done;
    }
    for (unsigned i = 0; i < NODES; i++) {
        close_slot(&nodes[i].relay_reservation);
        close_slot(&nodes[i].udp_reservation);
        close_slot(&nodes[i].http_reservation);
    }
    stage = "start applications";
    char bootstrap[80];
    snprintf(bootstrap, sizeof(bootstrap), "%s:%u", nodes[0].host, nodes[0].relay_port);
    for (unsigned i = 0; i < NODES; i++) {
        if (start_node(&nodes[i], argv[1], argv[2], bootstrap_only && i ? bootstrap : NULL)) goto done;
    }
    for (unsigned i = 0; i < NODES; i++) {
        uint64_t ready_deadline = now_ms()+10000;
        while (ready_node(&nodes[i])) {
            if (now_ms() >= ready_deadline || now_ms() >= deadline) goto done;
            delay_ms(20);
        }
    }
    stage = "verify ratchet-enabled application schema";
    for (unsigned i = 0; i < NODES; i++) {
        sqlite3 *db = NULL;
        if (open_readonly(&nodes[i], &db)) goto done;
        int present = scalar(db, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='ratchet_sessions'", NULL, NULL);
        sqlite3_close(db);
        if (present != 1) goto done;
    }
    if (bootstrap_only) {
        stage = "discover relay identities from bootstrap without peer files";
        while (!bootstrap_contacts_ready(nodes)) {
            if (now_ms() >= deadline) goto done;
            delay_ms(100);
        }
    } else {
        stage = "observe partial publication and two rejected storage attempts";
        while (descriptor_replica_count(nodes, 1) != 1 || !publication_block_observed(&nodes[0]) ||
               !publication_block_observed(&nodes[2])) {
            if (now_ms() >= deadline) goto done;
            delay_ms(100);
        }
        stage = "release blocked directory storage";
        if (unblock_descriptor_storage(&nodes[0]) || unblock_descriptor_storage(&nodes[2])) goto done;
        uint64_t retry_deadline = now_ms()+15000;
        stage = "retry incomplete signed descriptor publication";
        while (!descriptor_replicas_ready(nodes, 1)) {
            if (now_ms() >= deadline || now_ms() >= retry_deadline) goto done;
            delay_ms(100);
        }
    }
    stage = "queue forward message through HTTP";
    unsigned timeout = remaining_ms(deadline, 30000);
    if (!timeout || post_message(&nodes[0], &nodes[1], "process-ratchet-forward", timeout)) goto done;
    stage = "receive forward message through actual transports";
    while (received_count(&nodes[1], &nodes[0], "process-ratchet-forward") != 1) {
        if (now_ms() >= deadline) goto done;
        delay_ms(100);
    }
    stage = "queue reverse message through HTTP";
    timeout = remaining_ms(deadline, 30000);
    if (!timeout || post_message(&nodes[1], &nodes[0], "process-ratchet-reverse", timeout)) goto done;
    stage = "settle accepted messages and protocol outboxes";
    while (!settled(&nodes[0], &nodes[1], "process-ratchet-reverse", "process-ratchet-forward") ||
           !settled(&nodes[1], &nodes[0], "process-ratchet-forward", "process-ratchet-reverse")) {
        if (now_ms() >= deadline) goto done;
        delay_ms(100);
    }
    if (bootstrap_only) {
        stage = "same-IP descriptor quorum fails closed";
        for (unsigned i = 0; i < NODES; i++) {
            sqlite3 *db = NULL;
            if (!peer_file_absent(&nodes[i]) || open_readonly(&nodes[i], &db)) goto done;
            int count = scalar(db, "SELECT count(*) FROM descriptor_trust", NULL, NULL);
            sqlite3_close(db);
            if (count != 0) goto done;
        }
    } else {
        stage = "verify signed descriptor consensus from independent replica IPs";
        if (descriptor_count(&nodes[0], nodes[1].identity.pubkey, 1) <= 0) goto done;
    }
    ok = 1;
done:
    if (!stop_nodes(nodes)) {
        if (ok) stage = "graceful application shutdown";
        ok = 0;
    }
    if (!ok) {
        fprintf(stderr, "Process ratchet smoke failed at: %s\n", stage);
        print_diagnostics(nodes);
    }
    for (unsigned i = 0; i < NODES; i++) cleanup_node(&nodes[i]);
    if (rmdir(directory) != 0) perror("remove ratchet fixture root");
    if (ok) puts(bootstrap_only ?
        "PASS: bootstrap-only discovery without peer files, ratchet transport, and shutdown" :
        "PASS: real application forward/reverse ratchet transport and shutdown");
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
