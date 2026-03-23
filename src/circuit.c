#define _GNU_SOURCE
#include "circuit.h"
#include "net.h"
#include "proto.h"
#include "cell.h"
#include "crypto.h"
#include "db.h"

#include <pthread.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>

#define PCOMM_CIRC_ID 1
#define PCOMM_MAX_HOPS 3
#define STREAM_MAP_CAP 1024

typedef struct stream_wait {
    uint16_t id;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    uint8_t *buf;
    size_t len;
    int done;
    int saw_end;
    int err;
} stream_wait_t;

struct pcomm_circuit {
    int fd; // TCP connection to guard
    pcomm_peer_t path[PCOMM_MAX_HOPS];
    size_t nhops;

    uint8_t fwd[PCOMM_MAX_HOPS][32];
    uint8_t bwd[PCOMM_MAX_HOPS][32];

    pthread_t rx_thread;
    pthread_t maint_thread;

    pthread_mutex_t mu;
    uint16_t next_stream;

    // stream waiters
    stream_wait_t *streams[STREAM_MAP_CAP];

    // lifecycle
    time_t created_at;
    time_t last_io;
    uint64_t bytes_sent;
    uint64_t bytes_recv;

    int running;

    // Optional callback for non-RPC relay events
    pcomm_relay_event_cb event_cb;
    void *event_cb_arg;

    // config snapshot (used by maint thread)
    pcomm_config_t cfg;

    int is_dedicated;
};

// ---- Global circuit manager (primary + spare) ----

static pthread_t g_mgr_th;
static pthread_mutex_t g_mgr_mu = PTHREAD_MUTEX_INITIALIZER;
static pcomm_circuit_t *g_primary = NULL;
static pcomm_circuit_t *g_spare = NULL;

static pcomm_config_t g_cfg;
static pcomm_identity_t g_me;
static pcomm_db_t *g_db = NULL;

// ---- helpers ----

static void stream_wait_free(stream_wait_t *w) {
    if (!w) return;
    pthread_mutex_destroy(&w->mu);
    pthread_cond_destroy(&w->cv);
    free(w->buf);
    free(w);
}

static stream_wait_t *stream_wait_new(uint16_t id) {
    stream_wait_t *w = (stream_wait_t*)calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->id = id;
    pthread_mutex_init(&w->mu, NULL);
    pthread_cond_init(&w->cv, NULL);
    return w;
}

static void stream_deliver(stream_wait_t *w, const uint8_t *data, uint16_t len, int is_end) {
    if (!w) return;
    pthread_mutex_lock(&w->mu);
    if (w->done) {
        pthread_mutex_unlock(&w->mu);
        return;
    }
    if (data && len) {
        uint8_t *nb = (uint8_t*)realloc(w->buf, w->len + len);
        if (!nb) {
            w->err = 1;
            w->done = 1;
            pthread_cond_broadcast(&w->cv);
            pthread_mutex_unlock(&w->mu);
            return;
        }
        w->buf = nb;
        memcpy(w->buf + w->len, data, len);
        w->len += len;
    }
    if (is_end) {
        w->saw_end = 1;
        w->done = 1;
    }
    pthread_cond_broadcast(&w->cv);
    pthread_mutex_unlock(&w->mu);
}

static size_t stream_slot(uint16_t id) {
    return (size_t)id % STREAM_MAP_CAP;
}

static int stream_map_put(pcomm_circuit_t *c, stream_wait_t *w) {
    size_t i = stream_slot(w->id);
    for (size_t n = 0; n < STREAM_MAP_CAP; n++) {
        size_t idx = (i + n) % STREAM_MAP_CAP;
        if (!c->streams[idx]) {
            c->streams[idx] = w;
            return 0;
        }
    }
    return -1;
}

static stream_wait_t *stream_map_get(pcomm_circuit_t *c, uint16_t id) {
    size_t i = stream_slot(id);
    for (size_t n = 0; n < STREAM_MAP_CAP; n++) {
        size_t idx = (i + n) % STREAM_MAP_CAP;
        stream_wait_t *w = c->streams[idx];
        if (!w) return NULL;
        if (w->id == id) return w;
    }
    return NULL;
}

static void stream_map_del(pcomm_circuit_t *c, uint16_t id) {
    size_t i = stream_slot(id);
    for (size_t n = 0; n < STREAM_MAP_CAP; n++) {
        size_t idx = (i + n) % STREAM_MAP_CAP;
        stream_wait_t *w = c->streams[idx];
        if (!w) return;
        if (w->id == id) {
            c->streams[idx] = NULL;
            return;
        }
    }
}

static void circuit_touch(pcomm_circuit_t *c) {
    c->last_io = time(NULL);
}

static int derive_hop_keys(const uint8_t shared[32], uint8_t out_fwd[32], uint8_t out_bwd[32]) {
    const uint8_t salt[] = "pcomm-circ-v1";
    const uint8_t info[] = "pcomm-hop-keys";
    uint8_t okm[64];
    if (pcomm_hkdf_sha256(shared, 32, salt, sizeof(salt) - 1, info, sizeof(info) - 1, okm, sizeof(okm)) != 0) return -1;
    memcpy(out_fwd, okm, 32);
    memcpy(out_bwd, okm + 32, 32);
    return 0;
}

static int send_cell_raw(int fd, uint8_t cell_cmd, const uint8_t *cell_payload, uint16_t cell_pl_len) {
    uint8_t *cell = NULL;
    uint32_t cell_len = 0;
    if (pcomm_cell_pack(PCOMM_CIRC_ID, cell_cmd, 0, cell_payload, cell_pl_len, &cell, &cell_len) != 0) return -1;
    int rc = pcomm_send_packet(fd, PCOMM_MSG_CELL, NULL, cell, cell_len);
    free(cell);
    return rc;
}

static int recv_cell_raw(int fd, uint8_t *cell_cmd, uint8_t **cell_payload, uint16_t *cell_pl_len) {
    *cell_payload = NULL;
    *cell_pl_len = 0;
    *cell_cmd = 0;

    pcomm_msg_type_t t;
    uint8_t eph[32];
    uint8_t *p = NULL;
    uint32_t pl = 0;
    if (pcomm_recv_packet(fd, &t, eph, &p, &pl) != 0) {
        free(p);
        return -1;
    }
    if (t != PCOMM_MSG_CELL) {
        free(p);
        return -1;
    }

    uint32_t cid;
    uint8_t cmd, flags;
    const uint8_t *cpl;
    uint16_t cpll;
    if (pcomm_cell_unpack(p, pl, &cid, &cmd, &flags, &cpl, &cpll) != 0 || cid != PCOMM_CIRC_ID) {
        free(p);
        return -1;
    }
    (void)flags;
    *cell_cmd = cmd;
    if (cpll) {
        uint8_t *cp = (uint8_t*)malloc(cpll);
        if (!cp) {
            free(p);
            return -1;
        }
        memcpy(cp, cpl, cpll);
        *cell_payload = cp;
        *cell_pl_len = cpll;
    }
    free(p);
    return 0;
}

static int send_relay_plain_locked(pcomm_circuit_t *c, const uint8_t *plain, uint16_t plain_len) {
    uint8_t *wrapped = NULL;
    uint16_t wrapped_len = 0;
    if (pcomm_relay_wrap_forward(c->fwd, c->nhops, PCOMM_CIRC_ID, plain, plain_len, &wrapped, &wrapped_len) != 0) return -1;
    int rc = send_cell_raw(c->fd, PCOMM_CELL_RELAY, wrapped, wrapped_len);
    if (rc == 0) {
        c->bytes_sent += wrapped_len;
        circuit_touch(c);
    }
    free(wrapped);
    return rc;
}

static int send_relay_cmd_locked(pcomm_circuit_t *c, uint8_t relay_cmd, uint16_t stream_id, const uint8_t *body, uint16_t body_len) {
    uint8_t *plain = NULL;
    uint16_t plain_len = 0;
    if (pcomm_relay_plain_pack(relay_cmd, stream_id, body, body_len, &plain, &plain_len) != 0) return -1;
    int rc = send_relay_plain_locked(c, plain, plain_len);
    free(plain);
    return rc;
}

static uint16_t alloc_stream_id_locked(pcomm_circuit_t *c) {
    uint16_t sid = c->next_stream++;
    if (sid == 0) sid = c->next_stream++;
    return sid;
}

// ---- RX + maintenance threads ----

static void *rx_loop(void *arg) {
    pcomm_circuit_t *c = (pcomm_circuit_t*)arg;

    while (c->running) {
        pcomm_msg_type_t t;
        uint8_t eph[32];
        uint8_t *p = NULL;
        uint32_t pl = 0;

        if (pcomm_recv_packet(c->fd, &t, eph, &p, &pl) != 0) {
            free(p);
            break;
        }
        if (t != PCOMM_MSG_CELL) {
            free(p);
            continue;
        }

        uint32_t cid;
        uint8_t cmd, flags;
        const uint8_t *cpl;
        uint16_t cpll;
        if (pcomm_cell_unpack(p, pl, &cid, &cmd, &flags, &cpl, &cpll) != 0 || cid != PCOMM_CIRC_ID) {
            free(p);
            continue;
        }
        (void)flags;

        if (cmd == PCOMM_CELL_RELAY) {
            uint8_t *plain = NULL;
            uint16_t plain_len = 0;
            if (pcomm_relay_unwrap_backward_all(c->bwd, c->nhops, PCOMM_CIRC_ID, cpl, cpll, &plain, &plain_len) == 0) {
                uint8_t rcmd;
                uint16_t sid;
                const uint8_t *body;
                uint16_t bl;

                if (pcomm_relay_plain_unpack(plain, plain_len, &rcmd, &sid, &body, &bl) == 0) {
                    pthread_mutex_lock(&c->mu);
                    c->bytes_recv += cpll;
                    circuit_touch(c);

                    stream_wait_t *w = stream_map_get(c, sid);
                    pcomm_relay_event_cb cb = c->event_cb;
                    void *cb_arg = c->event_cb_arg;
                    pthread_mutex_unlock(&c->mu);

                    int consumed = 0;
                    if (w) {
                        if (rcmd == PCOMM_RELAY_DATA) {
                            stream_deliver(w, body, bl, 0);
                            consumed = 1;
                        } else if (rcmd == PCOMM_RELAY_END) {
                            stream_deliver(w, NULL, 0, 1);
                            consumed = 1;
                        } else if (rcmd == PCOMM_RELAY_CONNECTED) {
                            consumed = 1;
                        }
                    }

                    // Keepalive PONG on stream 0: just touch.
                    if (!consumed && rcmd == PCOMM_RELAY_PONG && sid == 0) {
                        consumed = 1;
                    }

                    if (!consumed && cb) {
                        cb(cb_arg, c, rcmd, sid, body, bl);
                    }
                }
                free(plain);
            }
        }

        free(p);
    }

    // signal waiters
    pthread_mutex_lock(&c->mu);
    for (size_t i = 0; i < STREAM_MAP_CAP; i++) {
        stream_wait_t *w = c->streams[i];
        if (w) stream_deliver(w, NULL, 0, 1);
    }
    pthread_mutex_unlock(&c->mu);

    c->running = 0;
    return NULL;
}

static void *maint_loop(void *arg) {
    pcomm_circuit_t *c = (pcomm_circuit_t*)arg;

    // jitter
    uint8_t r[1];
    (void)pcomm_random(r, 1);
    usleep((useconds_t)(1000 * (200 + (r[0] % 200))));

    for (;;) {
        if (!c->running) break;

        time_t now = time(NULL);
        time_t last = c->last_io ? c->last_io : c->created_at;

        // Dedicated circuits: close after long idle.
        if (c->is_dedicated && c->cfg.dedicated_circuit_idle_sec > 0) {
            if ((uint32_t)(now - last) > c->cfg.dedicated_circuit_idle_sec) {
                break;
            }
        }

        // Send periodic end-to-end keepalive when idle.
        if (c->cfg.circuit_keepalive_idle_ms > 0) {
            if ((uint32_t)(now - last) * 1000U >= c->cfg.circuit_keepalive_idle_ms) {
                uint8_t nonce[8];
                (void)pcomm_random(nonce, sizeof(nonce));
                pthread_mutex_lock(&c->mu);
                (void)send_relay_cmd_locked(c, PCOMM_RELAY_PING, 0, nonce, (uint16_t)sizeof(nonce));
                pthread_mutex_unlock(&c->mu);
            }
        }

        // Random sleep 8..16 seconds
        (void)pcomm_random(r, 1);
        int ms = 8000 + (r[0] % 9000);
        usleep((useconds_t)(1000 * ms));
    }

    // trigger close
    c->running = 0;
    shutdown(c->fd, SHUT_RDWR);
    return NULL;
}

// ---- build ----

static int db_pick_random_relays(pcomm_db_t *db,
                                const char *exclude1,
                                const char *exclude2,
                                const char *exclude3,
                                pcomm_peer_t *out,
                                size_t out_cap,
                                size_t *out_len) {
    *out_len = 0;
    const char *sql =
        "SELECT user_id, host, port, pubkey FROM contacts "
        "WHERE is_relay=1 AND host!='' AND port>0 "
        "AND user_id != ? AND user_id != ? AND user_id != ? "
        "ORDER BY RANDOM() LIMIT ?;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, exclude1 ? exclude1 : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, exclude2 ? exclude2 : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, exclude3 ? exclude3 : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, (int)out_cap);

    while (sqlite3_step(st) == SQLITE_ROW && *out_len < out_cap) {
        const char *uid = (const char*)sqlite3_column_text(st, 0);
        const char *host = (const char*)sqlite3_column_text(st, 1);
        int port = sqlite3_column_int(st, 2);
        const void *pk = sqlite3_column_blob(st, 3);
        int pklen = sqlite3_column_bytes(st, 3);
        if (!uid || !host || pklen != 32 || port <= 0 || port > 65535) continue;
        pcomm_peer_t *p = &out[*out_len];
        memset(p, 0, sizeof(*p));
        snprintf(p->user_id, sizeof(p->user_id), "%s", uid);
        snprintf(p->host, sizeof(p->host), "%s", host);
        p->port = (uint16_t)port;
        memcpy(p->pubkey, pk, 32);
        (*out_len)++;
    }

    sqlite3_finalize(st);
    return (*out_len > 0) ? 0 : -1;
}

static int db_pick_guard(pcomm_db_t *db, pcomm_peer_t *guard_out) {
    char guard_uid[128];
    if (pcomm_db_kv_get(db, "guard_uid", guard_uid, sizeof(guard_uid)) == 0 && guard_uid[0]) {
        char host[64];
        uint16_t port;
        uint8_t pk[32];
        int is_relay = 0;
        if (pcomm_db_get_contact(db, guard_uid, host, sizeof(host), &port, pk, &is_relay) == 0 && is_relay) {
            memset(guard_out, 0, sizeof(*guard_out));
            snprintf(guard_out->user_id, sizeof(guard_out->user_id), "%s", guard_uid);
            snprintf(guard_out->host, sizeof(guard_out->host), "%s", host);
            guard_out->port = port;
            memcpy(guard_out->pubkey, pk, 32);
            return 0;
        }
    }

    // pick a new guard
    pcomm_peer_t g;
    size_t n = 0;
    if (db_pick_random_relays(db, NULL, NULL, NULL, &g, 1, &n) != 0 || n == 0) return -1;

    (void)pcomm_db_kv_set(db, "guard_uid", g.user_id);

    *guard_out = g;
    return 0;
}

static int circuit_build(pcomm_circuit_t *c, const pcomm_peer_t *path, size_t path_len) {
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->mu, NULL);
    c->fd = -1;
    c->next_stream = 1;
    c->created_at = time(NULL);
    c->last_io = c->created_at;

    c->fd = net_connect_tcp(path[0].host, path[0].port);
    if (c->fd < 0) return -1;

    static const uint8_t basepoint[32] = {9};

    // hop1 CREATE
    uint8_t eph1_priv[32], eph1_pub[32];
    if (pcomm_random(eph1_priv, 32) != 0) return -1;
    if (pcomm_x25519_derive(eph1_priv, basepoint, eph1_pub) != 0) return -1;
    if (send_cell_raw(c->fd, PCOMM_CELL_CREATE, eph1_pub, 32) != 0) return -1;

    uint8_t rcmd;
    uint8_t *rpl = NULL;
    uint16_t rpll = 0;
    if (recv_cell_raw(c->fd, &rcmd, &rpl, &rpll) != 0 || rcmd != PCOMM_CELL_CREATED || rpll != 32) {
        free(rpl);
        return -1;
    }
    uint8_t shared1[32];
    if (pcomm_x25519_derive(eph1_priv, rpl, shared1) != 0) {
        free(rpl);
        return -1;
    }
    free(rpl);
    if (derive_hop_keys(shared1, c->fwd[0], c->bwd[0]) != 0) return -1;

    c->path[0] = path[0];
    c->nhops = 1;

    // extend further hops
    for (size_t hi = 1; hi < path_len; hi++) {
        uint8_t eph_priv[32], eph_pub[32];
        if (pcomm_random(eph_priv, 32) != 0) return -1;
        if (pcomm_x25519_derive(eph_priv, basepoint, eph_pub) != 0) return -1;

        uint8_t body[1 + 64 + 2 + 32];
        size_t hostlen = strlen(path[hi].host);
        if (hostlen == 0 || hostlen > 63) return -1;
        size_t bo = 0;
        body[bo++] = (uint8_t)hostlen;
        memcpy(body + bo, path[hi].host, hostlen); bo += hostlen;
        uint16_t p = htons(path[hi].port);
        memcpy(body + bo, &p, 2); bo += 2;
        memcpy(body + bo, eph_pub, 32); bo += 32;

        pthread_mutex_lock(&c->mu);
        if (send_relay_cmd_locked(c, PCOMM_RELAY_EXTEND, 0, body, (uint16_t)bo) != 0) {
            pthread_mutex_unlock(&c->mu);
            return -1;
        }
        pthread_mutex_unlock(&c->mu);

        // wait for EXTENDED
        pcomm_msg_type_t t;
        uint8_t eph[32];
        uint8_t *pp = NULL;
        uint32_t ppl = 0;
        if (pcomm_recv_packet(c->fd, &t, eph, &pp, &ppl) != 0) {
            free(pp);
            return -1;
        }
        if (t != PCOMM_MSG_CELL) {
            free(pp);
            return -1;
        }
        uint32_t cid;
        uint8_t cmd, flags;
        const uint8_t *cpl;
        uint16_t cpll;
        if (pcomm_cell_unpack(pp, ppl, &cid, &cmd, &flags, &cpl, &cpll) != 0 || cid != PCOMM_CIRC_ID || cmd != PCOMM_CELL_RELAY) {
            free(pp);
            return -1;
        }
        (void)flags;

        uint8_t *ext_plain = NULL;
        uint16_t ext_plain_len = 0;
        if (pcomm_relay_unwrap_backward_all(c->bwd, c->nhops, PCOMM_CIRC_ID, cpl, cpll, &ext_plain, &ext_plain_len) != 0) {
            free(pp);
            return -1;
        }
        free(pp);

        uint8_t rr;
        uint16_t sid;
        const uint8_t *bdy;
        uint16_t bl;
        if (pcomm_relay_plain_unpack(ext_plain, ext_plain_len, &rr, &sid, &bdy, &bl) != 0 || rr != PCOMM_RELAY_EXTENDED || bl != 32) {
            free(ext_plain);
            return -1;
        }

        uint8_t shared[32];
        if (pcomm_x25519_derive(eph_priv, bdy, shared) != 0) {
            free(ext_plain);
            return -1;
        }
        free(ext_plain);

        if (derive_hop_keys(shared, c->fwd[c->nhops], c->bwd[c->nhops]) != 0) return -1;
        c->path[c->nhops] = path[hi];
        c->nhops++;
    }

    c->running = 1;
    if (pthread_create(&c->rx_thread, NULL, rx_loop, c) != 0) return -1;
    if (pthread_create(&c->maint_thread, NULL, maint_loop, c) != 0) return -1;

    return 0;
}

static void circuit_close_internal(pcomm_circuit_t *c) {
    if (!c) return;

    c->running = 0;
    if (c->fd >= 0) shutdown(c->fd, SHUT_RDWR);

    if (c->rx_thread) pthread_join(c->rx_thread, NULL);
    if (c->maint_thread) pthread_join(c->maint_thread, NULL);

    if (c->fd >= 0) close(c->fd);

    pthread_mutex_lock(&c->mu);
    for (size_t i = 0; i < STREAM_MAP_CAP; i++) {
        stream_wait_t *w = c->streams[i];
        c->streams[i] = NULL;
        stream_wait_free(w);
    }
    pthread_mutex_unlock(&c->mu);

    pthread_mutex_destroy(&c->mu);
    free(c);
}

// ---- manager ----

static pcomm_circuit_t *build_new_circuit(int is_dedicated,
                                         const char *exit_host,
                                         uint16_t exit_port,
                                         const char *exclude_uid) {
    // Build a 1..3 hop circuit.
    pcomm_peer_t path[PCOMM_MAX_HOPS];
    size_t n = 0;

    if (!is_dedicated) {
        // global circuits: choose a stable guard
        pcomm_peer_t guard;
        if (db_pick_guard(g_db, &guard) != 0) return NULL;
        path[n++] = guard;
        // pick middle + exit relays
        pcomm_peer_t others[2];
        size_t on = 0;
        (void)db_pick_random_relays(g_db, guard.user_id, g_me.user_id, NULL, others, 2, &on);
        for (size_t i = 0; i < on && n < PCOMM_MAX_HOPS; i++) path[n++] = others[i];
    } else {
        // dedicated circuits: still prefer guard if available
        pcomm_peer_t guard;
        if (db_pick_guard(g_db, &guard) == 0) {
            path[n++] = guard;
        }
        // middle
        pcomm_peer_t mid[2]; size_t mn = 0;
        (void)db_pick_random_relays(g_db, (n ? path[0].user_id : NULL), exclude_uid, NULL, mid, (n ? 1 : 2), &mn);
        for (size_t i = 0; i < mn && n < 2; i++) path[n++] = mid[i];

        // exit is fixed host/port
        pcomm_peer_t exitp;
        memset(&exitp, 0, sizeof(exitp));
        snprintf(exitp.host, sizeof(exitp.host), "%s", exit_host);
        exitp.port = exit_port;
        path[n++] = exitp;

        // ensure at least 1 hop
        if (n == 0) return NULL;
    }

    // If dedicated and guard not chosen, ensure at least one hop exists.
    if (!is_dedicated && n == 0) return NULL;

    pcomm_circuit_t *c = (pcomm_circuit_t*)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->cfg = g_cfg;
    c->is_dedicated = is_dedicated;

    if (circuit_build(c, path, n) != 0) {
        circuit_close_internal(c);
        return NULL;
    }

    return c;
}

static void mgr_swap_primary_locked(void) {
    if (g_primary) {
        circuit_close_internal(g_primary);
        g_primary = NULL;
    }
    if (g_spare) {
        g_primary = g_spare;
        g_spare = NULL;
    }
}

static void mgr_tick(void) {
    pthread_mutex_lock(&g_mgr_mu);
    pcomm_circuit_t *p = g_primary;
    pcomm_circuit_t *s = g_spare;
    pthread_mutex_unlock(&g_mgr_mu);

    // Ensure primary
    if (!p) {
        pcomm_circuit_t *nc = build_new_circuit(0, NULL, 0, NULL);
        if (nc) {
            pthread_mutex_lock(&g_mgr_mu);
            if (!g_primary) g_primary = nc; else circuit_close_internal(nc);
            pthread_mutex_unlock(&g_mgr_mu);
        }
        return;
    }

    // Rotate by age
    time_t now = time(NULL);
    if (g_cfg.circuit_max_age_sec > 0 && (uint32_t)(now - p->created_at) > g_cfg.circuit_max_age_sec) {
        // Build a new spare first.
        if (!s) {
            pcomm_circuit_t *ns = build_new_circuit(0, NULL, 0, NULL);
            if (ns) {
                pthread_mutex_lock(&g_mgr_mu);
                if (!g_spare) g_spare = ns; else circuit_close_internal(ns);
                pthread_mutex_unlock(&g_mgr_mu);
            }
        }
        // Swap if spare ready
        pthread_mutex_lock(&g_mgr_mu);
        if (g_spare) {
            pcomm_circuit_t *old = g_primary;
            g_primary = g_spare;
            g_spare = NULL;
            pthread_mutex_unlock(&g_mgr_mu);
            circuit_close_internal(old);
            return;
        }
        pthread_mutex_unlock(&g_mgr_mu);
    }

    // Ensure spare
    if (g_cfg.circuit_pool_size >= 2 && !s) {
        pcomm_circuit_t *ns = build_new_circuit(0, NULL, 0, NULL);
        if (ns) {
            pthread_mutex_lock(&g_mgr_mu);
            if (!g_spare) g_spare = ns; else circuit_close_internal(ns);
            pthread_mutex_unlock(&g_mgr_mu);
        }
    }

    // Drop dead circuits
    if (p && !p->running) {
        pthread_mutex_lock(&g_mgr_mu);
        if (g_primary == p) {
            mgr_swap_primary_locked();
        }
        pthread_mutex_unlock(&g_mgr_mu);
    }
    if (s && !s->running) {
        pthread_mutex_lock(&g_mgr_mu);
        if (g_spare == s) {
            circuit_close_internal(g_spare);
            g_spare = NULL;
        }
        pthread_mutex_unlock(&g_mgr_mu);
    }
}

static void *mgr_loop(void *arg) {
    (void)arg;
    // seed rand for DHT sampling, etc.
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    for (;;) {
        mgr_tick();
        usleep(500 * 1000);
    }
    return NULL;
}

// ---- API ----

int pcomm_circuits_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db) {
    if (!cfg || !me || !db) return -1;
    g_cfg = *cfg;
    g_me = *me;
    g_db = db;

    if (pthread_create(&g_mgr_th, NULL, mgr_loop, NULL) != 0) return -1;
    pthread_detach(g_mgr_th);
    return 0;
}

pcomm_circuit_t *pcomm_circuit_get(void) {
    pthread_mutex_lock(&g_mgr_mu);
    pcomm_circuit_t *c = g_primary;
    pthread_mutex_unlock(&g_mgr_mu);
    return c;
}

int pcomm_circuit_set_event_cb(pcomm_circuit_t *c, pcomm_relay_event_cb cb, void *arg) {
    if (!c) return -1;
    pthread_mutex_lock(&c->mu);
    c->event_cb = cb;
    c->event_cb_arg = arg;
    pthread_mutex_unlock(&c->mu);
    return 0;
}

int pcomm_circuit_alloc_stream(pcomm_circuit_t *c, uint16_t *stream_id_out) {
    if (!c || !stream_id_out) return -1;
    pthread_mutex_lock(&c->mu);
    uint16_t sid = alloc_stream_id_locked(c);
    pthread_mutex_unlock(&c->mu);
    *stream_id_out = sid;
    return 0;
}

int pcomm_circuit_send_relay(pcomm_circuit_t *c, uint8_t relay_cmd, uint16_t stream_id,
                            const uint8_t *body, uint16_t body_len) {
    if (!c) return -1;
    pthread_mutex_lock(&c->mu);
    int rc = send_relay_cmd_locked(c, relay_cmd, stream_id, body, body_len);
    pthread_mutex_unlock(&c->mu);
    return rc;
}

static pcomm_circuit_t *build_dedicated_circuit(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db,
                                              const char *exit_host, uint16_t exit_port,
                                              const char *exclude_uid) {
    pcomm_peer_t path[PCOMM_MAX_HOPS];
    size_t n = 0;

    // Prefer the same guard selection logic (stored in settings).
    pcomm_peer_t guard;
    if (db_pick_guard(db, &guard) == 0) {
        path[n++] = guard;
    }

    // Optional middle hop (avoid duplicates).
    pcomm_peer_t mids[2];
    size_t mn = 0;
    (void)db_pick_random_relays(db, (n ? path[0].user_id : NULL), exclude_uid, NULL, mids, 1, &mn);
    for (size_t i = 0; i < mn && n < (PCOMM_MAX_HOPS - 1); i++) path[n++] = mids[i];

    // Exit hop.
    pcomm_peer_t exitp;
    memset(&exitp, 0, sizeof(exitp));
    snprintf(exitp.host, sizeof(exitp.host), "%s", exit_host);
    exitp.port = exit_port;
    path[n++] = exitp;

    if (n == 0) return NULL;

    pcomm_circuit_t *c = (pcomm_circuit_t*)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->cfg = *cfg;
    c->is_dedicated = 1;

    // For dedicated circuits we do not require global manager state.
    (void)me;
    if (circuit_build(c, path, n) != 0) {
        circuit_close_internal(c);
        return NULL;
    }
    return c;
}

pcomm_circuit_t *pcomm_circuit_create_to_exit(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db,
                                              const char *exit_host, uint16_t exit_port,
                                              const char *exclude_uid) {
    if (!cfg || !me || !db || !exit_host || exit_port == 0) return NULL;

    return build_dedicated_circuit(cfg, me, db, exit_host, exit_port, exclude_uid);
}

void pcomm_circuit_close(pcomm_circuit_t *c) {
    circuit_close_internal(c);
}

int pcomm_circuit_rpc(pcomm_circuit_t *c,
                      const char *dest_host, uint16_t dest_port,
                      pcomm_msg_type_t inner_type,
                      const uint8_t *inner_payload, uint32_t inner_payload_len,
                      int expect_resp,
                      pcomm_msg_type_t *resp_type_out,
                      uint8_t **resp_payload_out, uint32_t *resp_payload_len_out) {
    if (resp_payload_out) *resp_payload_out = NULL;
    if (resp_payload_len_out) *resp_payload_len_out = 0;
    if (resp_type_out) *resp_type_out = 0;

    if (!c || !dest_host || dest_port == 0) return -1;

    uint8_t *inner = NULL;
    uint32_t inner_len = 0;
    if (pcomm_pack_packet(inner_type, NULL, inner_payload, inner_payload_len, &inner, &inner_len) != 0) return -1;

    // Allocate stream + waiter
    pthread_mutex_lock(&c->mu);
    uint16_t sid = alloc_stream_id_locked(c);
    stream_wait_t *w = stream_wait_new(sid);
    if (!w || stream_map_put(c, w) != 0) {
        pthread_mutex_unlock(&c->mu);
        free(inner);
        stream_wait_free(w);
        return -1;
    }

    // BEGIN
    uint8_t b[1 + 64 + 2 + 1];
    size_t hl = strlen(dest_host);
    if (hl == 0 || hl > 63) {
        stream_map_del(c, sid);
        pthread_mutex_unlock(&c->mu);
        free(inner);
        stream_wait_free(w);
        return -1;
    }
    size_t bo = 0;
    b[bo++] = (uint8_t)hl;
    memcpy(b + bo, dest_host, hl); bo += hl;
    uint16_t np = htons(dest_port);
    memcpy(b + bo, &np, 2); bo += 2;
    b[bo++] = (uint8_t)(expect_resp ? 1 : 0);

    if (send_relay_cmd_locked(c, PCOMM_RELAY_BEGIN, sid, b, (uint16_t)bo) != 0) {
        stream_map_del(c, sid);
        pthread_mutex_unlock(&c->mu);
        free(inner);
        stream_wait_free(w);
        return -1;
    }

    // DATA
    if (send_relay_cmd_locked(c, PCOMM_RELAY_DATA, sid, inner, (uint16_t)inner_len) != 0) {
        // best-effort END
        (void)send_relay_cmd_locked(c, PCOMM_RELAY_END, sid, NULL, 0);
        stream_map_del(c, sid);
        pthread_mutex_unlock(&c->mu);
        free(inner);
        stream_wait_free(w);
        return -1;
    }

    // END
    (void)send_relay_cmd_locked(c, PCOMM_RELAY_END, sid, NULL, 0);

    pthread_mutex_unlock(&c->mu);
    free(inner);

    if (!expect_resp) {
        pthread_mutex_lock(&c->mu);
        stream_map_del(c, sid);
        pthread_mutex_unlock(&c->mu);
        stream_wait_free(w);
        return 0;
    }

    // Wait up to 5 seconds
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;

    pthread_mutex_lock(&w->mu);
    while (!w->done) {
        if (pthread_cond_timedwait(&w->cv, &w->mu, &ts) == ETIMEDOUT) break;
    }
    int ok = (w->done && w->saw_end && !w->err && w->len >= PCOMM_HDR_LEN);
    pthread_mutex_unlock(&w->mu);

    pthread_mutex_lock(&c->mu);
    stream_map_del(c, sid);
    pthread_mutex_unlock(&c->mu);

    if (!ok) {
        stream_wait_free(w);
        return -1;
    }

    pcomm_msg_type_t rt;
    uint8_t reph[32];
    uint8_t *rp = NULL;
    uint32_t rpl = 0;
    if (pcomm_unpack_packet(w->buf, (uint32_t)w->len, &rt, reph, &rp, &rpl) != 0) {
        stream_wait_free(w);
        return -1;
    }

    if (resp_type_out) *resp_type_out = rt;
    if (resp_payload_out) *resp_payload_out = rp; else free(rp);
    if (resp_payload_len_out) *resp_payload_len_out = rpl;

    stream_wait_free(w);
    return 0;
}
