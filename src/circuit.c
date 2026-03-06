#define _GNU_SOURCE
#include "circuit.h"
#include "net.h"
#include "proto.h"
#include "cell.h"
#include "crypto.h"

#include <pthread.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#define PCOMM_CIRC_ID 1
#define PCOMM_MAX_HOPS 3

typedef struct {
    uint16_t id;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int done;
    uint8_t *buf;
    uint32_t len;
    int saw_end;
    int err;
} stream_wait_t;

struct pcomm_circuit {
    int fd; // connection to guard
    pcomm_peer_t path[PCOMM_MAX_HOPS];
    size_t nhops;
    uint8_t fwd[PCOMM_MAX_HOPS][32];
    uint8_t bwd[PCOMM_MAX_HOPS][32];

    pthread_t rx_thread;
    pthread_mutex_t mu;
    uint16_t next_stream;

    // very small stream map (prototype)
    stream_wait_t *streams[256]; // index by low byte
    int running;
};

static pthread_t g_mgr_th;
static pthread_mutex_t g_mgr_mu = PTHREAD_MUTEX_INITIALIZER;
static pcomm_circuit_t *g_circ = NULL;
static pcomm_config_t g_cfg;
static pcomm_identity_t g_me;
static pcomm_db_t *g_db = NULL;

static void stream_wait_init(stream_wait_t *w, uint16_t id) {
    memset(w, 0, sizeof(*w));
    w->id = id;
    pthread_mutex_init(&w->mu, NULL);
    pthread_cond_init(&w->cv, NULL);
}

static void stream_wait_destroy(stream_wait_t *w) {
    pthread_mutex_destroy(&w->mu);
    pthread_cond_destroy(&w->cv);
    free(w->buf);
    w->buf = NULL;
}

static void stream_deliver(stream_wait_t *w, const uint8_t *data, uint16_t len, int is_end) {
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

static int db_pick_relays(pcomm_db_t *db, const char *exclude_uid, pcomm_peer_t out[PCOMM_MAX_HOPS], size_t *out_len) {
    *out_len = 0;
    const char *sql =
        "SELECT user_id, host, port, pubkey FROM contacts "
        "WHERE is_relay=1 AND host!='' AND port>0 AND user_id != ? "
        "ORDER BY RANDOM() LIMIT 3;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, exclude_uid ? exclude_uid : "", -1, SQLITE_TRANSIENT);

    while (sqlite3_step(st) == SQLITE_ROW) {
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
        if (*out_len >= PCOMM_MAX_HOPS) break;
    }

    sqlite3_finalize(st);
    return (*out_len > 0) ? 0 : -1;
}

static int derive_hop_keys(const uint8_t shared[32], uint8_t out_fwd[32], uint8_t out_bwd[32]) {
    const uint8_t salt[] = "pcomm-circ-v1";
    const uint8_t info[] = "pcomm-hop-keys";
    uint8_t okm[64];
    if (pcomm_hkdf_sha256(shared, 32, salt, sizeof(salt)-1, info, sizeof(info)-1, okm, sizeof(okm)) != 0) return -1;
    memcpy(out_fwd, okm, 32);
    memcpy(out_bwd, okm + 32, 32);
    return 0;
}

static int send_cell(int fd, uint8_t cell_cmd, const uint8_t *cell_payload, uint16_t cell_pl_len) {
    uint8_t *cell = NULL; uint32_t cell_len = 0;
    if (pcomm_cell_pack(PCOMM_CIRC_ID, cell_cmd, 0, cell_payload, cell_pl_len, &cell, &cell_len) != 0) return -1;
    int rc = pcomm_send_packet(fd, PCOMM_MSG_CELL, NULL, cell, cell_len);
    free(cell);
    return rc;
}

static int recv_cell(int fd, uint8_t *cell_cmd, uint8_t **cell_payload, uint16_t *cell_pl_len) {
    *cell_payload = NULL; *cell_pl_len = 0; *cell_cmd = 0;
    pcomm_msg_type_t t; uint8_t eph[32]; uint8_t *p = NULL; uint32_t pl = 0;
    if (pcomm_recv_packet(fd, &t, eph, &p, &pl) != 0) { free(p); return -1; }
    if (t != PCOMM_MSG_CELL) { free(p); return -1; }

    uint32_t cid; uint8_t cmd, flags; const uint8_t *cpl; uint16_t cpll;
    if (pcomm_cell_unpack(p, pl, &cid, &cmd, &flags, &cpl, &cpll) != 0 || cid != PCOMM_CIRC_ID) {
        free(p);
        return -1;
    }
    (void)flags;
    *cell_cmd = cmd;
    if (cpll) {
        uint8_t *cp = (uint8_t*)malloc(cpll);
        if (!cp) { free(p); return -1; }
        memcpy(cp, cpl, cpll);
        *cell_payload = cp;
        *cell_pl_len = cpll;
    }
    free(p);
    return 0;
}

static int send_relay_plain_locked(pcomm_circuit_t *c, const uint8_t *plain, uint16_t plain_len) {
    uint8_t *wrapped = NULL; uint16_t wrapped_len = 0;
    if (pcomm_relay_wrap_forward(c->fwd, c->nhops, PCOMM_CIRC_ID, plain, plain_len, &wrapped, &wrapped_len) != 0) {
        return -1;
    }
    int rc = send_cell(c->fd, PCOMM_CELL_RELAY, wrapped, wrapped_len);
    free(wrapped);
    return rc;
}

static void *rx_loop(void *arg) {
    pcomm_circuit_t *c = (pcomm_circuit_t*)arg;
    while (c->running) {
        pcomm_msg_type_t t; uint8_t eph[32]; uint8_t *p=NULL; uint32_t pl=0;
        if (pcomm_recv_packet(c->fd, &t, eph, &p, &pl) != 0) {
            free(p);
            break;
        }
        if (t != PCOMM_MSG_CELL) { free(p); continue; }
        uint32_t cid; uint8_t cmd, flags; const uint8_t *cpl; uint16_t cpll;
        if (pcomm_cell_unpack(p, pl, &cid, &cmd, &flags, &cpl, &cpll) != 0 || cid != PCOMM_CIRC_ID) {
            free(p);
            continue;
        }
        (void)flags;
        if (cmd == PCOMM_CELL_RELAY) {
            uint8_t *plain = NULL; uint16_t plain_len = 0;
            if (pcomm_relay_unwrap_backward_all(c->bwd, c->nhops, PCOMM_CIRC_ID, cpl, cpll, &plain, &plain_len) == 0) {
                uint8_t rcmd; uint16_t sid; const uint8_t *body; uint16_t bl;
                if (pcomm_relay_plain_unpack(plain, plain_len, &rcmd, &sid, &body, &bl) == 0) {
                    pthread_mutex_lock(&c->mu);
                    stream_wait_t *w = c->streams[sid & 0xFF];
                    pthread_mutex_unlock(&c->mu);
                    if (w && w->id == sid) {
                        if (rcmd == PCOMM_RELAY_DATA) {
                            stream_deliver(w, body, bl, 0);
                        } else if (rcmd == PCOMM_RELAY_END) {
                            stream_deliver(w, NULL, 0, 1);
                        } else if (rcmd == PCOMM_RELAY_CONNECTED) {
                            // ignore for now
                        }
                    }
                }
                free(plain);
            }
        }
        free(p);
    }

    // fail all waiters
    pthread_mutex_lock(&c->mu);
    for (int i=0;i<256;i++) {
        stream_wait_t *w = c->streams[i];
        if (w) stream_deliver(w, NULL, 0, 1);
    }
    pthread_mutex_unlock(&c->mu);
    return NULL;
}

static int circuit_build(pcomm_circuit_t *c, const pcomm_peer_t *path, size_t path_len) {
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->mu, NULL);
    c->next_stream = 1;

    c->fd = net_connect_tcp(path[0].host, path[0].port);
    if (c->fd < 0) return -1;

    // hop1 CREATE
    uint8_t eph1_priv[32], eph1_pub[32];
    if (pcomm_random(eph1_priv, 32) != 0) return -1;
    // OpenSSL X25519 expects clamped; EVP does.
    // We'll use pcomm_x25519_derive with basepoint to get pub? Not available.
    // Quick hack: use OpenSSL directly via pcomm_x25519_derive is shared only.
    // Instead, generate keypair via OpenSSL in crypto.c in a helper. For now, derive pub by X25519(priv, basepoint).
    static const uint8_t basepoint[32] = {9};
    if (pcomm_x25519_derive(eph1_priv, basepoint, eph1_pub) != 0) return -1;

    if (send_cell(c->fd, PCOMM_CELL_CREATE, eph1_pub, 32) != 0) return -1;

    uint8_t rcmd; uint8_t *rpl=NULL; uint16_t rpll=0;
    if (recv_cell(c->fd, &rcmd, &rpl, &rpll) != 0 || rcmd != PCOMM_CELL_CREATED || rpll != 32) {
        free(rpl);
        return -1;
    }
    uint8_t shared1[32];
    if (pcomm_x25519_derive(eph1_priv, rpl, shared1) != 0) { free(rpl); return -1; }
    free(rpl);
    if (derive_hop_keys(shared1, c->fwd[0], c->bwd[0]) != 0) return -1;

    c->path[0] = path[0];
    c->nhops = 1;

    // extend further hops
    for (size_t hi=1; hi<path_len; hi++) {
        uint8_t eph_priv[32], eph_pub[32];
        if (pcomm_random(eph_priv, 32) != 0) return -1;
        if (pcomm_x25519_derive(eph_priv, basepoint, eph_pub) != 0) return -1;

        // body: hostlen(1) host port(2) eph_pub(32)
        uint8_t body[1+64+2+32];
        size_t hostlen = strlen(path[hi].host);
        if (hostlen == 0 || hostlen > 63) return -1;
        size_t bo = 0;
        body[bo++] = (uint8_t)hostlen;
        memcpy(body+bo, path[hi].host, hostlen); bo += hostlen;
        uint16_t p = htons(path[hi].port);
        memcpy(body+bo, &p, 2); bo += 2;
        memcpy(body+bo, eph_pub, 32); bo += 32;

        uint8_t *plain=NULL; uint16_t plain_len=0;
        if (pcomm_relay_plain_pack(PCOMM_RELAY_EXTEND, 0, body, (uint16_t)bo, &plain, &plain_len) != 0) return -1;

        pthread_mutex_lock(&c->mu);
        int rc = send_relay_plain_locked(c, plain, plain_len);
        pthread_mutex_unlock(&c->mu);
        free(plain);
        if (rc != 0) return -1;

        // Wait for EXTENDED on stream 0 (we'll treat it specially: receiver doesn't dispatch stream 0)
        // For prototype, do a blocking read here: receive one cell and decrypt fully.
        pcomm_msg_type_t t; uint8_t eph[32]; uint8_t *pp=NULL; uint32_t ppl=0;
        if (pcomm_recv_packet(c->fd, &t, eph, &pp, &ppl) != 0) { free(pp); return -1; }
        if (t != PCOMM_MSG_CELL) { free(pp); return -1; }
        uint32_t cid; uint8_t cmd, flags; const uint8_t *cpl; uint16_t cpll;
        if (pcomm_cell_unpack(pp, ppl, &cid, &cmd, &flags, &cpl, &cpll) != 0 || cid != PCOMM_CIRC_ID || cmd != PCOMM_CELL_RELAY) {
            free(pp);
            return -1;
        }
        (void)flags;
        uint8_t *ext_plain=NULL; uint16_t ext_plain_len=0;
        if (pcomm_relay_unwrap_backward_all(c->bwd, c->nhops, PCOMM_CIRC_ID, cpl, cpll, &ext_plain, &ext_plain_len) != 0) {
            free(pp);
            return -1;
        }
        free(pp);
        uint8_t rr; uint16_t sid; const uint8_t *bdy; uint16_t bl;
        if (pcomm_relay_plain_unpack(ext_plain, ext_plain_len, &rr, &sid, &bdy, &bl) != 0 || rr != PCOMM_RELAY_EXTENDED || bl != 32) {
            free(ext_plain);
            return -1;
        }
        uint8_t shared[32];
        if (pcomm_x25519_derive(eph_priv, bdy, shared) != 0) { free(ext_plain); return -1; }
        free(ext_plain);

        if (derive_hop_keys(shared, c->fwd[c->nhops], c->bwd[c->nhops]) != 0) return -1;
        c->path[c->nhops] = path[hi];
        c->nhops++;
    }

    c->running = 1;
    if (pthread_create(&c->rx_thread, NULL, rx_loop, c) != 0) return -1;

    return 0;
}

static void circuit_free(pcomm_circuit_t *c) {
    if (!c) return;
    c->running = 0;
    if (c->fd >= 0) close(c->fd);
    if (c->rx_thread) pthread_join(c->rx_thread, NULL);
    pthread_mutex_destroy(&c->mu);
    free(c);
}

static void *mgr_loop(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&g_mgr_mu);
        pcomm_circuit_t *cur = g_circ;
        pthread_mutex_unlock(&g_mgr_mu);

        if (!cur) {
            // Build a circuit
            pcomm_peer_t path[PCOMM_MAX_HOPS]; size_t path_len=0;
            if (db_pick_relays(g_db, g_me.user_id, path, &path_len) == 0) {
                // Ensure at least 1 hop
                pcomm_circuit_t *nc = (pcomm_circuit_t*)calloc(1, sizeof(pcomm_circuit_t));
                if (nc) {
                    if (circuit_build(nc, path, path_len) == 0) {
                        pthread_mutex_lock(&g_mgr_mu);
                        g_circ = nc;
                        pthread_mutex_unlock(&g_mgr_mu);
                        fprintf(stderr, "[circuit] built %zu-hop circuit via %s\n", path_len, path[0].user_id);
                    } else {
                        circuit_free(nc);
                    }
                }
            }
        } else {
            // keepalive padding every ~10s
            uint8_t z=0;
            send_cell(cur->fd, PCOMM_CELL_PADDING, &z, 1);
        }

        sleep(10);
    }
    return NULL;
}

int pcomm_circuits_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db) {
    if (!cfg || !me || !db) return -1;
    g_cfg = *cfg;
    g_me = *me;
    g_db = db;
    if (pthread_create(&g_mgr_th, NULL, mgr_loop, NULL) != 0) return -1;
    return 0;
}

pcomm_circuit_t *pcomm_circuit_get(void) {
    pthread_mutex_lock(&g_mgr_mu);
    pcomm_circuit_t *c = g_circ;
    pthread_mutex_unlock(&g_mgr_mu);
    return c;
}

static uint16_t alloc_stream_id(pcomm_circuit_t *c) {
    uint16_t sid = c->next_stream++;
    if (sid == 0) sid = c->next_stream++;
    return sid;
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

    uint8_t *inner = NULL; uint32_t inner_len = 0;
    if (pcomm_pack_packet(inner_type, NULL, inner_payload, inner_payload_len, &inner, &inner_len) != 0) return -1;

    pthread_mutex_lock(&c->mu);
    uint16_t sid = alloc_stream_id(c);

    stream_wait_t w;
    stream_wait_init(&w, sid);
    c->streams[sid & 0xFF] = &w;

    // BEGIN body: hostlen(1) host port(2) expect(1)
    uint8_t b[1+64+2+1];
    size_t hl = strlen(dest_host);
    if (hl == 0 || hl > 63) { c->streams[sid & 0xFF] = NULL; pthread_mutex_unlock(&c->mu); free(inner); return -1; }
    size_t bo = 0;
    b[bo++] = (uint8_t)hl;
    memcpy(b+bo, dest_host, hl); bo += hl;
    uint16_t np = htons(dest_port);
    memcpy(b+bo, &np, 2); bo += 2;
    b[bo++] = (uint8_t)(expect_resp ? 1 : 0);

    uint8_t *plain=NULL; uint16_t plain_len=0;
    if (pcomm_relay_plain_pack(PCOMM_RELAY_BEGIN, sid, b, (uint16_t)bo, &plain, &plain_len) != 0) {
        c->streams[sid & 0xFF] = NULL;
        pthread_mutex_unlock(&c->mu);
        free(inner);
        return -1;
    }
    int rc = send_relay_plain_locked(c, plain, plain_len);
    free(plain);
    if (rc != 0) {
        c->streams[sid & 0xFF] = NULL;
        pthread_mutex_unlock(&c->mu);
        free(inner);
        stream_wait_destroy(&w);
        return -1;
    }

    // DATA body: inner packet bytes
    if (pcomm_relay_plain_pack(PCOMM_RELAY_DATA, sid, inner, (uint16_t)inner_len, &plain, &plain_len) != 0) {
        c->streams[sid & 0xFF] = NULL;
        pthread_mutex_unlock(&c->mu);
        free(inner);
        stream_wait_destroy(&w);
        return -1;
    }
    rc = send_relay_plain_locked(c, plain, plain_len);
    free(plain);
    free(inner);

    // END
    pcomm_relay_plain_pack(PCOMM_RELAY_END, sid, NULL, 0, &plain, &plain_len);
    if (plain) {
        send_relay_plain_locked(c, plain, plain_len);
        free(plain);
    }

    pthread_mutex_unlock(&c->mu);

    if (!expect_resp) {
        pthread_mutex_lock(&c->mu);
        c->streams[sid & 0xFF] = NULL;
        pthread_mutex_unlock(&c->mu);
        stream_wait_destroy(&w);
        return 0;
    }

    // Wait
    pthread_mutex_lock(&w.mu);
    while (!w.done) pthread_cond_wait(&w.cv, &w.mu);
    pthread_mutex_unlock(&w.mu);

    pthread_mutex_lock(&c->mu);
    c->streams[sid & 0xFF] = NULL;
    pthread_mutex_unlock(&c->mu);

    if (w.err || !w.saw_end || w.len == 0) {
        stream_wait_destroy(&w);
        return -1;
    }

    pcomm_msg_type_t rt; uint8_t reph[32]; uint8_t *rp=NULL; uint32_t rpl=0;
    if (pcomm_unpack_packet(w.buf, w.len, &rt, reph, &rp, &rpl) != 0) {
        stream_wait_destroy(&w);
        return -1;
    }

    if (resp_type_out) *resp_type_out = rt;
    if (resp_payload_out) *resp_payload_out = rp; else free(rp);
    if (resp_payload_len_out) *resp_payload_len_out = rpl;

    stream_wait_destroy(&w);
    return 0;
}
