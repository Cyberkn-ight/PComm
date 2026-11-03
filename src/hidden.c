#define _GNU_SOURCE
#include "hidden.h"
#include "net.h"
#include "proto.h"
#include "onion.h"
#include "crypto.h"
#include "identity.h"
#include "msg.h"
#include "dht.h"
#include "circuit.h"
#include "receive.h"
#include "ratchet.h"
#include "mailbox_limits.h"
#include "lifecycle.h"
#include "descriptor.h"
#include "directory.h"

#include <pthread.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdatomic.h>

static void put_u16(uint8_t *p, uint16_t v){ uint16_t n=htons(v); memcpy(p,&n,2); }
static void put_u32(uint8_t *p, uint32_t v){ uint32_t n=htonl(v); memcpy(p,&n,4); }
static uint16_t get_u16(const uint8_t *p){ uint16_t n; memcpy(&n,p,2); return ntohs(n); }
static uint32_t get_u32(const uint8_t *p){ uint32_t n; memcpy(&n,p,4); return ntohl(n); }

static uint32_t epoch_now(void) {
    time_t t = time(NULL);
    return (uint32_t)(t / (6 * 3600));
}

static void sha256_key(const char *tag, const char *user_id, uint32_t epoch, uint8_t out[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, tag, strlen(tag));
    uint8_t z = 0;
    SHA256_Update(&ctx, &z, 1);
    SHA256_Update(&ctx, user_id, strlen(user_id));
    SHA256_Update(&ctx, &z, 1);
    uint32_t e = htonl(epoch);
    SHA256_Update(&ctx, &e, sizeof(e));
    SHA256_Final(out, &ctx);
}

typedef struct rdv_wait rdv_wait_t;
typedef struct rdv_sess rdv_sess_t;

typedef struct {
    pcomm_peer_t intro;
    pcomm_circuit_t *circ;
} intro_circ_t;

struct rdv_wait {
    uint8_t cookie[20];
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int done;
    int ok;
    rdv_wait_t *next;
};

struct rdv_sess {
    char peer_id[96];
    uint8_t cookie[20];
    pcomm_circuit_t *circ;
    time_t last_used;
    int established;
    rdv_sess_t *next;
};

typedef struct {
    pcomm_config_t cfg;
    pcomm_identity_t me;
    pcomm_db_t *db;
    pcomm_peer_t intros[3];
    size_t intro_count;
    intro_circ_t intro_circs[3];
    pthread_mutex_t rdv_mu;
    rdv_wait_t *waits;
    rdv_sess_t *sessions;

    pthread_mutex_t lock;
    pthread_cond_t wake_cv;
    pthread_t workers[4];
    unsigned worker_count;
    atomic_int stopping;
    size_t users;
} hidden_state_t;

static int rdv_try_send(hidden_state_t *st, const char *to_user_id,
                        const uint8_t *sealed, size_t sealed_len);

static hidden_state_t *g_hidden = NULL;
static pthread_mutex_t g_hidden_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_hidden_cv = PTHREAD_COND_INITIALIZER;

static int hidden_stopping(hidden_state_t *st) {
    return atomic_load(&st->stopping) || pcomm_shutdown_requested();
}

static int hidden_wait(hidden_state_t *st, uint32_t milliseconds) {
    struct timespec deadline;
    if (timespec_get(&deadline, TIME_UTC) != TIME_UTC) return -1;
    deadline.tv_sec += milliseconds / 1000;
    deadline.tv_nsec += (long)(milliseconds % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&st->lock);
    int rc = 0;
    while (!hidden_stopping(st) && rc == 0) {
        rc = pthread_cond_timedwait(&st->wake_cv, &st->lock, &deadline);
    }
    int stopped = hidden_stopping(st);
    pthread_mutex_unlock(&st->lock);
    return stopped ? 1 : rc == ETIMEDOUT ? 0 : -1;
}

static hidden_state_t *hidden_acquire(void) {
    pthread_mutex_lock(&g_hidden_mu);
    hidden_state_t *st = g_hidden;
    if (st && !hidden_stopping(st)) st->users++;
    else st = NULL;
    pthread_mutex_unlock(&g_hidden_mu);
    return st;
}

static void hidden_release(hidden_state_t *st) {
    if (!st) return;
    pthread_mutex_lock(&g_hidden_mu);
    st->users--;
    pthread_cond_broadcast(&g_hidden_cv);
    pthread_mutex_unlock(&g_hidden_mu);
}

static int rdv_wait_init(rdv_wait_t *w, const uint8_t cookie[20]) {
    memset(w, 0, sizeof(*w));
    memcpy(w->cookie, cookie, 20);
    if (pthread_mutex_init(&w->mu, NULL) != 0) return -1;
    if (pthread_cond_init(&w->cv, NULL) != 0) {
        pthread_mutex_destroy(&w->mu);
        return -1;
    }
    return 0;
}

static void rdv_wait_destroy(rdv_wait_t *w) {
    pthread_mutex_destroy(&w->mu);
    pthread_cond_destroy(&w->cv);
}

static void rdv_signal(hidden_state_t *st, const uint8_t cookie[20], int ok) {
    pthread_mutex_lock(&st->rdv_mu);
    for (rdv_wait_t *w = st->waits; w; w = w->next) {
        if (memcmp(w->cookie, cookie, 20) == 0) {
            pthread_mutex_lock(&w->mu);
            w->ok = ok;
            w->done = 1;
            pthread_cond_broadcast(&w->cv);
            pthread_mutex_unlock(&w->mu);
            break;
        }
    }
    pthread_mutex_unlock(&st->rdv_mu);
}

static void rdv_wait_add(hidden_state_t *st, rdv_wait_t *w) {
    pthread_mutex_lock(&st->rdv_mu);
    w->next = st->waits;
    st->waits = w;
    if (hidden_stopping(st)) {
        pthread_mutex_lock(&w->mu);
        w->done = 1;
        w->ok = 0;
        pthread_cond_broadcast(&w->cv);
        pthread_mutex_unlock(&w->mu);
    }
    pthread_mutex_unlock(&st->rdv_mu);
}

static void rdv_wait_remove(hidden_state_t *st, rdv_wait_t *w) {
    pthread_mutex_lock(&st->rdv_mu);
    rdv_wait_t **pp = &st->waits;
    while (*pp) {
        if (*pp == w) {
            *pp = w->next;
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&st->rdv_mu);
}

static pcomm_circuit_t *rdv_find_session(hidden_state_t *st, const char *peer_id) {
    time_t now = time(NULL);
    pcomm_circuit_t *best = NULL;
    pthread_mutex_lock(&st->rdv_mu);
    for (rdv_sess_t *s = st->sessions; s; s = s->next) {
        if (peer_id && peer_id[0] && strcmp(s->peer_id, peer_id) == 0) {
            if (!hidden_stopping(st) && s->established && (now - s->last_used) < 900 &&
                s->circ && pcomm_circuit_retain(s->circ) == 0) {
                best = s->circ;
            }
            break;
        }
    }
    pthread_mutex_unlock(&st->rdv_mu);
    return best;
}

static int rdv_add_or_update_session(hidden_state_t *st, const char *peer_id, const uint8_t cookie[20], pcomm_circuit_t *circ) {
    pthread_mutex_lock(&st->rdv_mu);
    if (hidden_stopping(st)) {
        pthread_mutex_unlock(&st->rdv_mu);
        return -1;
    }
    rdv_sess_t *s = st->sessions;
    while (s) {
        if (strcmp(s->peer_id, peer_id) == 0) {
            memcpy(s->cookie, cookie, 20);
            pcomm_circuit_t *old = s->circ != circ ? s->circ : NULL;
            s->circ = circ;
            s->last_used = time(NULL);
            s->established = 0;
            pthread_mutex_unlock(&st->rdv_mu);
            pcomm_circuit_close(old);
            return 0;
        }
        s = s->next;
    }
    rdv_sess_t *ns = (rdv_sess_t*)calloc(1, sizeof(rdv_sess_t));
    if (!ns) { pthread_mutex_unlock(&st->rdv_mu); return -1; }
    snprintf(ns->peer_id, sizeof(ns->peer_id), "%s", peer_id);
    memcpy(ns->cookie, cookie, 20);
    ns->circ = circ;
    ns->last_used = time(NULL);
    ns->established = 0;
    ns->next = st->sessions;
    st->sessions = ns;
    pthread_mutex_unlock(&st->rdv_mu);
    return 0;
}

static void rdv_mark_established(hidden_state_t *st, const uint8_t cookie[20]) {
    pthread_mutex_lock(&st->rdv_mu);
    for (rdv_sess_t *s = st->sessions; s; s = s->next) {
        if (memcmp(s->cookie, cookie, 20) == 0) {
            s->established = 1;
            s->last_used = time(NULL);
        }
    }
    pthread_mutex_unlock(&st->rdv_mu);
}

static void *session_gc_thread(void *arg) {
    hidden_state_t *st = (hidden_state_t*)arg;
    const int ttl = 20 * 60;
    while (!hidden_stopping(st)) {
        time_t now = time(NULL);
        rdv_sess_t *expired = NULL;
        pthread_mutex_lock(&st->rdv_mu);
        rdv_sess_t **pp = &st->sessions;
        while (*pp) {
            rdv_sess_t *s = *pp;
            if ((now - s->last_used) > ttl) {
                *pp = s->next;
                s->next = expired;
                expired = s;
                continue;
            }
            pp = &(*pp)->next;
        }
        pthread_mutex_unlock(&st->rdv_mu);
        while (expired) {
            rdv_sess_t *next = expired->next;
            pcomm_circuit_close(expired->circ);
            free(expired);
            expired = next;
        }
        if (hidden_wait(st, 10000) != 0) break;
    }
    return NULL;
}

static void hidden_circuit_event(void *arg, pcomm_circuit_t *c,
                                 uint8_t relay_cmd, uint16_t stream_id,
                                 const uint8_t *body, uint16_t body_len);
static int load_onion_relays(pcomm_db_t *db, const char *ex1, const char *ex2, const char *ex3, pcomm_peer_t *out, size_t out_cap, size_t *out_len) {
    *out_len = 0;
    const char *sql =
        "SELECT user_id, host, port, pubkey FROM contacts "
        "WHERE is_relay=1 AND host!='' AND port>0 "
        "AND user_id != ? AND user_id != ? AND user_id != ? "
        "ORDER BY RANDOM() LIMIT ?;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, ex1 ? ex1 : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ex2 ? ex2 : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ex3 ? ex3 : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, (int)out_cap);

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
        if (*out_len >= out_cap) break;
    }
    sqlite3_finalize(st);
    return 0;
}

static int pick_random_relay(pcomm_db_t *db, const char *ex1, const char *ex2, const char *ex3, pcomm_peer_t *out) {
    if (!db || !out) return -1;
    memset(out, 0, sizeof(*out));
    const char *sql =
        "SELECT user_id, host, port, pubkey FROM contacts "
        "WHERE is_relay=1 AND host!='' AND port>0 "
        "AND user_id != ? AND user_id != ? AND user_id != ? "
        "ORDER BY RANDOM() LIMIT 1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, ex1 ? ex1 : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ex2 ? ex2 : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ex3 ? ex3 : "", -1, SQLITE_TRANSIENT);

    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *uid = (const char*)sqlite3_column_text(st, 0);
        const char *host = (const char*)sqlite3_column_text(st, 1);
        int port = sqlite3_column_int(st, 2);
        const void *pk = sqlite3_column_blob(st, 3);
        int pklen = sqlite3_column_bytes(st, 3);
        if (uid && host && pklen == 32 && port > 0 && port <= 65535) {
            snprintf(out->user_id, sizeof(out->user_id), "%s", uid);
            snprintf(out->host, sizeof(out->host), "%s", host);
            out->port = (uint16_t)port;
            memcpy(out->pubkey, pk, 32);
            rc = 0;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static int list_all_relays(pcomm_db_t *db, pcomm_peer_t **out, size_t *out_len) {
    *out = NULL; *out_len = 0;
    const char *sql = "SELECT user_id, host, port, pubkey FROM contacts WHERE is_relay=1 AND host!='' AND port>0 LIMIT 500;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;

    size_t cap = 64;
    pcomm_peer_t *arr = (pcomm_peer_t*)calloc(cap, sizeof(pcomm_peer_t));
    if (!arr) { sqlite3_finalize(st); return -1; }

    size_t n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *uid = (const char*)sqlite3_column_text(st, 0);
        const char *host = (const char*)sqlite3_column_text(st, 1);
        int port = sqlite3_column_int(st, 2);
        const void *pk = sqlite3_column_blob(st, 3);
        int pklen = sqlite3_column_bytes(st, 3);
        if (!uid || !host || pklen != 32 || port <= 0 || port > 65535) continue;
        if (n >= cap) {
            cap *= 2;
            pcomm_peer_t *tmp = (pcomm_peer_t*)realloc(arr, cap * sizeof(pcomm_peer_t));
            if (!tmp) break;
            arr = tmp;
        }
        memset(&arr[n], 0, sizeof(pcomm_peer_t));
        snprintf(arr[n].user_id, sizeof(arr[n].user_id), "%s", uid);
        snprintf(arr[n].host, sizeof(arr[n].host), "%s", host);
        arr[n].port = (uint16_t)port;
        memcpy(arr[n].pubkey, pk, 32);
        n++;
    }
    sqlite3_finalize(st);

    *out = arr;
    *out_len = n;
    return (n > 0) ? 0 : -1;
}

typedef struct {
    pcomm_peer_t p;
    uint8_t h[32];
} peer_hash_t;

static int cmp_peerhash(const void *a, const void *b) {
    const peer_hash_t *pa = (const peer_hash_t*)a;
    const peer_hash_t *pb = (const peer_hash_t*)b;
    return memcmp(pa->h, pb->h, 32);
}

static int select_hsdirs(pcomm_db_t *db, const char *target_user_id, uint32_t epoch, pcomm_peer_t out[3], size_t *out_len) {
    *out_len = 0;

    pcomm_peer_t *relays = NULL;
    size_t nrel = 0;
    if (list_all_relays(db, &relays, &nrel) != 0 || nrel == 0) {
        free(relays);
        return -1;
    }

    peer_hash_t *ph = (peer_hash_t*)calloc(nrel, sizeof(peer_hash_t));
    if (!ph) { free(relays); return -1; }
    for (size_t i = 0; i < nrel; i++) {
        ph[i].p = relays[i];
        SHA256((const unsigned char*)relays[i].user_id, strlen(relays[i].user_id), ph[i].h);
    }
    qsort(ph, nrel, sizeof(peer_hash_t), cmp_peerhash);

    uint8_t seed[32];
    sha256_key("pcomm-hsdir", target_user_id, epoch, seed);
    uint64_t idx = 0;
    for (int i = 0; i < 8; i++) idx = (idx << 8) | seed[i];
    idx = (nrel > 0) ? (idx % nrel) : 0;

    size_t want = (nrel >= 3) ? 3 : nrel;
    for (size_t k = 0; k < want; k++) {
        out[k] = ph[(idx + k) % nrel].p;
        (*out_len)++;
    }

    free(ph);
    free(relays);
    return (*out_len > 0) ? 0 : -1;
}

static int onion_send_ctrl(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                           const pcomm_peer_t *dest,
                           const uint8_t *ctrl_payload, uint32_t ctrl_len,
                           int roundtrip,
                           uint8_t **resp_payload, uint32_t *resp_len) {
    if (resp_payload) *resp_payload = NULL;
    if (resp_len) *resp_len = 0;
    if (!db || !cfg || !me || !dest || !dest->host[0] || !dest->port ||
        pcomm_shutdown_requested()) return -1;
    pcomm_circuit_t *c = pcomm_circuit_get();
    if (c) {
        pcomm_msg_type_t rt = 0; uint8_t *rp = NULL; uint32_t rpl = 0;
        int rc = pcomm_circuit_rpc(c, dest->host, dest->port, PCOMM_MSG_CTRL,
                                   ctrl_payload, ctrl_len, roundtrip,
                                   &rt, &rp, &rpl);
        pcomm_circuit_release(c);
        if (rc == 0) {
            if (roundtrip) {
                if (rt != PCOMM_MSG_CTRL) { free(rp); return -1; }
                if (resp_payload) *resp_payload = rp; else free(rp);
                if (resp_len) *resp_len = rpl;
            }
            return 0;
        }
        free(rp);
    }
    if (pcomm_shutdown_requested()) return -1;

    pcomm_peer_t path[3];
    size_t path_len = 0;
    load_onion_relays(db, me->user_id, dest->user_id, NULL, path, 3, &path_len);

    if (path_len == 0) {
        int fd = net_connect_tcp(dest->host, dest->port);
        if (fd < 0) return -1;
        int rc = pcomm_send_packet(fd, PCOMM_MSG_CTRL, NULL, ctrl_payload, ctrl_len);
        if (rc != 0) { net_close(fd); return -1; }
        if (roundtrip) {
            pcomm_msg_type_t rtype; uint8_t eph[32]; uint8_t *rp=NULL; uint32_t rpl=0;
            if (pcomm_recv_packet(fd, &rtype, eph, &rp, &rpl) == 0 && rtype == PCOMM_MSG_CTRL) {
                if (resp_payload) *resp_payload = rp; else free(rp);
                if (resp_len) *resp_len = rpl;
                net_close(fd);
                return 0;
            }
            free(rp);
            net_close(fd);
            return -1;
        }
        net_close(fd);
        return 0;
    }

    uint8_t eph_pub[32];
    uint8_t *onion = NULL; uint32_t onion_len = 0;
    if (pcomm_onion_build_v1(path, path_len, dest->host, dest->port, PCOMM_MSG_CTRL,
                             ctrl_payload, ctrl_len, roundtrip, eph_pub, &onion, &onion_len) != 0) {
        free(onion);
        return -1;
    }

    int fd = net_connect_tcp(path[0].host, path[0].port);
    if (fd < 0) { free(onion); return -1; }
    int rc = pcomm_send_packet(fd, PCOMM_MSG_ONION, eph_pub, onion, onion_len);
    free(onion);
    if (rc != 0) { net_close(fd); return -1; }

    if (!roundtrip) {
        net_close(fd);
        return 0;
    }

    pcomm_msg_type_t rtype; uint8_t eph[32]; uint8_t *rp=NULL; uint32_t rpl=0;
    if (pcomm_recv_packet(fd, &rtype, eph, &rp, &rpl) == 0 && rtype == PCOMM_MSG_CTRL) {
        if (resp_payload) *resp_payload = rp; else free(rp);
        if (resp_len) *resp_len = rpl;
        net_close(fd);
        return 0;
    }
    free(rp);
    net_close(fd);
    return -1;
}



static int ctrl_build_desc_put(const uint8_t infohash[20], const uint8_t dkey[32], uint32_t expires_unix, const uint8_t *blob, uint32_t blob_len,
                              uint8_t **out, uint32_t *out_len) {
    uint32_t len = 1 + 20 + 32 + 4 + 4 + blob_len;
    uint8_t *b = (uint8_t*)malloc(len);
    if (!b) return -1;
    uint32_t off = 0;
    b[off++] = (uint8_t)PCOMM_CTRL_DESC_PUT;
    memcpy(b + off, infohash, 20); off += 20;
    memcpy(b + off, dkey, 32); off += 32;
    put_u32(b + off, expires_unix); off += 4;
    put_u32(b + off, blob_len); off += 4;
    memcpy(b + off, blob, blob_len); off += blob_len;
    if (off != len) { free(b); return -1; }
    *out = b; *out_len = len;
    return 0;
}

static int ctrl_build_mb_put(const uint8_t infohash[20], const uint8_t mkey[32], const uint8_t *blob, uint32_t blob_len, uint8_t **out, uint32_t *out_len) {
    if (!infohash || !mkey || !blob || !out || !out_len ||
        blob_len == 0 || blob_len > PCOMM_MAILBOX_MAX_BLOB_LEN) return -1;
    uint32_t len = 1 + 20 + 32 + 4 + blob_len;
    uint8_t *b = (uint8_t*)malloc(len);
    if (!b) return -1;
    uint32_t off = 0;
    b[off++] = (uint8_t)PCOMM_CTRL_MB_PUT;
    memcpy(b + off, infohash, 20); off += 20;
    memcpy(b + off, mkey, 32); off += 32;
    put_u32(b + off, blob_len); off += 4;
    memcpy(b + off, blob, blob_len); off += blob_len;
    if (off != len) { free(b); return -1; }
    *out = b; *out_len = len;
    return 0;
}

static int ctrl_build_mb_get(const uint8_t infohash[20], const uint8_t mkey[32], uint8_t **out, uint32_t *out_len) {
    uint32_t len = 1 + 20 + 32;
    uint8_t *b = (uint8_t*)malloc(len);
    if (!b) return -1;
    uint32_t off = 0;
    b[off++] = (uint8_t)PCOMM_CTRL_MB_GET;
    memcpy(b + off, infohash, 20); off += 20;
    memcpy(b + off, mkey, 32); off += 32;
    *out = b; *out_len = len;
    return 0;
}

static int ctrl_build_noop(uint8_t **out, uint32_t *out_len) {
    uint8_t *b = (uint8_t*)malloc(1);
    if (!b) return -1;
    b[0] = (uint8_t)PCOMM_CTRL_NOOP;
    *out = b; *out_len = 1;
    return 0;
}



static int fetch_descriptor(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                            const char *target_id, uint32_t epoch, pcomm_peer_t *intros, size_t intros_cap, size_t *intros_len) {
    if (!db || !cfg || !me || !target_id || !intros || !intros_len || !intros_cap) return -1;
    *intros_len = 0;
    uint8_t owner[32], dkey[32], infohash[20];
    char canonical[96];
    if (pcomm_pubkey_from_user_id(target_id, owner) ||
        pcomm_user_id_from_pubkey(owner, canonical) ||
        pcomm_descriptor_keys(owner, epoch, dkey, infohash)) return -1;

    pcomm_peer_t candidates[PCOMM_DESCRIPTOR_MAX_SOURCES] = {0};
    size_t count = 0;
    char hosts[8][64]; uint16_t ports[8]; size_t hn = 0;
    if (pcomm_dht_get_peers_hosts(infohash, hosts, ports, 8, &hn) == 0) {
        for (size_t i = 0; i < hn && count < PCOMM_DESCRIPTOR_MAX_SOURCES; i++) {
            memcpy(candidates[count].host, hosts[i], sizeof(candidates[count].host));
            candidates[count++].port = ports[i];
        }
    }
    pcomm_peer_t directories[3]; size_t directory_count = 0;
    if (select_hsdirs(db, canonical, epoch, directories, &directory_count) == 0) {
        for (size_t i = 0; i < directory_count && count < PCOMM_DESCRIPTOR_MAX_SOURCES; i++) {
            size_t j;
            for (j = 0; j < count; j++) {
                if (candidates[j].port == directories[i].port &&
                    strcmp(candidates[j].host, directories[i].host) == 0) break;
            }
            if (j == count) candidates[count++] = directories[i];
        }
    }

    uint32_t addresses[PCOMM_DESCRIPTOR_MAX_SOURCES]; size_t address_count = 0;
    for (size_t i = 0; i < count; i++) {
        struct in_addr address;
        if (inet_pton(AF_INET, candidates[i].host, &address) != 1) continue;
        size_t j;
        for (j = 0; j < address_count; j++) if (addresses[j] == address.s_addr) break;
        if (j == address_count) addresses[address_count++] = address.s_addr;
    }
    if (address_count < 2) return -1;

    pcomm_descriptor_quorum_t quorum = {0};
    for (size_t i = 0; i < count && !pcomm_shutdown_requested(); i++) {
        struct in_addr address;
        if (inet_pton(AF_INET, candidates[i].host, &address) != 1) continue;
        pcomm_peer_t provider;
        if (pcomm_dht_resolve_relay(candidates[i].host, candidates[i].port, &provider) != 0) continue;
        uint8_t nonce[32], *request = NULL, *response = NULL, *blob = NULL;
        uint32_t request_len = 0, response_len = 0, blob_len = 0;
        if (pcomm_random(nonce, sizeof(nonce)) ||
            pcomm_directory_request(infohash, dkey, nonce, &request, &request_len)) continue;
        int rc = onion_send_ctrl(db, cfg, me, &provider, request, request_len, 1, &response, &response_len);
        free(request);
        if (rc == 0 && response &&
            pcomm_directory_parse_response(response, response_len, provider.pubkey, nonce, dkey, &blob, &blob_len) == 0) {
            pcomm_descriptor_t descriptor;
            if (pcomm_descriptor_parse(blob, blob_len, canonical, epoch, (uint32_t)time(NULL), &descriptor) == 0) {
                (void)pcomm_descriptor_vote(&quorum, provider.host, provider.pubkey, &descriptor);
            }
        }
        free(blob);
        free(response);
    }
    pcomm_descriptor_t accepted;
    time_t checked_at = time(NULL);
    if (pcomm_shutdown_requested() || pcomm_descriptor_consensus(&quorum, &accepted) != 0 ||
        checked_at < 0 || (uint64_t)checked_at > UINT32_MAX ||
        accepted.expires <= (uint32_t)checked_at || (uint64_t)accepted.issued > (uint64_t)checked_at+120 ||
        accepted.intro_count > intros_cap ||
        pcomm_db_descriptor_trust(db, accepted.owner, accepted.epoch, accepted.issued, accepted.digest) != 0) return -1;
    memcpy(intros, accepted.intros, accepted.intro_count*sizeof(*intros));
    *intros_len = accepted.intro_count;
    return 0;
}

static int descriptor_stored_at(hidden_state_t *st, const pcomm_peer_t *provider,
                                  const uint8_t infohash[20], const uint8_t dkey[32],
                                  const uint8_t *expected, uint32_t expected_len) {
    uint8_t nonce[32], *request = NULL, *response = NULL, *stored = NULL;
    uint32_t request_len = 0, response_len = 0, stored_len = 0;
    if (hidden_stopping(st) || pcomm_random(nonce, sizeof(nonce)) ||
        pcomm_directory_request(infohash, dkey, nonce, &request, &request_len)) return -1;
    int rc = onion_send_ctrl(st->db, &st->cfg, &st->me, provider,
                              request, request_len, 1, &response, &response_len);
    free(request);
    if (rc == 0) rc = pcomm_directory_parse_response(response, response_len, provider->pubkey,
                                                     nonce, dkey, &stored, &stored_len);
    if (rc == 0 && (stored_len != expected_len || CRYPTO_memcmp(stored, expected, expected_len))) rc = -1;
    free(stored);
    free(response);
    return rc == 0 ? 0 : -1;
}

static int publish_descriptor(hidden_state_t *st) {
    if (hidden_stopping(st)) return -1;
    time_t clock = time(NULL);
    if (clock < 0 || (uint64_t)clock > UINT32_MAX-PCOMM_DESCRIPTOR_MAX_TTL) return -1;
    uint32_t issued = (uint32_t)clock;
    uint32_t ep = issued/PCOMM_DESCRIPTOR_EPOCH_SECONDS;
    uint32_t expires = issued+PCOMM_DESCRIPTOR_MAX_TTL;
    pcomm_peer_t rel[3]; size_t rel_n = 0;
    if (load_onion_relays(st->db, st->me.user_id, NULL, NULL, rel, 3, &rel_n) != 0 || !rel_n) return -1;

    pthread_mutex_lock(&st->lock);
    st->intro_count = rel_n;
    for (size_t i = 0; i < rel_n; i++) st->intros[i] = rel[i];
    pthread_mutex_unlock(&st->lock);

    uint8_t *blob = NULL, *put = NULL;
    uint32_t blob_len = 0, put_len = 0;
    uint8_t dkey[32], infohash[20];
    pcomm_descriptor_t published;
    if (pcomm_descriptor_build(&st->me, ep, issued, expires, rel, rel_n, &blob, &blob_len) ||
        pcomm_descriptor_parse(blob, blob_len, st->me.user_id, ep, issued, &published) ||
        pcomm_descriptor_keys(st->me.pubkey, ep, dkey, infohash) ||
        ctrl_build_desc_put(infohash, dkey, expires, blob, blob_len, &put, &put_len)) {
        free(blob);
        return -1;
    }
    pcomm_peer_t destinations[6]; size_t count = rel_n;
    memcpy(destinations, rel, rel_n*sizeof(*rel));
    pcomm_peer_t directories[3]; size_t directory_count = 0;
    if (select_hsdirs(st->db, st->me.user_id, ep, directories, &directory_count) == 0) {
        for (size_t i = 0; i < directory_count; i++) {
            size_t j;
            for (j = 0; j < count; j++) {
                if (destinations[j].port == directories[i].port &&
                    strcmp(destinations[j].host, directories[i].host) == 0) break;
            }
            if (j == count) destinations[count++] = directories[i];
        }
    }
    uint8_t submitted[6] = {0};
    for (size_t i = 0; i < count && !hidden_stopping(st); i++) {
        if (onion_send_ctrl(st->db, &st->cfg, &st->me, &destinations[i], put, put_len, 0, NULL, NULL) == 0) submitted[i] = 1;
    }
    pcomm_descriptor_quorum_t confirmations = {0};
    for (size_t i = 0; i < count && !hidden_stopping(st); i++) {
        if (submitted[i] && descriptor_stored_at(st, &destinations[i], infohash, dkey, blob, blob_len) == 0) {
            (void)pcomm_descriptor_vote(&confirmations, destinations[i].host, destinations[i].pubkey, &published);
        }
    }
    pcomm_descriptor_t confirmed;
    int replicated = pcomm_descriptor_consensus(&confirmations, &confirmed) == 0;
    free(put);
    free(blob);
    return replicated ? 0 : -1;
}

static int ensure_intro_circuits(hidden_state_t *st) {
    if (!st || hidden_stopping(st)) return -1;

    pthread_mutex_lock(&st->lock);
    size_t n = st->intro_count;
    pcomm_peer_t intros[3];
    for (size_t i = 0; i < n && i < 3; i++) intros[i] = st->intros[i];
    pthread_mutex_unlock(&st->lock);

    for (size_t i = 0; i < n && i < 3 && !hidden_stopping(st); i++) {
        intro_circ_t *ic = &st->intro_circs[i];
        int need_new = 1;
        if (ic->circ && strcmp(ic->intro.host, intros[i].host) == 0 && ic->intro.port == intros[i].port) {
            need_new = 0;
        } else {
            if (ic->circ) {
                pcomm_circuit_close(ic->circ);
                ic->circ = NULL;
            }
        }

        ic->intro = intros[i];

        if (need_new) {
            ic->circ = pcomm_circuit_create_to_exit(&st->cfg, &st->me, st->db, ic->intro.host, ic->intro.port, st->me.user_id);
            if (!ic->circ) continue;
            if (pcomm_circuit_set_event_cb(ic->circ, hidden_circuit_event, st) != 0) {
                pcomm_circuit_close(ic->circ);
                ic->circ = NULL;
                continue;
            }
        }

        uint8_t body[1 + 96];
        size_t sidlen = strlen(st->me.user_id);
        if (sidlen > 95) sidlen = 95;
        body[0] = (uint8_t)sidlen;
        memcpy(body + 1, st->me.user_id, sidlen);

        pcomm_circuit_send_relay(ic->circ, PCOMM_RELAY_ESTABLISH_INTRO, 0, body, (uint16_t)(1 + sidlen));
    }

    for (size_t j = n; j < 3; j++) {
        if (st->intro_circs[j].circ) {
            pcomm_circuit_close(st->intro_circs[j].circ);
            st->intro_circs[j].circ = NULL;
            memset(&st->intro_circs[j].intro, 0, sizeof(st->intro_circs[j].intro));
        }
    }

    return 0;
}

static int handle_introduce2(hidden_state_t *st, const uint8_t *body, uint16_t bl) {
    if (!st || !body || hidden_stopping(st)) return -1;
    if (bl < 1 + 20 + 1 + 2) return -1;
    size_t off = 0;
    uint8_t cl = body[off++];
    if (cl == 0 || cl > 95 || bl < off + cl + 20 + 1 + 2) return -1;
    char client_id[96];
    memcpy(client_id, body + off, cl); client_id[cl] = '\0';
    off += cl;

    uint8_t cookie[20];
    memcpy(cookie, body + off, 20); off += 20;

    uint8_t hl = body[off++];
    if (hl == 0 || hl > 63 || bl < off + hl + 2) return -1;
    char rphost[64];
    memcpy(rphost, body + off, hl); rphost[hl] = '\0';
    off += hl;
    uint16_t rpport = get_u16(body + off); off += 2;
    pcomm_circuit_t *rc = pcomm_circuit_create_to_exit(&st->cfg, &st->me, st->db, rphost, rpport, st->me.user_id);
    if (!rc) return -1;
    if (pcomm_circuit_set_event_cb(rc, hidden_circuit_event, st) != 0 ||
        pcomm_circuit_retain(rc) != 0) {
        pcomm_circuit_close(rc);
        return -1;
    }
    if (rdv_add_or_update_session(st, client_id, cookie, rc) != 0) {
        pcomm_circuit_release(rc);
        pcomm_circuit_close(rc);
        return -1;
    }
    int result = pcomm_circuit_send_relay(rc, PCOMM_RELAY_RENDEZVOUS1, 0, cookie, 20);
    pcomm_circuit_release(rc);
    return result;
}

static int parse_mb_resp_items(hidden_state_t *st, const uint8_t *payload, uint32_t payload_len) {
    if (!payload || payload_len < 1 + 2) return -1;
    uint32_t off = 0;
    if (payload[off++] != (uint8_t)PCOMM_CTRL_MB_RESP) return -1;
    if (payload_len < off + 2) return -1;
    uint16_t count = get_u16(payload + off); off += 2;

    for (uint16_t i = 0; i < count && !hidden_stopping(st); i++) {
        if (payload_len - off < 8 + 4 + 4) break;
        off += 8;
        uint32_t ts = get_u32(payload + off); off += 4;
        uint32_t bl = get_u32(payload + off); off += 4;
        if (bl > payload_len - off) break;
        const uint8_t *sealed = payload + off;
        off += bl;

        (void)pcomm_receive_sealed(st->db, &st->me, sealed, bl, ts);
    }

    return 0;
}

static int poll_mailbox_from_peer(hidden_state_t *st, const pcomm_peer_t *peer, const uint8_t infohash[20], const uint8_t mkey[32]) {
    if (hidden_stopping(st)) return -1;
    uint8_t *req = NULL; uint32_t req_len = 0;
    if (ctrl_build_mb_get(infohash, mkey, &req, &req_len) != 0) return -1;

    uint8_t *resp = NULL; uint32_t resp_len = 0;
    int rc = onion_send_ctrl(st->db, &st->cfg, &st->me, peer, req, req_len, 1, &resp, &resp_len);
    free(req);
    if (rc != 0 || !resp) { free(resp); return -1; }

    parse_mb_resp_items(st, resp, resp_len);
    free(resp);
    return 0;
}

static void poll_local_mailbox(hidden_state_t *st, const uint8_t mkey[32]) {
    uint8_t *body = NULL; uint32_t body_len = 0;
    if (hidden_stopping(st) || pcomm_db_mailbox_get_and_delete(st->db, mkey, (int64_t)time(NULL), &body, &body_len)) return;
    uint8_t *response = malloc((size_t)body_len+1);
    if (response) {
        response[0] = PCOMM_CTRL_MB_RESP;
        memcpy(response+1, body, body_len);
        (void)parse_mb_resp_items(st, response, body_len+1);
        free(response);
    }
    free(body);
}

static void poll_unique_mailbox(hidden_state_t *st, const pcomm_peer_t *peer,
                                  pcomm_peer_t seen[17], size_t *seen_count,
                                  const uint8_t infohash[20], const uint8_t current[32], const uint8_t previous[32]) {
    if (hidden_stopping(st) || *seen_count >= 17 || !strcmp(peer->user_id, st->me.user_id)) return;
    for (size_t i = 0; i < *seen_count; i++) {
        if (seen[i].port == peer->port && !strcmp(seen[i].host, peer->host)) return;
    }
    seen[(*seen_count)++] = *peer;
    (void)poll_mailbox_from_peer(st, peer, infohash, current);
    (void)poll_mailbox_from_peer(st, peer, infohash, previous);
}

static void flush_ratchet_outbox(pcomm_db_t *db, const pcomm_config_t *cfg,
                                  const pcomm_identity_t *me,
                                  hidden_state_t *hidden, unsigned limit) {
    for (unsigned i = 0; i < limit && !pcomm_shutdown_requested() &&
         (!hidden || !hidden_stopping(hidden)); i++) {
        pcomm_ratchet_outgoing_t outgoing = {0};
        int next = pcomm_ratchet_outbox_next(db, (int64_t)time(NULL), &outgoing);
        if (next <= 0) break;
        int rc = hidden ? rdv_try_send(hidden, outgoing.peer,
                                       outgoing.sealed, outgoing.sealed_len) : -1;
        if (rc != 0 && !pcomm_shutdown_requested() &&
            (!hidden || !hidden_stopping(hidden))) {
            rc = pcomm_hidden_mailbox_send(db, cfg, me, outgoing.peer,
                                           outgoing.sealed, outgoing.sealed_len);
        }
        (void)pcomm_ratchet_outbox_sent(db, outgoing.id, rc == 0);
        pcomm_ratchet_outgoing_free(&outgoing);
    }
}

static void flush_after_send(pcomm_db_t *db, const pcomm_config_t *cfg,
                              const pcomm_identity_t *me) {
    hidden_state_t *hidden = hidden_acquire();
    if (hidden && hidden->db != db) {
        hidden_release(hidden);
        hidden = NULL;
    }
    flush_ratchet_outbox(db, cfg, me, hidden, 1);
    hidden_release(hidden);
}

static void *sync_thread(void *arg) {
    hidden_state_t *st = (hidden_state_t*)arg;

    while (!hidden_stopping(st)) {
        uint32_t ep = epoch_now();
        uint8_t mkey_now[32];
        sha256_key("pcomm-mb-v1", st->me.user_id, ep, mkey_now);
        uint8_t mkey_prev[32];
        sha256_key("pcomm-mb-v1", st->me.user_id, ep ? (ep-1) : ep, mkey_prev);
        poll_local_mailbox(st, mkey_now);
        poll_local_mailbox(st, mkey_prev);
        flush_ratchet_outbox(st->db, &st->cfg, &st->me, st, 8);
        if (hidden_stopping(st)) break;

        uint8_t infohash[20];
        pcomm_dht_infohash_mb(st->me.user_id, infohash);
        pcomm_peer_t seen[17]; size_t seen_count = 0;
        for (unsigned previous = 0; previous < 2; previous++) {
            pcomm_peer_t hs[3]; size_t hs_len = 0;
            uint32_t directory_epoch = previous && ep ? ep-1 : ep;
            if (select_hsdirs(st->db, st->me.user_id, directory_epoch, hs, &hs_len) == 0) {
                for (size_t i = 0; i < hs_len; i++) {
                    poll_unique_mailbox(st, &hs[i], seen, &seen_count, infohash, mkey_now, mkey_prev);
                }
            }
        }
        char hosts[8][64]; uint16_t ports[8]; size_t hn = 0;
        if (pcomm_dht_get_peers_hosts(infohash, hosts, ports, 8, &hn) == 0 && hn > 0) {
            for (size_t i = 0; i < hn && !hidden_stopping(st); i++) {
                pcomm_peer_t p; memset(&p, 0, sizeof(p));
                snprintf(p.host, sizeof(p.host), "%s", hosts[i]);
                p.port = ports[i];
                poll_unique_mailbox(st, &p, seen, &seen_count, infohash, mkey_now, mkey_prev);
            }
        }

        pthread_mutex_lock(&st->lock);
        pcomm_peer_t intros[3]; size_t intro_n = st->intro_count;
        for (size_t i = 0; i < intro_n; i++) intros[i] = st->intros[i];
        pthread_mutex_unlock(&st->lock);
        for (size_t i = 0; i < intro_n && !hidden_stopping(st); i++) {
            poll_unique_mailbox(st, &intros[i], seen, &seen_count, infohash, mkey_now, mkey_prev);
        }

        flush_ratchet_outbox(st->db, &st->cfg, &st->me, st, 8);

        {
        uint8_t r2[2] = {0};
        pcomm_random(r2, 2);
        int base = (int)st->cfg.mailbox_poll_base_ms;
        if (base < 800) base = 800;
        int jitter = ((int)r2[0] << 8 | (int)r2[1]) % base;
        if (hidden_wait(st, (uint32_t)(base/2 + jitter)) != 0) break;
    }
    }
    return NULL;
}

static void *publish_thread(void *arg) {
    hidden_state_t *st = (hidden_state_t*)arg;
    while (!hidden_stopping(st)) {
        int published = publish_descriptor(st);
        ensure_intro_circuits(st);
        uint32_t delay = published == 0 ? 10u*60u*1000u : 5000u;
        time_t clock = time(NULL);
        if (clock >= 0) {
            uint32_t until_epoch = (PCOMM_DESCRIPTOR_EPOCH_SECONDS-(uint32_t)((uint64_t)clock%PCOMM_DESCRIPTOR_EPOCH_SECONDS))*1000u;
            if (delay > until_epoch) delay = until_epoch;
        }
        if (hidden_wait(st, delay) != 0) break;
    }
    return NULL;
}

static void *cover_thread(void *arg) {
    hidden_state_t *st = (hidden_state_t*)arg;
    while (!hidden_stopping(st)) {
        uint8_t r[1] = {0};
        pcomm_random(r, 1);
        int delay = 2 + (r[0] % 5);
        pcomm_peer_t dest;
        const char *sql = "SELECT user_id, host, port, pubkey FROM contacts WHERE is_relay=1 AND host!='' AND port>0 ORDER BY RANDOM() LIMIT 1;";
        sqlite3_stmt *stq = NULL;
        if (sqlite3_prepare_v2(st->db->db, sql, -1, &stq, NULL) == SQLITE_OK) {
            if (sqlite3_step(stq) == SQLITE_ROW) {
                const char *uid = (const char*)sqlite3_column_text(stq, 0);
                const char *host = (const char*)sqlite3_column_text(stq, 1);
                int port = sqlite3_column_int(stq, 2);
                const void *pk = sqlite3_column_blob(stq, 3);
                int pklen = sqlite3_column_bytes(stq, 3);
                if (uid && host && pklen == 32 && port > 0 && port <= 65535) {
                    memset(&dest, 0, sizeof(dest));
                    snprintf(dest.user_id, sizeof(dest.user_id), "%s", uid);
                    snprintf(dest.host, sizeof(dest.host), "%s", host);
                    dest.port = (uint16_t)port;
                    memcpy(dest.pubkey, pk, 32);

                    uint8_t *noop = NULL; uint32_t noop_len = 0;
                    if (ctrl_build_noop(&noop, &noop_len) == 0) {
                        onion_send_ctrl(st->db, &st->cfg, &st->me, &dest, noop, noop_len, 0, NULL, NULL);
                    }
                    free(noop);
                }
            }
        }
        sqlite3_finalize(stq);

        if (hidden_wait(st, (uint32_t)delay * 1000) != 0) break;
    }
    return NULL;
}

static void hidden_circuit_event(void *arg, pcomm_circuit_t *c,
                                 uint8_t relay_cmd, uint16_t stream_id,
                                 const uint8_t *body, uint16_t body_len) {
    (void)c;
    hidden_state_t *st = (hidden_state_t*)arg;
    if (!st || hidden_stopping(st)) return;

    if (relay_cmd == PCOMM_RELAY_INTRODUCE2) {
        handle_introduce2(st, body, (uint16_t)body_len);
        return;
    }

    if (relay_cmd == PCOMM_RELAY_RENDEZVOUS2) {
        if (body_len >= 21) {
            const uint8_t *cookie = body;
            int ok = body[20] ? 1 : 0;
            rdv_signal(st, cookie, ok);
            if (ok) rdv_mark_established(st, cookie);
        }
        return;
    }

    if (relay_cmd == PCOMM_RELAY_DATA && body && body_len >= PCOMM_HDR_LEN) {
        pcomm_msg_type_t mt;
        uint8_t eph[32];
        uint8_t *pl = NULL; uint32_t pll = 0;
        if (pcomm_unpack_packet(body, (uint32_t)body_len, &mt, eph, &pl, &pll) == 0) {
            if (mt == PCOMM_MSG_DELIVER && pl && pll > 0) {
                (void)pcomm_receive_sealed(st->db, &st->me, pl, pll, (uint32_t)time(NULL));
            }
            free(pl);
        }
        (void)stream_id;
        return;
    }
}

int pcomm_hidden_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db) {
    if (!cfg || !me || !db || pcomm_shutdown_requested()) return -1;
    pthread_mutex_lock(&g_hidden_mu);
    int started = g_hidden != NULL;
    pthread_mutex_unlock(&g_hidden_mu);
    if (started) return 0;

    hidden_state_t *st = (hidden_state_t*)calloc(1, sizeof(hidden_state_t));
    if (!st) return -1;
    st->cfg = *cfg;
    st->me = *me;
    st->db = db;
    atomic_init(&st->stopping, 0);
    if (pthread_mutex_init(&st->lock, NULL) != 0) {
        free(st);
        return -1;
    }
    if (pthread_mutex_init(&st->rdv_mu, NULL) != 0) {
        pthread_mutex_destroy(&st->lock);
        free(st);
        return -1;
    }
    if (pthread_cond_init(&st->wake_cv, NULL) != 0) {
        pthread_mutex_destroy(&st->rdv_mu);
        pthread_mutex_destroy(&st->lock);
        free(st);
        return -1;
    }
    st->waits = NULL;
    st->sessions = NULL;

    pthread_mutex_lock(&g_hidden_mu);
    g_hidden = st;
    pthread_mutex_unlock(&g_hidden_mu);
    void *(*workers[4])(void *) = {publish_thread, sync_thread, cover_thread, session_gc_thread};
    for (unsigned i = 0; i < 4; i++) {
        if (pthread_create(&st->workers[i], NULL, workers[i], st) != 0) {

            pcomm_shutdown_request();
            net_shutdown_all();
            pcomm_circuits_request_stop();
            pcomm_hidden_stop();
            return -1;
        }
        st->worker_count++;
    }

    fprintf(stderr, "Hidden-service style mailbox started (publish/sync/cover)\n");
    return 0;
}

void pcomm_hidden_request_stop(void) {
    pthread_mutex_lock(&g_hidden_mu);
    hidden_state_t *st = g_hidden;
    if (st) {
        atomic_store(&st->stopping, 1);
        pthread_mutex_lock(&st->lock);
        pthread_cond_broadcast(&st->wake_cv);
        pthread_mutex_unlock(&st->lock);
        pthread_mutex_lock(&st->rdv_mu);
        for (rdv_wait_t *w = st->waits; w; w = w->next) {
            pthread_mutex_lock(&w->mu);
            w->ok = 0;
            w->done = 1;
            pthread_cond_broadcast(&w->cv);
            pthread_mutex_unlock(&w->mu);
        }
        pthread_mutex_unlock(&st->rdv_mu);
    }
    pthread_mutex_unlock(&g_hidden_mu);
}

void pcomm_hidden_stop(void) {
    pcomm_hidden_request_stop();
    pthread_mutex_lock(&g_hidden_mu);
    hidden_state_t *st = g_hidden;
    g_hidden = NULL;
    pthread_mutex_unlock(&g_hidden_mu);
    if (!st) return;
    for (unsigned i = 0; i < st->worker_count; i++) pthread_join(st->workers[i], NULL);
    pthread_mutex_lock(&g_hidden_mu);
    while (st->users) pthread_cond_wait(&g_hidden_cv, &g_hidden_mu);
    pthread_mutex_unlock(&g_hidden_mu);

    pcomm_circuits_detach_events(st);
    for (size_t i = 0; i < 3; i++) pcomm_circuit_close(st->intro_circs[i].circ);
    rdv_sess_t *session = st->sessions;
    while (session) {
        rdv_sess_t *next = session->next;
        pcomm_circuit_close(session->circ);
        free(session);
        session = next;
    }
    pthread_cond_destroy(&st->wake_cv);
    pthread_mutex_destroy(&st->rdv_mu);
    pthread_mutex_destroy(&st->lock);
    free(st);
}

int pcomm_hidden_mailbox_send(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                             const char *recipient_id,
                             const uint8_t *sealed, size_t sealed_len) {
    if (!db || !cfg || !me || !recipient_id || !sealed || sealed_len == 0 ||
        sealed_len > PCOMM_MAILBOX_MAX_BLOB_LEN || pcomm_shutdown_requested()) return -1;

    uint32_t ep = epoch_now();
    uint8_t mkey[32];
    sha256_key("pcomm-mb-v1", recipient_id, ep, mkey);

    uint8_t infohash[20];
    pcomm_dht_infohash_mb(recipient_id, infohash);

    pcomm_peer_t intros[3]; size_t intro_n = 0;
    fetch_descriptor(db, cfg, me, recipient_id, ep, intros, 3, &intro_n);

    uint8_t *put = NULL; uint32_t put_len = 0;
    if (ctrl_build_mb_put(infohash, mkey, sealed, (uint32_t)sealed_len, &put, &put_len) != 0) return -1;

    int ok = -1;

    char hosts[8][64]; uint16_t ports[8]; size_t hn = 0;
    if (pcomm_dht_get_peers_hosts(infohash, hosts, ports, 8, &hn) == 0 && hn > 0) {
        size_t send_n = (hn > 3) ? 3 : hn;
        for (size_t i = 0; i < send_n; i++) {
            pcomm_peer_t dest; memset(&dest, 0, sizeof(dest));
            snprintf(dest.host, sizeof(dest.host), "%s", hosts[i]);
            dest.port = ports[i];
            if (onion_send_ctrl(db, cfg, me, &dest, put, put_len, 0, NULL, NULL) == 0) ok = 0;
        }
    }

    if (intro_n > 0) {
        if (onion_send_ctrl(db, cfg, me, &intros[0], put, put_len, 0, NULL, NULL) == 0) ok = 0;
    }

    if (ok != 0) {
        pcomm_peer_t hs[3]; size_t hs_n = 0;
        if (select_hsdirs(db, recipient_id, ep, hs, &hs_n) == 0) {
            for (size_t i = 0; i < hs_n && i < 2; i++) {
                if (onion_send_ctrl(db, cfg, me, &hs[i], put, put_len, 0, NULL, NULL) == 0) ok = 0;
            }
        }
    }

    free(put);
    return ok;
}

static int rdv_send_over_session(hidden_state_t *st, pcomm_circuit_t *circ, const uint8_t *sealed, size_t sealed_len) {
    if (!st || !circ || !sealed || sealed_len == 0 || hidden_stopping(st)) return -1;

    uint8_t *pkt = NULL; uint32_t pkt_len = 0;
    if (pcomm_pack_packet(PCOMM_MSG_DELIVER, NULL, sealed, (uint32_t)sealed_len, &pkt, &pkt_len) != 0) return -1;

    uint16_t sid = 0;
    int rc = pcomm_circuit_alloc_stream(circ, &sid);
    if (rc == 0) rc = pcomm_circuit_send_relay(circ, PCOMM_RELAY_DATA, sid, pkt, (uint16_t)pkt_len);
    if (rc == 0) rc = pcomm_circuit_send_relay(circ, PCOMM_RELAY_END, sid, NULL, 0);
    free(pkt);

    if (rc == 0) {
        pthread_mutex_lock(&st->rdv_mu);
        for (rdv_sess_t *session = st->sessions; session; session = session->next) {
            if (session->circ == circ) session->last_used = time(NULL);
        }
        pthread_mutex_unlock(&st->rdv_mu);
    }
    return rc;
}

static int rdv_connect_and_send(hidden_state_t *st, const char *service_id, const uint8_t *sealed, size_t sealed_len) {
    if (!st || !service_id || !sealed || sealed_len == 0 || hidden_stopping(st)) return -1;

    uint32_t ep = epoch_now();

    pcomm_peer_t intros[3]; size_t intro_n = 0;
    if (fetch_descriptor(st->db, &st->cfg, &st->me, service_id, ep, intros, 3, &intro_n) != 0 || intro_n == 0) {
        return -1;
    }

    pcomm_peer_t rp;
    if (pick_random_relay(st->db, st->me.user_id, intros[0].user_id, service_id, &rp) != 0) {
        rp = intros[0];
    }

    uint8_t cookie[20];
    pcomm_random(cookie, 20);

    pcomm_circuit_t *rp_c = pcomm_circuit_create_to_exit(&st->cfg, &st->me, st->db, rp.host, rp.port, st->me.user_id);
    if (!rp_c) return -1;
    if (pcomm_circuit_set_event_cb(rp_c, hidden_circuit_event, st) != 0) {
        pcomm_circuit_close(rp_c);
        return -1;
    }

    rdv_wait_t w;
    if (rdv_wait_init(&w, cookie) != 0) {
        pcomm_circuit_close(rp_c);
        return -1;
    }
    rdv_wait_add(st, &w);

    if (pcomm_circuit_send_relay(rp_c, PCOMM_RELAY_ESTABLISH_RENDEZVOUS, 0, cookie, 20) != 0) {
        rdv_wait_remove(st, &w);
        rdv_wait_destroy(&w);
        pcomm_circuit_close(rp_c);
        return -1;
    }

    pcomm_circuit_t *intro_c = pcomm_circuit_create_to_exit(&st->cfg, &st->me, st->db, intros[0].host, intros[0].port, st->me.user_id);
    if (intro_c) {
        uint8_t body[1 + 95 + 1 + 95 + 20 + 1 + 63 + 2];
        size_t off = 0;
        size_t sl = strlen(service_id); if (sl > 95) sl = 95;
        size_t cl = strlen(st->me.user_id); if (cl > 95) cl = 95;
        size_t hl = strlen(rp.host); if (hl > 63) hl = 63;

        body[off++] = (uint8_t)sl;
        memcpy(body + off, service_id, sl); off += sl;
        body[off++] = (uint8_t)cl;
        memcpy(body + off, st->me.user_id, cl); off += cl;
        memcpy(body + off, cookie, 20); off += 20;
        body[off++] = (uint8_t)hl;
        memcpy(body + off, rp.host, hl); off += hl;
        put_u16(body + off, rp.port); off += 2;

        pcomm_circuit_send_relay(intro_c, PCOMM_RELAY_INTRODUCE1, 0, body, (uint16_t)off);
        pcomm_circuit_close(intro_c);
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 8;

    pthread_mutex_lock(&w.mu);
    while (!w.done && !hidden_stopping(st)) {
        if (pthread_cond_timedwait(&w.cv, &w.mu, &ts) == ETIMEDOUT) break;
    }
    int ok = w.ok && !hidden_stopping(st);
    pthread_mutex_unlock(&w.mu);

    rdv_wait_remove(st, &w);
    rdv_wait_destroy(&w);

    if (!ok) {
        pcomm_circuit_close(rp_c);
        return -1;
    }

    if (rdv_add_or_update_session(st, service_id, cookie, rp_c) != 0) {
        pcomm_circuit_close(rp_c);
        return -1;
    }
    rdv_mark_established(st, cookie);

    pcomm_circuit_t *session = rdv_find_session(st, service_id);
    if (!session) return -1;
    int rc = rdv_send_over_session(st, session, sealed, sealed_len);
    pcomm_circuit_release(session);
    return rc;
}

static int rdv_try_send(hidden_state_t *st, const char *to_user_id, const uint8_t *sealed, size_t sealed_len) {
    if (!st || hidden_stopping(st)) return -1;
    pcomm_circuit_t *session = rdv_find_session(st, to_user_id);
    if (session) {
        int rc = rdv_send_over_session(st, session, sealed, sealed_len);
        pcomm_circuit_release(session);
        if (rc == 0) return 0;
    }
    return rdv_connect_and_send(st, to_user_id, sealed, sealed_len);
}

int pcomm_hidden_send_direct_text(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                                 const char *to_user_id, const char *text) {
    if (!db || !cfg || !me || !to_user_id || !text || pcomm_shutdown_requested()) return -1;

    uint8_t recip_pub[32];
    char canonical[96];
    if (pcomm_pubkey_from_user_id(to_user_id, recip_pub) != 0 ||
        pcomm_user_id_from_pubkey(recip_pub, canonical) != 0) {
        fprintf(stderr, "Bad recipient id\n");
        return -1;
    }

    uint32_t ts = (uint32_t)time(NULL);

    uint8_t *plain = NULL; size_t plain_len = 0;
    if (pcomm_msg_pack_direct_text(ts, me->user_id, text, &plain, &plain_len) != 0) return -1;

    int rc = pcomm_ratchet_send(db, me, canonical, "", plain, plain_len);
    OPENSSL_cleanse(plain, plain_len);
    free(plain);
    if (rc == 0) flush_after_send(db, cfg, me);
    return rc;
}

int pcomm_hidden_send_group_invite(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                                  const char *member_id,
                                  const char *group_uuid, const char *title,
                                  char **members, int member_count) {
    if (!db || !cfg || !me || !member_id || !group_uuid || pcomm_shutdown_requested()) return -1;

    uint32_t ts = (uint32_t)time(NULL);
    uint8_t *plain = NULL; size_t plain_len = 0;
    if (pcomm_msg_pack_group_invite(ts, me->user_id, group_uuid, title, members, member_count, &plain, &plain_len) != 0) return -1;

    int rc = pcomm_ratchet_send(db, me, member_id, group_uuid, plain, plain_len);
    OPENSSL_cleanse(plain, plain_len);
    free(plain);
    if (rc == 0) flush_after_send(db, cfg, me);
    return rc;
}

int pcomm_hidden_send_group_text(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                                const char *member_id,
                                const char *group_uuid, const char *text) {
    if (!db || !cfg || !me || !member_id || !group_uuid || !text || pcomm_shutdown_requested()) return -1;

    uint32_t ts = (uint32_t)time(NULL);
    uint8_t *plain = NULL; size_t plain_len = 0;
    if (pcomm_msg_pack_group_text(ts, me->user_id, group_uuid, text, &plain, &plain_len) != 0) return -1;

    int rc = pcomm_ratchet_send(db, me, member_id, group_uuid, plain, plain_len);
    OPENSSL_cleanse(plain, plain_len);
    free(plain);
    if (rc == 0) flush_after_send(db, cfg, me);
    return rc;
}
