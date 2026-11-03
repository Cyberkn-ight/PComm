#define _GNU_SOURCE
#include "dht.h"
#include "bencode.h"
#include "crypto.h"
#include "identity.h"
#include "sign.h"
#include "net.h"
#include "lifecycle.h"

#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <netdb.h>


#define DHT_MAX_NODES        1024
#define DHT_QUERY_FANOUT     24
#define DHT_MAX_QUERIES      96

#define DHT_NODE_STALE_SEC   (60 * 60)
#define DHT_NODE_PRUNE_SEC   (2 * 60 * 60)

typedef struct {
    uint8_t id[20];
    struct sockaddr_in addr;
    time_t last_seen;
    uint8_t ok;
} dht_node_t;

typedef struct peer_item {
    uint8_t infohash[20];
    uint8_t *peers;
    size_t peers_len;
    struct peer_item *next;
} peer_item_t;

typedef struct {
    uint16_t tx;
    int used;
    int done;
    benc_t *resp;
    struct sockaddr_in expected;
    uint8_t nonce[32];
    int require_proof;
    pthread_cond_t cv;
} pending_t;

typedef struct {
    int udp_fd;
    uint8_t node_id[20];
    uint8_t secret[20];
    uint16_t listen_port;
    uint16_t relay_port;
    uint8_t public_key[32];
    uint8_t private_key[32];
    pcomm_bootstrap_t bootstrap[PCOMM_MAX_BOOTSTRAP];
    time_t bootstrap_retry[PCOMM_MAX_BOOTSTRAP];
    size_t bootstrap_count;

    int running;
    uint32_t maint_interval_sec;
    int allow_private_addrs;

    pthread_t rx_th;
    pthread_t maint_th;
    int rx_started;
    int maint_started;
    pthread_mutex_t mu;
    pthread_cond_t users_done;
    size_t active_calls;
    size_t pending_initialized;

    dht_node_t nodes[DHT_MAX_NODES];
    size_t nodes_len;

    peer_item_t *peers_head;

    pending_t pending[DHT_MAX_QUERIES];

    pcomm_db_t *db;
} dht_state_t;

static dht_state_t *g_dht = NULL;
static pthread_mutex_t g_dht_mu = PTHREAD_MUTEX_INITIALIZER;

static int dht_running(dht_state_t *st) {
    pthread_mutex_lock(&st->mu);
    int running = st->running;
    pthread_mutex_unlock(&st->mu);
    return running && !pcomm_shutdown_requested();
}

static dht_state_t *dht_acquire(void) {
    if (pcomm_shutdown_requested()) return NULL;
    pthread_mutex_lock(&g_dht_mu);
    dht_state_t *st = g_dht;
    if (st) {
        pthread_mutex_lock(&st->mu);
        int usable = st->running && !pcomm_shutdown_requested();
        if (usable) st->active_calls++;
        pthread_mutex_unlock(&st->mu);
        if (!usable) st = NULL;
    }
    pthread_mutex_unlock(&g_dht_mu);
    return st;
}

static void dht_release(dht_state_t *st) {
    pthread_mutex_lock(&st->mu);
    st->active_calls--;
    if (st->active_calls == 0) pthread_cond_broadcast(&st->users_done);
    pthread_mutex_unlock(&st->mu);
}

static void dht_request_stop_state(dht_state_t *st) {
    pthread_mutex_lock(&st->mu);
    st->running = 0;
    for (size_t i = 0; i < st->pending_initialized; i++) {
        pthread_cond_broadcast(&st->pending[i].cv);
    }
    pthread_mutex_unlock(&st->mu);
}

static int dht_wait(dht_state_t *st, uint64_t milliseconds) {
    while (milliseconds > 0 && dht_running(st)) {
        uint32_t chunk = milliseconds > 100u ? 100u : (uint32_t)milliseconds;
        if (pcomm_shutdown_wait(chunk) != 0) return -1;
        milliseconds -= chunk;
    }
    return dht_running(st) ? 0 : -1;
}

static void sha1_bytes(const uint8_t *in, size_t in_len, uint8_t out20[20]) {
    SHA_CTX c;
    SHA1_Init(&c);
    SHA1_Update(&c, in, in_len);
    SHA1_Final(out20, &c);
}

void pcomm_dht_infohash_desc(const char *user_id, uint8_t out20[20]) {
    uint8_t buf[256];
    size_t n = 0;
    const char *tag = "pcomm-desc:";
    memcpy(buf + n, tag, strlen(tag)); n += strlen(tag);
    memcpy(buf + n, user_id, strlen(user_id)); n += strlen(user_id);
    sha1_bytes(buf, n, out20);
}

void pcomm_dht_infohash_mb(const char *user_id, uint8_t out20[20]) {
    uint8_t buf[256];
    size_t n = 0;
    const char *tag = "pcomm-mb:";
    memcpy(buf + n, tag, strlen(tag)); n += strlen(tag);
    memcpy(buf + n, user_id, strlen(user_id)); n += strlen(user_id);
    sha1_bytes(buf, n, out20);
}

static void compute_node_id(const pcomm_identity_t *me, uint8_t out20[20]) {
    uint8_t buf[64];
    memcpy(buf, "pcomm-dht", 9);
    memcpy(buf + 9, me->pubkey, 32);
    sha1_bytes(buf, 41, out20);
}

static void token_for_ip(const uint8_t secret[20], const struct sockaddr_in *addr, uint8_t out4[4]) {
    uint8_t buf[64];
    size_t n = 0;
    memcpy(buf + n, secret, 20); n += 20;
    memcpy(buf + n, &addr->sin_addr, 4); n += 4;
    uint32_t bucket = (uint32_t)(time(NULL) / 300);
    bucket = htonl(bucket);
    memcpy(buf + n, &bucket, 4); n += 4;
    uint8_t h[20];
    sha1_bytes(buf, n, h);
    memcpy(out4, h, 4);
}

static int addr_eq(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

static int addr_is_valid(dht_state_t *st, const struct sockaddr_in *addr) {
    if (!addr || addr->sin_port == 0) return 0;
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    if ((ip >> 24) == 0 || (ip >> 24) >= 224) return 0;
    if (!st->allow_private_addrs) {
        if (net_addr_is_private(&addr->sin_addr, AF_INET)) return 0;
    }
    return 1;
}

static void add_node_locked(dht_state_t *st, const uint8_t id[20], const struct sockaddr_in *addr) {
    if (!addr_is_valid(st, addr)) return;
    if (id && memcmp(id, st->node_id, 20) == 0) return;

    for (size_t i = 0; i < st->nodes_len; i++) {
        if (addr_eq(&st->nodes[i].addr, addr)) {
            if (id) memcpy(st->nodes[i].id, id, 20);
            st->nodes[i].last_seen = time(NULL);
            st->nodes[i].ok = 1;
            return;
        }
    }

    if (st->nodes_len >= DHT_MAX_NODES) {
        size_t worst = 0;
        time_t best_t = st->nodes[0].last_seen;
        for (size_t i = 1; i < st->nodes_len; i++) {
            if (st->nodes[i].last_seen < best_t) {
                best_t = st->nodes[i].last_seen;
                worst = i;
            }
        }
        st->nodes[worst].addr = *addr;
        if (id) memcpy(st->nodes[worst].id, id, 20);
        st->nodes[worst].last_seen = time(NULL);
        st->nodes[worst].ok = 1;
        return;
    }

    dht_node_t *n = &st->nodes[st->nodes_len++];
    memset(n, 0, sizeof(*n));
    if (id) memcpy(n->id, id, 20);
    n->addr = *addr;
    n->last_seen = time(NULL);
    n->ok = 1;
}

static void peers_add_locked(dht_state_t *st, const uint8_t infohash[20], const uint8_t compact6[6]) {
    peer_item_t *it = st->peers_head;
    while (it) {
        if (memcmp(it->infohash, infohash, 20) == 0) break;
        it = it->next;
    }
    if (!it) {
        it = (peer_item_t*)calloc(1, sizeof(peer_item_t));
        if (!it) return;
        memcpy(it->infohash, infohash, 20);
        it->next = st->peers_head;
        st->peers_head = it;
    }

    for (size_t i = 0; i + 6 <= it->peers_len; i += 6) {
        if (memcmp(it->peers + i, compact6, 6) == 0) return;
    }

    if (it->peers_len >= 6 * 96) return;

    uint8_t *nb = (uint8_t*)realloc(it->peers, it->peers_len + 6);
    if (!nb) return;
    it->peers = nb;
    memcpy(it->peers + it->peers_len, compact6, 6);
    it->peers_len += 6;
}

static int peers_get_locked(dht_state_t *st, const uint8_t infohash[20], uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;
    peer_item_t *it = st->peers_head;
    while (it) {
        if (memcmp(it->infohash, infohash, 20) == 0) break;
        it = it->next;
    }
    if (!it || it->peers_len == 0) return -1;
    uint8_t *b = (uint8_t*)malloc(it->peers_len);
    if (!b) return -1;
    memcpy(b, it->peers, it->peers_len);
    *out = b;
    *out_len = it->peers_len;
    return 0;
}

static pending_t *pending_alloc_locked(dht_state_t *st, uint16_t tx) {
    for (int i = 0; i < DHT_MAX_QUERIES; i++) {
        if (!st->pending[i].used) {
            st->pending[i].used = 1;
            st->pending[i].done = 0;
            st->pending[i].tx = tx;
            st->pending[i].resp = NULL;
            return &st->pending[i];
        }
    }
    return NULL;
}

static pending_t *pending_find_locked(dht_state_t *st, uint16_t tx) {
    for (int i = 0; i < DHT_MAX_QUERIES; i++) {
        if (st->pending[i].used && st->pending[i].tx == tx) return &st->pending[i];
    }
    return NULL;
}

static void pending_free_locked(pending_t *p) {
    if (!p) return;
    benc_free(p->resp);
    p->resp = NULL;
    p->used = 0;
    p->done = 0;
    p->tx = 0;
    p->require_proof = 0;
    memset(&p->expected, 0, sizeof(p->expected));
    OPENSSL_cleanse(p->nonce, sizeof(p->nonce));
}

static int send_krpc(dht_state_t *st, const struct sockaddr_in *to, const benc_t *msg) {
    if (!dht_running(st)) return -1;
    uint8_t *buf = NULL;
    size_t len = 0;
    if (benc_encode(msg, &buf, &len) != 0) return -1;
    int rc = (sendto(st->udp_fd, buf, len, 0, (const struct sockaddr*)to, sizeof(*to)) == (ssize_t)len) ? 0 : -1;
    free(buf);
    return rc;
}

static uint16_t rand_tx(void) {
    uint8_t r[2] = {0};
    (void)pcomm_random(r, 2);
    return (uint16_t)((r[0] << 8) | r[1]);
}

static int dict_add(benc_t *dict, const char *key, benc_t *value) {
    if (!value || benc_dict_set(dict, key, value) != 0) {
        benc_free(value);
        return -1;
    }
    return 0;
}

static benc_t *krpc_build_query(dht_state_t *st, uint16_t tx, const char *q, benc_t *a) {
    benc_t *m = benc_new_dict();
    if (!m) { benc_free(a); return NULL; }
    uint8_t txb[2] = {(uint8_t)(tx >> 8), (uint8_t)(tx & 0xFF)};
    if (!a) a = benc_new_dict();
    if (!a || dict_add(m, "t", benc_new_str(txb, 2)) ||
        dict_add(m, "y", benc_new_str((const uint8_t*)"q", 1)) ||
        dict_add(m, "q", benc_new_str((const uint8_t*)q, strlen(q))) ||
        dict_add(a, "id", benc_new_str(st->node_id, 20))) {
        benc_free(a); benc_free(m); return NULL;
    }
    if (dict_add(m, "a", a)) { benc_free(m); return NULL; }
    return m;
}

static void proof_input(const uint8_t tx[2], const uint8_t nonce[32], const uint8_t node_id[20],
                          const uint8_t public_key[32], uint16_t relay_port, uint8_t out[98]) {
    memcpy(out, "PCOMM-DHT2", 10);
    memcpy(out+10, tx, 2);
    memcpy(out+12, nonce, 32);
    memcpy(out+44, node_id, 20);
    memcpy(out+64, public_key, 32);
    out[96] = (uint8_t)(relay_port >> 8);
    out[97] = (uint8_t)relay_port;
}

static benc_t *krpc_build_resp(dht_state_t *st, const uint8_t txb[2], benc_t *r, const uint8_t *nonce) {
    benc_t *m = benc_new_dict();
    if (!m) { benc_free(r); return NULL; }
    if (!r) r = benc_new_dict();
    if (!r || dict_add(m, "t", benc_new_str(txb, 2)) ||
        dict_add(m, "y", benc_new_str((const uint8_t*)"r", 1)) ||
        dict_add(r, "id", benc_new_str(st->node_id, 20))) {
        benc_free(r); benc_free(m); return NULL;
    }
    if (nonce) {
        uint8_t input[98], signature[64];
        proof_input(txb, nonce, st->node_id, st->public_key, st->relay_port, input);
        if (pcomm_sign(st->private_key, input, sizeof(input), signature) ||
            dict_add(r, "pcomm_pub", benc_new_str(st->public_key, 32)) ||
            dict_add(r, "relay_port", benc_new_int(st->relay_port)) ||
            dict_add(r, "pcomm_nonce", benc_new_str(nonce, 32)) ||
            dict_add(r, "pcomm_sig", benc_new_str(signature, 64))) {
            benc_free(r); benc_free(m); return NULL;
        }
    }
    if (dict_add(m, "r", r)) { benc_free(m); return NULL; }
    return m;
}

static void compact_nodes_locked(dht_state_t *st, uint8_t **out, size_t *out_len) {
    size_t want = st->nodes_len < 8 ? st->nodes_len : 8;
    size_t len = want * 26;
    uint8_t *b = (uint8_t*)malloc(len);
    if (!b) {
        *out = NULL;
        *out_len = 0;
        return;
    }
    size_t o = 0;
    for (size_t i = 0; i < want; i++) {
        memcpy(b + o, st->nodes[i].id, 20); o += 20;
        memcpy(b + o, &st->nodes[i].addr.sin_addr, 4); o += 4;
        memcpy(b + o, &st->nodes[i].addr.sin_port, 2); o += 2;
    }
    *out = b;
    *out_len = len;
}

static void parse_nodes_into_state(dht_state_t *st, const uint8_t *nodes, size_t nodes_len) {
    if (!nodes || nodes_len % 26 != 0) return;
    for (size_t i = 0; i + 26 <= nodes_len; i += 26) {
        uint8_t nid[20];
        memcpy(nid, nodes + i, 20);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        memcpy(&a.sin_addr, nodes + i + 20, 4);
        memcpy(&a.sin_port, nodes + i + 24, 2);
        pthread_mutex_lock(&st->mu);
        add_node_locked(st, nid, &a);
        pthread_mutex_unlock(&st->mu);
    }
}

static void handle_query(dht_state_t *st, const struct sockaddr_in *from, benc_t *msg) {
    benc_t *t = benc_dict_get(msg, "t");
    benc_t *q = benc_dict_get(msg, "q");
    benc_t *a = benc_dict_get(msg, "a");
    if (!t || t->t != BENC_STR || t->slen != 2 || !q || q->t != BENC_STR) return;
    benc_t *nonce_field = a ? benc_dict_get(a, "pcomm_nonce") : NULL;
    const uint8_t *nonce = nonce_field && nonce_field->t == BENC_STR && nonce_field->slen == 32 ? nonce_field->s : NULL;

    // record node if possible
    if (a && a->t == BENC_DICT) {
        benc_t *id = benc_dict_get(a, "id");
        if (id && id->t == BENC_STR && id->slen == 20) {
            pthread_mutex_lock(&st->mu);
            add_node_locked(st, id->s, from);
            pthread_mutex_unlock(&st->mu);
        }
    }

    char qname[32] = {0};
    size_t qn = q->slen < sizeof(qname) - 1 ? q->slen : sizeof(qname) - 1;
    memcpy(qname, q->s, qn);

    if (strcmp(qname, "ping") == 0) {
        benc_t *resp = krpc_build_resp(st, t->s, benc_new_dict(), nonce);
        send_krpc(st, from, resp);
        benc_free(resp);
        return;
    }

    if (strcmp(qname, "find_node") == 0 || strcmp(qname, "get_peers") == 0) {
        benc_t *r = benc_new_dict();
        uint8_t *nodes = NULL;
        size_t nodes_len = 0;
        pthread_mutex_lock(&st->mu);
        compact_nodes_locked(st, &nodes, &nodes_len);
        pthread_mutex_unlock(&st->mu);
        if (nodes) {
            benc_dict_set(r, "nodes", benc_new_str(nodes, nodes_len));
            free(nodes);
        }

        if (strcmp(qname, "get_peers") == 0) {
            benc_t *ih = a ? benc_dict_get(a, "info_hash") : NULL;
            if (ih && ih->t == BENC_STR && ih->slen == 20) {
                uint8_t tok[4];
                token_for_ip(st->secret, from, tok);
                benc_dict_set(r, "token", benc_new_str(tok, 4));

                pthread_mutex_lock(&st->mu);
                uint8_t *vals = NULL;
                size_t vlen = 0;
                int ok = peers_get_locked(st, ih->s, &vals, &vlen);
                pthread_mutex_unlock(&st->mu);
                if (ok == 0 && vlen >= 6) {
                    benc_t *lst = benc_new_list();
                    for (size_t i = 0; i + 6 <= vlen; i += 6) {
                        benc_list_add(lst, benc_new_str(vals + i, 6));
                    }
                    benc_dict_set(r, "values", lst);
                    free(vals);
                }
            }
        }

        benc_t *resp = krpc_build_resp(st, t->s, r, nonce);
        send_krpc(st, from, resp);
        benc_free(resp);
        return;
    }

    if (strcmp(qname, "announce_peer") == 0) {
        benc_t *ih = a ? benc_dict_get(a, "info_hash") : NULL;
        benc_t *port = a ? benc_dict_get(a, "port") : NULL;
        benc_t *tok = a ? benc_dict_get(a, "token") : NULL;
        if (ih && ih->t == BENC_STR && ih->slen == 20 && port && port->t == BENC_INT && tok && tok->t == BENC_STR && tok->slen == 4) {
            uint8_t exp[4];
            token_for_ip(st->secret, from, exp);
            if (memcmp(exp, tok->s, 4) == 0) {
                uint16_t p = (uint16_t)port->i;
                if (p > 0) {
                    uint8_t comp[6];
                    memcpy(comp, &from->sin_addr, 4);
                    uint16_t np = htons(p);
                    memcpy(comp + 4, &np, 2);
                    pthread_mutex_lock(&st->mu);
                    peers_add_locked(st, ih->s, comp);
                    pthread_mutex_unlock(&st->mu);
                }
            }
        }
        benc_t *resp = krpc_build_resp(st, t->s, benc_new_dict(), nonce);
        send_krpc(st, from, resp);
        benc_free(resp);
        return;
    }

    benc_t *resp = krpc_build_resp(st, t->s, benc_new_dict(), nonce);
    send_krpc(st, from, resp);
    benc_free(resp);
}

static int signed_response_peer(const struct sockaddr_in *from, const uint8_t tx[2], const uint8_t nonce[32],
                                  benc_t *msg, pcomm_peer_t *peer);

static void handle_response(dht_state_t *st, const struct sockaddr_in *from, benc_t *msg) {
    benc_t *t = benc_dict_get(msg, "t");
    benc_t *r = benc_dict_get(msg, "r");
    benc_t *id = r ? benc_dict_get(r, "id") : NULL;
    if (!t || t->t != BENC_STR || t->slen != 2 || !r || r->t != BENC_DICT ||
        !id || id->t != BENC_STR || id->slen != 20) {
        benc_free(msg);
        return;
    }
    uint16_t tx = (uint16_t)((t->s[0] << 8) | t->s[1]);

    pthread_mutex_lock(&st->mu);
    pending_t *p = pending_find_locked(st, tx);
    if (p && st->running && !p->done && addr_eq(&p->expected, from)) {
        benc_t *nonce = benc_dict_get(r, "pcomm_nonce");
        if (nonce && (nonce->t != BENC_STR || nonce->slen != 32 || CRYPTO_memcmp(nonce->s, p->nonce, 32))) {
            pthread_mutex_unlock(&st->mu);
            benc_free(msg);
            return;
        }
        if (p->require_proof) {
            pcomm_peer_t peer;
            if (signed_response_peer(from, t->s, p->nonce, msg, &peer) || peer.port != ntohs(p->expected.sin_port)) {
                pthread_mutex_unlock(&st->mu);
                benc_free(msg);
                return;
            }
        }
        p->resp = msg;
        p->done = 1;
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&st->mu);
        return;
    }
    pthread_mutex_unlock(&st->mu);
    benc_free(msg);
}

static void *dht_rx_thread(void *arg) {
    dht_state_t *st = (dht_state_t*)arg;
    uint8_t buf[4096];

    while (dht_running(st)) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(st->udp_fd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
        if (n <= 0) continue;
        if (!dht_running(st)) break;
        if (fl != sizeof(from) || from.sin_family != AF_INET || !addr_is_valid(st, &from)) continue;

        benc_t *msg = NULL;
        size_t used = 0;
        if (benc_parse(buf, (size_t)n, &msg, &used) != 0 || !msg || msg->t != BENC_DICT || used != (size_t)n) {
            benc_free(msg);
            continue;
        }

        benc_t *y = benc_dict_get(msg, "y");
        if (!y || y->t != BENC_STR || y->slen != 1) {
            benc_free(msg);
            continue;
        }
        if (y->s[0] == 'q') {
            handle_query(st, &from, msg);
            benc_free(msg);
        } else if (y->s[0] == 'r') {
            handle_response(st, &from, msg);
        } else {
            benc_free(msg);
        }
    }
    return NULL;
}

static int load_bootstrap_from_contacts(dht_state_t *st) {
    const char *sql = "SELECT host, port, pubkey FROM contacts WHERE is_relay=1 AND host!='' AND port>0 LIMIT 400;";
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(st->db->db, sql, -1, &q, NULL) != SQLITE_OK) return -1;

    while (sqlite3_step(q) == SQLITE_ROW) {
        const char *host = (const char*)sqlite3_column_text(q, 0);
        int port = sqlite3_column_int(q, 1);
        const void *pk = sqlite3_column_blob(q, 2);
        int pklen = sqlite3_column_bytes(q, 2);
        if (!host || port <= 0 || port > 65535 || pklen != 32) continue;
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, host, &a.sin_addr) != 1) continue;
        uint8_t nid[20], binding[41];
        memcpy(binding, "pcomm-dht", 9);
        memcpy(binding+9, pk, 32);
        sha1_bytes(binding, sizeof(binding), nid);
        pthread_mutex_lock(&st->mu);
        add_node_locked(st, nid, &a);
        pthread_mutex_unlock(&st->mu);
    }

    sqlite3_finalize(q);
    return 0;
}

static int load_bootstrap_from_db_nodes(dht_state_t *st) {
    char hosts[256][64];
    uint16_t ports[256];
    uint8_t nids[256][20];
    size_t n = 0;
    if (pcomm_db_dhtnode_load_some(st->db, hosts, ports, nids, 256, &n) != 0) return -1;

    for (size_t i = 0; i < n; i++) {
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(ports[i]);
        if (inet_pton(AF_INET, hosts[i], &a.sin_addr) != 1) continue;
        pthread_mutex_lock(&st->mu);
        add_node_locked(st, nids[i], &a);
        pthread_mutex_unlock(&st->mu);
    }
    return 0;
}

static void load_bootstrap_from_config(dht_state_t *st) {
    time_t now = time(NULL);
    for (size_t i = 0; i < st->bootstrap_count && dht_running(st); i++) {
        if (st->bootstrap_retry[i] > now && st->bootstrap_retry[i] <= now+600) continue;
        struct addrinfo hints, *addresses = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        char service[6];
        snprintf(service, sizeof(service), "%u", st->bootstrap[i].port);
        st->bootstrap_retry[i] = now+10;
        if (getaddrinfo(st->bootstrap[i].host, service, &hints, &addresses) != 0) continue;
        int accepted = 0;
        for (struct addrinfo *item = addresses; item && dht_running(st); item = item->ai_next) {
            if (item->ai_family != AF_INET || item->ai_addrlen != sizeof(struct sockaddr_in)) continue;
            const struct sockaddr_in *addr = (const struct sockaddr_in *)item->ai_addr;
            if (!addr_is_valid(st, addr)) continue;
            pthread_mutex_lock(&st->mu);
            add_node_locked(st, NULL, addr);
            pthread_mutex_unlock(&st->mu);
            accepted = 1;
        }
        freeaddrinfo(addresses);
        if (accepted) st->bootstrap_retry[i] = now+300;
    }
}

static int signed_response_peer(const struct sockaddr_in *from, const uint8_t tx[2], const uint8_t nonce[32],
                                  benc_t *msg, pcomm_peer_t *peer) {
    benc_t *r = benc_dict_get(msg, "r");
    benc_t *id = r ? benc_dict_get(r, "id") : NULL;
    if (!id || id->t != BENC_STR || id->slen != 20) return -1;
    benc_t *public_key = benc_dict_get(r, "pcomm_pub");
    benc_t *relay_port = benc_dict_get(r, "relay_port");
    benc_t *reply_nonce = benc_dict_get(r, "pcomm_nonce"), *signature = benc_dict_get(r, "pcomm_sig");
    if (!public_key || public_key->t != BENC_STR || public_key->slen != 32 ||
        !relay_port || relay_port->t != BENC_INT || relay_port->i <= 0 || relay_port->i > 65535 ||
        !reply_nonce || reply_nonce->t != BENC_STR || reply_nonce->slen != 32 ||
        CRYPTO_memcmp(reply_nonce->s, nonce, 32) || !signature || signature->t != BENC_STR || signature->slen != 64) return -1;
    uint8_t binding[41], expected[20], input[98];
    memcpy(binding, "pcomm-dht", 9);
    memcpy(binding+9, public_key->s, 32);
    sha1_bytes(binding, sizeof(binding), expected);
    if (memcmp(expected, id->s, 20) != 0) return -1;
    proof_input(tx, nonce, id->s, public_key->s, (uint16_t)relay_port->i, input);
    if (pcomm_verify(public_key->s, input, sizeof(input), signature->s)) return -1;
    memset(peer, 0, sizeof(*peer));
    if (pcomm_user_id_from_pubkey(public_key->s, peer->user_id) != 0 ||
        !inet_ntop(AF_INET, &from->sin_addr, peer->host, sizeof(peer->host))) return -1;
    memcpy(peer->pubkey, public_key->s, 32);
    peer->port = (uint16_t)relay_port->i;
    return 0;
}

static void learn_response_peer(dht_state_t *st, const struct sockaddr_in *from, const uint8_t tx[2],
                                  const uint8_t nonce[32], benc_t *msg) {
    benc_t *r = benc_dict_get(msg, "r");
    benc_t *id = r ? benc_dict_get(r, "id") : NULL;
    if (!id || id->t != BENC_STR || id->slen != 20 || !addr_is_valid(st, from)) return;
    pthread_mutex_lock(&st->mu);
    add_node_locked(st, id->s, from);
    pthread_mutex_unlock(&st->mu);
    pcomm_peer_t peer;
    if (signed_response_peer(from, tx, nonce, msg, &peer) || memcmp(peer.pubkey, st->public_key, 32) == 0) return;
    (void)pcomm_db_upsert_contact(st->db, peer.user_id, peer.host, peer.port, peer.pubkey, 1);
}

static int krpc_query_one_impl(dht_state_t *st, const struct sockaddr_in *to, benc_t *query,
                                benc_t **resp_out, int require_proof) {
    *resp_out = NULL;
    benc_t *t = benc_dict_get(query, "t");
    benc_t *a = benc_dict_get(query, "a");
    if (!t || t->t != BENC_STR || t->slen != 2 || !addr_is_valid(st, to)) return -1;
    uint8_t nonce[32];
    if (!a || a->t != BENC_DICT || pcomm_random(nonce, sizeof(nonce)) ||
        dict_add(a, "pcomm_nonce", benc_new_str(nonce, sizeof(nonce)))) return -1;

    pthread_mutex_lock(&st->mu);
    if (!st->running || pcomm_shutdown_requested()) {
        pthread_mutex_unlock(&st->mu);
        return -1;
    }
    pending_t *p = NULL;
    for (unsigned attempt = 0; attempt < 256; attempt++) {
        if (pcomm_random(t->s, 2) != 0) break;
        uint16_t tx = (uint16_t)((t->s[0] << 8) | t->s[1]);
        if (!pending_find_locked(st, tx)) { p = pending_alloc_locked(st, tx); break; }
    }
    if (p) {
        p->expected = *to;
        p->require_proof = require_proof;
        memcpy(p->nonce, nonce, sizeof(p->nonce));
    }
    pthread_mutex_unlock(&st->mu);
    if (!p) return -1;

    if (send_krpc(st, to, query) != 0) {
        pthread_mutex_lock(&st->mu);
        pending_free_locked(p);
        pthread_mutex_unlock(&st->mu);
        return -1;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        pthread_mutex_lock(&st->mu);
        pending_free_locked(p);
        pthread_mutex_unlock(&st->mu);
        return -1;
    }
    ts.tv_sec += 1;

    pthread_mutex_lock(&st->mu);
    while (!p->done && st->running && !pcomm_shutdown_requested()) {
        if (pthread_cond_timedwait(&p->cv, &st->mu, &ts) != 0) break;
    }
    if (st->running && !pcomm_shutdown_requested() && p->done && p->resp) {
        *resp_out = p->resp;
        p->resp = NULL;
    }
    pending_free_locked(p);
    pthread_mutex_unlock(&st->mu);

    if (*resp_out) learn_response_peer(st, to, t->s, nonce, *resp_out);
    return (*resp_out) ? 0 : -1;
}

static int krpc_query_one(dht_state_t *st, const struct sockaddr_in *to, benc_t *query, benc_t **resp_out) {
    return krpc_query_one_impl(st, to, query, resp_out, 0);
}

int pcomm_dht_resolve_relay(const char *host, uint16_t port, pcomm_peer_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!host || !*host || strlen(host) >= 64 || !port) return -1;
    dht_state_t *st = dht_acquire();
    if (!st) return -1;
    struct addrinfo hints, *addresses = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    char service[6];
    snprintf(service, sizeof(service), "%u", port);
    int rc = -1;
    if (getaddrinfo(host, service, &hints, &addresses) != 0) goto done;
    unsigned queried = 0;
    for (struct addrinfo *item = addresses; item && queried < 8 && dht_running(st); item = item->ai_next) {
        if (item->ai_family != AF_INET || item->ai_addrlen != sizeof(struct sockaddr_in)) continue;
        const struct sockaddr_in *to = (const struct sockaddr_in *)item->ai_addr;
        if (!addr_is_valid(st, to)) continue;
        queried++;
        benc_t *query = krpc_build_query(st, rand_tx(), "ping", NULL), *response = NULL;
        if (!query) continue;
        if (krpc_query_one_impl(st, to, query, &response, 1) == 0 && response) {
            benc_t *t = benc_dict_get(query, "t"), *a = benc_dict_get(query, "a");
            benc_t *nonce = a ? benc_dict_get(a, "pcomm_nonce") : NULL;
            pcomm_peer_t peer;
            if (t && nonce && !signed_response_peer(to, t->s, nonce->s, response, &peer) && peer.port == port) {
                *out = peer; rc = 0;
            }
        }
        benc_free(response); benc_free(query);
        if (!rc) break;
    }
done:
    if (addresses) freeaddrinfo(addresses);
    if (!dht_running(st)) { memset(out, 0, sizeof(*out)); rc = -1; }
    dht_release(st);
    return rc;
}

static void dht_prune_locked(dht_state_t *st) {
    time_t now = time(NULL);
    size_t w = 0;
    for (size_t i = 0; i < st->nodes_len; i++) {
        if (st->nodes[i].addr.sin_port == 0) continue;
        if ((now - st->nodes[i].last_seen) > DHT_NODE_PRUNE_SEC) continue;
        if (w != i) st->nodes[w] = st->nodes[i];
        w++;
    }
    st->nodes_len = w;
}

static void dht_flush_nodes_to_db(dht_state_t *st) {
    pthread_mutex_lock(&st->mu);
    size_t take = st->nodes_len < 256 ? st->nodes_len : 256;
    dht_node_t snap[256];
    for (size_t i = 0; i < take; i++) snap[i] = st->nodes[i];
    pthread_mutex_unlock(&st->mu);

    for (size_t i = 0; i < take; i++) {
        char host[64];
        inet_ntop(AF_INET, &snap[i].addr.sin_addr, host, sizeof(host));
        uint16_t port = ntohs(snap[i].addr.sin_port);
        (void)pcomm_db_dhtnode_upsert(st->db, snap[i].id, host, port, (int64_t)snap[i].last_seen);
    }
}

static void dht_refresh_once(dht_state_t *st) {
    struct sockaddr_in work[16];
    size_t wlen = 0;

    pthread_mutex_lock(&st->mu);
    if (st->nodes_len == 0) {
        pthread_mutex_unlock(&st->mu);
        return;
    }

    size_t take = st->nodes_len < 16 ? st->nodes_len : 16;
    uint32_t random = 0;
    (void)pcomm_random((uint8_t *)&random, sizeof(random));
    size_t first = random % st->nodes_len;
    for (size_t i = 0; i < take; i++) {
        size_t idx = (first+i) % st->nodes_len;
        work[wlen++] = st->nodes[idx].addr;
    }

    dht_prune_locked(st);
    pthread_mutex_unlock(&st->mu);

    uint8_t target[20];
    (void)pcomm_random(target, 20);

    for (size_t i = 0; i < wlen && dht_running(st); i++) {
        uint16_t tx = rand_tx();
        benc_t *q = krpc_build_query(st, tx, "ping", benc_new_dict());
        if (!q) continue;
        benc_t *resp = NULL;
        if (krpc_query_one(st, &work[i], q, &resp) == 0 && resp) {
            benc_t *r = benc_dict_get(resp, "r");
            if (r && r->t == BENC_DICT) {
                benc_t *nds = benc_dict_get(r, "nodes");
                if (nds && nds->t == BENC_STR && nds->slen >= 26) {
                    parse_nodes_into_state(st, nds->s, nds->slen);
                }
            }
            benc_free(resp);
        }
        benc_free(q);
        if (!dht_running(st)) break;

        uint16_t tx2 = rand_tx();
        benc_t *a2 = benc_new_dict();
        benc_dict_set(a2, "target", benc_new_str(target, 20));
        benc_t *q2 = krpc_build_query(st, tx2, "find_node", a2);
        if (!q2) continue;
        benc_t *resp2 = NULL;
        if (krpc_query_one(st, &work[i], q2, &resp2) == 0 && resp2) {
            benc_t *r = benc_dict_get(resp2, "r");
            if (r && r->t == BENC_DICT) {
                benc_t *nds = benc_dict_get(r, "nodes");
                if (nds && nds->t == BENC_STR && nds->slen >= 26) {
                    parse_nodes_into_state(st, nds->s, nds->slen);
                }
            }
            benc_free(resp2);
        }
        benc_free(q2);
    }
}

static void *dht_maint_thread(void *arg) {
    dht_state_t *st = (dht_state_t*)arg;
    while (dht_running(st)) {
        load_bootstrap_from_config(st);
        dht_refresh_once(st);
        dht_flush_nodes_to_db(st);
        if (dht_wait(st, (uint64_t)st->maint_interval_sec * 1000u) != 0) break;
    }
    return NULL;
}

int pcomm_dht_get_peers_hosts(const uint8_t infohash20[20],
                             char (*hosts)[64], uint16_t *ports,
                             size_t cap, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!hosts || !ports || !out_len || !infohash20) return -1;
    dht_state_t *st = dht_acquire();
    if (!st) return -1;

    struct sockaddr_in work[128];
    size_t wlen = 0;

    pthread_mutex_lock(&st->mu);
    size_t take = st->nodes_len < DHT_QUERY_FANOUT ? st->nodes_len : DHT_QUERY_FANOUT;
    for (size_t i = 0; i < take; i++) work[wlen++] = st->nodes[i].addr;
    pthread_mutex_unlock(&st->mu);

    size_t queried = 0;
    for (size_t wi = 0; wi < wlen && queried < 64 && *out_len < cap && dht_running(st); wi++, queried++) {
        uint16_t tx = rand_tx();
        benc_t *a = benc_new_dict();
        benc_dict_set(a, "info_hash", benc_new_str(infohash20, 20));
        benc_t *q = krpc_build_query(st, tx, "get_peers", a);
        if (!q) continue;

        benc_t *resp = NULL;
        if (krpc_query_one(st, &work[wi], q, &resp) == 0 && resp) {
            benc_t *r = benc_dict_get(resp, "r");
            if (r && r->t == BENC_DICT) {
                benc_t *vals = benc_dict_get(r, "values");
                if (vals && vals->t == BENC_LIST) {
                    for (size_t i = 0; i < vals->list_len && *out_len < cap; i++) {
                        benc_t *s = vals->list[i];
                        if (!s || s->t != BENC_STR || s->slen != 6) continue;
                        struct in_addr ip;
                        memcpy(&ip, s->s, 4);
                        uint16_t p;
                        memcpy(&p, s->s + 4, 2);
                        p = ntohs(p);
                        struct sockaddr_in candidate;
                        memset(&candidate, 0, sizeof(candidate));
                        candidate.sin_family = AF_INET;
                        candidate.sin_addr = ip;
                        candidate.sin_port = htons(p);
                        if (!addr_is_valid(st, &candidate)) continue;
                        char ipstr[64];
                        if (!inet_ntop(AF_INET, &ip, ipstr, sizeof(ipstr))) continue;
                        int duplicate = 0;
                        for (size_t j = 0; j < *out_len; j++) {
                            if (ports[j] == p && strcmp(hosts[j], ipstr) == 0) { duplicate = 1; break; }
                        }
                        if (duplicate) continue;
                        snprintf(hosts[*out_len], 64, "%s", ipstr);
                        ports[*out_len] = p;
                        (*out_len)++;
                    }
                }

                benc_t *nodes = benc_dict_get(r, "nodes");
                if (nodes && nodes->t == BENC_STR && nodes->slen >= 26) {
                    parse_nodes_into_state(st, nodes->s, nodes->slen);
                }
            }
            benc_free(resp);
        }
        benc_free(q);
    }

    int rc = (*out_len > 0 && dht_running(st)) ? 0 : -1;
    if (rc != 0) *out_len = 0;
    dht_release(st);
    return rc;
}

int pcomm_dht_announce(const uint8_t infohash20[20], uint16_t port) {
    if (!infohash20 || port == 0) return -1;
    dht_state_t *st = dht_acquire();
    if (!st) return -1;

    struct sockaddr_in nodes[DHT_QUERY_FANOUT];
    size_t nlen = 0;
    pthread_mutex_lock(&st->mu);
    size_t take = st->nodes_len < DHT_QUERY_FANOUT ? st->nodes_len : DHT_QUERY_FANOUT;
    for (size_t i = 0; i < take; i++) nodes[nlen++] = st->nodes[i].addr;
    pthread_mutex_unlock(&st->mu);

    for (size_t i = 0; i < nlen && dht_running(st); i++) {
        uint16_t tx = rand_tx();
        benc_t *a = benc_new_dict();
        benc_dict_set(a, "info_hash", benc_new_str(infohash20, 20));
        benc_t *q = krpc_build_query(st, tx, "get_peers", a);
        if (!q) continue;

        uint8_t tok[4];
        memset(tok, 0, sizeof(tok));
        benc_t *resp = NULL;
        if (krpc_query_one(st, &nodes[i], q, &resp) == 0 && resp) {
            benc_t *r = benc_dict_get(resp, "r");
            if (r && r->t == BENC_DICT) {
                benc_t *tkn = benc_dict_get(r, "token");
                if (tkn && tkn->t == BENC_STR && tkn->slen == 4) memcpy(tok, tkn->s, 4);
                benc_t *nds = benc_dict_get(r, "nodes");
                if (nds && nds->t == BENC_STR && nds->slen >= 26) parse_nodes_into_state(st, nds->s, nds->slen);
            }
            benc_free(resp);
        }
        benc_free(q);

        if (tok[0] == 0 && tok[1] == 0 && tok[2] == 0 && tok[3] == 0) continue;

        uint16_t tx2 = rand_tx();
        benc_t *a2 = benc_new_dict();
        benc_dict_set(a2, "info_hash", benc_new_str(infohash20, 20));
        benc_dict_set(a2, "port", benc_new_int(port));
        benc_dict_set(a2, "token", benc_new_str(tok, 4));
        benc_t *q2 = krpc_build_query(st, tx2, "announce_peer", a2);
        if (!q2) continue;
        benc_t *resp2 = NULL;
        (void)krpc_query_one(st, &nodes[i], q2, &resp2);
        benc_free(resp2);
        benc_free(q2);
    }

    int rc = dht_running(st) ? 0 : -1;
    dht_release(st);
    return rc;
}

static void dht_free_state(dht_state_t *st) {
    if (st->udp_fd >= 0) close(st->udp_fd);
    peer_item_t *peer = st->peers_head;
    while (peer) {
        peer_item_t *next = peer->next;
        free(peer->peers);
        free(peer);
        peer = next;
    }
    for (size_t i = 0; i < st->pending_initialized; i++) {
        benc_free(st->pending[i].resp);
        pthread_cond_destroy(&st->pending[i].cv);
    }
    pthread_cond_destroy(&st->users_done);
    pthread_mutex_destroy(&st->mu);
    OPENSSL_cleanse(st, sizeof(*st));
    free(st);
}

static int bind_dht_socket(dht_state_t *st, const pcomm_config_t *cfg) {
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(cfg->relay_port);
    if (inet_pton(AF_INET, cfg->relay_host, &address.sin_addr) == 1) {
        uint32_t ip = ntohl(address.sin_addr.s_addr);
        if (ip && ((ip >> 24) == 0 || (ip >> 24) >= 224)) return -1;
        return bind(st->udp_fd, (struct sockaddr *)&address, sizeof(address));
    }
    struct addrinfo hints, *addresses = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    char service[6];
    snprintf(service, sizeof(service), "%u", cfg->relay_port);
    if (getaddrinfo(cfg->relay_host, service, &hints, &addresses)) return -1;
    int rc = -1;
    for (struct addrinfo *item = addresses; item && dht_running(st); item = item->ai_next) {
        if (item->ai_family != AF_INET || item->ai_addrlen != sizeof(address)) continue;
        const struct sockaddr_in *candidate = (const struct sockaddr_in *)item->ai_addr;
        uint32_t ip = ntohl(candidate->sin_addr.s_addr);
        if ((ip >> 24) == 0 || (ip >> 24) >= 224) continue;
        if (bind(st->udp_fd, item->ai_addr, item->ai_addrlen) == 0) { rc = 0; break; }
    }
    freeaddrinfo(addresses);
    return rc;
}

int pcomm_dht_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db) {
    if (!cfg || !me || !db || !db->db || cfg->bootstrap_count > PCOMM_MAX_BOOTSTRAP ||
        !memchr(cfg->relay_host, 0, sizeof(cfg->relay_host)) || !cfg->relay_host[0] || pcomm_shutdown_requested()) return -1;
    for (size_t i = 0; i < cfg->bootstrap_count; i++) {
        if (!memchr(cfg->bootstrap[i].host, 0, sizeof(cfg->bootstrap[i].host)) ||
            !cfg->bootstrap[i].host[0] || !cfg->bootstrap[i].port) return -1;
    }
    pthread_mutex_lock(&g_dht_mu);
    if (g_dht) {
        int rc = dht_running(g_dht) ? 0 : -1;
        pthread_mutex_unlock(&g_dht_mu);
        return rc;
    }

    dht_state_t *st = (dht_state_t*)calloc(1, sizeof(dht_state_t));
    if (!st) {
        pthread_mutex_unlock(&g_dht_mu);
        return -1;
    }
    st->udp_fd = -1;
    if (pthread_mutex_init(&st->mu, NULL) != 0) {
        free(st);
        pthread_mutex_unlock(&g_dht_mu);
        return -1;
    }
    if (pthread_cond_init(&st->users_done, NULL) != 0) {
        pthread_mutex_destroy(&st->mu);
        free(st);
        pthread_mutex_unlock(&g_dht_mu);
        return -1;
    }
    for (size_t i = 0; i < DHT_MAX_QUERIES; i++) {
        if (pthread_cond_init(&st->pending[i].cv, NULL) != 0) goto fail;
        st->pending_initialized++;
    }
    st->db = db;
    st->listen_port = cfg->relay_port;
    st->relay_port = cfg->advertise_port ? cfg->advertise_port : cfg->relay_port;
    memcpy(st->public_key, me->pubkey, 32);
    memcpy(st->private_key, me->privkey, 32);
    st->bootstrap_count = cfg->bootstrap_count;
    memcpy(st->bootstrap, cfg->bootstrap, cfg->bootstrap_count*sizeof(cfg->bootstrap[0]));
    st->running = 1;
    st->maint_interval_sec = cfg->dht_maint_interval_sec > 3 ? cfg->dht_maint_interval_sec : 10;
    st->allow_private_addrs = cfg->allow_private_addrs ? 1 : 0;

    compute_node_id(me, st->node_id);
    if (pcomm_random(st->secret, sizeof(st->secret)) != 0) goto fail;

    st->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (st->udp_fd < 0) goto fail;

    int yes = 1;
    setsockopt(st->udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct timeval timeout = {0, 200000};
    if (setsockopt(st->udp_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(st->udp_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) goto fail;

    if (bind_dht_socket(st, cfg) != 0) goto fail;

    load_bootstrap_from_contacts(st);
    load_bootstrap_from_db_nodes(st);

    if (pthread_create(&st->rx_th, NULL, dht_rx_thread, st) != 0) goto fail;
    st->rx_started = 1;

    if (pthread_create(&st->maint_th, NULL, dht_maint_thread, st) != 0) goto fail;
    st->maint_started = 1;

    g_dht = st;
    fprintf(stderr, "[dht] started on UDP %u (maint %us)\n", (unsigned)cfg->relay_port, (unsigned)st->maint_interval_sec);
    pthread_mutex_unlock(&g_dht_mu);
    return 0;

fail:
    dht_request_stop_state(st);
    if (st->rx_started) pthread_join(st->rx_th, NULL);
    if (st->maint_started) pthread_join(st->maint_th, NULL);
    dht_free_state(st);
    pthread_mutex_unlock(&g_dht_mu);
    return -1;
}

void pcomm_dht_request_stop(void) {
    pthread_mutex_lock(&g_dht_mu);
    if (g_dht) dht_request_stop_state(g_dht);
    pthread_mutex_unlock(&g_dht_mu);
}

void pcomm_dht_stop(void) {
    pthread_mutex_lock(&g_dht_mu);
    dht_state_t *st = g_dht;
    if (st) {
        dht_request_stop_state(st);
        if (st->rx_started) pthread_join(st->rx_th, NULL);
        if (st->maint_started) pthread_join(st->maint_th, NULL);
        pthread_mutex_lock(&st->mu);
        while (st->active_calls > 0) pthread_cond_wait(&st->users_done, &st->mu);
        pthread_mutex_unlock(&st->mu);
        dht_flush_nodes_to_db(st);
        g_dht = NULL;
        dht_free_state(st);
    }
    pthread_mutex_unlock(&g_dht_mu);
}
