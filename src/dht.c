#define _GNU_SOURCE
#include "dht.h"
#include "bencode.h"
#include "crypto.h"

#include <pthread.h>
#include <openssl/sha.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>

#define DHT_MAX_NODES 512
#define DHT_QUERY_FANOUT 24
#define DHT_MAX_QUERIES 64

typedef struct {
    uint8_t id[20];
    struct sockaddr_in addr;
    time_t last_seen;
} dht_node_t;

typedef struct peer_item {
    uint8_t infohash[20];
    uint8_t *peers; // compact peers concatenated (6*n)
    size_t peers_len;
    struct peer_item *next;
} peer_item_t;

typedef struct {
    uint16_t tx;
    int used;
    int done;
    benc_t *resp;
    pthread_cond_t cv;
} pending_t;

typedef struct {
    int udp_fd;
    uint8_t node_id[20];
    uint8_t secret[20];
    uint16_t listen_port;

    pthread_t th;
    pthread_mutex_t mu;

    dht_node_t nodes[DHT_MAX_NODES];
    size_t nodes_len;

    peer_item_t *peers_head;

    pending_t pending[DHT_MAX_QUERIES];

    pcomm_db_t *db;
} dht_state_t;

static dht_state_t *g_dht = NULL;

static void sha1_bytes(const uint8_t *in, size_t in_len, uint8_t out20[20]) {
    SHA_CTX c;
    SHA1_Init(&c);
    SHA1_Update(&c, in, in_len);
    SHA1_Final(out20, &c);
}

void pcomm_dht_infohash_desc(const char *user_id, uint8_t out20[20]) {
    // BEP-5 uses SHA1 infohash; we scope ours with a tag.
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
    // DHT node id derived from identity pubkey (stable) + tag.
    uint8_t buf[64];
    memcpy(buf, "pcomm-dht", 9);
    memcpy(buf + 9, me->pubkey, 32);
    sha1_bytes(buf, 41, out20);
}

static void token_for_ip(const uint8_t secret[20], const struct sockaddr_in *addr, uint8_t out4[4]) {
    // token = first 4 bytes of SHA1(secret || ip || timebucket)
    uint8_t buf[64];
    size_t n = 0;
    memcpy(buf + n, secret, 20); n += 20;
    memcpy(buf + n, &addr->sin_addr, 4); n += 4;
    uint32_t bucket = (uint32_t)(time(NULL) / 300); // 5 minutes
    bucket = htonl(bucket);
    memcpy(buf + n, &bucket, 4); n += 4;
    uint8_t h[20];
    sha1_bytes(buf, n, h);
    memcpy(out4, h, 4);
}

static int addr_eq(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

static void add_node_locked(dht_state_t *st, const uint8_t id[20], const struct sockaddr_in *addr) {
    if (!addr || addr->sin_port == 0) return;
    // ignore 0.0.0.0
    if (addr->sin_addr.s_addr == 0) return;

    for (size_t i=0;i<st->nodes_len;i++) {
        if (addr_eq(&st->nodes[i].addr, addr)) {
            if (id) memcpy(st->nodes[i].id, id, 20);
            st->nodes[i].last_seen = time(NULL);
            return;
        }
    }
    if (st->nodes_len >= DHT_MAX_NODES) return;
    dht_node_t *n = &st->nodes[st->nodes_len++];
    memset(n, 0, sizeof(*n));
    if (id) memcpy(n->id, id, 20);
    n->addr = *addr;
    n->last_seen = time(NULL);
}

static void peers_add_locked(dht_state_t *st, const uint8_t infohash[20], const uint8_t compact6[6]) {
    // find bucket by first byte
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
    // dedupe
    for (size_t i=0;i+6<=it->peers_len;i+=6) {
        if (memcmp(it->peers + i, compact6, 6) == 0) return;
    }
    if (it->peers_len >= 6*64) return; // cap
    uint8_t *nb = (uint8_t*)realloc(it->peers, it->peers_len + 6);
    if (!nb) return;
    it->peers = nb;
    memcpy(it->peers + it->peers_len, compact6, 6);
    it->peers_len += 6;
}

static int peers_get_locked(dht_state_t *st, const uint8_t infohash[20], uint8_t **out, size_t *out_len) {
    *out = NULL; *out_len = 0;
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
    for (int i=0;i<DHT_MAX_QUERIES;i++) {
        if (!st->pending[i].used) {
            st->pending[i].used = 1;
            st->pending[i].done = 0;
            st->pending[i].tx = tx;
            st->pending[i].resp = NULL;
            pthread_cond_init(&st->pending[i].cv, NULL);
            return &st->pending[i];
        }
    }
    return NULL;
}

static pending_t *pending_find_locked(dht_state_t *st, uint16_t tx) {
    for (int i=0;i<DHT_MAX_QUERIES;i++) if (st->pending[i].used && st->pending[i].tx == tx) return &st->pending[i];
    return NULL;
}

static void pending_free_locked(pending_t *p) {
    if (!p) return;
    benc_free(p->resp);
    p->resp = NULL;
    pthread_cond_destroy(&p->cv);
    p->used = 0;
    p->done = 0;
    p->tx = 0;
}

static int send_krpc(dht_state_t *st, const struct sockaddr_in *to, const benc_t *msg) {
    uint8_t *buf=NULL; size_t len=0;
    if (benc_encode(msg, &buf, &len) != 0) return -1;
    int rc = (sendto(st->udp_fd, buf, len, 0, (const struct sockaddr*)to, sizeof(*to)) == (ssize_t)len) ? 0 : -1;
    free(buf);
    return rc;
}

static uint16_t rand_tx(void) {
    uint8_t r[2];
    pcomm_random(r, 2);
    return (uint16_t)((r[0] << 8) | r[1]);
}

static benc_t *krpc_build_query(dht_state_t *st, uint16_t tx, const char *q, benc_t *a) {
    benc_t *m = benc_new_dict();
    if (!m) return NULL;
    uint8_t txb[2] = {(uint8_t)(tx>>8), (uint8_t)(tx&0xFF)};
    benc_dict_set(m, "t", benc_new_str(txb, 2));
    benc_dict_set(m, "y", benc_new_str((const uint8_t*)"q", 1));
    benc_dict_set(m, "q", benc_new_str((const uint8_t*)q, strlen(q)));

    if (!a) a = benc_new_dict();
    benc_dict_set(a, "id", benc_new_str(st->node_id, 20));
    benc_dict_set(m, "a", a);
    return m;
}

static benc_t *krpc_build_resp(dht_state_t *st, const uint8_t txb[2], benc_t *r) {
    benc_t *m = benc_new_dict();
    if (!m) return NULL;
    benc_dict_set(m, "t", benc_new_str(txb, 2));
    benc_dict_set(m, "y", benc_new_str((const uint8_t*)"r", 1));
    if (!r) r = benc_new_dict();
    benc_dict_set(r, "id", benc_new_str(st->node_id, 20));
    benc_dict_set(m, "r", r);
    return m;
}

static void compact_nodes_locked(dht_state_t *st, uint8_t **out, size_t *out_len) {
    // up to 8 nodes
    size_t want = st->nodes_len < 8 ? st->nodes_len : 8;
    size_t len = want * 26;
    uint8_t *b = (uint8_t*)malloc(len);
    if (!b) { *out=NULL; *out_len=0; return; }
    size_t o=0;
    for (size_t i=0;i<want;i++) {
        memcpy(b+o, st->nodes[i].id, 20); o+=20;
        memcpy(b+o, &st->nodes[i].addr.sin_addr, 4); o+=4;
        memcpy(b+o, &st->nodes[i].addr.sin_port, 2); o+=2;
    }
    *out = b;
    *out_len = len;
}

static void handle_query(dht_state_t *st, const struct sockaddr_in *from, benc_t *msg) {
    benc_t *t = benc_dict_get(msg, "t");
    benc_t *q = benc_dict_get(msg, "q");
    benc_t *a = benc_dict_get(msg, "a");
    if (!t || t->t != BENC_STR || t->slen != 2 || !q || q->t != BENC_STR) return;

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
    size_t qn = q->slen < sizeof(qname)-1 ? q->slen : sizeof(qname)-1;
    memcpy(qname, q->s, qn);

    if (strcmp(qname, "ping") == 0) {
        benc_t *r = benc_new_dict();
        benc_t *resp = krpc_build_resp(st, t->s, r);
        send_krpc(st, from, resp);
        benc_free(resp);
        return;
    }

    if (strcmp(qname, "find_node") == 0 || strcmp(qname, "get_peers") == 0) {
        benc_t *r = benc_new_dict();
        uint8_t *nodes=NULL; size_t nodes_len=0;
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

                // if we have peers, include values
                pthread_mutex_lock(&st->mu);
                uint8_t *vals=NULL; size_t vlen=0;
                int ok = peers_get_locked(st, ih->s, &vals, &vlen);
                pthread_mutex_unlock(&st->mu);
                if (ok == 0 && vlen >= 6) {
                    benc_t *lst = benc_new_list();
                    for (size_t i=0;i+6<=vlen;i+=6) {
                        benc_list_add(lst, benc_new_str(vals+i, 6));
                    }
                    benc_dict_set(r, "values", lst);
                    free(vals);
                }
            }
        }

        benc_t *resp = krpc_build_resp(st, t->s, r);
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
                // add announcing peer address
                uint16_t p = (uint16_t)port->i;
                uint8_t comp[6];
                memcpy(comp, &from->sin_addr, 4);
                uint16_t np = htons(p);
                memcpy(comp+4, &np, 2);
                pthread_mutex_lock(&st->mu);
                peers_add_locked(st, ih->s, comp);
                pthread_mutex_unlock(&st->mu);
            }
        }
        benc_t *resp = krpc_build_resp(st, t->s, benc_new_dict());
        send_krpc(st, from, resp);
        benc_free(resp);
        return;
    }

    // unknown query
    benc_t *resp = krpc_build_resp(st, t->s, benc_new_dict());
    send_krpc(st, from, resp);
    benc_free(resp);
}

static void handle_response(dht_state_t *st, benc_t *msg) {
    benc_t *t = benc_dict_get(msg, "t");
    if (!t || t->t != BENC_STR || t->slen != 2) return;
    uint16_t tx = (uint16_t)((t->s[0] << 8) | t->s[1]);

    pthread_mutex_lock(&st->mu);
    pending_t *p = pending_find_locked(st, tx);
    if (p) {
        p->resp = msg;
        p->done = 1;
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&st->mu);
        return;
    }
    pthread_mutex_unlock(&st->mu);
    // no pending; free
    benc_free(msg);
}

static void *dht_thread(void *arg) {
    dht_state_t *st = (dht_state_t*)arg;
    uint8_t buf[4096];

    while (1) {
        struct sockaddr_in from; socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(st->udp_fd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
        if (n <= 0) continue;

        benc_t *msg = NULL; size_t used=0;
        if (benc_parse(buf, (size_t)n, &msg, &used) != 0 || !msg || msg->t != BENC_DICT) {
            benc_free(msg);
            continue;
        }
        benc_t *y = benc_dict_get(msg, "y");
        if (!y || y->t != BENC_STR || y->slen < 1) { benc_free(msg); continue; }
        if (y->slen == 1 && y->s[0] == 'q') {
            handle_query(st, &from, msg);
            benc_free(msg);
        } else if (y->slen == 1 && y->s[0] == 'r') {
            // response is handed to pending (takes ownership)
            handle_response(st, msg);
        } else {
            benc_free(msg);
        }
    }
    return NULL;
}

static int load_bootstrap_from_db(dht_state_t *st) {
    const char *sql = "SELECT host, port, pubkey FROM contacts WHERE is_relay=1 AND host!='' AND port>0 LIMIT 200;";
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(st->db->db, sql, -1, &q, NULL) != SQLITE_OK) return -1;

    while (sqlite3_step(q) == SQLITE_ROW) {
        const char *host = (const char*)sqlite3_column_text(q, 0);
        int port = sqlite3_column_int(q, 1);
        const void *pk = sqlite3_column_blob(q, 2);
        int pklen = sqlite3_column_bytes(q, 2);
        if (!host || port <= 0 || port > 65535 || pklen != 32) continue;
        struct sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, host, &a.sin_addr) != 1) continue;
        uint8_t nid[20];
        sha1_bytes((const uint8_t*)pk, 32, nid);
        pthread_mutex_lock(&st->mu);
        add_node_locked(st, nid, &a);
        pthread_mutex_unlock(&st->mu);
    }

    sqlite3_finalize(q);
    return 0;
}

static int krpc_query_one(dht_state_t *st, const struct sockaddr_in *to, benc_t *query, benc_t **resp_out) {
    *resp_out = NULL;
    benc_t *t = benc_dict_get(query, "t");
    if (!t || t->t != BENC_STR || t->slen != 2) return -1;
    uint16_t tx = (uint16_t)((t->s[0] << 8) | t->s[1]);

    pthread_mutex_lock(&st->mu);
    pending_t *p = pending_alloc_locked(st, tx);
    pthread_mutex_unlock(&st->mu);
    if (!p) return -1;

    if (send_krpc(st, to, query) != 0) {
        pthread_mutex_lock(&st->mu);
        pending_free_locked(p);
        pthread_mutex_unlock(&st->mu);
        return -1;
    }

    // wait up to 900ms
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 900 * 1000 * 1000;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }

    pthread_mutex_lock(&st->mu);
    while (!p->done) {
        if (pthread_cond_timedwait(&p->cv, &st->mu, &ts) == ETIMEDOUT) break;
    }
    if (p->done && p->resp) {
        *resp_out = p->resp;
        p->resp = NULL;
    }
    pending_free_locked(p);
    pthread_mutex_unlock(&st->mu);

    return (*resp_out) ? 0 : -1;
}

static void parse_nodes_into_state(dht_state_t *st, const uint8_t *nodes, size_t nodes_len) {
    if (!nodes || nodes_len % 26 != 0) return;
    for (size_t i=0;i+26<=nodes_len;i+=26) {
        uint8_t nid[20];
        memcpy(nid, nodes+i, 20);
        struct sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        memcpy(&a.sin_addr, nodes+i+20, 4);
        memcpy(&a.sin_port, nodes+i+24, 2);
        pthread_mutex_lock(&st->mu);
        add_node_locked(st, nid, &a);
        pthread_mutex_unlock(&st->mu);
    }
}

int pcomm_dht_get_peers_hosts(const uint8_t infohash20[20],
                             char (*hosts)[64], uint16_t *ports,
                             size_t cap, size_t *out_len) {
    if (!g_dht || !hosts || !ports || !out_len) return -1;
    *out_len = 0;

    // Seed worklist from known nodes
    struct sockaddr_in work[128];
    size_t wlen = 0;
    pthread_mutex_lock(&g_dht->mu);
    size_t take = g_dht->nodes_len < DHT_QUERY_FANOUT ? g_dht->nodes_len : DHT_QUERY_FANOUT;
    for (size_t i=0;i<take;i++) work[wlen++] = g_dht->nodes[i].addr;
    pthread_mutex_unlock(&g_dht->mu);

    size_t queried = 0;
    for (size_t wi=0; wi<wlen && queried < 64 && *out_len < cap; wi++, queried++) {
        uint16_t tx = rand_tx();
        benc_t *a = benc_new_dict();
        benc_dict_set(a, "info_hash", benc_new_str(infohash20, 20));
        benc_t *q = krpc_build_query(g_dht, tx, "get_peers", a);
        if (!q) continue;

        benc_t *resp = NULL;
        if (krpc_query_one(g_dht, &work[wi], q, &resp) == 0 && resp) {
            benc_t *r = benc_dict_get(resp, "r");
            if (r && r->t == BENC_DICT) {
                benc_t *vals = benc_dict_get(r, "values");
                if (vals && vals->t == BENC_LIST) {
                    for (size_t i=0;i<vals->list_len && *out_len < cap;i++) {
                        benc_t *s = vals->list[i];
                        if (!s || s->t != BENC_STR || s->slen != 6) continue;
                        struct in_addr ip; memcpy(&ip, s->s, 4);
                        uint16_t p; memcpy(&p, s->s+4, 2); p = ntohs(p);
                        const char *ipstr = inet_ntoa(ip);
                        snprintf(hosts[*out_len], 64, "%s", ipstr);
                        ports[*out_len] = p;
                        (*out_len)++;
                    }
                }
                benc_t *nodes = benc_dict_get(r, "nodes");
                if (nodes && nodes->t == BENC_STR && nodes->slen >= 26) {
                    parse_nodes_into_state(g_dht, nodes->s, nodes->slen);
                    // also add a few to worklist (depth 2)
                    if (wlen < 128) {
                        size_t can = (128 - wlen);
                        size_t add = nodes->slen / 26;
                        if (add > can) add = can;
                        for (size_t i=0;i<add;i++) {
                            struct sockaddr_in a2; memset(&a2,0,sizeof(a2));
                            a2.sin_family = AF_INET;
                            memcpy(&a2.sin_addr, nodes->s + i*26 + 20, 4);
                            memcpy(&a2.sin_port, nodes->s + i*26 + 24, 2);
                            work[wlen++] = a2;
                        }
                    }
                }
            }
            benc_free(resp);
        }
        benc_free(q);
    }

    return (*out_len > 0) ? 0 : -1;
}

int pcomm_dht_announce(const uint8_t infohash20[20], uint16_t port) {
    if (!g_dht) return -1;

    // For each known node: get_peers to obtain token, then announce_peer.
    struct sockaddr_in nodes[DHT_QUERY_FANOUT];
    size_t nlen = 0;
    pthread_mutex_lock(&g_dht->mu);
    size_t take = g_dht->nodes_len < DHT_QUERY_FANOUT ? g_dht->nodes_len : DHT_QUERY_FANOUT;
    for (size_t i=0;i<take;i++) nodes[nlen++] = g_dht->nodes[i].addr;
    pthread_mutex_unlock(&g_dht->mu);

    for (size_t i=0;i<nlen;i++) {
        uint16_t tx = rand_tx();
        benc_t *a = benc_new_dict();
        benc_dict_set(a, "info_hash", benc_new_str(infohash20, 20));
        benc_t *q = krpc_build_query(g_dht, tx, "get_peers", a);
        if (!q) continue;

        benc_t *resp = NULL;
        uint8_t tok[4]; memset(tok,0,4);
        if (krpc_query_one(g_dht, &nodes[i], q, &resp) == 0 && resp) {
            benc_t *r = benc_dict_get(resp, "r");
            if (r && r->t == BENC_DICT) {
                benc_t *tkn = benc_dict_get(r, "token");
                if (tkn && tkn->t == BENC_STR && tkn->slen == 4) memcpy(tok, tkn->s, 4);
                benc_t *nds = benc_dict_get(r, "nodes");
                if (nds && nds->t == BENC_STR && nds->slen >= 26) parse_nodes_into_state(g_dht, nds->s, nds->slen);
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
        benc_t *q2 = krpc_build_query(g_dht, tx2, "announce_peer", a2);
        if (!q2) continue;
        benc_t *resp2=NULL;
        krpc_query_one(g_dht, &nodes[i], q2, &resp2);
        benc_free(resp2);
        benc_free(q2);
    }

    return 0;
}

int pcomm_dht_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db) {
    if (!cfg || !me || !db) return -1;
    if (g_dht) return 0;

    dht_state_t *st = (dht_state_t*)calloc(1, sizeof(dht_state_t));
    if (!st) return -1;
    pthread_mutex_init(&st->mu, NULL);
    st->db = db;
    st->listen_port = cfg->relay_port;

    compute_node_id(me, st->node_id);
    pcomm_random(st->secret, sizeof(st->secret));

    st->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (st->udp_fd < 0) { free(st); return -1; }

    int yes = 1;
    setsockopt(st->udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(cfg->relay_port);
    if (bind(st->udp_fd, (struct sockaddr*)&a, sizeof(a)) != 0) {
        close(st->udp_fd);
        free(st);
        return -1;
    }

    // bootstrap from DB
    load_bootstrap_from_db(st);

    if (pthread_create(&st->th, NULL, dht_thread, st) != 0) {
        close(st->udp_fd);
        free(st);
        return -1;
    }

    g_dht = st;
    fprintf(stderr, "[dht] started on UDP %u\n", (unsigned)cfg->relay_port);
    return 0;
}
