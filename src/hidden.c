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

#include <pthread.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

static void put_u16(uint8_t *p, uint16_t v){ uint16_t n=htons(v); memcpy(p,&n,2); }
static void put_u32(uint8_t *p, uint32_t v){ uint32_t n=htonl(v); memcpy(p,&n,4); }
static uint16_t get_u16(const uint8_t *p){ uint16_t n; memcpy(&n,p,2); return ntohs(n); }
static uint32_t get_u32(const uint8_t *p){ uint32_t n; memcpy(&n,p,4); return ntohl(n); }

static uint32_t epoch_now(void) {
    // 6-hour epochs
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

typedef struct {
    pcomm_config_t cfg;
    pcomm_identity_t me;
    pcomm_db_t *db;

    // cached intro points from last publish
    pcomm_peer_t intros[3];
    size_t intro_count;

    pthread_mutex_t lock;
} hidden_state_t;

static hidden_state_t *g_hidden = NULL;

// Load a random onion path (0..3 relays) excluding specific IDs.
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

// List all known relays (cap limited)
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

    // Prefer long-lived circuit + stream multiplexing when available.
    pcomm_circuit_t *c = pcomm_circuit_get();
    if (c && dest && dest->host[0] && dest->port) {
        pcomm_msg_type_t rt = 0; uint8_t *rp = NULL; uint32_t rpl = 0;
        int rc = pcomm_circuit_rpc(c, dest->host, dest->port, PCOMM_MSG_CTRL,
                                   ctrl_payload, ctrl_len, roundtrip,
                                   &rt, &rp, &rpl);
        if (rc == 0) {
            if (roundtrip) {
                if (rt != PCOMM_MSG_CTRL) { free(rp); return -1; }
                if (resp_payload) *resp_payload = rp; else free(rp);
                if (resp_len) *resp_len = rpl;
            }
            return 0;
        }
        free(rp);
        // fall back to single-shot onions if circuit fails
    }

    // Build a random onion path (up to 3 relays), excluding self and dest.
    pcomm_peer_t path[3];
    size_t path_len = 0;
    load_onion_relays(db, me->user_id, dest->user_id, NULL, path, 3, &path_len);

    if (path_len == 0) {
        // direct
        int fd = net_connect_tcp(dest->host, dest->port);
        if (fd < 0) return -1;
        int rc = pcomm_send_packet(fd, PCOMM_MSG_CTRL, NULL, ctrl_payload, ctrl_len);
        if (rc != 0) { close(fd); return -1; }
        if (roundtrip) {
            pcomm_msg_type_t rtype; uint8_t eph[32]; uint8_t *rp=NULL; uint32_t rpl=0;
            if (pcomm_recv_packet(fd, &rtype, eph, &rp, &rpl) == 0 && rtype == PCOMM_MSG_CTRL) {
                if (resp_payload) *resp_payload = rp; else free(rp);
                if (resp_len) *resp_len = rpl;
                close(fd);
                return 0;
            }
            free(rp);
            close(fd);
            return -1;
        }
        close(fd);
        return 0;
    }

    // Onion deliver to dest with CTRL
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
    if (rc != 0) { close(fd); return -1; }

    if (!roundtrip) {
        close(fd);
        return 0;
    }

    pcomm_msg_type_t rtype; uint8_t eph[32]; uint8_t *rp=NULL; uint32_t rpl=0;
    if (pcomm_recv_packet(fd, &rtype, eph, &rp, &rpl) == 0 && rtype == PCOMM_MSG_CTRL) {
        if (resp_payload) *resp_payload = rp; else free(rp);
        if (resp_len) *resp_len = rpl;
        close(fd);
        return 0;
    }
    free(rp);
    close(fd);
    return -1;
}

static int ctrl_build_desc_get(const uint8_t infohash[20], const uint8_t dkey[32], uint8_t **out, uint32_t *out_len) {
    uint32_t len = 1 + 20 + 32;
    uint8_t *b = (uint8_t*)malloc(len);
    if (!b) return -1;
    uint32_t off = 0;
    b[off++] = (uint8_t)PCOMM_CTRL_DESC_GET;
    memcpy(b + off, infohash, 20); off += 20;
    memcpy(b + off, dkey, 32); off += 32;
    *out = b; *out_len = len;
    return 0;
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

static int parse_desc_resp(const uint8_t *payload, uint32_t payload_len, uint8_t **blob_out, uint32_t *blob_len_out) {
    *blob_out = NULL; *blob_len_out = 0;
    if (!payload || payload_len < 1 + 1 + 4) return -1;
    uint32_t off = 0;
    if (payload[off++] != (uint8_t)PCOMM_CTRL_DESC_RESP) return -1;
    uint8_t ok = payload[off++];
    uint32_t bl = get_u32(payload + off); off += 4;
    if (!ok || payload_len < off + bl) return -1;
    uint8_t *b = (uint8_t*)malloc(bl);
    if (!b) return -1;
    memcpy(b, payload + off, bl);
    *blob_out = b; *blob_len_out = bl;
    return 0;
}

static int parse_descriptor_blob(const uint8_t *blob, uint32_t blob_len, pcomm_peer_t *intros, size_t intros_cap, size_t *intros_len) {
    *intros_len = 0;
    if (!blob || blob_len < 1 + 4 + 1) return -1;
    uint32_t off = 0;
    uint8_t ver = blob[off++];
    if (ver != 1) return -1;
    (void)get_u32(blob + off); off += 4; // epoch
    uint8_t cnt = blob[off++];
    if (cnt > intros_cap) cnt = (uint8_t)intros_cap;

    for (uint8_t i = 0; i < cnt; i++) {
        if (blob_len < off + 2) break;
        uint16_t uid_len = get_u16(blob + off); off += 2;
        if (uid_len == 0 || uid_len > 95 || blob_len < off + uid_len) break;
        char uid[96];
        memcpy(uid, blob + off, uid_len); uid[uid_len] = '\0';
        off += uid_len;

        if (blob_len < off + 1) break;
        uint8_t hlen = blob[off++];
        if (hlen == 0 || hlen > 63 || blob_len < off + hlen + 2 + 32) break;
        char host[64];
        memcpy(host, blob + off, hlen); host[hlen] = '\0';
        off += hlen;
        uint16_t port = get_u16(blob + off); off += 2;
        uint8_t pk[32];
        memcpy(pk, blob + off, 32); off += 32;

        pcomm_peer_t *p = &intros[*intros_len];
        memset(p, 0, sizeof(*p));
        snprintf(p->user_id, sizeof(p->user_id), "%s", uid);
        snprintf(p->host, sizeof(p->host), "%s", host);
        p->port = port;
        memcpy(p->pubkey, pk, 32);
        (*intros_len)++;
    }
    return (*intros_len > 0) ? 0 : -1;
}

static int build_descriptor_blob(uint32_t epoch, const pcomm_peer_t *intros, size_t intro_count, uint8_t **out, uint32_t *out_len) {
    if (!out || !out_len) return -1;
    if (intro_count > 3) intro_count = 3;

    uint32_t len = 1 + 4 + 1;
    for (size_t i = 0; i < intro_count; i++) {
        size_t uid_len = strlen(intros[i].user_id);
        size_t host_len = strlen(intros[i].host);
        len += 2 + (uint32_t)uid_len + 1 + (uint32_t)host_len + 2 + 32;
    }

    uint8_t *b = (uint8_t*)malloc(len);
    if (!b) return -1;
    uint32_t off = 0;
    b[off++] = 1;
    put_u32(b + off, epoch); off += 4;
    b[off++] = (uint8_t)intro_count;
    for (size_t i = 0; i < intro_count; i++) {
        uint16_t uid_len = (uint16_t)strlen(intros[i].user_id);
        uint8_t host_len = (uint8_t)strlen(intros[i].host);
        put_u16(b + off, uid_len); off += 2;
        memcpy(b + off, intros[i].user_id, uid_len); off += uid_len;
        b[off++] = host_len;
        memcpy(b + off, intros[i].host, host_len); off += host_len;
        put_u16(b + off, intros[i].port); off += 2;
        memcpy(b + off, intros[i].pubkey, 32); off += 32;
    }
    if (off != len) { free(b); return -1; }
    *out = b; *out_len = len;
    return 0;
}

static int fetch_descriptor(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                            const char *target_id, uint32_t epoch, pcomm_peer_t *intros, size_t intros_cap, size_t *intros_len) {
    *intros_len = 0;
    uint8_t dkey[32];
    sha256_key("pcomm-desc-v1", target_id, epoch, dkey);

    uint8_t infohash[20];
    pcomm_dht_infohash_desc(target_id, infohash);

    // Prefer DHT-discovered descriptor hosts
    char hosts[8][64]; uint16_t ports[8]; size_t hn = 0;
    if (pcomm_dht_get_peers_hosts(infohash, hosts, ports, 8, &hn) == 0 && hn > 0) {
        for (size_t i = 0; i < hn; i++) {
            pcomm_peer_t dest; memset(&dest, 0, sizeof(dest));
            snprintf(dest.host, sizeof(dest.host), "%s", hosts[i]);
            dest.port = ports[i];

            uint8_t *req = NULL; uint32_t req_len = 0;
            if (ctrl_build_desc_get(infohash, dkey, &req, &req_len) != 0) continue;

            uint8_t *resp = NULL; uint32_t resp_len = 0;
            int rc = onion_send_ctrl(db, cfg, me, &dest, req, req_len, 1, &resp, &resp_len);
            free(req);
            if (rc != 0 || !resp) { free(resp); continue; }

            uint8_t *blob = NULL; uint32_t blob_len = 0;
            if (parse_desc_resp(resp, resp_len, &blob, &blob_len) == 0) {
                if (parse_descriptor_blob(blob, blob_len, intros, intros_cap, intros_len) == 0) {
                    free(blob);
                    free(resp);
                    return 0;
                }
                free(blob);
            }
            free(resp);
        }
    }

    // Fallback: deterministic HSDirs (v2 behavior)
    pcomm_peer_t hs[3]; size_t hs_len = 0;
    if (select_hsdirs(db, target_id, epoch, hs, &hs_len) != 0) return -1;
    for (size_t i = 0; i < hs_len; i++) {
        uint8_t *req = NULL; uint32_t req_len = 0;
        if (ctrl_build_desc_get(infohash, dkey, &req, &req_len) != 0) continue;
        uint8_t *resp = NULL; uint32_t resp_len = 0;
        int rc = onion_send_ctrl(db, cfg, me, &hs[i], req, req_len, 1, &resp, &resp_len);
        free(req);
        if (rc != 0 || !resp) { free(resp); continue; }
        uint8_t *blob = NULL; uint32_t blob_len = 0;
        if (parse_desc_resp(resp, resp_len, &blob, &blob_len) == 0) {
            if (parse_descriptor_blob(blob, blob_len, intros, intros_cap, intros_len) == 0) {
                free(blob);
                free(resp);
                return 0;
            }
            free(blob);
        }
        free(resp);
    }
    return -1;
}

static int publish_descriptor(hidden_state_t *st) {
    uint32_t ep = epoch_now();

    // choose intro points randomly from relays
    pcomm_peer_t rel[3]; size_t rel_n = 0;
    load_onion_relays(st->db, st->me.user_id, NULL, NULL, rel, 3, &rel_n);
    if (rel_n == 0) return -1;

    pthread_mutex_lock(&st->lock);
    st->intro_count = rel_n;
    for (size_t i = 0; i < rel_n; i++) st->intros[i] = rel[i];
    pthread_mutex_unlock(&st->lock);

    uint8_t *blob = NULL; uint32_t blob_len = 0;
    if (build_descriptor_blob(ep, rel, rel_n, &blob, &blob_len) != 0) return -1;

    uint8_t dkey[32];
    sha256_key("pcomm-desc-v1", st->me.user_id, ep, dkey);

    uint8_t infohash[20];
    pcomm_dht_infohash_desc(st->me.user_id, infohash);

    // expires in ~12 hours
    uint32_t expires = (uint32_t)(time(NULL) + 12*3600);

    uint8_t *put = NULL; uint32_t put_len = 0;
    if (ctrl_build_desc_put(infohash, dkey, expires, blob, blob_len, &put, &put_len) != 0) {
        free(blob);
        return -1;
    }

    // Store the descriptor on a few random relays. Those relays will announce themselves in the DHT
    // (BEP-5 announce_peer) under our descriptor infohash.
    for (size_t i = 0; i < rel_n; i++) {
        onion_send_ctrl(st->db, &st->cfg, &st->me, &rel[i], put, put_len, 0, NULL, NULL);
    }

    free(put);
    free(blob);
    return 0;
}

static int parse_mb_resp_items(hidden_state_t *st, const uint8_t *payload, uint32_t payload_len) {
    if (!payload || payload_len < 1 + 2) return -1;
    uint32_t off = 0;
    if (payload[off++] != (uint8_t)PCOMM_CTRL_MB_RESP) return -1;
    if (payload_len < off + 2) return -1;
    uint16_t count = get_u16(payload + off); off += 2;

    for (uint16_t i = 0; i < count; i++) {
        if (payload_len < off + 8 + 4 + 4) break;
        // id (ignored)
        off += 8;
        uint32_t ts = get_u32(payload + off); off += 4;
        uint32_t bl = get_u32(payload + off); off += 4;
        if (payload_len < off + bl) break;
        const uint8_t *sealed = payload + off;
        off += bl;

        uint8_t *plain = NULL; size_t plain_len = 0;
        if (pcomm_open_seal(st->me.privkey, sealed, bl, &plain, &plain_len) != 0) continue;

        pcomm_plain_kind_t kind;
        uint32_t mts = 0;
        char sender[96] = {0};
        char group_uuid[64] = {0};
        char *title = NULL;
        char **members = NULL; int member_count = 0;
        char *text = NULL;

        if (pcomm_msg_unpack_any(plain, plain_len, &kind, &mts, sender, sizeof(sender),
                                 group_uuid, sizeof(group_uuid),
                                 &title, &members, &member_count, &text) == 0) {
            if (kind == PCOMM_PLAIN_DIRECT_TEXT) {
                int64_t conv_id = pcomm_db_get_or_create_direct_conv(st->db, sender);
                if (conv_id >= 0) {
                    pcomm_db_insert_message(st->db, conv_id, 0, sender, sender, text ? text : "", sealed, bl, (int64_t)(mts ? mts : ts));
                }
            } else if (kind == PCOMM_PLAIN_GROUP_INVITE) {
                int64_t conv_id = pcomm_db_get_or_create_group_conv(st->db, group_uuid, title ? title : "");
                if (conv_id >= 0) {
                    // add participants
                    for (int k = 0; k < member_count; k++) {
                        pcomm_db_add_participant(st->db, conv_id, members[k]);
                    }
                    // store as a system message
                    const char *body = title ? title : "Group invite";
                    pcomm_db_insert_message(st->db, conv_id, 0, group_uuid, sender, body, sealed, bl, (int64_t)(mts ? mts : ts));
                }
            } else if (kind == PCOMM_PLAIN_GROUP_TEXT) {
                int64_t conv_id = pcomm_db_get_or_create_group_conv(st->db, group_uuid, NULL);
                if (conv_id >= 0) {
                    pcomm_db_insert_message(st->db, conv_id, 0, group_uuid, sender, text ? text : "", sealed, bl, (int64_t)(mts ? mts : ts));
                }
            }
        }

        free(plain);
        free(title);
        pcomm_msg_free_members(members, member_count);
        free(text);
    }

    return 0;
}

static int poll_mailbox_from_peer(hidden_state_t *st, const pcomm_peer_t *peer, const uint8_t infohash[20], const uint8_t mkey[32]) {
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

static void *sync_thread(void *arg) {
    hidden_state_t *st = (hidden_state_t*)arg;

    for (;;) {
        uint32_t ep = epoch_now();
        uint8_t mkey_now[32];
        sha256_key("pcomm-mb-v1", st->me.user_id, ep, mkey_now);
        uint8_t mkey_prev[32];
        sha256_key("pcomm-mb-v1", st->me.user_id, ep ? (ep-1) : ep, mkey_prev);

        uint8_t infohash[20];
        pcomm_dht_infohash_mb(st->me.user_id, infohash);

        // Prefer DHT-discovered mailbox hosts
        char hosts[8][64]; uint16_t ports[8]; size_t hn = 0;
        if (pcomm_dht_get_peers_hosts(infohash, hosts, ports, 8, &hn) == 0 && hn > 0) {
            for (size_t i = 0; i < hn; i++) {
                pcomm_peer_t p; memset(&p, 0, sizeof(p));
                snprintf(p.host, sizeof(p.host), "%s", hosts[i]);
                p.port = ports[i];
                poll_mailbox_from_peer(st, &p, infohash, mkey_now);
                poll_mailbox_from_peer(st, &p, infohash, mkey_prev);
            }
        } else {
            // Fallback: old HSDir selection
            pcomm_peer_t hs[3]; size_t hs_len = 0;
            if (select_hsdirs(st->db, st->me.user_id, ep, hs, &hs_len) == 0) {
                for (size_t i = 0; i < hs_len; i++) {
                    poll_mailbox_from_peer(st, &hs[i], infohash, mkey_now);
                    poll_mailbox_from_peer(st, &hs[i], infohash, mkey_prev);
                }
            }
        }

        // Also poll intro points from last publish (extra redundancy)
        pthread_mutex_lock(&st->lock);
        pcomm_peer_t intros[3]; size_t intro_n = st->intro_count;
        for (size_t i = 0; i < intro_n; i++) intros[i] = st->intros[i];
        pthread_mutex_unlock(&st->lock);
        for (size_t i = 0; i < intro_n; i++) {
            poll_mailbox_from_peer(st, &intros[i], infohash, mkey_now);
            poll_mailbox_from_peer(st, &intros[i], infohash, mkey_prev);
        }

        sleep(3);
    }
    return NULL;
}

static void *publish_thread(void *arg) {
    hidden_state_t *st = (hidden_state_t*)arg;
    for (;;) {
        publish_descriptor(st);
        sleep(10 * 60);
    }
    return NULL;
}

static void *cover_thread(void *arg) {
    hidden_state_t *st = (hidden_state_t*)arg;
    for (;;) {
        // random jitter 2..6 seconds
        uint8_t r[1];
        pcomm_random(r, 1);
        int delay = 2 + (r[0] % 5);

        // pick a random relay as destination
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

        sleep(delay);
    }
    return NULL;
}

int pcomm_hidden_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db) {
    if (!cfg || !me || !db) return -1;

    hidden_state_t *st = (hidden_state_t*)calloc(1, sizeof(hidden_state_t));
    if (!st) return -1;
    st->cfg = *cfg;
    st->me = *me;
    st->db = db;
    pthread_mutex_init(&st->lock, NULL);

    g_hidden = st;

    pthread_t th1, th2, th3;
    pthread_create(&th1, NULL, publish_thread, st);
    pthread_detach(th1);
    pthread_create(&th2, NULL, sync_thread, st);
    pthread_detach(th2);
    pthread_create(&th3, NULL, cover_thread, st);
    pthread_detach(th3);

    fprintf(stderr, "Hidden-service style mailbox started (publish/sync/cover)\n");
    return 0;
}

int pcomm_hidden_mailbox_send(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                             const char *recipient_id,
                             const uint8_t *sealed, size_t sealed_len) {
    if (!db || !cfg || !me || !recipient_id || !sealed || sealed_len == 0) return -1;

    uint32_t ep = epoch_now();
    uint8_t mkey[32];
    sha256_key("pcomm-mb-v1", recipient_id, ep, mkey);

    uint8_t infohash[20];
    pcomm_dht_infohash_mb(recipient_id, infohash);

    // Try descriptor -> intro points
    pcomm_peer_t intros[3]; size_t intro_n = 0;
    fetch_descriptor(db, cfg, me, recipient_id, ep, intros, 3, &intro_n);

    uint8_t *put = NULL; uint32_t put_len = 0;
    if (ctrl_build_mb_put(infohash, mkey, sealed, (uint32_t)sealed_len, &put, &put_len) != 0) return -1;

    int ok = -1;

    // Prefer DHT-discovered mailbox hosts
    char hosts[8][64]; uint16_t ports[8]; size_t hn = 0;
    if (pcomm_dht_get_peers_hosts(infohash, hosts, ports, 8, &hn) == 0 && hn > 0) {
        size_t send_n = (hn > 3) ? 3 : hn;
        for (size_t i = 0; i < send_n; i++) {
            pcomm_peer_t dest; memset(&dest, 0, sizeof(dest));
            snprintf(dest.host, sizeof(dest.host), "%s", hosts[i]);
            dest.port = ports[i];
            onion_send_ctrl(db, cfg, me, &dest, put, put_len, 0, NULL, NULL);
            ok = 0;
        }
    }

    // Also send to 1 intro point if available (extra redundancy)
    if (intro_n > 0) {
        onion_send_ctrl(db, cfg, me, &intros[0], put, put_len, 0, NULL, NULL);
        ok = 0;
    }

    // Fallback: old deterministic HSDirs
    if (ok != 0) {
        pcomm_peer_t hs[3]; size_t hs_n = 0;
        if (select_hsdirs(db, recipient_id, ep, hs, &hs_n) == 0) {
            for (size_t i = 0; i < hs_n && i < 2; i++) {
                onion_send_ctrl(db, cfg, me, &hs[i], put, put_len, 0, NULL, NULL);
                ok = 0;
            }
        }
    }

    free(put);
    return ok;
}

int pcomm_hidden_send_direct_text(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                                 const char *to_user_id, const char *text) {
    if (!db || !cfg || !me || !to_user_id || !text) return -1;

    // recipient pubkey is self-certifying from the id
    uint8_t recip_pub[32];
    if (pcomm_pubkey_from_user_id(to_user_id, recip_pub) != 0) {
        fprintf(stderr, "Bad recipient id\n");
        return -1;
    }

    uint32_t ts = (uint32_t)time(NULL);

    uint8_t *plain = NULL; size_t plain_len = 0;
    if (pcomm_msg_pack_direct_text(ts, me->user_id, text, &plain, &plain_len) != 0) return -1;

    uint8_t *sealed = NULL; size_t sealed_len = 0;
    if (pcomm_seal_for_recipient(recip_pub, plain, plain_len, &sealed, &sealed_len) != 0) {
        free(plain);
        return -1;
    }
    free(plain);

    int send_rc = pcomm_hidden_mailbox_send(db, cfg, me, to_user_id, sealed, sealed_len);

    // Store outbound (direct)
    int64_t conv_id = pcomm_db_get_or_create_direct_conv(db, to_user_id);
    if (conv_id >= 0) {
        pcomm_db_insert_message(db, conv_id, 1, to_user_id, me->user_id, text, sealed, sealed_len, (int64_t)ts);
    }

    free(sealed);
    return send_rc;
}

int pcomm_hidden_send_group_invite(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                                  const char *member_id,
                                  const char *group_uuid, const char *title,
                                  char **members, int member_count) {
    if (!db || !cfg || !me || !member_id || !group_uuid) return -1;

    uint8_t recip_pub[32];
    if (pcomm_pubkey_from_user_id(member_id, recip_pub) != 0) return -1;

    uint32_t ts = (uint32_t)time(NULL);
    uint8_t *plain = NULL; size_t plain_len = 0;
    if (pcomm_msg_pack_group_invite(ts, me->user_id, group_uuid, title, members, member_count, &plain, &plain_len) != 0) return -1;

    uint8_t *sealed = NULL; size_t sealed_len = 0;
    if (pcomm_seal_for_recipient(recip_pub, plain, plain_len, &sealed, &sealed_len) != 0) {
        free(plain);
        return -1;
    }
    free(plain);

    int rc = pcomm_hidden_mailbox_send(db, cfg, me, member_id, sealed, sealed_len);
    free(sealed);
    return rc;
}

int pcomm_hidden_send_group_text(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                                const char *member_id,
                                const char *group_uuid, const char *text) {
    if (!db || !cfg || !me || !member_id || !group_uuid || !text) return -1;

    uint8_t recip_pub[32];
    if (pcomm_pubkey_from_user_id(member_id, recip_pub) != 0) return -1;

    uint32_t ts = (uint32_t)time(NULL);
    uint8_t *plain = NULL; size_t plain_len = 0;
    if (pcomm_msg_pack_group_text(ts, me->user_id, group_uuid, text, &plain, &plain_len) != 0) return -1;

    uint8_t *sealed = NULL; size_t sealed_len = 0;
    if (pcomm_seal_for_recipient(recip_pub, plain, plain_len, &sealed, &sealed_len) != 0) {
        free(plain);
        return -1;
    }
    free(plain);

    int rc = pcomm_hidden_mailbox_send(db, cfg, me, member_id, sealed, sealed_len);
    free(sealed);
    return rc;
}
