#include "relay.h"
#include "net.h"
#include "proto.h"
#include "onion.h"
#include "crypto.h"
#include "msg.h"
#include "identity.h"
#include "db.h"
#include "cell.h"
#include "dht.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <sys/select.h>

typedef struct intro_reg intro_reg_t;
typedef struct rdv_reg rdv_reg_t;
typedef struct {
    pcomm_config_t cfg;
    pcomm_identity_t id;
    pcomm_db_t *db;
    int listen_fd;

    // Hidden-service intro/rendezvous registries (shared across cell-loop threads)
    pthread_mutex_t hs_mu;
    intro_reg_t *intro_regs;
    rdv_reg_t *rdv_regs;
    uint64_t next_conn_id;
} relay_state_t;

typedef struct {
    relay_state_t *st;
    int fd;
} conn_arg_t;

static void put_u16(uint8_t *p, uint16_t v){ uint16_t n=htons(v); memcpy(p,&n,2); }
static void put_u32(uint8_t *p, uint32_t v){ uint32_t n=htonl(v); memcpy(p,&n,4); }
static uint16_t get_u16(const uint8_t *p){ uint16_t n; memcpy(&n,p,2); return ntohs(n); }
static uint32_t get_u32(const uint8_t *p){ uint32_t n; memcpy(&n,p,4); return ntohl(n); }

static int ctrl_send_peers_resp(relay_state_t *st, int fd, uint16_t want) {
    if (want == 0) want = 32;
    if (want > 200) want = 200;

    const char *sql = "SELECT user_id, host, port, pubkey FROM contacts WHERE is_relay=1 AND host!='' AND port>0 ORDER BY added_at DESC LIMIT ?;";
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(st->db->db, sql, -1, &q, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(q, 1, (int)want);

    // First pass: count and size
    struct item { const char *uid; const char *host; int port; const void *pk; int pklen; } items[200];
    int count = 0;
    size_t total = 1 + 2; // cmd + count

    while (sqlite3_step(q) == SQLITE_ROW && count < (int)want) {
        const char *uid = (const char*)sqlite3_column_text(q, 0);
        const char *host = (const char*)sqlite3_column_text(q, 1);
        int port = sqlite3_column_int(q, 2);
        const void *pk = sqlite3_column_blob(q, 3);
        int pklen = sqlite3_column_bytes(q, 3);
        if (!uid || !host || pklen != 32 || port <= 0 || port > 65535) continue;
        items[count].uid = uid;
        items[count].host = host;
        items[count].port = port;
        items[count].pk = pk;
        items[count].pklen = pklen;
        size_t uid_len = strlen(uid);
        size_t host_len = strlen(host);
        if (uid_len > 95 || host_len > 63) continue;
        total += 2 + uid_len + 1 + host_len + 2 + 32;
        count++;
    }

    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) { sqlite3_finalize(q); return -1; }

    size_t off = 0;
    buf[off++] = (uint8_t)PCOMM_CTRL_PEERS_RESP;
    put_u16(buf + off, (uint16_t)count); off += 2;

    for (int i = 0; i < count; i++) {
        uint16_t uid_len = (uint16_t)strlen(items[i].uid);
        uint8_t host_len = (uint8_t)strlen(items[i].host);
        put_u16(buf + off, uid_len); off += 2;
        memcpy(buf + off, items[i].uid, uid_len); off += uid_len;
        buf[off++] = host_len;
        memcpy(buf + off, items[i].host, host_len); off += host_len;
        put_u16(buf + off, (uint16_t)items[i].port); off += 2;
        memcpy(buf + off, items[i].pk, 32); off += 32;
    }

    sqlite3_finalize(q);

    int rc = pcomm_send_packet(fd, PCOMM_MSG_CTRL, NULL, buf, (uint32_t)off);
    free(buf);
    return rc;
}

static int ctrl_handle(relay_state_t *st, int fd, const uint8_t *payload, uint32_t payload_len) {
    if (!payload || payload_len < 1) return -1;
    uint32_t off = 0;
    uint8_t cmd = payload[off++];

    if (cmd == PCOMM_CTRL_HELLO) {
        if (payload_len < off + 2) return 0;
        uint16_t uid_len = get_u16(payload + off); off += 2;
        if (uid_len == 0 || uid_len > 95 || payload_len < off + uid_len + 1) return 0;
        char uid[96];
        memcpy(uid, payload + off, uid_len); uid[uid_len] = '\0';
        off += uid_len;

        uint8_t hlen = payload[off++];
        if (hlen == 0 || hlen > 63 || payload_len < off + hlen + 2 + 32) return 0;
        char host[64];
        memcpy(host, payload + off, hlen); host[hlen] = '\0';
        off += hlen;

        uint16_t port = get_u16(payload + off); off += 2;
        uint8_t pk[32];
        memcpy(pk, payload + off, 32);

        // verify
        char derived[96];
        if (pcomm_user_id_from_pubkey(pk, derived) != 0) return 0;
        if (strcmp(uid, derived) != 0) return 0;

        pcomm_db_upsert_contact(st->db, uid, host, port, pk, 1);
        return 0;
    }

    if (cmd == PCOMM_CTRL_PEERS_REQ) {
        if (payload_len < off + 2) return 0;
        uint16_t want = get_u16(payload + off);
        return ctrl_send_peers_resp(st, fd, want);
    }

    if (cmd == PCOMM_CTRL_DESC_PUT) {
        // payload: cmd(1) infohash(20) dkey(32) expires(4) bloblen(4) blob
        if (payload_len < off + 20 + 32 + 4 + 4) return 0;
        uint8_t infohash[20];
        memcpy(infohash, payload + off, 20); off += 20;
        uint8_t dkey[32];
        memcpy(dkey, payload + off, 32); off += 32;
        uint32_t expires = get_u32(payload + off); off += 4;
        uint32_t bl = get_u32(payload + off); off += 4;
        if (payload_len < off + bl) return 0;
        int64_t now = (int64_t)time(NULL);
        pcomm_db_desc_put(st->db, dkey, payload + off, bl, (int64_t)expires, now);
        // announce ourselves as a descriptor host
        pcomm_dht_announce(infohash, st->cfg.relay_port);
        return 0;
    }

    if (cmd == PCOMM_CTRL_DESC_GET) {
        // payload: cmd(1) infohash(20) dkey(32)
        if (payload_len < off + 20 + 32) return 0;
        // infohash unused for get
        off += 20;
        uint8_t dkey[32];
        memcpy(dkey, payload + off, 32);

        uint8_t *blob = NULL; uint32_t bl = 0;
        int ok = (pcomm_db_desc_get(st->db, dkey, &blob, &bl) == 0) ? 1 : 0;

        uint32_t resp_len = 1 + 1 + 4 + (ok ? bl : 0);
        uint8_t *resp = (uint8_t*)malloc(resp_len);
        if (!resp) { free(blob); return -1; }
        uint32_t ro = 0;
        resp[ro++] = (uint8_t)PCOMM_CTRL_DESC_RESP;
        resp[ro++] = (uint8_t)ok;
        put_u32(resp + ro, ok ? bl : 0); ro += 4;
        if (ok && bl) {
            memcpy(resp + ro, blob, bl);
            ro += bl;
        }
        free(blob);
        pcomm_send_packet(fd, PCOMM_MSG_CTRL, NULL, resp, ro);
        free(resp);
        return 0;
    }

    if (cmd == PCOMM_CTRL_MB_PUT) {
        // payload: cmd(1) infohash(20) mkey(32) bloblen(4) blob
        if (payload_len < off + 20 + 32 + 4) return 0;
        uint8_t infohash[20];
        memcpy(infohash, payload + off, 20); off += 20;
        uint8_t mkey[32];
        memcpy(mkey, payload + off, 32); off += 32;
        uint32_t bl = get_u32(payload + off); off += 4;
        if (payload_len < off + bl) return 0;
        int64_t now = (int64_t)time(NULL);
        pcomm_db_mailbox_put(st->db, mkey, payload + off, bl, now);
        // announce ourselves as a mailbox host
        pcomm_dht_announce(infohash, st->cfg.relay_port);
        return 0;
    }

    if (cmd == PCOMM_CTRL_MB_GET) {
        // payload: cmd(1) infohash(20) mkey(32)
        if (payload_len < off + 20 + 32) return 0;
        off += 20;
        uint8_t mkey[32];
        memcpy(mkey, payload + off, 32);

        uint8_t *body = NULL; uint32_t body_len = 0;
        if (pcomm_db_mailbox_get_and_delete(st->db, mkey, &body, &body_len) != 0) {
            // empty response
            body = (uint8_t*)malloc(2);
            if (!body) return -1;
            body[0] = 0; body[1] = 0;
            body_len = 2;
        }

        uint32_t resp_len = 1 + body_len;
        uint8_t *resp = (uint8_t*)malloc(resp_len);
        if (!resp) { free(body); return -1; }
        resp[0] = (uint8_t)PCOMM_CTRL_MB_RESP;
        memcpy(resp + 1, body, body_len);
        pcomm_send_packet(fd, PCOMM_MSG_CTRL, NULL, resp, resp_len);
        free(resp);
        free(body);
        return 0;
    }

    // NOOP or unknown
    return 0;
}


// ---- Long-lived circuits (CELL) ----

typedef struct out_item {
    uint8_t *plain;
    uint16_t plain_len;
    struct out_item *next;
} out_item_t;

typedef struct cell_conn cell_conn_t;

struct intro_reg {
    char service_id[96];
    cell_conn_t *cc; // acquired ref
    time_t added;
    intro_reg_t *next;
};

struct rdv_reg {
    uint8_t cookie[20];
    cell_conn_t *cc; // acquired ref
    time_t added;
    rdv_reg_t *next;
};

struct cell_conn {
    relay_state_t *st;
    uint64_t conn_id;

    int up_fd;
    int down_fd; // -1 if exit
    int built;
    uint8_t k_fwd[32];
    uint8_t k_bwd[32];

    // rendezvous join (if set, this exit is a rendezvous point and forwards)
    cell_conn_t *rdv_partner; // acquired ref
    uint8_t rdv_cookie[20];

    // outgoing upstream queue (for cross-thread delivery to this circuit's client)
    pthread_mutex_t qmu;
    out_item_t *qhead;
    out_item_t *qtail;

    // lifecycle
    int closed;
    int refcnt;

    // exit-side stream buffering (TCP exit mode; not used when rdv_partner != NULL)
    struct {
        uint16_t id;
        int used;
        int expect_resp;
        char host[64];
        uint16_t port;
        uint8_t *req;
        uint32_t req_len;
    } streams[32];
};

static void cc_acquire(cell_conn_t *cc) {
    __sync_add_and_fetch(&cc->refcnt, 1);
}

static void cc_release(cell_conn_t *cc) {
    if (!cc) return;
    int rc = __sync_sub_and_fetch(&cc->refcnt, 1);
    if (rc == 0 && cc->closed) {
        // final free
        for (int i=0;i<32;i++) free(cc->streams[i].req);
        pthread_mutex_lock(&cc->qmu);
        out_item_t *it = cc->qhead;
        while (it) {
            out_item_t *n = it->next;
            free(it->plain);
            free(it);
            it = n;
        }
        cc->qhead = cc->qtail = NULL;
        pthread_mutex_unlock(&cc->qmu);
        pthread_mutex_destroy(&cc->qmu);
        free(cc);
    }
}

static int cc_enqueue_up_plain(cell_conn_t *cc, const uint8_t *plain, uint16_t plain_len) {
    if (!cc || !plain || plain_len == 0) return -1;
    cc_acquire(cc);
    pthread_mutex_lock(&cc->qmu);
    if (cc->closed) {
        pthread_mutex_unlock(&cc->qmu);
        cc_release(cc);
        return -1;
    }
    out_item_t *it = (out_item_t*)calloc(1, sizeof(out_item_t));
    if (!it) {
        pthread_mutex_unlock(&cc->qmu);
        cc_release(cc);
        return -1;
    }
    it->plain = (uint8_t*)malloc(plain_len);
    if (!it->plain) {
        free(it);
        pthread_mutex_unlock(&cc->qmu);
        cc_release(cc);
        return -1;
    }
    memcpy(it->plain, plain, plain_len);
    it->plain_len = plain_len;

    if (!cc->qtail) {
        cc->qhead = cc->qtail = it;
    } else {
        cc->qtail->next = it;
        cc->qtail = it;
    }
    pthread_mutex_unlock(&cc->qmu);
    cc_release(cc);
    return 0;
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

static int send_cell_link(int fd, uint8_t cmd, const uint8_t *payload, uint16_t payload_len) {
    uint8_t *cell = NULL; uint32_t cell_len = 0;
    if (pcomm_cell_pack(1, cmd, 0, payload, payload_len, &cell, &cell_len) != 0) return -1;
    int rc = pcomm_send_packet(fd, PCOMM_MSG_CELL, NULL, cell, cell_len);
    free(cell);
    return rc;
}

static int recv_cell_link(int fd, uint8_t *cmd_out, uint8_t **payload_out, uint16_t *payload_len_out) {
    *payload_out = NULL; *payload_len_out = 0; *cmd_out = 0;
    pcomm_msg_type_t t; uint8_t eph[32]; uint8_t *p=NULL; uint32_t pl=0;
    if (pcomm_recv_packet(fd, &t, eph, &p, &pl) != 0) { free(p); return -1; }
    if (t != PCOMM_MSG_CELL) { free(p); return -1; }
    uint32_t cid; uint8_t cmd, flags; const uint8_t *cpl; uint16_t cpll;
    if (pcomm_cell_unpack(p, pl, &cid, &cmd, &flags, &cpl, &cpll) != 0 || cid != 1) { free(p); return -1; }
    (void)flags;
    *cmd_out = cmd;
    if (cpll) {
        uint8_t *cp = (uint8_t*)malloc(cpll);
        if (!cp) { free(p); return -1; }
        memcpy(cp, cpl, cpll);
        *payload_out = cp;
        *payload_len_out = cpll;
    }
    free(p);
    return 0;
}

static int exit_send_relay_plain(cell_conn_t *cc, uint8_t relay_cmd, uint16_t stream_id, const uint8_t *body, uint16_t body_len) {
    uint8_t *plain=NULL; uint16_t plain_len=0;
    if (pcomm_relay_plain_pack(relay_cmd, stream_id, body, body_len, &plain, &plain_len) != 0) return -1;
    uint8_t *wrapped=NULL; uint16_t wrapped_len=0;
    if (pcomm_relay_wrap_one_backward(cc->k_bwd, 1, plain, plain_len, &wrapped, &wrapped_len) != 0) {
        free(plain);
        return -1;
    }
    free(plain);
    int rc = send_cell_link(cc->up_fd, PCOMM_CELL_RELAY, wrapped, wrapped_len);
    free(wrapped);
    return rc;
}

static void hs_unregister_by_cc(relay_state_t *st, cell_conn_t *cc) {
    if (!st || !cc) return;
    pthread_mutex_lock(&st->hs_mu);

    // intro regs
    intro_reg_t **pi = &st->intro_regs;
    while (*pi) {
        if ((*pi)->cc == cc) {
            intro_reg_t *dead = *pi;
            *pi = dead->next;
            cc_release(dead->cc);
            free(dead);
            continue;
        }
        pi = &(*pi)->next;
    }

    // rdv regs
    rdv_reg_t **pr = &st->rdv_regs;
    while (*pr) {
        if ((*pr)->cc == cc) {
            rdv_reg_t *dead = *pr;
            *pr = dead->next;
            cc_release(dead->cc);
            free(dead);
            continue;
        }
        pr = &(*pr)->next;
    }

    pthread_mutex_unlock(&st->hs_mu);
}

static int hs_intro_register(relay_state_t *st, const char *service_id, cell_conn_t *cc) {
    if (!st || !service_id || !cc) return -1;
    pthread_mutex_lock(&st->hs_mu);

    // replace existing
    intro_reg_t *it = st->intro_regs;
    while (it) {
        if (strcmp(it->service_id, service_id) == 0) {
            cc_release(it->cc);
            it->cc = cc; cc_acquire(cc);
            it->added = time(NULL);
            pthread_mutex_unlock(&st->hs_mu);
            return 0;
        }
        it = it->next;
    }

    intro_reg_t *nr = (intro_reg_t*)calloc(1, sizeof(intro_reg_t));
    if (!nr) { pthread_mutex_unlock(&st->hs_mu); return -1; }
    snprintf(nr->service_id, sizeof(nr->service_id), "%s", service_id);
    nr->cc = cc; cc_acquire(cc);
    nr->added = time(NULL);
    nr->next = st->intro_regs;
    st->intro_regs = nr;

    pthread_mutex_unlock(&st->hs_mu);
    return 0;
}

static cell_conn_t *hs_intro_lookup(relay_state_t *st, const char *service_id) {
    if (!st || !service_id) return NULL;
    pthread_mutex_lock(&st->hs_mu);
    intro_reg_t *it = st->intro_regs;
    while (it) {
        if (strcmp(it->service_id, service_id) == 0) {
            cell_conn_t *cc = it->cc;
            cc_acquire(cc);
            pthread_mutex_unlock(&st->hs_mu);
            return cc;
        }
        it = it->next;
    }
    pthread_mutex_unlock(&st->hs_mu);
    return NULL;
}

static int hs_rdv_register(relay_state_t *st, const uint8_t cookie[20], cell_conn_t *cc) {
    if (!st || !cookie || !cc) return -1;
    pthread_mutex_lock(&st->hs_mu);

    // reject duplicates
    rdv_reg_t *it = st->rdv_regs;
    while (it) {
        if (memcmp(it->cookie, cookie, 20) == 0) {
            pthread_mutex_unlock(&st->hs_mu);
            return -1;
        }
        it = it->next;
    }

    rdv_reg_t *nr = (rdv_reg_t*)calloc(1, sizeof(rdv_reg_t));
    if (!nr) { pthread_mutex_unlock(&st->hs_mu); return -1; }
    memcpy(nr->cookie, cookie, 20);
    nr->cc = cc; cc_acquire(cc);
    nr->added = time(NULL);
    nr->next = st->rdv_regs;
    st->rdv_regs = nr;

    pthread_mutex_unlock(&st->hs_mu);
    return 0;
}

static cell_conn_t *hs_rdv_take(relay_state_t *st, const uint8_t cookie[20]) {
    if (!st || !cookie) return NULL;
    pthread_mutex_lock(&st->hs_mu);
    rdv_reg_t **pp = &st->rdv_regs;
    while (*pp) {
        if (memcmp((*pp)->cookie, cookie, 20) == 0) {
            rdv_reg_t *hit = *pp;
            *pp = hit->next;
            // Transfer the registry-held reference to the caller.
            cell_conn_t *cc = hit->cc;
            free(hit);
            pthread_mutex_unlock(&st->hs_mu);
            return cc;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&st->hs_mu);
    return NULL;
}

static void hs_rdv_unlink(cell_conn_t *a, cell_conn_t *b) {
    if (!a || !b) return;
    if (a->rdv_partner == b) {
        a->rdv_partner = NULL;
        cc_release(b);
    }
    if (b->rdv_partner == a) {
        b->rdv_partner = NULL;
        cc_release(a);
    }
}

static int exit_process_stream_done(cell_conn_t *cc, uint16_t sid) {
    // find stream
    int idx = -1;
    for (int i=0;i<32;i++) if (cc->streams[i].used && cc->streams[i].id == sid) { idx=i; break; }
    if (idx < 0) return -1;
    // connect dest
    int fd = net_connect_tcp(cc->streams[idx].host, cc->streams[idx].port);
    if (fd < 0) {
        cc->streams[idx].used = 0;
        free(cc->streams[idx].req);
        cc->streams[idx].req = NULL;
        cc->streams[idx].req_len = 0;
        return exit_send_relay_plain(cc, PCOMM_RELAY_END, sid, NULL, 0);
    }
    // send raw request bytes
    if (net_sendall(fd, cc->streams[idx].req, cc->streams[idx].req_len) != 0) {
        close(fd);
        cc->streams[idx].used = 0;
        free(cc->streams[idx].req);
        cc->streams[idx].req = NULL;
        cc->streams[idx].req_len = 0;
        return exit_send_relay_plain(cc, PCOMM_RELAY_END, sid, NULL, 0);
    }

    if (cc->streams[idx].expect_resp) {
        pcomm_msg_type_t rt; uint8_t reph[32]; uint8_t *rp=NULL; uint32_t rpl=0;
        if (pcomm_recv_packet(fd, &rt, reph, &rp, &rpl) == 0) {
            uint8_t *packed=NULL; uint32_t packed_len=0;
            if (pcomm_pack_packet(rt, reph, rp, rpl, &packed, &packed_len) == 0) {
                exit_send_relay_plain(cc, PCOMM_RELAY_DATA, sid, packed, (uint16_t)packed_len);
                free(packed);
            }
            free(rp);
        }
    }
    close(fd);

    cc->streams[idx].used = 0;
    free(cc->streams[idx].req);
    cc->streams[idx].req = NULL;
    cc->streams[idx].req_len = 0;
    return exit_send_relay_plain(cc, PCOMM_RELAY_END, sid, NULL, 0);
}

static int cell_handle_exit_plain(relay_state_t *st, cell_conn_t *cc, const uint8_t *plain, uint16_t plain_len) {
    uint8_t rcmd; uint16_t sid; const uint8_t *body; uint16_t bl;
    if (pcomm_relay_plain_unpack(plain, plain_len, &rcmd, &sid, &body, &bl) != 0) return -1;

    // Rendezvous join mode: forward certain relay commands to the partner circuit.
    if (cc->rdv_partner) {
        if (rcmd == PCOMM_RELAY_BEGIN || rcmd == PCOMM_RELAY_CONNECTED || rcmd == PCOMM_RELAY_DATA || rcmd == PCOMM_RELAY_END) {
            cc_enqueue_up_plain(cc->rdv_partner, plain, plain_len);
            return 0;
        }
        // Drop any other commands.
        return 0;
    }

    // ---- Hidden-service rendezvous / intro commands (exit-side processing) ----

    if (rcmd == PCOMM_RELAY_ESTABLISH_INTRO) {
        // body: service_id_len(1) service_id
        if (bl < 1) return -1;
        uint8_t sl = body[0];
        if (sl == 0 || sl > 95 || bl < 1 + sl) return -1;
        char sidstr[96];
        memcpy(sidstr, body + 1, sl);
        sidstr[sl] = '\0';

        hs_intro_register(st, sidstr, cc);
        return exit_send_relay_plain(cc, PCOMM_RELAY_INTRO_ESTABLISHED, 0, NULL, 0);
    }

    if (rcmd == PCOMM_RELAY_INTRODUCE1) {
        // body:
        // service_id_len(1) service_id
        // client_id_len(1) client_id
        // cookie(20)
        // rp_host_len(1) rp_host
        // rp_port(2)
        if (bl < 1 + 1 + 20 + 1 + 2) return -1;
        size_t off = 0;
        uint8_t sl = body[off++];
        if (sl == 0 || sl > 95 || bl < off + sl + 1) return -1;
        char service_id[96];
        memcpy(service_id, body + off, sl); service_id[sl] = '\0';
        off += sl;

        uint8_t cl = body[off++];
        if (cl == 0 || cl > 95 || bl < off + cl + 20 + 1 + 2) return -1;
        char client_id[96];
        memcpy(client_id, body + off, cl); client_id[cl] = '\0';
        off += cl;

        const uint8_t *cookie = body + off; off += 20;

        uint8_t hl = body[off++];
        if (hl == 0 || hl > 63 || bl < off + hl + 2) return -1;
        char rphost[64];
        memcpy(rphost, body + off, hl); rphost[hl] = '\0';
        off += hl;
        uint16_t rpport = get_u16(body + off); off += 2;

        cell_conn_t *svc = hs_intro_lookup(st, service_id);
        if (!svc) {
            return exit_send_relay_plain(cc, PCOMM_RELAY_END, 0, NULL, 0);
        }

        // Build INTRODUCE2 to service:
        // client_id_len(1) client_id cookie(20) rp_host_len(1) rp_host rp_port(2)
        uint8_t buf[1 + 95 + 20 + 1 + 63 + 2];
        size_t bo = 0;
        buf[bo++] = (uint8_t)cl;
        memcpy(buf + bo, client_id, cl); bo += cl;
        memcpy(buf + bo, cookie, 20); bo += 20;
        buf[bo++] = (uint8_t)hl;
        memcpy(buf + bo, rphost, hl); bo += hl;
        put_u16(buf + bo, rpport); bo += 2;

        uint8_t *p2 = NULL; uint16_t p2l = 0;
        if (pcomm_relay_plain_pack(PCOMM_RELAY_INTRODUCE2, 0, buf, (uint16_t)bo, &p2, &p2l) == 0) {
            cc_enqueue_up_plain(svc, p2, p2l);
            free(p2);
        }
        cc_release(svc);

        return exit_send_relay_plain(cc, PCOMM_RELAY_INTRODUCE_ACK, 0, NULL, 0);
    }

    if (rcmd == PCOMM_RELAY_ESTABLISH_RENDEZVOUS) {
        if (bl != 20) return -1;
        hs_rdv_register(st, body, cc);
        // no immediate response; RDV2 will be sent once matched.
        return 0;
    }

    if (rcmd == PCOMM_RELAY_RENDEZVOUS1) {
        if (bl != 20) return -1;
        const uint8_t *cookie = body;

        cell_conn_t *client = hs_rdv_take(st, cookie);
        if (!client) {
            return exit_send_relay_plain(cc, PCOMM_RELAY_END, 0, NULL, 0);
        }

        // Join cc <-> client
        cc->rdv_partner = client; cc_acquire(client);
        client->rdv_partner = cc; cc_acquire(cc);
        memcpy(cc->rdv_cookie, cookie, 20);
        memcpy(client->rdv_cookie, cookie, 20);

        // Notify both ends
        uint8_t msg[21];
        memcpy(msg, cookie, 20);
        msg[20] = 1;
        exit_send_relay_plain(client, PCOMM_RELAY_RENDEZVOUS2, 0, msg, sizeof(msg));
        exit_send_relay_plain(cc, PCOMM_RELAY_RENDEZVOUS2, 0, msg, sizeof(msg));

        cc_release(client);
        return 0;
    }

    // ---- Normal exit behavior (TCP exit + extend) ----

    if (rcmd == PCOMM_RELAY_EXTEND) {
        // body: hostlen host port eph_pub
        if (bl < 1 + 2 + 32) return -1;
        size_t off = 0;
        uint8_t hl = body[off++];
        if (hl == 0 || hl > 63 || bl < 1 + hl + 2 + 32) return -1;
        char host[64];
        memcpy(host, body+off, hl); host[hl] = '\0';
        off += hl;
        uint16_t port = get_u16(body + off); off += 2;
        const uint8_t *client_eph_pub = body + off;

        int nfd = net_connect_tcp(host, port);
        if (nfd < 0) {
            return exit_send_relay_plain(cc, PCOMM_RELAY_END, 0, NULL, 0);
        }
        if (send_cell_link(nfd, PCOMM_CELL_CREATE, client_eph_pub, 32) != 0) { close(nfd); return -1; }
        uint8_t ccmd; uint8_t *cpl=NULL; uint16_t cpll=0;
        if (recv_cell_link(nfd, &ccmd, &cpl, &cpll) != 0 || ccmd != PCOMM_CELL_CREATED || cpll != 32) {
            free(cpl);
            close(nfd);
            return -1;
        }
        int rc = exit_send_relay_plain(cc, PCOMM_RELAY_EXTENDED, 0, cpl, 32);
        free(cpl);
        cc->down_fd = nfd;
        return rc;
    }

    if (rcmd == PCOMM_RELAY_BEGIN) {
        if (bl < 1 + 2 + 1) return -1;
        size_t off = 0;
        uint8_t hl = body[off++];
        if (hl == 0 || hl > 63 || bl < 1 + hl + 2 + 1) return -1;
        char host[64];
        memcpy(host, body+off, hl); host[hl] = '\0';
        off += hl;
        uint16_t port = get_u16(body + off); off += 2;
        uint8_t expect = body[off++];

        for (int i=0;i<32;i++) {
            if (!cc->streams[i].used) {
                cc->streams[i].used = 1;
                cc->streams[i].id = sid;
                cc->streams[i].expect_resp = (expect != 0);
                snprintf(cc->streams[i].host, sizeof(cc->streams[i].host), "%s", host);
                cc->streams[i].port = port;
                cc->streams[i].req = NULL;
                cc->streams[i].req_len = 0;
                break;
            }
        }
        return exit_send_relay_plain(cc, PCOMM_RELAY_CONNECTED, sid, NULL, 0);
    }

    if (rcmd == PCOMM_RELAY_DATA) {
        for (int i=0;i<32;i++) {
            if (cc->streams[i].used && cc->streams[i].id == sid) {
                uint8_t *nb = (uint8_t*)realloc(cc->streams[i].req, cc->streams[i].req_len + bl);
                if (!nb) return -1;
                cc->streams[i].req = nb;
                memcpy(cc->streams[i].req + cc->streams[i].req_len, body, bl);
                cc->streams[i].req_len += bl;
                return 0;
            }
        }
        return 0;
    }

    if (rcmd == PCOMM_RELAY_END) {
        return exit_process_stream_done(cc, sid);
    }

    return 0;
}

static int drain_up_queue(cell_conn_t *cc) {
    for (;;) {
        out_item_t *it = NULL;
        pthread_mutex_lock(&cc->qmu);
        if (cc->qhead) {
            it = cc->qhead;
            cc->qhead = it->next;
            if (!cc->qhead) cc->qtail = NULL;
        }
        pthread_mutex_unlock(&cc->qmu);
        if (!it) break;

        uint8_t *wrapped = NULL; uint16_t wrapped_len = 0;
        if (!cc->closed && pcomm_relay_wrap_one_backward(cc->k_bwd, 1, it->plain, it->plain_len, &wrapped, &wrapped_len) == 0) {
            send_cell_link(cc->up_fd, PCOMM_CELL_RELAY, wrapped, wrapped_len);
            free(wrapped);
        }
        free(it->plain);
        free(it);
    }
    return 0;
}

static int cell_loop(relay_state_t *st, int fd, const uint8_t *first_cell, uint32_t first_cell_len) {
    cell_conn_t *cc = (cell_conn_t*)calloc(1, sizeof(cell_conn_t));
    if (!cc) return -1;
    cc->st = st;
    cc->conn_id = __sync_add_and_fetch(&st->next_conn_id, 1);
    cc->up_fd = fd;
    cc->down_fd = -1;
    cc->refcnt = 1;
    pthread_mutex_init(&cc->qmu, NULL);

    // handle first message as if received
    uint8_t *buf = (uint8_t*)malloc(first_cell_len);
    if (!buf) { cc->closed = 1; cc_release(cc); return -1; }
    memcpy(buf, first_cell, first_cell_len);

    uint8_t *pending_payload = buf;
    uint32_t pending_len = first_cell_len;

    static const uint8_t basepoint[32] = {9};

    while (1) {
        // Drain any cross-thread queued upstream messages (best-effort).
        if (cc->built) drain_up_queue(cc);

        uint8_t cmd=0, flags=0; uint32_t cid=0; const uint8_t *cpl=NULL; uint16_t cpll=0;
        if (pcomm_cell_unpack(pending_payload, pending_len, &cid, &cmd, &flags, &cpl, &cpll) != 0 || cid != 1) {
            free(pending_payload);
            break;
        }
        (void)flags;

        if (cmd == PCOMM_CELL_CREATE) {
            if (cc->built || cpll != 32) { free(pending_payload); break; }
            const uint8_t *client_eph_pub = cpl;
            uint8_t eph_priv[32], eph_pub[32];
            pcomm_random(eph_priv, 32);
            if (pcomm_x25519_derive(eph_priv, basepoint, eph_pub) != 0) { free(pending_payload); break; }
            uint8_t shared[32];
            if (pcomm_x25519_derive(eph_priv, client_eph_pub, shared) != 0) { free(pending_payload); break; }
            if (derive_hop_keys(shared, cc->k_fwd, cc->k_bwd) != 0) { free(pending_payload); break; }
            cc->built = 1;
            send_cell_link(cc->up_fd, PCOMM_CELL_CREATED, eph_pub, 32);
        } else if (cmd == PCOMM_CELL_RELAY) {
            if (!cc->built) { free(pending_payload); break; }
            if (cc->down_fd >= 0) {
                uint8_t *dec=NULL; uint16_t decl=0;
                if (pcomm_relay_unwrap_one_forward(cc->k_fwd, 1, cpl, cpll, &dec, &decl) != 0) { free(pending_payload); break; }
                send_cell_link(cc->down_fd, PCOMM_CELL_RELAY, dec, decl);
                free(dec);
            } else {
                uint8_t *plain=NULL; uint16_t plain_len=0;
                if (pcomm_relay_unwrap_one_forward(cc->k_fwd, 1, cpl, cpll, &plain, &plain_len) == 0) {
                    cell_handle_exit_plain(st, cc, plain, plain_len);
                    free(plain);
                }
            }
        } else if (cmd == PCOMM_CELL_PADDING) {
            // ignore
        } else if (cmd == PCOMM_CELL_DESTROY) {
            free(pending_payload);
            break;
        }

        free(pending_payload);
        pending_payload = NULL;
        pending_len = 0;

        // select for next message from upstream or downstream with timeout so we can drain the queue.
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(cc->up_fd, &rfds);
        int maxfd = cc->up_fd;
        if (cc->down_fd >= 0) {
            FD_SET(cc->down_fd, &rfds);
            if (cc->down_fd > maxfd) maxfd = cc->down_fd;
        }
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000; // 200ms
        int sel = select(maxfd+1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) {
            // timeout: loop to drain queue
            continue;
        }

        if (cc->down_fd >= 0 && FD_ISSET(cc->down_fd, &rfds)) {
            uint8_t dcmd; uint8_t *dpl=NULL; uint16_t dpll=0;
            if (recv_cell_link(cc->down_fd, &dcmd, &dpl, &dpll) != 0) { free(dpl); break; }
            if (dcmd == PCOMM_CELL_RELAY) {
                uint8_t *enc=NULL; uint16_t encl=0;
                if (pcomm_relay_wrap_one_backward(cc->k_bwd, 1, dpl, dpll, &enc, &encl) == 0) {
                    send_cell_link(cc->up_fd, PCOMM_CELL_RELAY, enc, encl);
                    free(enc);
                }
            }
            free(dpl);
            continue;
        }

        if (FD_ISSET(cc->up_fd, &rfds)) {
            pcomm_msg_type_t t; uint8_t eph[32]; uint8_t *p=NULL; uint32_t pl=0;
            if (pcomm_recv_packet(cc->up_fd, &t, eph, &p, &pl) != 0) { free(p); break; }
            if (t != PCOMM_MSG_CELL) { free(p); continue; }
            pending_payload = p;
            pending_len = pl;
            continue;
        }
    }

    // teardown
    cc->closed = 1;

    // unlink rendezvous partner if any
    if (cc->rdv_partner) {
        cell_conn_t *other = cc->rdv_partner;
        hs_rdv_unlink(cc, other);
        // other ref released inside hs_rdv_unlink
    }

    // remove any registry entries pointing at us
    hs_unregister_by_cc(st, cc);

    if (cc->down_fd >= 0) close(cc->down_fd);
    // drain any queued items
    drain_up_queue(cc);

    // free any stream buffers
    for (int i=0;i<32;i++) free(cc->streams[i].req);

    cc_release(cc); // releases the loop's own ref; final free may happen here
    return 0;
}


static void *handle_conn(void *arg) {
    conn_arg_t *ca = (conn_arg_t*)arg;
    relay_state_t *st = ca->st;
    int fd = ca->fd;
    free(ca);

    pcomm_msg_type_t type;
    uint8_t eph_pub[32];
    uint8_t *payload = NULL;
    uint32_t payload_len = 0;

    if (pcomm_recv_packet(fd, &type, eph_pub, &payload, &payload_len) != 0) {
        close(fd);
        free(payload);
        return NULL;
    }

    if (type == PCOMM_MSG_CELL) {
        // Long-lived circuit connection.
        cell_loop(st, fd, payload, payload_len);
        free(payload);
        close(fd);
        return NULL;
    }

    if (type == PCOMM_MSG_ONION) {
        pcomm_inst_t inst;
        char next_host[128] = {0};
        uint16_t next_port = 0;
        uint8_t *next_payload = NULL;
        uint32_t next_payload_len = 0;

        char dest_host[128] = {0};
        uint16_t dest_port = 0;
        pcomm_msg_type_t deliver_type = 0;
        uint8_t deliver_flags = 0;
        uint8_t *deliver_payload = NULL;
        uint32_t deliver_len = 0;

        int rc = pcomm_onion_unwrap_v1(st->id.privkey, eph_pub, payload, payload_len,
                                      &inst,
                                      next_host, sizeof(next_host), &next_port,
                                      &next_payload, &next_payload_len,
                                      dest_host, sizeof(dest_host), &dest_port,
                                      &deliver_type, &deliver_flags,
                                      &deliver_payload, &deliver_len);

        if (rc == 0 && (inst == PCOMM_INST_FORWARD || inst == PCOMM_INST_FORWARD_RR)) {
            int outfd = net_connect_tcp(next_host, next_port);
            if (outfd >= 0) {
                if (pcomm_send_packet(outfd, PCOMM_MSG_ONION, eph_pub, next_payload, next_payload_len) == 0) {
                    if (inst == PCOMM_INST_FORWARD_RR) {
                        // read exactly one response packet and send it back
                        pcomm_msg_type_t rtype;
                        uint8_t reph[32];
                        uint8_t *rp = NULL; uint32_t rpl = 0;
                        if (pcomm_recv_packet(outfd, &rtype, reph, &rp, &rpl) == 0) {
                            pcomm_send_packet(fd, rtype, reph, rp, rpl);
                            free(rp);
                        }
                    }
                }
                close(outfd);
            }
            free(next_payload);
        } else if (rc == 0 && inst == PCOMM_INST_DELIVER) {
            int outfd = net_connect_tcp(dest_host, dest_port);
            if (outfd >= 0) {
                if (pcomm_send_packet(outfd, deliver_type, NULL, deliver_payload, deliver_len) == 0) {
                    if (deliver_flags & 0x01) {
                        pcomm_msg_type_t rtype;
                        uint8_t reph[32];
                        uint8_t *rp = NULL; uint32_t rpl = 0;
                        if (pcomm_recv_packet(outfd, &rtype, reph, &rp, &rpl) == 0) {
                            pcomm_send_packet(fd, rtype, reph, rp, rpl);
                            free(rp);
                        }
                    }
                }
                close(outfd);
            }
            free(deliver_payload);
        }
    } else if (type == PCOMM_MSG_DELIVER) {
        // payload = sealed box to us
        uint8_t *plain = NULL;
        size_t plain_len = 0;
        if (pcomm_open_seal(st->id.privkey, payload, payload_len, &plain, &plain_len) == 0) {
            pcomm_plain_kind_t kind;
            uint32_t ts = 0;
            char sender[96] = {0};
            char group_uuid[64] = {0};
            char *title = NULL;
            char **members = NULL; int member_count = 0;
            char *text = NULL;

            if (pcomm_msg_unpack_any(plain, plain_len, &kind, &ts, sender, sizeof(sender),
                                     group_uuid, sizeof(group_uuid),
                                     &title, &members, &member_count, &text) == 0) {
                if (kind == PCOMM_PLAIN_DIRECT_TEXT) {
                    int64_t conv_id = pcomm_db_get_or_create_direct_conv(st->db, sender);
                    if (conv_id >= 0) {
                        pcomm_db_insert_message(st->db, conv_id, 0, sender, sender, text ? text : "", payload, payload_len, (int64_t)ts);
                    }
                } else if (kind == PCOMM_PLAIN_GROUP_INVITE) {
                    int64_t conv_id = pcomm_db_get_or_create_group_conv(st->db, group_uuid, title ? title : "");
                    if (conv_id >= 0) {
                        for (int k = 0; k < member_count; k++) pcomm_db_add_participant(st->db, conv_id, members[k]);
                        const char *body = title ? title : "Group invite";
                        pcomm_db_insert_message(st->db, conv_id, 0, group_uuid, sender, body, payload, payload_len, (int64_t)ts);
                    }
                } else if (kind == PCOMM_PLAIN_GROUP_TEXT) {
                    int64_t conv_id = pcomm_db_get_or_create_group_conv(st->db, group_uuid, NULL);
                    if (conv_id >= 0) {
                        pcomm_db_insert_message(st->db, conv_id, 0, group_uuid, sender, text ? text : "", payload, payload_len, (int64_t)ts);
                    }
                }
            }
            free(plain);
            free(title);
            pcomm_msg_free_members(members, member_count);
            free(text);
        }
    } else if (type == PCOMM_MSG_CTRL) {
        ctrl_handle(st, fd, payload, payload_len);
    }

    free(payload);
    close(fd);
    return NULL;
}

static void *relay_thread(void *arg) {
    relay_state_t *st = (relay_state_t*)arg;
    for (;;) {
        int cfd = net_accept(st->listen_fd, NULL, 0, NULL);
        if (cfd < 0) continue;

        conn_arg_t *ca = (conn_arg_t*)malloc(sizeof(conn_arg_t));
        if (!ca) { close(cfd); continue; }
        ca->st = st;
        ca->fd = cfd;

        pthread_t th;
        if (pthread_create(&th, NULL, handle_conn, ca) == 0) {
            pthread_detach(th);
        } else {
            free(ca);
            close(cfd);
        }
    }
    return NULL;
}

int pcomm_relay_start(const pcomm_config_t *cfg, const pcomm_identity_t *id, pcomm_db_t *db) {
    if (!cfg || !id || !db) return -1;

    relay_state_t *st = (relay_state_t*)calloc(1, sizeof(relay_state_t));
    if (!st) return -1;
    st->cfg = *cfg;
    st->id = *id;
    st->db = db;

    pthread_mutex_init(&st->hs_mu, NULL);
    st->intro_regs = NULL;
    st->rdv_regs = NULL;
    st->next_conn_id = 1000;

    st->listen_fd = net_listen_tcp(cfg->relay_host, cfg->relay_port, 64);
    if (st->listen_fd < 0) {
        fprintf(stderr, "Failed to listen on relay %s:%u\n", cfg->relay_host, (unsigned)cfg->relay_port);
        free(st);
        return -1;
    }

    pthread_t th;
    if (pthread_create(&th, NULL, relay_thread, st) != 0) {
        close(st->listen_fd);
        free(st);
        return -1;
    }
    pthread_detach(th);

    fprintf(stderr, "Relay listening on %s:%u\n", cfg->relay_host, (unsigned)cfg->relay_port);
    if (cfg->advertise_host[0] != '\0') {
        fprintf(stderr, "Advertised relay: %s:%u\n", cfg->advertise_host, (unsigned)cfg->advertise_port);
    }
    return 0;
}
