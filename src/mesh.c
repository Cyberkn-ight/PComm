#include "mesh.h"
#include "net.h"
#include "proto.h"
#include "identity.h"

#include <pthread.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

static void put_u16(uint8_t *p, uint16_t v){ uint16_t n=htons(v); memcpy(p,&n,2); }
static uint16_t get_u16(const uint8_t *p){ uint16_t n; memcpy(&n,p,2); return ntohs(n); }

static int pick_random_relay(pcomm_db_t *db, pcomm_peer_t *out) {
    const char *sql = "SELECT user_id, host, port, pubkey FROM contacts WHERE is_relay=1 AND host!='' AND port>0 ORDER BY RANDOM() LIMIT 1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }

    const char *uid = (const char*)sqlite3_column_text(st, 0);
    const char *host = (const char*)sqlite3_column_text(st, 1);
    int port = sqlite3_column_int(st, 2);
    const void *pk = sqlite3_column_blob(st, 3);
    int pklen = sqlite3_column_bytes(st, 3);

    if (!uid || !host || pklen != 32 || port <= 0 || port > 65535) { sqlite3_finalize(st); return -1; }
    memset(out, 0, sizeof(*out));
    snprintf(out->user_id, sizeof(out->user_id), "%s", uid);
    snprintf(out->host, sizeof(out->host), "%s", host);
    out->port = (uint16_t)port;
    memcpy(out->pubkey, pk, 32);

    sqlite3_finalize(st);
    return 0;
}

static int build_hello(const pcomm_config_t *cfg, const pcomm_identity_t *me, uint8_t **out, uint32_t *out_len) {
    const char *adv_host = (cfg->advertise_host[0] != '\0') ? cfg->advertise_host : cfg->relay_host;
    uint16_t adv_port = (cfg->advertise_port != 0) ? cfg->advertise_port : cfg->relay_port;
    if (strcmp(adv_host, "0.0.0.0") == 0) adv_host = "127.0.0.1"; // last-resort

    size_t uid_len = strlen(me->user_id);
    size_t host_len = strlen(adv_host);
    if (uid_len > 255 || host_len > 63) return -1;

    uint32_t len = 1 + 2 + (uint32_t)uid_len + 1 + (uint32_t)host_len + 2 + 32;
    uint8_t *buf = (uint8_t*)malloc(len);
    if (!buf) return -1;

    uint32_t off = 0;
    buf[off++] = (uint8_t)PCOMM_CTRL_HELLO;
    put_u16(buf + off, (uint16_t)uid_len); off += 2;
    memcpy(buf + off, me->user_id, uid_len); off += (uint32_t)uid_len;
    buf[off++] = (uint8_t)host_len;
    memcpy(buf + off, adv_host, host_len); off += (uint32_t)host_len;
    put_u16(buf + off, adv_port); off += 2;
    memcpy(buf + off, me->pubkey, 32); off += 32;

    if (off != len) { free(buf); return -1; }
    *out = buf; *out_len = len;
    return 0;
}

static int build_peers_req(uint16_t want, uint8_t **out, uint32_t *out_len) {
    uint8_t *buf = (uint8_t*)malloc(1 + 2);
    if (!buf) return -1;
    buf[0] = (uint8_t)PCOMM_CTRL_PEERS_REQ;
    put_u16(buf + 1, want);
    *out = buf; *out_len = 3;
    return 0;
}

static int parse_peers_resp(pcomm_db_t *db, const uint8_t *payload, uint32_t payload_len) {
    if (!payload || payload_len < 1 + 2) return -1;
    uint32_t off = 0;
    uint8_t cmd = payload[off++];
    if (cmd != PCOMM_CTRL_PEERS_RESP) return -1;
    uint16_t count = get_u16(payload + off); off += 2;

    for (uint16_t i = 0; i < count; i++) {
        if (payload_len < off + 2) break;
        uint16_t uid_len = get_u16(payload + off); off += 2;
        if (uid_len == 0 || uid_len > 95 || payload_len < off + uid_len) break;
        char uid[128];
        memcpy(uid, payload + off, uid_len); uid[uid_len] = '\0';
        off += uid_len;

        if (payload_len < off + 1) break;
        uint8_t hlen = payload[off++];
        if (hlen == 0 || hlen > 63 || payload_len < off + hlen + 2 + 32) break;
        char host[128];
        memcpy(host, payload + off, hlen); host[hlen] = '\0';
        off += hlen;

        uint16_t port = get_u16(payload + off); off += 2;
        uint8_t pk[32];
        memcpy(pk, payload + off, 32); off += 32;

        // verify uid matches pk
        char derived[96];
        if (pcomm_user_id_from_pubkey(pk, derived) != 0) continue;
        if (strcmp(uid, derived) != 0) continue;
        if (port == 0) continue;

        pcomm_db_upsert_contact(db, uid, host, port, pk, 1);
    }
    return 0;
}

typedef struct {
    pcomm_config_t cfg;
    pcomm_identity_t me;
    pcomm_db_t *db;
} mesh_state_t;

static void *mesh_thread(void *arg) {
    mesh_state_t *st = (mesh_state_t*)arg;

    for (;;) {
        // try to learn from a random relay
        pcomm_peer_t peer;
        if (pick_random_relay(st->db, &peer) == 0) {
            // HELLO (one-shot connection)
            {
                int fd = net_connect_tcp(peer.host, peer.port);
                if (fd >= 0) {
                    uint8_t *hello = NULL; uint32_t hello_len = 0;
                    if (build_hello(&st->cfg, &st->me, &hello, &hello_len) == 0) {
                        pcomm_send_packet(fd, PCOMM_MSG_CTRL, NULL, hello, hello_len);
                    }
                    free(hello);
                    close(fd);
                }
            }

            // PEERS_REQ -> PEERS_RESP (one-shot connection)
            {
                int fd = net_connect_tcp(peer.host, peer.port);
                if (fd >= 0) {
                    uint8_t *req = NULL; uint32_t req_len = 0;
                    if (build_peers_req(64, &req, &req_len) == 0) {
                        if (pcomm_send_packet(fd, PCOMM_MSG_CTRL, NULL, req, req_len) == 0) {
                            pcomm_msg_type_t rtype;
                            uint8_t eph[32];
                            uint8_t *rp = NULL; uint32_t rpl = 0;
                            if (pcomm_recv_packet(fd, &rtype, eph, &rp, &rpl) == 0) {
                                if (rtype == PCOMM_MSG_CTRL) {
                                    parse_peers_resp(st->db, rp, rpl);
                                }
                                free(rp);
                            }
                        }
                    }
                    free(req);
                    close(fd);
                }
            }
        }

        sleep(5);
    }
    return NULL;
}

int pcomm_mesh_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db) {
    if (!cfg || !me || !db) return -1;

    mesh_state_t *st = (mesh_state_t*)calloc(1, sizeof(mesh_state_t));
    if (!st) return -1;
    st->cfg = *cfg;
    st->me = *me;
    st->db = db;

    pthread_t th;
    if (pthread_create(&th, NULL, mesh_thread, st) != 0) {
        free(st);
        return -1;
    }
    pthread_detach(th);
    fprintf(stderr, "Mesh gossip started\n");
    return 0;
}
