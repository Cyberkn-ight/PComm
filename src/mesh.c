#include "mesh.h"
#include "net.h"
#include "proto.h"
#include "identity.h"
#include "crypto.h"
#include "lifecycle.h"

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
    if (strcmp(adv_host, "0.0.0.0") == 0) adv_host = "127.0.0.1";

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
    pthread_t thread;
    pthread_mutex_t mu;
    pthread_mutex_t fd_mu;
    int fd;
    int running;
} mesh_state_t;

static mesh_state_t *g_mesh = NULL;
static pthread_mutex_t g_mesh_mu = PTHREAD_MUTEX_INITIALIZER;

static int mesh_running(mesh_state_t *st) {
    pthread_mutex_lock(&st->mu);
    int running = st->running;
    pthread_mutex_unlock(&st->mu);
    return running && !pcomm_shutdown_requested();
}

static int mesh_wait(mesh_state_t *st, uint64_t milliseconds) {
    while (milliseconds > 0 && mesh_running(st)) {
        uint32_t chunk = milliseconds > 100u ? 100u : (uint32_t)milliseconds;
        if (pcomm_shutdown_wait(chunk) != 0) return -1;
        milliseconds -= chunk;
    }
    return mesh_running(st) ? 0 : -1;
}

static int mesh_connect_tcp(mesh_state_t *st, const char *host, uint16_t port) {
    int fd = net_connect_tcp(host, port);
    if (fd < 0) return -1;
    pthread_mutex_lock(&st->fd_mu);
    if (!mesh_running(st)) {
        net_shutdown(fd);
        net_close(fd);
        fd = -1;
    } else {
        st->fd = fd;
    }
    pthread_mutex_unlock(&st->fd_mu);
    return fd;
}

static void mesh_close_tcp(mesh_state_t *st, int fd) {
    pthread_mutex_lock(&st->fd_mu);
    st->fd = -1;
    net_close(fd);
    pthread_mutex_unlock(&st->fd_mu);
}

static void *mesh_thread(void *arg) {
    mesh_state_t *st = (mesh_state_t*)arg;

    while (mesh_running(st)) {
        pcomm_peer_t peer;
        if (pick_random_relay(st->db, &peer) == 0) {
            {
                int fd = mesh_connect_tcp(st, peer.host, peer.port);
                if (fd >= 0) {
                    uint8_t *hello = NULL; uint32_t hello_len = 0;
                    if (build_hello(&st->cfg, &st->me, &hello, &hello_len) == 0) {
                        pcomm_send_packet(fd, PCOMM_MSG_CTRL, NULL, hello, hello_len);
                    }
                    free(hello);
                    mesh_close_tcp(st, fd);
                }
            }

            if (!mesh_running(st)) break;
            {
                int fd = mesh_connect_tcp(st, peer.host, peer.port);
                if (fd >= 0) {
                    uint8_t *req = NULL; uint32_t req_len = 0;
                    if (build_peers_req(64, &req, &req_len) == 0) {
                        if (pcomm_send_packet(fd, PCOMM_MSG_CTRL, NULL, req, req_len) == 0) {
                            pcomm_msg_type_t rtype;
                            uint8_t eph[32];
                            uint8_t *rp = NULL; uint32_t rpl = 0;
                            if (pcomm_recv_packet(fd, &rtype, eph, &rp, &rpl) == 0) {
                                if (rtype == PCOMM_MSG_CTRL && mesh_running(st)) {
                                    parse_peers_resp(st->db, rp, rpl);
                                }
                                free(rp);
                            }
                        }
                    }
                    free(req);
                    mesh_close_tcp(st, fd);
                }
            }
        }

        uint8_t r = 0;
        (void)pcomm_random(&r, 1);
        uint32_t base = st->cfg.mesh_gossip_base_sec;
        if (base < 3) base = 3;
        uint64_t delay = (uint64_t)base + (r % base);
        if (mesh_wait(st, delay * 1000u) != 0) break;
    }
    return NULL;
}

int pcomm_mesh_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db) {
    if (!cfg || !me || !db || !db->db || pcomm_shutdown_requested()) return -1;
    pthread_mutex_lock(&g_mesh_mu);
    if (g_mesh) {
        pthread_mutex_unlock(&g_mesh_mu);
        return 0;
    }

    mesh_state_t *st = (mesh_state_t*)calloc(1, sizeof(mesh_state_t));
    if (!st) {
        pthread_mutex_unlock(&g_mesh_mu);
        return -1;
    }
    if (pthread_mutex_init(&st->mu, NULL) != 0) {
        free(st);
        pthread_mutex_unlock(&g_mesh_mu);
        return -1;
    }
    if (pthread_mutex_init(&st->fd_mu, NULL) != 0) {
        pthread_mutex_destroy(&st->mu);
        free(st);
        pthread_mutex_unlock(&g_mesh_mu);
        return -1;
    }
    st->cfg = *cfg;
    st->me = *me;
    st->db = db;
    st->fd = -1;
    st->running = 1;

    if (pthread_create(&st->thread, NULL, mesh_thread, st) != 0) {
        pthread_mutex_destroy(&st->fd_mu);
        pthread_mutex_destroy(&st->mu);
        free(st);
        pthread_mutex_unlock(&g_mesh_mu);
        return -1;
    }
    g_mesh = st;
    pthread_mutex_unlock(&g_mesh_mu);
    fprintf(stderr, "Mesh gossip started\n");
    return 0;
}

void pcomm_mesh_stop(void) {
    pthread_mutex_lock(&g_mesh_mu);
    mesh_state_t *st = g_mesh;
    if (st) {
        pthread_mutex_lock(&st->mu);
        st->running = 0;
        pthread_mutex_unlock(&st->mu);
        pthread_mutex_lock(&st->fd_mu);
        if (st->fd >= 0) net_shutdown(st->fd);
        pthread_mutex_unlock(&st->fd_mu);
        pthread_join(st->thread, NULL);
        pthread_mutex_destroy(&st->fd_mu);
        pthread_mutex_destroy(&st->mu);
        g_mesh = NULL;
        free(st);
    }
    pthread_mutex_unlock(&g_mesh_mu);
}
