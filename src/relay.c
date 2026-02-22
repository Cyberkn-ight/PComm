#include "relay.h"
#include "net.h"
#include "proto.h"
#include "onion.h"
#include "crypto.h"
#include "msg.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    pcomm_config_t cfg;
    pcomm_identity_t id;
    pcomm_db_t *db;
    int listen_fd;
} relay_state_t;

typedef struct {
    relay_state_t *st;
    int fd;
} conn_arg_t;

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

    if (type == PCOMM_MSG_ONION) {
        pcomm_inst_t inst;
        char next_host[128] = {0};
        uint16_t next_port = 0;
        uint8_t *next_payload = NULL;
        uint32_t next_payload_len = 0;

        char recipient_id[96] = {0};
        uint8_t *sealed = NULL;
        uint32_t sealed_len = 0;
        char dest_host[128] = {0};
        uint16_t dest_port = 0;

        int rc = pcomm_onion_unwrap(st->id.privkey, eph_pub, payload, payload_len,
                                   &inst,
                                   next_host, sizeof(next_host), &next_port,
                                   &next_payload, &next_payload_len,
                                   recipient_id, sizeof(recipient_id),
                                   &sealed, &sealed_len,
                                   dest_host, sizeof(dest_host), &dest_port);

        if (rc == 0 && inst == PCOMM_INST_FORWARD) {
            int outfd = net_connect_tcp(next_host, next_port);
            if (outfd >= 0) {
                pcomm_send_packet(outfd, PCOMM_MSG_ONION, eph_pub, next_payload, next_payload_len);
                close(outfd);
            }
            free(next_payload);
        } else if (rc == 0 && inst == PCOMM_INST_DELIVER) {
            int outfd = net_connect_tcp(dest_host, dest_port);
            if (outfd >= 0) {
                pcomm_send_packet(outfd, PCOMM_MSG_DELIVER, NULL, sealed, sealed_len);
                close(outfd);
            }
            free(sealed);
        }
    } else if (type == PCOMM_MSG_DELIVER) {
        uint8_t *plain = NULL;
        size_t plain_len = 0;
        if (pcomm_open_seal(st->id.privkey, payload, payload_len, &plain, &plain_len) == 0) {
            uint32_t ts = 0;
            char sender_id[96] = {0};
            char *text = NULL;
            if (pcomm_msg_unpack_plain(plain, plain_len, &ts, sender_id, sizeof(sender_id), &text) == 0) {
                int64_t conv_id = pcomm_db_get_or_create_direct_conv(st->db, sender_id);
                if (conv_id >= 0) {
                    pcomm_db_insert_message(st->db, conv_id, 0, sender_id, sender_id, text, payload, payload_len, (int64_t)ts);
                }
                free(text);
            }
            free(plain);
        }
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
    return 0;
}
