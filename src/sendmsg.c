#include "sendmsg.h"
#include "identity.h"
#include "crypto.h"
#include "msg.h"
#include "net.h"
#include "proto.h"
#include "onion.h"

#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static int load_relays(pcomm_db_t *db, const char *exclude1, const char *exclude2, pcomm_peer_t *out, size_t out_cap, size_t *out_len) {
    *out_len = 0;
    const char *sql =
        "SELECT user_id, host, port, pubkey FROM contacts WHERE is_relay=1 AND user_id != ? AND user_id != ? LIMIT ?;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, exclude1, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, exclude2, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, (int)out_cap);

    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *uid = (const char*)sqlite3_column_text(st, 0);
        const char *host = (const char*)sqlite3_column_text(st, 1);
        int port = sqlite3_column_int(st, 2);
        const void *pk = sqlite3_column_blob(st, 3);
        int pklen = sqlite3_column_bytes(st, 3);

        if (!uid || !host || pklen != 32) continue;
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

int pcomm_send_text(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                    const char *to_user_id, const char *text) {
    if (!db || !cfg || !me || !to_user_id || !text) return -1;

    char host[128];
    uint16_t port = 0;
    uint8_t recip_pub[32];
    int is_relay = 0;
    if (pcomm_db_get_contact(db, to_user_id, host, sizeof(host), &port, recip_pub, &is_relay) != 0) {
        fprintf(stderr, "Unknown contact: %s\n", to_user_id);
        return -1;
    }

    uint32_t ts = (uint32_t)time(NULL);

    uint8_t *plain = NULL;
    size_t plain_len = 0;
    if (pcomm_msg_pack_plain(ts, me->user_id, text, &plain, &plain_len) != 0) return -1;

    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    if (pcomm_seal_for_recipient(recip_pub, plain, plain_len, &sealed, &sealed_len) != 0) {
        free(plain);
        return -1;
    }
    free(plain);

    pcomm_peer_t relays[3];
    size_t relay_count = 0;
    load_relays(db, me->user_id, to_user_id, relays, 3, &relay_count);

    int send_rc = -1;

    if (relay_count >= 1) {
        uint8_t eph_pub[32];
        uint8_t *onion_payload = NULL;
        uint32_t onion_len = 0;

        if (pcomm_onion_build(relays, relay_count, host, port, to_user_id, sealed, sealed_len,
                              eph_pub, &onion_payload, &onion_len) == 0) {
            int fd = net_connect_tcp(relays[0].host, relays[0].port);
            if (fd >= 0) {
                if (pcomm_send_packet(fd, PCOMM_MSG_ONION, eph_pub, onion_payload, onion_len) == 0) {
                    send_rc = 0;
                }
                close(fd);
            }
        }
        free(onion_payload);
    } else {
        int fd = net_connect_tcp(host, port);
        if (fd >= 0) {
            if (pcomm_send_packet(fd, PCOMM_MSG_DELIVER, NULL, sealed, (uint32_t)sealed_len) == 0) {
                send_rc = 0;
            }
            close(fd);
        }
    }

    int64_t conv_id = pcomm_db_get_or_create_direct_conv(db, to_user_id);
    if (conv_id >= 0) {
        pcomm_db_insert_message(db, conv_id, 1, to_user_id, me->user_id, text, sealed, sealed_len, (int64_t)ts);
    }

    free(sealed);
    return send_rc;
}
