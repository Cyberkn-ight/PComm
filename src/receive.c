#include "receive.h"
#include "crypto.h"
#include "identity.h"
#include "msg.h"
#include "ratchet.h"
#include "replay.h"

#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    pcomm_db_t *db;
    const pcomm_identity_t *recipient;
    const uint8_t *sealed;
    size_t sealed_len;
    pcomm_plain_kind_t kind;
    uint32_t ts;
    char sender[96];
    char group_uuid[64];
    char *title;
    char **members;
    int member_count;
    char *text;
    uint32_t fallback_ts;
} received_message_t;

static int store_received_message(void *arg) {
    received_message_t *msg = (received_message_t *)arg;
    int64_t conv_id;
    const char *peer;
    const char *body = msg->text ? msg->text : "";

    if (msg->kind == PCOMM_PLAIN_DIRECT_TEXT) {
        peer = msg->sender;
        conv_id = pcomm_db_get_or_create_direct_conv(msg->db, peer);
    } else {
        peer = msg->group_uuid;
        const char *title = msg->kind == PCOMM_PLAIN_GROUP_INVITE ? msg->title : NULL;
        conv_id = pcomm_db_get_or_create_group_conv(msg->db, peer, title);
    }
    if (conv_id < 0) return -1;

    if (msg->kind == PCOMM_PLAIN_GROUP_INVITE) {
        for (int i = 0; i < msg->member_count; i++) {
            if (pcomm_db_add_participant(msg->db, conv_id, msg->members[i]) != 0) return -1;
        }
        body = msg->title ? msg->title : "Group invite";
    }

    return pcomm_db_insert_message(msg->db, conv_id, 0, peer, msg->sender,
                                   body, msg->sealed, msg->sealed_len, msg->ts);
}

static int unpack_received_message(received_message_t *msg,
                                    const uint8_t *plain, size_t plain_len) {
    if (pcomm_msg_unpack_any(plain, plain_len, &msg->kind, &msg->ts,
                             msg->sender, sizeof(msg->sender),
                             msg->group_uuid, sizeof(msg->group_uuid),
                             &msg->title, &msg->members, &msg->member_count,
                             &msg->text) != 0) return -1;
    if (!msg->ts) msg->ts = msg->fallback_ts;
    return 0;
}

static int store_ratchet_message(void *arg, const char *sender,
                                  const char *context,
                                  const uint8_t *plain, size_t plain_len) {
    received_message_t *msg = (received_message_t *)arg;
    uint8_t claimed_pub[32], authenticated_pub[32];
    if (unpack_received_message(msg, plain, plain_len) != 0 ||
        pcomm_pubkey_from_user_id(msg->sender, claimed_pub) != 0 ||
        pcomm_pubkey_from_user_id(sender, authenticated_pub) != 0 ||
        CRYPTO_memcmp(claimed_pub, authenticated_pub, sizeof(claimed_pub)) != 0 ||
        pcomm_user_id_from_pubkey(authenticated_pub, msg->sender) != 0) return -1;

    if (msg->kind == PCOMM_PLAIN_DIRECT_TEXT) {
        if (context[0] != '\0') return -1;
    } else if (context[0] == '\0' || strcmp(context, msg->group_uuid) != 0) {
        return -1;
    }
    return store_received_message(msg);
}

static int store_legacy_message(void *arg) {
    received_message_t *msg = (received_message_t *)arg;
    uint8_t sender_pub[32];
    char canonical[96];
    const char *context = msg->kind == PCOMM_PLAIN_DIRECT_TEXT ? "" : msg->group_uuid;
    sqlite3_mutex *mutex = sqlite3_db_mutex(msg->db->db);
    sqlite3_mutex_enter(mutex);
    int rc = 0;
    if (pcomm_pubkey_from_user_id(msg->sender, sender_pub) == 0) {
        if (pcomm_user_id_from_pubkey(sender_pub, canonical) != 0 ||
            pcomm_ratchet_has_session(msg->db, msg->recipient, canonical, context) != 0) {
            rc = -1;
        } else {
            strcpy(msg->sender, canonical);
        }
    }
    if (rc == 0) rc = store_received_message(msg);
    sqlite3_mutex_leave(mutex);
    return rc;
}

int pcomm_receive_sealed(pcomm_db_t *db, const pcomm_identity_t *recipient,
                         const uint8_t *sealed, size_t sealed_len,
                         uint32_t fallback_ts) {
    if (!db || !db->db || !db->replay_cache || !recipient || !sealed ||
        sealed_len > INT_MAX) return -1;

    uint8_t *plain = NULL;
    size_t plain_len = 0;
    if (pcomm_open_seal(recipient->privkey, sealed, sealed_len, &plain, &plain_len) != 0) return -1;

    received_message_t msg = {0};
    msg.db = db;
    msg.recipient = recipient;
    msg.sealed = sealed;
    msg.sealed_len = sealed_len;
    msg.fallback_ts = fallback_ts;
    int rc = -1;

    if (pcomm_ratchet_is_packet(plain, plain_len)) {

        rc = pcomm_ratchet_receive(db, recipient, plain, plain_len,
                                   store_ratchet_message, &msg);
    } else if (unpack_received_message(&msg, plain, plain_len) == 0) {
        uint8_t tag[PCOMM_REPLAY_TAG_LEN];
        uint64_t now_ms;

        if (SHA256(sealed + PCOMM_SEAL_EPH_PUB_LEN, sealed_len - PCOMM_SEAL_EPH_PUB_LEN, tag) &&
            pcomm_replay_now_ms(&now_ms) == 0) {
            rc = pcomm_replay_apply(db->replay_cache, tag, now_ms, store_legacy_message, &msg);
        }
    }

    OPENSSL_cleanse(plain, plain_len);
    free(plain);
    free(msg.title);
    pcomm_msg_free_members(msg.members, msg.member_count);
    free(msg.text);
    return rc;
}
