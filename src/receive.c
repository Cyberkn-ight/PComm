#include "receive.h"
#include "crypto.h"
#include "msg.h"
#include "replay.h"

#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdlib.h>

typedef struct {
    pcomm_db_t *db;
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
} received_message_t;

/* The replay cache serializes this callback so two ingress workers cannot both
 * create conversation/group side effects for the same accepted envelope.
 */
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
    msg.sealed = sealed;
    msg.sealed_len = sealed_len;
    int rc = -1;

    if (pcomm_msg_unpack_any(plain, plain_len, &msg.kind, &msg.ts,
                             msg.sender, sizeof(msg.sender),
                             msg.group_uuid, sizeof(msg.group_uuid),
                             &msg.title, &msg.members, &msg.member_count, &msg.text) == 0) {
        if (!msg.ts) msg.ts = fallback_ts;
        uint8_t tag[PCOMM_REPLAY_TAG_LEN];
        uint64_t now_ms;
        /* X25519 public keys have equivalent encodings (RFC 7748, section 7).
         * Fingerprint the authenticated nonce/ciphertext/tag, not the malleable
         * ephemeral-key prefix, after successful decryption and parsing.
         */
        if (SHA256(sealed + PCOMM_SEAL_EPH_PUB_LEN, sealed_len - PCOMM_SEAL_EPH_PUB_LEN, tag) &&
            pcomm_replay_now_ms(&now_ms) == 0) {
            rc = pcomm_replay_apply(db->replay_cache, tag, now_ms, store_received_message, &msg);
        }
    }

    OPENSSL_cleanse(plain, plain_len);
    free(plain);
    free(msg.title);
    pcomm_msg_free_members(msg.members, msg.member_count);
    free(msg.text);
    return rc;
}
