#include "crypto.h"
#include "db.h"
#include "identity.h"
#include "msg.h"
#include "ratchet.h"
#include "ratchet_crypto.h"
#include "receive.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    pcomm_db_t db;
    pcomm_identity_t identity;
} peer_t;

typedef struct {
    uint8_t *bytes;
    size_t len;
} envelope_t;

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; \
        goto done; \
    } \
} while (0)

static int sql_exec(peer_t *peer, const char *sql) {
    char *error = NULL;
    int rc = sqlite3_exec(peer->db.db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) fprintf(stderr, "test SQL: %s\n", error ? error : "failure");
    sqlite3_free(error);
    return rc == SQLITE_OK ? 0 : -1;
}

static sqlite3_int64 sql_value(peer_t *peer, const char *sql) {
    sqlite3_stmt *st = NULL;
    sqlite3_int64 value = -1;
    if (sqlite3_prepare_v2(peer->db.db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) value = sqlite3_column_int64(st, 0);
    else fprintf(stderr, "test SQL query: %s\n", sqlite3_errmsg(peer->db.db));
    sqlite3_finalize(st);
    return value;
}

static int make_identity(pcomm_identity_t *identity) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    size_t priv_len = 32, pub_len = 32;
    int rc = ctx && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1 &&
        EVP_PKEY_get_raw_private_key(key, identity->privkey, &priv_len) == 1 &&
        EVP_PKEY_get_raw_public_key(key, identity->pubkey, &pub_len) == 1 &&
        priv_len == 32 && pub_len == 32 &&
        pcomm_user_id_from_pubkey(identity->pubkey, identity->user_id) == 0 ? 0 : -1;
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int open_database(pcomm_db_t *db) {
    if (sqlite3_open_v2(":memory:", &db->db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) return -1;
    db->replay_cache = pcomm_replay_cache_create(PCOMM_REPLAY_CACHE_CAPACITY,
                                               PCOMM_REPLAY_CACHE_TTL_MS);
    return db->replay_cache &&
        sqlite3_exec(db->db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL) == SQLITE_OK &&
        pcomm_db_init_schema(db) == 0 ? 0 : -1;
}

static int peer_open(peer_t *peer) {
    memset(peer, 0, sizeof(*peer));
    return open_database(&peer->db) == 0 && make_identity(&peer->identity) == 0 ? 0 : -1;
}

static void peer_close(peer_t *peer) {
    pcomm_db_close(&peer->db);
    OPENSSL_cleanse(&peer->identity, sizeof(peer->identity));
}

static int reopen_database(peer_t *peer) {
    pcomm_db_t replacement = {0};
    if (open_database(&replacement)) { pcomm_db_close(&replacement); return -1; }
    sqlite3_backup *backup = sqlite3_backup_init(replacement.db, "main", peer->db.db, "main");
    if (!backup) { pcomm_db_close(&replacement); return -1; }
    int copied = sqlite3_backup_step(backup, -1);
    int finished = sqlite3_backup_finish(backup);
    if (copied != SQLITE_DONE || finished != SQLITE_OK) {
        pcomm_db_close(&replacement);
        return -1;
    }
    pcomm_db_close(&peer->db);
    peer->db = replacement;
    return 0;
}

static int queue_direct(peer_t *from, peer_t *to, const char *text) {
    uint8_t *plain = NULL;
    size_t len = 0;
    if (pcomm_msg_pack_direct_text(42, from->identity.user_id, text, &plain, &len)) return -1;
    int rc = pcomm_ratchet_send(&from->db, &from->identity, to->identity.user_id, "", plain, len);
    OPENSSL_cleanse(plain, len);
    free(plain);
    return rc;
}

static int transfer_one(peer_t *from, peer_t *to, envelope_t *capture_data) {
    pcomm_ratchet_outgoing_t out = {0};
    int rc = pcomm_ratchet_outbox_next(&from->db, 2000000000, &out);
    if (rc <= 0) return rc;
    uint8_t *inner = NULL;
    size_t inner_len = 0;
    if (strcmp(out.peer, to->identity.user_id) != 0 ||
        pcomm_open_seal(to->identity.privkey, out.sealed, out.sealed_len, &inner, &inner_len) ||
        inner_len < 6 || !pcomm_ratchet_is_packet(inner, inner_len)) {
        pcomm_ratchet_outgoing_free(&out);
        free(inner);
        return -1;
    }
    if (capture_data && inner[5] == 4 && !capture_data->bytes) {
        capture_data->bytes = malloc(out.sealed_len);
        if (!capture_data->bytes) { free(inner); pcomm_ratchet_outgoing_free(&out); return -1; }
        memcpy(capture_data->bytes, out.sealed, out.sealed_len);
        capture_data->len = out.sealed_len;
    }
    OPENSSL_cleanse(inner, inner_len);
    free(inner);
    rc = pcomm_receive_sealed(&to->db, &to->identity, out.sealed, out.sealed_len, 999);
    int sent = pcomm_ratchet_outbox_sent(&from->db, out.id, 1);
    pcomm_ratchet_outgoing_free(&out);
    return (rc == 0 || rc == 1) && sent == 0 ? 1 : -1;
}

static int pump(peer_t *a, peer_t *b, envelope_t *capture_data) {
    for (unsigned i = 0; i < 256; i++) {
        int forward = transfer_one(a, b, capture_data);
        int backward = transfer_one(b, a, NULL);
        if (forward < 0 || backward < 0) return -1;
        if (!forward && !backward) return 0;
    }
    fprintf(stderr, "outbox pump did not quiesce\n");
    return -1;
}

static int establish(peer_t *a, peer_t *b) {
    return queue_direct(a, b, "bootstrap message") == 0 && pump(a, b, NULL) == 0 ? 0 : -1;
}

static void put_u64(uint8_t bytes[8], uint64_t value) {
    for (unsigned i = 0; i < 8; i++) bytes[7-i] = (uint8_t)(value >> (8*i));
}

static int forge_application(peer_t *from, peer_t *to, const char *context,
                              const uint8_t *plain, size_t plain_len,
                              envelope_t *out) {
    sqlite3_stmt *st = NULL;
    uint8_t sid[16], chain[32], next[32] = {0}, key[32] = {0};
    uint8_t packet[3072];
    sqlite3_int64 counter = 0;
    int rc = -1;
    if (sqlite3_prepare_v2(from->db.db,
            "SELECT sid,send_chain,send_n FROM ratchet_sessions WHERE peer=? AND context=?",
            -1, &st, NULL) != SQLITE_OK) goto done;
    sqlite3_bind_text(st, 1, to->identity.user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, context, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW || sqlite3_column_bytes(st, 0) != 16 ||
        sqlite3_column_bytes(st, 1) != 32) goto done;
    memcpy(sid, sqlite3_column_blob(st, 0), 16);
    memcpy(chain, sqlite3_column_blob(st, 1), 32);
    counter = sqlite3_column_int64(st, 2);
    if (counter < 0 || strlen(context) > 63) goto done;
    memcpy(packet, "PCR3", 4);
    packet[4] = 1; packet[5] = 4;
    memcpy(packet+6, from->identity.pubkey, 32);
    memcpy(packet+38, to->identity.pubkey, 32);
    memcpy(packet+70, sid, 16);
    packet[86] = (uint8_t)strlen(context);
    memcpy(packet+87, context, strlen(context));
    size_t h = 87 + strlen(context);
    put_u64(packet+h, (uint64_t)counter); h += 8;
    memset(packet+h, 0x5a, 12); h += 12;
    size_t ciphertext_len = sizeof(packet)-h;
    if (pcomm_ratchet_chain_step(chain, next, key) ||
        pcomm_aead_encrypt(key, packet+h-12, packet, h, plain, plain_len,
                            packet+h, &ciphertext_len) ||
        pcomm_seal_for_recipient(to->identity.pubkey, packet, h+ciphertext_len,
                                  &out->bytes, &out->len)) goto done;
    rc = 0;
done:
    sqlite3_finalize(st);
    OPENSSL_cleanse(chain, sizeof(chain));
    OPENSSL_cleanse(next, sizeof(next));
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(packet, sizeof(packet));
    return rc;
}

static int test_direct_replay_survives_database_reopen(void) {
    peer_t a = {0}, b = {0};
    envelope_t data = {0};
    int ok = 1;
    CHECK(peer_open(&a) == 0 && peer_open(&b) == 0);
    CHECK(queue_direct(&a, &b, "private direct text") == 0);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages") == 0);
    CHECK(pump(&a, &b, &data) == 0 && data.bytes);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0 AND body='private direct text'") == 1);
    CHECK(sql_value(&a, "SELECT count(*) FROM messages WHERE direction=1") == 1);
    CHECK(sql_value(&a, "SELECT count(*) FROM ratchet_outbox") == 0);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_outbox") == 0);
    CHECK(reopen_database(&b) == 0);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, data.bytes, data.len, 777) == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0") == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_outbox WHERE kind=5") == 1);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, data.bytes, data.len, 777) == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_outbox WHERE kind=5") == 1);
    CHECK(pump(&a, &b, NULL) == 0);
    CHECK(queue_direct(&b, &a, "reply after reopen") == 0 && pump(&a, &b, NULL) == 0);
    CHECK(sql_value(&a, "SELECT count(*) FROM messages WHERE direction=0 AND body='reply after reopen'") == 1);
done:
    free(data.bytes);
    peer_close(&a); peer_close(&b);
    return ok;
}

static int test_group_context_and_side_effects(void) {
    peer_t a = {0}, b = {0};
    envelope_t invite = {0}, forgery = {0};
    uint8_t *plain = NULL;
    size_t len = 0;
    char *members[2];
    int ok = 1;
    CHECK(peer_open(&a) == 0 && peer_open(&b) == 0);
    members[0] = a.identity.user_id; members[1] = b.identity.user_id;
    CHECK(pcomm_msg_pack_group_invite(42, a.identity.user_id, "group-one", "Private group",
                                      members, 2, &plain, &len) == 0);
    CHECK(pcomm_ratchet_send(&a.db, &a.identity, b.identity.user_id, "group-one", plain, len) == 0);
    free(plain); plain = NULL;
    CHECK(pcomm_msg_pack_group_text(43, a.identity.user_id, "group-one", "group text", &plain, &len) == 0);
    CHECK(pcomm_ratchet_send(&a.db, &a.identity, b.identity.user_id, "group-one", plain, len) == 0);
    free(plain); plain = NULL;
    CHECK(pump(&a, &b, &invite) == 0 && invite.bytes);
    CHECK(sql_value(&b, "SELECT count(*) FROM conversations WHERE type='group' AND uuid='group-one' AND title='Private group'") == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM participants") == 2);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0") == 2);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, invite.bytes, invite.len, 777) == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM participants") == 2);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0") == 2);
    CHECK(pump(&a, &b, NULL) == 0);

    CHECK(pcomm_msg_pack_group_text(44, a.identity.user_id, "different-group", "wrong context", &plain, &len) == 0);
    CHECK(forge_application(&a, &b, "group-one", plain, len, &forgery) == 0);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, forgery.bytes, forgery.len, 777) == -1);
    CHECK(sql_value(&b, "SELECT count(*) FROM conversations") == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0") == 2);
    CHECK(sql_value(&b, "SELECT recv_n FROM ratchet_sessions WHERE context='group-one'") == 2);
done:
    free(plain); free(invite.bytes); free(forgery.bytes);
    peer_close(&a); peer_close(&b);
    return ok;
}

static int test_duplicate_bootstrap_controls_are_idempotent(void) {
    peer_t a = {0}, b = {0};
    pcomm_ratchet_outgoing_t offer = {0}, response = {0};
    int ok = 1;
    CHECK(peer_open(&a) == 0 && peer_open(&b) == 0);
    CHECK(queue_direct(&a, &b, "bootstrap retries") == 0);
    CHECK(pcomm_ratchet_outbox_next(&a.db, 2000000000, &offer) == 1);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, offer.sealed, offer.sealed_len, 777) == 0);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, offer.sealed, offer.sealed_len, 777) == 0);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_outbox WHERE kind=2") == 1);
    CHECK(pcomm_ratchet_outbox_next(&b.db, 2000000000, &response) == 1);
    CHECK(pcomm_receive_sealed(&a.db, &a.identity, response.sealed, response.sealed_len, 777) == 0);
    CHECK(pcomm_receive_sealed(&a.db, &a.identity, response.sealed, response.sealed_len, 777) == 0);
    CHECK(sql_value(&a, "SELECT send_n FROM ratchet_sessions WHERE context=''") == 1);
    CHECK(sql_value(&a, "SELECT count(*) FROM ratchet_outbox WHERE kind=3") == 1);
    CHECK(pump(&a, &b, NULL) == 0);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0") == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_outbox") == 0);

    CHECK(pcomm_receive_sealed(&b.db, &b.identity, offer.sealed, offer.sealed_len, 777) == 0);
    CHECK(pump(&a, &b, NULL) == 0);
    CHECK(sql_value(&a, "SELECT count(*) FROM ratchet_outbox") == 0);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_outbox") == 0);
    CHECK(sql_value(&a, "SELECT send_n FROM ratchet_sessions WHERE context=''") == 1);
    CHECK(sql_value(&b, "SELECT recv_n FROM ratchet_sessions WHERE context=''") == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0") == 1);
done:
    pcomm_ratchet_outgoing_free(&offer);
    pcomm_ratchet_outgoing_free(&response);
    peer_close(&a); peer_close(&b);
    return ok;
}

static int test_authenticated_sender_and_kind_binding(void) {
    peer_t a = {0}, b = {0};
    pcomm_identity_t impersonated = {0};
    uint8_t *plain = NULL;
    size_t len = 0;
    envelope_t forgery = {0};
    int ok = 1;
    CHECK(peer_open(&a) == 0 && peer_open(&b) == 0 && make_identity(&impersonated) == 0);
    CHECK(establish(&a, &b) == 0);
    CHECK(pcomm_msg_pack_direct_text(43, impersonated.user_id, "forged sender", &plain, &len) == 0);
    CHECK(forge_application(&a, &b, "", plain, len, &forgery) == 0);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, forgery.bytes, forgery.len, 777) == -1);
    CHECK(sql_value(&b, "SELECT recv_n FROM ratchet_sessions WHERE context=''") == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_received") == 1);
    free(plain); plain = NULL; free(forgery.bytes); forgery = (envelope_t){0};

    CHECK(pcomm_msg_pack_group_text(44, a.identity.user_id, "injected-group", "wrong kind", &plain, &len) == 0);
    CHECK(forge_application(&a, &b, "", plain, len, &forgery) == 0);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, forgery.bytes, forgery.len, 777) == -1);
    CHECK(sql_value(&b, "SELECT count(*) FROM conversations WHERE type='group'") == 0);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_received") == 1);
    CHECK(queue_direct(&a, &b, "valid after rejected forgeries") == 0 && pump(&a, &b, NULL) == 0);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0") == 2);
done:
    free(plain); free(forgery.bytes);
    OPENSSL_cleanse(&impersonated, sizeof(impersonated));
    peer_close(&a); peer_close(&b);
    return ok;
}

static int test_legacy_downgrade_rejects_identity_alias(void) {
    peer_t a = {0}, b = {0};
    uint8_t *plain = NULL, *sealed = NULL;
    size_t plain_len = 0, sealed_len = 0;
    uint8_t alias_key[32];
    int ok = 1;
    CHECK(peer_open(&a) == 0 && peer_open(&b) == 0);
    CHECK(establish(&a, &b) == 0);
    const char *alias = a.identity.user_id + strlen("pcomm1_");
    CHECK(pcomm_pubkey_from_user_id(alias, alias_key) == 0 &&
          CRYPTO_memcmp(alias_key, a.identity.pubkey, 32) == 0);
    CHECK(pcomm_msg_pack_direct_text(44, alias, "legacy downgrade", &plain, &plain_len) == 0);
    CHECK(pcomm_seal_for_recipient(b.identity.pubkey, plain, plain_len, &sealed, &sealed_len) == 0);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, sealed, sealed_len, 777) == -1);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0") == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM conversations") == 1);
done:
    free(plain); free(sealed);
    peer_close(&a); peer_close(&b);
    return ok;
}

static int test_storage_failure_rolls_back_and_can_retry(void) {
    peer_t a = {0}, b = {0};
    pcomm_ratchet_outgoing_t data = {0};
    int ok = 1;
    CHECK(peer_open(&a) == 0 && peer_open(&b) == 0);
    CHECK(establish(&a, &b) == 0);
    CHECK(queue_direct(&a, &b, "retry exact ciphertext after storage failure") == 0);
    CHECK(pcomm_ratchet_outbox_next(&a.db, 2000000000, &data) == 1);
    CHECK(sql_exec(&b, "CREATE TRIGGER reject_message BEFORE INSERT ON messages WHEN NEW.direction=0 "
                        "BEGIN SELECT RAISE(FAIL, 'injected write failure'); END;") == 0);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, data.sealed, data.sealed_len, 777) == -1);
    CHECK(sql_value(&b, "SELECT recv_n FROM ratchet_sessions WHERE context=''") == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_received") == 1);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_outbox") == 0);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0") == 1);
    CHECK(sql_exec(&b, "DROP TRIGGER reject_message") == 0);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, data.sealed, data.sealed_len, 777) == 0);
    CHECK(pcomm_receive_sealed(&b.db, &b.identity, data.sealed, data.sealed_len, 777) == 1);
    CHECK(sql_value(&b, "SELECT recv_n FROM ratchet_sessions WHERE context=''") == 2);
    CHECK(sql_value(&b, "SELECT count(*) FROM ratchet_received") == 2);
    CHECK(sql_value(&b, "SELECT count(*) FROM messages WHERE direction=0") == 2);
    CHECK(pump(&a, &b, NULL) == 0);
    CHECK(sql_value(&a, "SELECT count(*) FROM ratchet_outbox") == 0);
done:
    pcomm_ratchet_outgoing_free(&data);
    peer_close(&a); peer_close(&b);
    return ok;
}

int main(void) {
    const struct { const char *name; int (*run)(void); } tests[] = {
        {"direct replay survives database reopen and re-ACKs", test_direct_replay_survives_database_reopen},
        {"group context and side effects", test_group_context_and_side_effects},
        {"duplicate bootstrap controls remain idempotent", test_duplicate_bootstrap_controls_are_idempotent},
        {"authenticated sender and kind binding", test_authenticated_sender_and_kind_binding},
        {"legacy downgrade rejects identity alias", test_legacy_downgrade_rejects_identity_alias},
        {"storage failure rolls back and exact DATA retries", test_storage_failure_rolls_back_and_can_retry},
    };
    unsigned failed = 0;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        int passed = tests[i].run();
        printf("%s: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if (!passed) failed++;
    }
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
