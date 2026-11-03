#include "ratchet.h"
#include "ratchet_crypto.h"
#include "crypto.h"
#include "identity.h"
#include "msg.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; goto done; \
    } \
} while (0)

enum { OFFER = 1, RESPONSE, CONFIRM, DATA, ACK };
typedef struct { pcomm_db_t db; pcomm_identity_t me; } node_t;
typedef struct { node_t a, b; int64_t now; } pair_t;
typedef struct {
    pcomm_ratchet_outgoing_t outgoing;
    uint8_t *packet;
    size_t packet_len;
    unsigned kind;
} envelope_t;

static int make_identity(pcomm_identity_t *me) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    size_t private_len = 32, public_len = 32;
    int good = ctx && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1 &&
        EVP_PKEY_get_raw_private_key(key, me->privkey, &private_len) == 1 &&
        EVP_PKEY_get_raw_public_key(key, me->pubkey, &public_len) == 1 &&
        private_len == 32 && public_len == 32 && pcomm_user_id_from_pubkey(me->pubkey, me->user_id) == 0;
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return good ? 0 : -1;
}

static int node_open(node_t *node, const pcomm_identity_t *identity) {
    memset(node, 0, sizeof(*node));
    if (sqlite3_open_v2(":memory:", &node->db.db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK ||
        sqlite3_exec(node->db.db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL) != SQLITE_OK ||
        pcomm_db_init_schema(&node->db) != 0) return -1;
    if (identity) { node->me = *identity; return 0; }
    return make_identity(&node->me);
}

static void node_close(node_t *node) {
    pcomm_db_close(&node->db);
    OPENSSL_cleanse(&node->me, sizeof(node->me));
}

static int pair_open(pair_t *pair) {
    memset(pair, 0, sizeof(*pair));
    pair->now = 1000;
    return node_open(&pair->a, NULL) == 0 && node_open(&pair->b, NULL) == 0 ? 0 : -1;
}

static void pair_close(pair_t *pair) {
    node_close(&pair->a);
    node_close(&pair->b);
}

static sqlite3_int64 scalar(node_t *node, const char *sql) {
    sqlite3_stmt *st = NULL;
    sqlite3_int64 value = -1;
    if (sqlite3_prepare_v2(node->db.db, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return value;
}

static int exec_sql(node_t *node, const char *sql) {
    return sqlite3_exec(node->db.db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static int session_snapshot(node_t *node, char out[1024]) {
    sqlite3_stmt *st = NULL;
    int rc = -1;
    const char *sql = "SELECT hex(sid)||':'||state||':'||initiator||':'||send_n||':'||recv_n||':'||"
        "hex(private_eph)||':'||hex(root_key)||':'||hex(send_chain)||':'||hex(recv_chain) FROM ratchet_sessions;";
    if (sqlite3_prepare_v2(node->db.db, sql, -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW) goto done;
    int bytes = sqlite3_column_bytes(st, 0);
    if (bytes < 0 || bytes >= 1024) goto done;
    memcpy(out, sqlite3_column_text(st, 0), (size_t)bytes);
    out[bytes] = '\0';
    rc = 0;
done:
    sqlite3_finalize(st);
    return rc;
}

static int read_blob(node_t *node, const char *sql, uint8_t *out, int length) {
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (sqlite3_prepare_v2(node->db.db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) == SQLITE_BLOB &&
        sqlite3_column_bytes(st, 0) == length) {
        memcpy(out, sqlite3_column_blob(st, 0), (size_t)length);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int store_message(void *arg, const char *sender, const char *context,
                           const uint8_t *plain, size_t plain_len) {
    node_t *node = arg;
    pcomm_plain_kind_t kind;
    uint32_t ts = 0;
    char claimed_sender[96], group[64], *title = NULL, **members = NULL, *text = NULL;
    int member_count = 0, rc = -1;
    if (pcomm_msg_unpack_any(plain, plain_len, &kind, &ts, claimed_sender, sizeof(claimed_sender),
        group, sizeof(group), &title, &members, &member_count, &text) != 0 ||
        kind != PCOMM_PLAIN_DIRECT_TEXT || *context || strcmp(sender, claimed_sender)) goto done;
    int64_t conv = pcomm_db_get_or_create_direct_conv(&node->db, sender);
    if (conv >= 0) rc = pcomm_db_insert_message(&node->db, conv, 0, sender, sender, text,
                                               plain, plain_len, ts);
done:
    free(title); free(text); pcomm_msg_free_members(members, member_count);
    return rc;
}

static int send_text(node_t *from, const node_t *to, const char *text) {
    uint8_t *plain = NULL;
    size_t len = 0;
    if (pcomm_msg_pack_direct_text(123, from->me.user_id, text, &plain, &len) != 0) return -1;
    int rc = pcomm_ratchet_send(&from->db, &from->me, to->me.user_id, "", plain, len);
    OPENSSL_cleanse(plain, len);
    free(plain);
    return rc;
}

static void envelope_free(envelope_t *envelope) {
    pcomm_ratchet_outgoing_free(&envelope->outgoing);
    free(envelope->packet);
    memset(envelope, 0, sizeof(*envelope));
}

static int take(node_t *from, node_t *to, int64_t now, envelope_t *envelope) {
    memset(envelope, 0, sizeof(*envelope));
    int rc = pcomm_ratchet_outbox_next(&from->db, now, &envelope->outgoing);
    if (rc != 1) return rc;
    if (strcmp(envelope->outgoing.peer, to->me.user_id) ||
        pcomm_open_seal(to->me.privkey, envelope->outgoing.sealed, envelope->outgoing.sealed_len,
                         &envelope->packet, &envelope->packet_len) != 0 ||
        envelope->packet_len < 6 || !pcomm_ratchet_is_packet(envelope->packet, envelope->packet_len)) {
        envelope_free(envelope);
        return -1;
    }
    envelope->kind = envelope->packet[5];
    return 1;
}

static int deliver(node_t *to, const envelope_t *envelope) {
    return pcomm_ratchet_receive(&to->db, &to->me, envelope->packet, envelope->packet_len, store_message, to);
}

static int transfer(node_t *from, node_t *to, int64_t now) {
    envelope_t envelope = {0};
    int rc = take(from, to, now, &envelope);
    if (rc == 1) {
        if (deliver(to, &envelope) < 0 || pcomm_ratchet_outbox_sent(&from->db, envelope.outgoing.id, 1) != 0) rc = -1;
    }
    envelope_free(&envelope);
    return rc;
}

static int pump(pair_t *pair) {
    for (unsigned step = 0; step < 1024; step++, pair->now += 5) {
        if (scalar(&pair->a, "SELECT count(*) FROM ratchet_outbox;") == 0 &&
            scalar(&pair->b, "SELECT count(*) FROM ratchet_outbox;") == 0 &&
            scalar(&pair->a, "SELECT count(*) FROM ratchet_pending;") == 0 &&
            scalar(&pair->b, "SELECT count(*) FROM ratchet_pending;") == 0) return 0;
        if (transfer(&pair->a, &pair->b, pair->now) < 0 || transfer(&pair->b, &pair->a, pair->now) < 0) return -1;
    }
    fprintf(stderr, "ratchet pump did not reach quiescence\n");
    return -1;
}

static int establish(pair_t *pair, envelope_t *saved_offer) {
    envelope_t offer = {0};
    if (send_text(&pair->a, &pair->b, "bootstrap message") != 0 ||
        take(&pair->a, &pair->b, pair->now, &offer) != 1 || offer.kind != OFFER ||
        deliver(&pair->b, &offer) != 0 || pcomm_ratchet_outbox_sent(&pair->a.db, offer.outgoing.id, 1) != 0) {
        envelope_free(&offer); return -1;
    }
    if (saved_offer) { *saved_offer = offer; memset(&offer, 0, sizeof(offer)); }
    envelope_free(&offer);
    return pump(pair);
}

static int test_bootstrap_and_two_way_chains(void) {
    pair_t pair = {0};
    envelope_t offer = {0}, response = {0};
    int ok = 1;
    CHECK(pair_open(&pair) == 0);
    CHECK(send_text(&pair.a, &pair.b, "first plaintext waits for response") == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_pending;") == 1);
    CHECK(scalar(&pair.a, "SELECT length(private_eph) FROM ratchet_sessions;") == 32);
    CHECK(scalar(&pair.a, "SELECT send_n FROM ratchet_sessions;") == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_outbox WHERE kind=4;") == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &offer) == 1 && offer.kind == OFFER);
    CHECK(deliver(&pair.b, &offer) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_pending;") == 1);
    CHECK(take(&pair.b, &pair.a, pair.now, &response) == 1 && response.kind == RESPONSE);
    CHECK(deliver(&pair.a, &response) == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_pending;") == 0);
    CHECK(scalar(&pair.a, "SELECT private_eph IS NULL FROM ratchet_sessions;") == 1);
    CHECK(pump(&pair) == 0);
    CHECK(send_text(&pair.b, &pair.a, "reply uses the opposite chain") == 0 && pump(&pair) == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM messages WHERE direction=0;") == 1);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == 1);
    CHECK(scalar(&pair.a, "SELECT send_n=1 AND recv_n=1 FROM ratchet_sessions;") == 1);
    CHECK(scalar(&pair.b, "SELECT send_n=1 AND recv_n=1 AND private_eph IS NULL FROM ratchet_sessions;") == 1);
done:
    envelope_free(&offer); envelope_free(&response); pair_close(&pair);
    return ok;
}

static int test_immutable_retry_and_lost_ack(void) {
    pair_t pair = {0};
    envelope_t data = {0}, retry = {0}, ack = {0};
    int ok = 1;
    CHECK(pair_open(&pair) == 0 && establish(&pair, NULL) == 0);
    CHECK(send_text(&pair.a, &pair.b, "retry exact ciphertext") == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &data) == 1 && data.kind == DATA);
    CHECK(pcomm_ratchet_outbox_sent(&pair.a.db, data.outgoing.id, 0) == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &retry) == 0);
    CHECK(take(&pair.a, &pair.b, pair.now + 5, &retry) == 1);
    CHECK(data.outgoing.id == retry.outgoing.id && data.outgoing.sealed_len == retry.outgoing.sealed_len);
    CHECK(memcmp(data.outgoing.sealed, retry.outgoing.sealed, data.outgoing.sealed_len) == 0);
    CHECK(pcomm_ratchet_outbox_sent(&pair.a.db, retry.outgoing.id, 1) == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_outbox WHERE kind=4;") == 1);
    CHECK(deliver(&pair.b, &data) == 0);
    CHECK(take(&pair.b, &pair.a, pair.now, &ack) == 1 && ack.kind == ACK);
    ack.packet[ack.packet_len - 1] ^= 1;
    CHECK(deliver(&pair.a, &ack) == -1);
    ack.packet[ack.packet_len - 1] ^= 1;
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_outbox WHERE kind=4;") == 1);

    CHECK(pcomm_ratchet_outbox_sent(&pair.b.db, ack.outgoing.id, 1) == 0);
    envelope_free(&ack);
    CHECK(deliver(&pair.b, &retry) == 1);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == 2);
    CHECK(take(&pair.b, &pair.a, pair.now + 10, &ack) == 1 && ack.kind == ACK);
    CHECK(deliver(&pair.a, &ack) == 0);
    CHECK(pcomm_ratchet_outbox_sent(&pair.b.db, ack.outgoing.id, 1) == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_outbox WHERE kind=4;") == 0);
done:
    envelope_free(&data); envelope_free(&retry); envelope_free(&ack); pair_close(&pair);
    return ok;
}

static int test_out_of_order_and_skip_bound(void) {
    pair_t pair = {0};
    envelope_t messages[3] = {0};
    uint8_t *invalid = NULL;
    char before[1024], after[1024];
    int ok = 1;
    CHECK(pair_open(&pair) == 0 && establish(&pair, NULL) == 0);
    for (unsigned i = 0; i < 3; i++) {
        CHECK(send_text(&pair.a, &pair.b, "out-of-order message") == 0);
        CHECK(take(&pair.a, &pair.b, pair.now, &messages[i]) == 1 && messages[i].kind == DATA);
    }
    CHECK(deliver(&pair.b, &messages[2]) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_skipped;") == 2);
    CHECK(deliver(&pair.b, &messages[0]) == 0 && deliver(&pair.b, &messages[1]) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_skipped;") == 0);
    CHECK(deliver(&pair.b, &messages[2]) == 1);
    CHECK(session_snapshot(&pair.b, before) == 0);
    invalid = malloc(messages[2].packet_len);
    CHECK(invalid != NULL && messages[2].packet_len > 95);
    memcpy(invalid, messages[2].packet, messages[2].packet_len);
    size_t counter_offset = 87u + invalid[86];
    CHECK(counter_offset + 8 <= messages[2].packet_len);
    uint64_t forged = (uint64_t)scalar(&pair.b, "SELECT recv_n FROM ratchet_sessions;") + PCOMM_RATCHET_MAX_SKIP + 1u;
    for (unsigned i = 0; i < 8; i++) invalid[counter_offset + 7u - i] = (uint8_t)(forged >> (i * 8u));
    CHECK(pcomm_ratchet_receive(&pair.b.db, &pair.b.me, invalid, messages[2].packet_len,
                                 store_message, &pair.b) == -1);
    CHECK(session_snapshot(&pair.b, after) == 0 && strcmp(before, after) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_skipped;") == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == 4);
    pair.now += 10;
    CHECK(pump(&pair) == 0);
done:
    for (unsigned i = 0; i < 3; i++) envelope_free(&messages[i]);
    free(invalid); pair_close(&pair);
    return ok;
}

static int test_sender_window_tracks_oldest_unacked(void) {
    pair_t pair = {0};
    envelope_t oldest = {0}, newer = {0}, ack = {0};
    int ok = 1;
    CHECK(pair_open(&pair) == 0 && establish(&pair, NULL) == 0);
    CHECK(send_text(&pair.a, &pair.b, "oldest held back") == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &oldest) == 1 && oldest.kind == DATA);
    for (unsigned i = 1; i < PCOMM_RATCHET_MAX_SKIP; i++) {
        CHECK(send_text(&pair.a, &pair.b, "newer message acknowledged") == 0);
        CHECK(take(&pair.a, &pair.b, pair.now, &newer) == 1 && newer.kind == DATA);
        CHECK(deliver(&pair.b, &newer) == 0);
        CHECK(take(&pair.b, &pair.a, pair.now, &ack) == 1 && ack.kind == ACK);
        CHECK(deliver(&pair.a, &ack) == 0 && pcomm_ratchet_outbox_sent(&pair.b.db, ack.outgoing.id, 1) == 0);
        envelope_free(&newer); envelope_free(&ack);
    }
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_outbox WHERE kind=4;") == 1);
    sqlite3_int64 send_n = scalar(&pair.a, "SELECT send_n FROM ratchet_sessions;");
    CHECK(send_n == PCOMM_RATCHET_MAX_SKIP + 1u);
    CHECK(send_text(&pair.a, &pair.b, "wait until oldest is acknowledged") == 0);
    CHECK(scalar(&pair.a, "SELECT send_n FROM ratchet_sessions;") == send_n);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_pending;") == 1);
    CHECK(deliver(&pair.b, &oldest) == 0);
    CHECK(take(&pair.b, &pair.a, pair.now, &ack) == 1 && ack.kind == ACK);
    CHECK(deliver(&pair.a, &ack) == 0 && pcomm_ratchet_outbox_sent(&pair.b.db, ack.outgoing.id, 1) == 0);
    CHECK(scalar(&pair.a, "SELECT send_n FROM ratchet_sessions;") == send_n + 1);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_pending;") == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &newer) == 1 && newer.kind == DATA);
    CHECK(deliver(&pair.b, &newer) == 0);
    pair.now += 10;
    CHECK(pump(&pair) == 0);
done:
    envelope_free(&oldest); envelope_free(&newer); envelope_free(&ack); pair_close(&pair);
    return ok;
}

static int test_simultaneous_offers_and_reset_rejection(void) {
    pair_t pair = {0};
    node_t reset = {0};
    envelope_t offer_a = {0}, offer_b = {0}, reset_offer = {0};
    char original_a[1024], original_b[1024], before[1024], after[1024];
    int ok = 1;
    CHECK(pair_open(&pair) == 0);
    CHECK(send_text(&pair.a, &pair.b, "simultaneous A") == 0 && send_text(&pair.b, &pair.a, "simultaneous B") == 0);
    CHECK(session_snapshot(&pair.a, original_a) == 0 && session_snapshot(&pair.b, original_b) == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &offer_a) == 1 && offer_a.kind == OFFER);
    CHECK(take(&pair.b, &pair.a, pair.now, &offer_b) == 1 && offer_b.kind == OFFER);
    CHECK(deliver(&pair.b, &offer_a) == 0 && deliver(&pair.a, &offer_b) == 0);
    CHECK(pump(&pair) == 0);
    int a_wins = memcmp(pair.a.me.pubkey, pair.b.me.pubkey, 32) < 0;
    node_t *initiator = a_wins ? &pair.a : &pair.b;
    node_t *responder = a_wins ? &pair.b : &pair.a;
    envelope_t *winner = a_wins ? &offer_a : &offer_b;
    envelope_t *loser = a_wins ? &offer_b : &offer_a;
    const char *chosen_sid = a_wins ? original_a : original_b;
    CHECK(session_snapshot(&pair.a, before) == 0 && strncmp(before, chosen_sid, 32) == 0);
    CHECK(session_snapshot(&pair.b, after) == 0 && strncmp(after, chosen_sid, 32) == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM messages WHERE direction=0;") == 1);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == 1);
    CHECK(deliver(initiator, loser) == -1);
    CHECK(session_snapshot(responder, before) == 0);
    CHECK(deliver(responder, winner) == 0);
    CHECK(session_snapshot(responder, after) == 0 && strcmp(before, after) == 0);
    CHECK(pump(&pair) == 0);
    CHECK(node_open(&reset, &initiator->me) == 0);
    CHECK(send_text(&reset, responder, "new session must not replace active session") == 0);
    CHECK(take(&reset, responder, pair.now, &reset_offer) == 1 && reset_offer.kind == OFFER);
    CHECK(session_snapshot(responder, before) == 0);
    CHECK(deliver(responder, &reset_offer) == -1);
    CHECK(session_snapshot(responder, after) == 0 && strcmp(before, after) == 0);
done:
    envelope_free(&offer_a); envelope_free(&offer_b); envelope_free(&reset_offer);
    node_close(&reset); pair_close(&pair);
    return ok;
}

static int test_storage_failures_roll_back_state_and_messages(void) {
    static const char *faults[] = {
        "CREATE TEMP TRIGGER ratchet_fault BEFORE INSERT ON messages WHEN NEW.direction=0 "
        "BEGIN SELECT RAISE(ABORT,'message write failure'); END;",
        "CREATE TEMP TRIGGER ratchet_fault BEFORE INSERT ON ratchet_outbox WHEN NEW.kind=5 "
        "BEGIN SELECT RAISE(ABORT,'ACK write failure'); END;",
        "CREATE TEMP TRIGGER ratchet_fault BEFORE UPDATE ON ratchet_sessions "
        "BEGIN SELECT RAISE(ABORT,'state write failure'); END;",
    };
    pair_t pair = {0};
    envelope_t data = {0};
    char before[1024], after[1024];
    int ok = 1;
    CHECK(pair_open(&pair) == 0 && establish(&pair, NULL) == 0);
    for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); i++) {
        CHECK(send_text(&pair.a, &pair.b, "retry after receiver storage failure") == 0);
        CHECK(take(&pair.a, &pair.b, pair.now, &data) == 1 && data.kind == DATA);
        CHECK(session_snapshot(&pair.b, before) == 0 && exec_sql(&pair.b, faults[i]) == 0);
        sqlite3_int64 received = scalar(&pair.b, "SELECT count(*) FROM ratchet_received;");
        sqlite3_int64 messages = scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;");
        CHECK(deliver(&pair.b, &data) == -1);
        CHECK(sqlite3_get_autocommit(pair.b.db.db) != 0);
        CHECK(session_snapshot(&pair.b, after) == 0 && strcmp(before, after) == 0);
        CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_received;") == received);
        CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == messages);
        CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_outbox;") == 0);
        CHECK(exec_sql(&pair.b, "DROP TRIGGER ratchet_fault;") == 0);
        CHECK(deliver(&pair.b, &data) == 0);
        envelope_free(&data);
        pair.now += 5;
        CHECK(pump(&pair) == 0);
    }
    CHECK(session_snapshot(&pair.a, before) == 0);
    sqlite3_int64 sent = scalar(&pair.a, "SELECT count(*) FROM messages WHERE direction=1;");
    CHECK(exec_sql(&pair.a,
        "CREATE TEMP TRIGGER ratchet_fault BEFORE INSERT ON ratchet_outbox WHEN NEW.kind=4 "
        "BEGIN SELECT RAISE(ABORT,'outbox write failure'); END;") == 0);
    CHECK(send_text(&pair.a, &pair.b, "outgoing write must be atomic") == -1);
    CHECK(session_snapshot(&pair.a, after) == 0 && strcmp(before, after) == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_pending;") == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM messages WHERE direction=1;") == sent);
    CHECK(exec_sql(&pair.a, "DROP TRIGGER ratchet_fault;") == 0);
    CHECK(send_text(&pair.a, &pair.b, "outgoing write must be atomic") == 0 && pump(&pair) == 0);
done:
    envelope_free(&data); pair_close(&pair);
    return ok;
}

static int node_restart(node_t *node) {
    sqlite3_int64 size = 0;
    uint8_t *image = sqlite3_serialize(node->db.db, "main", &size, 0);
    pcomm_db_t replacement = {0};
    if (!image || size <= 0) { sqlite3_free(image); return -1; }
    if (sqlite3_open_v2(":memory:", &replacement.db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) {
        sqlite3_free(image); pcomm_db_close(&replacement); return -1;
    }

    if (sqlite3_deserialize(replacement.db, "main", image, size, size,
        SQLITE_DESERIALIZE_FREEONCLOSE | SQLITE_DESERIALIZE_RESIZEABLE) != SQLITE_OK ||
        sqlite3_exec(replacement.db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL) != SQLITE_OK ||
        pcomm_db_init_schema(&replacement) != 0) {
        pcomm_db_close(&replacement); return -1;
    }
    if (sqlite3_next_stmt(node->db.db, NULL) != NULL || sqlite3_close(node->db.db) != SQLITE_OK) {
        pcomm_db_close(&replacement); return -1;
    }
    node->db.db = NULL;
    pcomm_db_close(&node->db);
    node->db = replacement;
    return 0;
}

static int test_restart_preserves_pending_keys_and_counters(void) {
    pair_t pair = {0};
    envelope_t offer = {0}, response = {0}, data = {0}, retry = {0}, ack = {0};
    int ok = 1;
    CHECK(pair_open(&pair) == 0);
    CHECK(send_text(&pair.a, &pair.b, "pending plaintext survives restart") == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &offer) == 1 && offer.kind == OFFER);
    CHECK(node_restart(&pair.a) == 0);
    CHECK(scalar(&pair.a, "SELECT length(private_eph) FROM ratchet_sessions;") == 32);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_pending;") == 1);
    CHECK(take(&pair.a, &pair.b, pair.now + 5, &retry) == 1);
    CHECK(offer.outgoing.id == retry.outgoing.id && offer.outgoing.sealed_len == retry.outgoing.sealed_len);
    CHECK(memcmp(offer.outgoing.sealed, retry.outgoing.sealed, offer.outgoing.sealed_len) == 0);
    envelope_free(&retry);
    CHECK(deliver(&pair.b, &offer) == 0 && node_restart(&pair.b) == 0);
    CHECK(scalar(&pair.b, "SELECT private_eph IS NULL AND length(root_key)=32 FROM ratchet_sessions;") == 1);
    CHECK(take(&pair.b, &pair.a, pair.now, &response) == 1 && response.kind == RESPONSE);
    CHECK(deliver(&pair.a, &response) == 0 && node_restart(&pair.a) == 0);
    CHECK(scalar(&pair.a, "SELECT send_n FROM ratchet_sessions;") == 1);
    CHECK(scalar(&pair.a, "SELECT private_eph IS NULL FROM ratchet_sessions;") == 1);
    CHECK(pump(&pair) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == 1);

    CHECK(send_text(&pair.a, &pair.b, "active chain survives restart") == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &data) == 1 && data.kind == DATA);
    CHECK(node_restart(&pair.a) == 0);
    CHECK(take(&pair.a, &pair.b, pair.now + 5, &retry) == 1 && retry.kind == DATA);
    CHECK(data.outgoing.id == retry.outgoing.id && data.outgoing.sealed_len == retry.outgoing.sealed_len);
    CHECK(memcmp(data.outgoing.sealed, retry.outgoing.sealed, data.outgoing.sealed_len) == 0);
    CHECK(deliver(&pair.b, &data) == 0 && node_restart(&pair.b) == 0);
    CHECK(deliver(&pair.b, &retry) == 1);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == 2);
    CHECK(take(&pair.b, &pair.a, pair.now + 5, &ack) == 1 && ack.kind == ACK);
    CHECK(deliver(&pair.a, &ack) == 0 && pcomm_ratchet_outbox_sent(&pair.b.db, ack.outgoing.id, 1) == 0);
    CHECK(node_restart(&pair.a) == 0);
    CHECK(scalar(&pair.a, "SELECT send_n FROM ratchet_sessions;") == 2);
    CHECK(scalar(&pair.b, "SELECT recv_n FROM ratchet_sessions;") == 2);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_outbox;") == 0);
    CHECK(sqlite3_next_stmt(pair.a.db.db, NULL) == NULL && sqlite3_next_stmt(pair.b.db.db, NULL) == NULL);
done:
    envelope_free(&offer); envelope_free(&response); envelope_free(&data);
    envelope_free(&retry); envelope_free(&ack); pair_close(&pair);
    return ok;
}

static int test_skip_cache_at_send_window_limit(void) {
    pair_t pair = {0};
    envelope_t newest = {0};
    int ok = 1;
    CHECK(pair_open(&pair) == 0 && establish(&pair, NULL) == 0);
    for (unsigned i = 0; i < PCOMM_RATCHET_MAX_SKIP; i++)
        CHECK(send_text(&pair.a, &pair.b, "deliver the entire window backwards") == 0);
    for (unsigned i = 0; i < PCOMM_RATCHET_MAX_SKIP; i++) {
        envelope_free(&newest);
        CHECK(take(&pair.a, &pair.b, pair.now, &newest) == 1 && newest.kind == DATA);
    }
    CHECK(deliver(&pair.b, &newest) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_skipped;") == PCOMM_RATCHET_MAX_SKIP - 1u);
    CHECK(scalar(&pair.b, "SELECT recv_n FROM ratchet_sessions;") == PCOMM_RATCHET_MAX_SKIP + 1u);
    CHECK(deliver(&pair.b, &newest) == 1);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_skipped;") == PCOMM_RATCHET_MAX_SKIP - 1u);
done:
    envelope_free(&newest); pair_close(&pair);
    return ok;
}

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready;
    int released;
} send_gate_t;

typedef struct {
    pair_t *pair;
    send_gate_t *gate;
    unsigned index;
    int result;
} writer_t;

static void *send_concurrently(void *arg) {
    writer_t *writer = arg;
    char text[64];
    snprintf(text, sizeof(text), "concurrent message %u", writer->index);
    pthread_mutex_lock(&writer->gate->mutex);
    writer->gate->ready++;
    pthread_cond_broadcast(&writer->gate->condition);
    while (!writer->gate->released) pthread_cond_wait(&writer->gate->condition, &writer->gate->mutex);
    pthread_mutex_unlock(&writer->gate->mutex);
    writer->result = send_text(&writer->pair->a, &writer->pair->b, text);
    return NULL;
}

static int test_concurrent_sends_use_unique_counters(void) {
    enum { WORKERS = 8 };
    pair_t pair = {0};
    send_gate_t gate = {0};
    pthread_t threads[WORKERS];
    writer_t writers[WORKERS];
    unsigned started = 0;
    int mutex_ready = 0, condition_ready = 0;
    int ok = 1;
    CHECK(pair_open(&pair) == 0 && establish(&pair, NULL) == 0);
    CHECK(pthread_mutex_init(&gate.mutex, NULL) == 0);
    mutex_ready = 1;
    CHECK(pthread_cond_init(&gate.condition, NULL) == 0);
    condition_ready = 1;
    for (unsigned i = 0; i < WORKERS; i++) {
        writers[i] = (writer_t){&pair, &gate, i, -99};
        if (pthread_create(&threads[i], NULL, send_concurrently, &writers[i]) != 0) { ok = 0; break; }
        started++;
    }
    pthread_mutex_lock(&gate.mutex);
    while (gate.ready < started) pthread_cond_wait(&gate.condition, &gate.mutex);
    gate.released = 1;
    pthread_cond_broadcast(&gate.condition);
    pthread_mutex_unlock(&gate.mutex);
    for (unsigned i = 0; i < started; i++) {
        if (pthread_join(threads[i], NULL) != 0 || writers[i].result != 0) ok = 0;
    }
    CHECK(started == WORKERS && ok);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_outbox WHERE kind=4;") == WORKERS);
    CHECK(scalar(&pair.a, "SELECT count(DISTINCT n) FROM ratchet_outbox WHERE kind=4;") == WORKERS);
    CHECK(scalar(&pair.a, "SELECT min(n)=1 AND max(n)=8 FROM ratchet_outbox WHERE kind=4;") == 1);
    CHECK(scalar(&pair.a, "SELECT send_n FROM ratchet_sessions;") == WORKERS + 1u);
    CHECK(pump(&pair) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == WORKERS + 1u);
done:
    if (condition_ready) pthread_cond_destroy(&gate.condition);
    if (mutex_ready) pthread_mutex_destroy(&gate.mutex);
    pair_close(&pair);
    return ok;
}

static int fill_synthetic_outbox(node_t *node, const uint8_t sid[16], unsigned first,
                                  unsigned count, int64_t now) {
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (count > PCOMM_RATCHET_MAX_OUTBOX || exec_sql(node, "BEGIN;") != 0) return -1;
    if (sqlite3_prepare_v2(node->db.db,
        "INSERT INTO ratchet_outbox(peer,context,sid,kind,n,wire,next_attempt) "
        "VALUES('synthetic','',?1,99,?2,zeroblob(1),?3);", -1, &st, NULL) != SQLITE_OK) goto done;
    for (unsigned i = 0; i < count; i++) {
        if (sqlite3_bind_blob(st, 1, sid, 16, SQLITE_TRANSIENT) != SQLITE_OK ||
            sqlite3_bind_int64(st, 2, (sqlite3_int64)first + i) != SQLITE_OK ||
            sqlite3_bind_int64(st, 3, now + 30) != SQLITE_OK ||
            sqlite3_step(st) != SQLITE_DONE || sqlite3_reset(st) != SQLITE_OK) goto done;
    }
    rc = 0;
done:
    sqlite3_finalize(st);
    if (rc == 0) return exec_sql(node, "COMMIT;");
    exec_sql(node, "ROLLBACK;");
    return -1;
}

static int test_reack_refreshes_existing_entry_at_outbox_capacity(void) {
    pair_t pair = {0};
    envelope_t data = {0}, ack = {0}, refreshed = {0};
    uint8_t synthetic_sid[16];
    char before[1024], after[1024];
    int ok = 1;
    CHECK(pair_open(&pair) == 0 && establish(&pair, NULL) == 0);
    CHECK(send_text(&pair.a, &pair.b, "re-ACK while outbox is full") == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &data) == 1 && data.kind == DATA);
    CHECK(deliver(&pair.b, &data) == 0);
    CHECK(take(&pair.b, &pair.a, pair.now, &ack) == 1 && ack.kind == ACK);
    CHECK(read_blob(&pair.b, "SELECT sid FROM ratchet_sessions;", synthetic_sid, sizeof(synthetic_sid)) == 0);
    synthetic_sid[0] ^= 0x80;
    CHECK(fill_synthetic_outbox(&pair.b, synthetic_sid, 0, PCOMM_RATCHET_MAX_OUTBOX - 1u, pair.now) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_outbox;") == PCOMM_RATCHET_MAX_OUTBOX);
    CHECK(session_snapshot(&pair.b, before) == 0);
    sqlite3_int64 receipts = scalar(&pair.b, "SELECT count(*) FROM ratchet_received;");
    CHECK(deliver(&pair.b, &data) == 1);
    CHECK(take(&pair.b, &pair.a, pair.now, &refreshed) == 1 && refreshed.kind == ACK);
    CHECK(refreshed.outgoing.id == ack.outgoing.id && refreshed.outgoing.sealed_len == ack.outgoing.sealed_len);
    CHECK(memcmp(refreshed.outgoing.sealed, ack.outgoing.sealed, ack.outgoing.sealed_len) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_outbox;") == PCOMM_RATCHET_MAX_OUTBOX);
    CHECK(session_snapshot(&pair.b, after) == 0 && strcmp(before, after) == 0);
    envelope_free(&refreshed);

    CHECK(exec_sql(&pair.b, "DELETE FROM ratchet_outbox WHERE kind=5;") == 0);
    CHECK(fill_synthetic_outbox(&pair.b, synthetic_sid, PCOMM_RATCHET_MAX_OUTBOX - 1u, 1, pair.now) == 0);
    CHECK(deliver(&pair.b, &data) == -1);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_outbox;") == PCOMM_RATCHET_MAX_OUTBOX);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_outbox WHERE kind=5;") == 0);
    CHECK(session_snapshot(&pair.b, after) == 0 && strcmp(before, after) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_received;") == receipts);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == 2);
    CHECK(exec_sql(&pair.b,
        "DELETE FROM ratchet_outbox WHERE id=(SELECT min(id) FROM ratchet_outbox WHERE kind=99);") == 0);
    CHECK(deliver(&pair.b, &data) == 1);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_outbox;") == PCOMM_RATCHET_MAX_OUTBOX);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_outbox WHERE kind=5;") == 1);
    CHECK(session_snapshot(&pair.b, after) == 0 && strcmp(before, after) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM ratchet_received;") == receipts);
    CHECK(take(&pair.b, &pair.a, pair.now, &refreshed) == 1 && refreshed.kind == ACK);
    CHECK(deliver(&pair.a, &refreshed) == 0);
    CHECK(scalar(&pair.a, "SELECT count(*) FROM ratchet_outbox WHERE kind=4;") == 0);
done:
    envelope_free(&data); envelope_free(&ack); envelope_free(&refreshed); pair_close(&pair);
    return ok;
}

static int decrypt_inner_data(const envelope_t *data, const uint8_t key[32], uint8_t *out, size_t *out_len) {
    if (data->kind != DATA || data->packet_len < 87) return -1;
    size_t header_len = 87u + data->packet[86];
    size_t aad_len = header_len + 8u + 12u;
    if (data->packet_len < aad_len + 16u) return -1;
    return pcomm_aead_decrypt(key, data->packet + header_len + 8u, data->packet, aad_len,
                               data->packet + aad_len, data->packet_len - aad_len, out, out_len);
}

static int test_current_keys_do_not_decrypt_past_data(void) {
    pair_t pair = {0};
    envelope_t offer = {0}, response = {0}, confirm = {0}, first = {0}, next = {0};
    uint8_t chain[32] = {0}, root[32] = {0}, future_key[32] = {0}, root_key[32] = {0};
    uint8_t advanced[32] = {0}, root_advanced[32] = {0};
    uint8_t *candidate = NULL, *expected = NULL;
    size_t candidate_len = 0, candidate_capacity = 0, expected_len = 0;
    const char *next_text = "the next chain key still decrypts the next message";
    int ok = 1;
    CHECK(pair_open(&pair) == 0);
    CHECK(send_text(&pair.a, &pair.b, "the first ciphertext uses a subsequently deleted key") == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &offer) == 1 && offer.kind == OFFER && deliver(&pair.b, &offer) == 0);
    CHECK(take(&pair.b, &pair.a, pair.now, &response) == 1 && response.kind == RESPONSE && deliver(&pair.a, &response) == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &confirm) == 1 && confirm.kind == CONFIRM && deliver(&pair.b, &confirm) == 0);
    CHECK(pcomm_ratchet_outbox_sent(&pair.a.db, confirm.outgoing.id, 1) == 0);

    CHECK(take(&pair.a, &pair.b, pair.now, &first) == 1 && first.kind == DATA);
    CHECK(deliver(&pair.b, &first) == 0);
    CHECK(scalar(&pair.a, "SELECT private_eph IS NULL FROM ratchet_sessions;") == 1);
    CHECK(scalar(&pair.b, "SELECT private_eph IS NULL AND recv_n=1 FROM ratchet_sessions;") == 1);
    CHECK(read_blob(&pair.b, "SELECT recv_chain FROM ratchet_sessions;", chain, sizeof(chain)) == 0);
    CHECK(read_blob(&pair.b, "SELECT root_key FROM ratchet_sessions;", root, sizeof(root)) == 0);
    CHECK(pcomm_ratchet_chain_step(chain, advanced, future_key) == 0);
    CHECK(pcomm_ratchet_chain_step(root, root_advanced, root_key) == 0);
    candidate = malloc(first.packet_len);
    CHECK(candidate != NULL);
    candidate_capacity = first.packet_len;
    candidate_len = first.packet_len;
    CHECK(decrypt_inner_data(&first, future_key, candidate, &candidate_len) == -1);
    candidate_len = first.packet_len;
    CHECK(decrypt_inner_data(&first, root_key, candidate, &candidate_len) == -1);
    free(candidate);
    candidate = NULL;

    CHECK(send_text(&pair.a, &pair.b, next_text) == 0);
    CHECK(take(&pair.a, &pair.b, pair.now, &next) == 1 && next.kind == DATA);
    candidate = malloc(next.packet_len);
    CHECK(candidate != NULL);
    candidate_capacity = next.packet_len;
    candidate_len = next.packet_len;
    CHECK(decrypt_inner_data(&next, future_key, candidate, &candidate_len) == 0);
    CHECK(pcomm_msg_pack_direct_text(123, pair.a.me.user_id, next_text, &expected, &expected_len) == 0);
    CHECK(candidate_len == expected_len && memcmp(candidate, expected, expected_len) == 0);
    CHECK(deliver(&pair.b, &next) == 0);
    CHECK(scalar(&pair.b, "SELECT count(*) FROM messages WHERE direction=0;") == 2);
done:
    OPENSSL_cleanse(chain, sizeof(chain)); OPENSSL_cleanse(root, sizeof(root));
    OPENSSL_cleanse(future_key, sizeof(future_key)); OPENSSL_cleanse(root_key, sizeof(root_key));
    OPENSSL_cleanse(advanced, sizeof(advanced)); OPENSSL_cleanse(root_advanced, sizeof(root_advanced));
    if (candidate) OPENSSL_cleanse(candidate, candidate_capacity);
    if (expected) OPENSSL_cleanse(expected, expected_len);
    free(candidate); free(expected);
    envelope_free(&offer); envelope_free(&response); envelope_free(&confirm);
    envelope_free(&first); envelope_free(&next); pair_close(&pair);
    return ok;
}

int main(void) {
    const struct { const char *name; int (*run)(void); } tests[] = {
        {"ephemeral bootstrap and two-way chains", test_bootstrap_and_two_way_chains},
        {"immutable retry and lost ACK recovery", test_immutable_retry_and_lost_ack},
        {"out-of-order delivery and bounded skipping", test_out_of_order_and_skip_bound},
        {"sender window tracks oldest unacknowledged DATA", test_sender_window_tracks_oldest_unacked},
        {"simultaneous offers and reset rejection", test_simultaneous_offers_and_reset_rejection},
        {"storage failures roll back state and messages", test_storage_failures_roll_back_state_and_messages},
        {"restart preserves pending keys and active counters", test_restart_preserves_pending_keys_and_counters},
        {"skip cache stays bounded at the send window", test_skip_cache_at_send_window_limit},
        {"concurrent sends use unique counters", test_concurrent_sends_use_unique_counters},
        {"re-ACK refreshes an existing entry at outbox capacity", test_reack_refreshes_existing_entry_at_outbox_capacity},
        {"current session keys do not decrypt past DATA", test_current_keys_do_not_decrypt_past_data},
    };
    size_t failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int passed = tests[i].run();
        printf("%s: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if (!passed) failures++;
    }
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
