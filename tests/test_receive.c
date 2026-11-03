#include "receive.h"
#include "replay.h"
#include "crypto.h"
#include "msg.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    pcomm_db_t db;
    pcomm_identity_t recipient;
} fixture_t;

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; \
        goto done; \
    } \
} while (0)

static int make_identity(pcomm_identity_t *identity) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    size_t private_len = sizeof(identity->privkey);
    size_t public_len = sizeof(identity->pubkey);
    int ok = ctx && EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_keygen(ctx, &key) == 1 &&
        EVP_PKEY_get_raw_private_key(key, identity->privkey, &private_len) == 1 &&
        EVP_PKEY_get_raw_public_key(key, identity->pubkey, &public_len) == 1 &&
        private_len == sizeof(identity->privkey) &&
        public_len == sizeof(identity->pubkey);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int sql_exec(fixture_t *fixture, const char *sql) {
    char *error = NULL;
    int rc = sqlite3_exec(fixture->db.db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) fprintf(stderr, "test SQL failed: %s\n", error);
    sqlite3_free(error);
    return rc == SQLITE_OK ? 0 : -1;
}

static sqlite3_int64 sql_value(fixture_t *fixture, const char *sql) {
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 value = -1;
    if (sqlite3_prepare_v2(fixture->db.db, sql, -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW) {
        value = sqlite3_column_int64(statement, 0);
    } else {
        fprintf(stderr, "test SQL query failed: %s\n", sqlite3_errmsg(fixture->db.db));
    }
    sqlite3_finalize(statement);
    return value;
}

static int fixture_open(fixture_t *fixture, size_t capacity) {
    memset(fixture, 0, sizeof(*fixture));
    if (sqlite3_open_v2(":memory:", &fixture->db.db,
                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                       NULL) != SQLITE_OK) return -1;
    fixture->db.replay_cache = pcomm_replay_cache_create(capacity, PCOMM_REPLAY_CACHE_TTL_MS);
    if (!fixture->db.replay_cache || sql_exec(fixture, "PRAGMA foreign_keys=ON;") != 0 ||
        pcomm_db_init_schema(&fixture->db) != 0 || make_identity(&fixture->recipient) != 0) return -1;
    return 0;
}

static int seal_plain(fixture_t *fixture, uint8_t *plain, size_t plain_len,
                      uint8_t **sealed, size_t *sealed_len) {
    int rc = pcomm_seal_for_recipient(fixture->recipient.pubkey, plain, plain_len,
                                     sealed, sealed_len);
    free(plain);
    return rc;
}

static int make_direct(fixture_t *fixture, const char *text, uint8_t **sealed, size_t *sealed_len) {
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    if (pcomm_msg_pack_direct_text(0, "test-sender", text, &plain, &plain_len) != 0) return -1;
    return seal_plain(fixture, plain, plain_len, sealed, sealed_len);
}

static int make_invite(fixture_t *fixture, uint8_t **sealed, size_t *sealed_len) {
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    char *members[] = {"test-member-a", "test-member-b"};
    if (pcomm_msg_pack_group_invite(42, "test-sender", "test-group", "Test group",
                                     members, 2, &plain, &plain_len) != 0) return -1;
    return seal_plain(fixture, plain, plain_len, sealed, sealed_len);
}

static int test_shared_delivery_and_distinct_envelopes(void) {
    fixture_t fixture = {0};
    uint8_t *sealed = NULL, *second = NULL;
    size_t sealed_len = 0, second_len = 0;
    int ok = 1;
    CHECK(fixture_open(&fixture, PCOMM_REPLAY_CACHE_CAPACITY) == 0);
    CHECK(make_direct(&fixture, "same plaintext", &sealed, &sealed_len) == 0);
    CHECK(make_direct(&fixture, "same plaintext", &second, &second_len) == 0);
    CHECK(sealed_len != second_len || memcmp(sealed, second, sealed_len) != 0);

    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, sealed, sealed_len, 100) == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, sealed, sealed_len, 200) == 1);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, sealed, sealed_len, 0) == 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 1);
    CHECK(sql_value(&fixture, "SELECT ts_unix FROM messages;") == 100);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, second, second_len, 300) == 0);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 2);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM conversations;") == 1);

done:
    free(sealed);
    free(second);
    pcomm_db_close(&fixture.db);
    return ok;
}

static int test_invalid_messages_do_not_poison_cache(void) {
    fixture_t fixture = {0};
    pcomm_identity_t wrong_recipient = {0};
    uint8_t *sealed = NULL, *tampered = NULL, *malformed = NULL;
    size_t sealed_len = 0, malformed_len = 0;
    const uint8_t invalid_plain[] = {0xff};
    int ok = 1;
    CHECK(fixture_open(&fixture, 1) == 0);
    CHECK(make_direct(&fixture, "valid after rejected input", &sealed, &sealed_len) == 0);
    CHECK(make_identity(&wrong_recipient) == 0);
    tampered = (uint8_t *)malloc(sealed_len);
    CHECK(tampered != NULL);
    memcpy(tampered, sealed, sealed_len);
    tampered[sealed_len - 1] ^= 0x80;
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, tampered, sealed_len, 10) == -1);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, sealed, 10, 10) == -1);
    CHECK(pcomm_receive_sealed(&fixture.db, &wrong_recipient, sealed, sealed_len, 10) == -1);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, NULL, 0, 10) == -1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, sealed, sealed_len, 10) == 0);

    CHECK(pcomm_seal_for_recipient(fixture.recipient.pubkey, invalid_plain, sizeof(invalid_plain),
                                    &malformed, &malformed_len) == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, malformed, malformed_len, 10) == -1);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, sealed, sealed_len, 10) == 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 1);

done:
    free(sealed);
    free(tampered);
    free(malformed);
    pcomm_db_close(&fixture.db);
    return ok;
}

static int test_equivalent_x25519_envelopes_are_replays(void) {
    fixture_t fixture = {0};
    uint8_t *sealed = NULL, *high_bit_alias = NULL, *reciprocal_alias = NULL;
    uint8_t *plain = NULL, *alias_plain = NULL;
    size_t sealed_len = 0, plain_len = 0, alias_plain_len = 0;
    BN_CTX *context = NULL;
    BIGNUM *coordinate = NULL, *prime = NULL, *reciprocal = NULL;
    int ok = 1;
    CHECK(fixture_open(&fixture, PCOMM_REPLAY_CACHE_CAPACITY) == 0);
    CHECK(make_direct(&fixture, "one authenticated message, equivalent public keys", &sealed, &sealed_len) == 0);
    high_bit_alias = (uint8_t *)malloc(sealed_len);
    reciprocal_alias = (uint8_t *)malloc(sealed_len);
    CHECK(high_bit_alias != NULL && reciprocal_alias != NULL);
    memcpy(high_bit_alias, sealed, sealed_len);
    memcpy(reciprocal_alias, sealed, sealed_len);

    high_bit_alias[31] ^= 0x80;
    context = BN_CTX_new();
    coordinate = BN_lebin2bn(sealed, 32, NULL);
    CHECK(context != NULL && coordinate != NULL);
    CHECK(BN_hex2bn(&prime, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED") > 0);
    reciprocal = BN_mod_inverse(NULL, coordinate, prime, context);
    CHECK(reciprocal != NULL);
    CHECK(BN_bn2lebinpad(reciprocal, reciprocal_alias, 32) == 32);
    CHECK((reciprocal_alias[31] & 0x80) == 0);
    CHECK(memcmp(sealed, high_bit_alias, sealed_len) != 0);
    CHECK(memcmp(sealed, reciprocal_alias, sealed_len) != 0);

    CHECK(pcomm_open_seal(fixture.recipient.privkey, sealed, sealed_len, &plain, &plain_len) == 0);
    CHECK(pcomm_open_seal(fixture.recipient.privkey, high_bit_alias, sealed_len,
                          &alias_plain, &alias_plain_len) == 0);
    CHECK(alias_plain_len == plain_len && memcmp(alias_plain, plain, plain_len) == 0);
    free(alias_plain);
    alias_plain = NULL;
    CHECK(pcomm_open_seal(fixture.recipient.privkey, reciprocal_alias, sealed_len,
                          &alias_plain, &alias_plain_len) == 0);
    CHECK(alias_plain_len == plain_len && memcmp(alias_plain, plain, plain_len) == 0);

    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, sealed, sealed_len, 100) == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, high_bit_alias, sealed_len, 200) == 1);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, reciprocal_alias, sealed_len, 300) == 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 1);
done:
    BN_free(reciprocal);
    BN_free(prime);
    BN_free(coordinate);
    BN_CTX_free(context);
    free(alias_plain);
    free(plain);
    free(sealed);
    free(high_bit_alias);
    free(reciprocal_alias);
    pcomm_db_close(&fixture.db);
    return ok;
}

static int test_group_replay_has_no_repeated_side_effects(void) {
    fixture_t fixture = {0};
    uint8_t *invite = NULL, *group_text = NULL, *plain = NULL;
    size_t invite_len = 0, group_text_len = 0, plain_len = 0;
    int ok = 1;
    CHECK(fixture_open(&fixture, PCOMM_REPLAY_CACHE_CAPACITY) == 0);
    CHECK(make_invite(&fixture, &invite, &invite_len) == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, invite, invite_len, 100) == 0);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM participants;") == 2);
    CHECK(sql_exec(&fixture, "DELETE FROM participants WHERE user_id='test-member-b';") == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, invite, invite_len, 200) == 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM participants;") == 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM conversations;") == 1);

    CHECK(pcomm_msg_pack_group_text(43, "test-sender", "test-group", "Group message",
                                   &plain, &plain_len) == 0);
    CHECK(pcomm_seal_for_recipient(fixture.recipient.pubkey, plain, plain_len,
                                    &group_text, &group_text_len) == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, group_text, group_text_len, 100) == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, group_text, group_text_len, 200) == 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 2);

done:
    free(invite);
    free(group_text);
    free(plain);
    pcomm_db_close(&fixture.db);
    return ok;
}

static int test_failed_message_write_can_be_retried(void) {
    fixture_t fixture = {0};
    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    int ok = 1;
    CHECK(fixture_open(&fixture, PCOMM_REPLAY_CACHE_CAPACITY) == 0);
    CHECK(make_direct(&fixture, "retry after insert failure", &sealed, &sealed_len) == 0);
    CHECK(sql_exec(&fixture,
        "CREATE TEMP TRIGGER fail_message BEFORE INSERT ON messages "
        "BEGIN SELECT RAISE(ABORT,'injected insert failure'); END;") == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, sealed, sealed_len, 100) == -1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 0);
    CHECK(sql_exec(&fixture, "DROP TRIGGER fail_message;") == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, sealed, sealed_len, 100) == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, sealed, sealed_len, 100) == 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 1);

done:
    free(sealed);
    pcomm_db_close(&fixture.db);
    return ok;
}

static int test_failed_participant_write_can_be_retried(void) {
    fixture_t fixture = {0};
    uint8_t *invite = NULL;
    size_t invite_len = 0;
    int ok = 1;
    CHECK(fixture_open(&fixture, PCOMM_REPLAY_CACHE_CAPACITY) == 0);
    CHECK(make_invite(&fixture, &invite, &invite_len) == 0);
    CHECK(sql_exec(&fixture,
        "CREATE TEMP TRIGGER fail_participant BEFORE INSERT ON participants "
        "WHEN NEW.user_id='test-member-b' "
        "BEGIN SELECT RAISE(ABORT,'injected participant failure'); END;") == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, invite, invite_len, 100) == -1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 0);
    CHECK(sql_exec(&fixture, "DROP TRIGGER fail_participant;") == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, invite, invite_len, 100) == 0);
    CHECK(pcomm_receive_sealed(&fixture.db, &fixture.recipient, invite, invite_len, 100) == 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM participants;") == 2);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 1);

done:
    free(invite);
    pcomm_db_close(&fixture.db);
    return ok;
}

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int ready;
    int released;
} start_gate_t;

typedef struct {
    fixture_t *fixture;
    start_gate_t *gate;
    const uint8_t *sealed;
    size_t sealed_len;
    int result;
} delivery_t;

static void *deliver_concurrently(void *arg) {
    delivery_t *delivery = (delivery_t *)arg;
    pthread_mutex_lock(&delivery->gate->mutex);
    delivery->gate->ready++;
    pthread_cond_broadcast(&delivery->gate->condition);
    while (!delivery->gate->released) pthread_cond_wait(&delivery->gate->condition, &delivery->gate->mutex);
    pthread_mutex_unlock(&delivery->gate->mutex);
    delivery->result = pcomm_receive_sealed(&delivery->fixture->db, &delivery->fixture->recipient,
                                           delivery->sealed, delivery->sealed_len, 100);
    return NULL;
}

static int test_concurrent_delivery_accepts_once(void) {
    enum { WORKERS = 8 };
    fixture_t fixture = {0};
    start_gate_t gate;
    pthread_t threads[WORKERS];
    delivery_t deliveries[WORKERS];
    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    int started = 0, accepted = 0, duplicates = 0;
    int gate_mutex_ready = 0, gate_condition_ready = 0;
    int ok = 1;
    memset(&gate, 0, sizeof(gate));
    CHECK(fixture_open(&fixture, PCOMM_REPLAY_CACHE_CAPACITY) == 0);
    CHECK(make_direct(&fixture, "concurrent envelope", &sealed, &sealed_len) == 0);
    CHECK(pthread_mutex_init(&gate.mutex, NULL) == 0);
    gate_mutex_ready = 1;
    CHECK(pthread_cond_init(&gate.condition, NULL) == 0);
    gate_condition_ready = 1;
    for (int i = 0; i < WORKERS; i++) {
        deliveries[i] = (delivery_t){&fixture, &gate, sealed, sealed_len, -99};
        if (pthread_create(&threads[i], NULL, deliver_concurrently, &deliveries[i]) != 0) {
            fprintf(stderr, "could not start delivery worker %d\n", i);
            ok = 0;
            break;
        }
        started++;
    }
    pthread_mutex_lock(&gate.mutex);
    while (gate.ready < started) pthread_cond_wait(&gate.condition, &gate.mutex);
    gate.released = 1;
    pthread_cond_broadcast(&gate.condition);
    pthread_mutex_unlock(&gate.mutex);
    for (int i = 0; i < started; i++) {
        if (pthread_join(threads[i], NULL) != 0) ok = 0;
        if (deliveries[i].result == 0) accepted++;
        else if (deliveries[i].result == 1) duplicates++;
        else ok = 0;
    }
    CHECK(started == WORKERS);
    CHECK(accepted == 1);
    CHECK(duplicates == WORKERS - 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM messages;") == 1);

done:
    if (gate_condition_ready) pthread_cond_destroy(&gate.condition);
    if (gate_mutex_ready) pthread_mutex_destroy(&gate.mutex);
    free(sealed);
    pcomm_db_close(&fixture.db);
    return ok;
}

int main(void) {
    const struct {
        const char *name;
        int (*run)(void);
    } tests[] = {
        {"shared delivery and distinct envelopes", test_shared_delivery_and_distinct_envelopes},
        {"invalid envelopes do not poison cache", test_invalid_messages_do_not_poison_cache},
        {"equivalent X25519 envelopes are replays", test_equivalent_x25519_envelopes_are_replays},
        {"group replay has no repeated side effects", test_group_replay_has_no_repeated_side_effects},
        {"failed message write can be retried", test_failed_message_write_can_be_retried},
        {"failed participant write can be retried", test_failed_participant_write_can_be_retried},
        {"concurrent delivery accepts once", test_concurrent_delivery_accepts_once},
    };
    size_t failed = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int passed = tests[i].run();
        printf("%s: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if (!passed) failed++;
    }
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
