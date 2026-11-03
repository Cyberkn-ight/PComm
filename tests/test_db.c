#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; \
        goto done; \
    } \
} while (0)

static int open_memory_db(pcomm_db_t *db) {
    memset(db, 0, sizeof(*db));
    if (sqlite3_open_v2(":memory:", &db->db,
                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                       NULL) != SQLITE_OK) return -1;
    if (sqlite3_exec(db->db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL) != SQLITE_OK) return -1;
    return pcomm_db_init_schema(db);
}

static sqlite3_int64 count_rows(pcomm_db_t *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    sqlite3_int64 count = -1;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return count;
}

static int test_contact_insert_fetch_and_update(void) {
    pcomm_db_t db = {0};
    uint8_t public_key[32], fetched_key[32];
    char host[64];
    uint16_t port = 0;
    int relay = 0;
    int ok = 1;
    for (size_t i = 0; i < sizeof(public_key); i++) public_key[i] = (uint8_t)(i * 17u);
    CHECK(open_memory_db(&db) == 0);
    CHECK(pcomm_db_upsert_contact(&db, "test'contact", "192.0.2.1", 9001, public_key, 1) == 0);
    CHECK(pcomm_db_get_contact(&db, "test'contact", host, sizeof(host), &port, fetched_key, &relay) == 0);
    CHECK(strcmp(host, "192.0.2.1") == 0 && port == 9001 && relay == 1);
    CHECK(memcmp(public_key, fetched_key, sizeof(public_key)) == 0);
    public_key[0] = 0xff;
    CHECK(pcomm_db_upsert_contact(&db, "test'contact", "198.51.100.2", 9002, public_key, 0) == 0);
    CHECK(pcomm_db_get_contact(&db, "test'contact", host, sizeof(host), &port, fetched_key, &relay) == 0);
    CHECK(strcmp(host, "198.51.100.2") == 0 && port == 9002 && relay == 0);
    CHECK(memcmp(public_key, fetched_key, sizeof(public_key)) == 0);
    CHECK(pcomm_db_get_contact(&db, "missing", host, sizeof(host), &port, fetched_key, NULL) == -1);
    CHECK(count_rows(&db, "SELECT count(*) FROM contacts;") == 1);
    CHECK(pcomm_db_init_schema(&db) == 0);
    CHECK(count_rows(&db, "SELECT count(*) FROM contacts;") == 1);
done:
    pcomm_db_close(&db);
    return ok;
}

static int test_direct_conversation_and_message_storage(void) {
    pcomm_db_t db = {0};
    sqlite3_stmt *st = NULL;
    const char body[] = "UTF-8: \xc3\xa9 \xf0\x9f\x94\x92";
    uint8_t cipher[] = {0, 1, 0xff, 0x80, 0};
    const uint8_t expected_cipher[] = {0, 1, 0xff, 0x80, 0};
    char uuid[128], type[16];
    int ok = 1;
    CHECK(open_memory_db(&db) == 0);
    int64_t conversation = pcomm_db_get_or_create_direct_conv(&db, "test-peer");
    CHECK(conversation > 0);
    CHECK(pcomm_db_get_or_create_direct_conv(&db, "test-peer") == conversation);
    int64_t other = pcomm_db_get_or_create_direct_conv(&db, "other-peer");
    CHECK(other > 0 && other != conversation);
    CHECK(pcomm_db_get_conversation_uuid(&db, conversation, uuid, sizeof(uuid), type, sizeof(type)) == 0);
    CHECK(strcmp(type, "direct") == 0 && uuid[0] != '\0');
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 2);
    CHECK(count_rows(&db, "SELECT count(*) FROM participants;") == 2);

    CHECK(pcomm_db_insert_message(&db, conversation, 0, "test-peer", "test-sender",
                                   body, cipher, sizeof(cipher), INT64_C(2000000000)) == 0);
    memset(cipher, 0x55, sizeof(cipher));
    CHECK(sqlite3_prepare_v2(db.db,
        "SELECT conversation_id,direction,peer_user_id,sender_user_id,body,ciphertext,ts_unix,status FROM messages;",
        -1, &st, NULL) == SQLITE_OK);
    CHECK(sqlite3_step(st) == SQLITE_ROW);
    CHECK(sqlite3_column_int64(st, 0) == conversation && sqlite3_column_int(st, 1) == 0);
    CHECK(strcmp((const char *)sqlite3_column_text(st, 2), "test-peer") == 0);
    CHECK(strcmp((const char *)sqlite3_column_text(st, 3), "test-sender") == 0);
    CHECK(strcmp((const char *)sqlite3_column_text(st, 4), body) == 0);
    CHECK(sqlite3_column_bytes(st, 5) == (int)sizeof(expected_cipher));
    CHECK(memcmp(sqlite3_column_blob(st, 5), expected_cipher, sizeof(expected_cipher)) == 0);
    CHECK(sqlite3_column_int64(st, 6) == INT64_C(2000000000) && sqlite3_column_int(st, 7) == 0);
    CHECK(sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);
    st = NULL;
    CHECK(pcomm_db_insert_message(&db, other, 1, "other-peer", "local-sender",
                                   "", (const uint8_t *)"", 0, 1) == 0);
    CHECK(pcomm_db_insert_message(&db, INT64_MAX, 0, "peer", "sender", "invalid parent",
                                   expected_cipher, sizeof(expected_cipher), 1) == -1);
    CHECK(count_rows(&db, "SELECT count(*) FROM messages;") == 2);
done:
    sqlite3_finalize(st);
    pcomm_db_close(&db);
    return ok;
}

static int test_group_membership_storage(void) {
    pcomm_db_t db = {0};
    char **members = NULL;
    int member_count = 0;
    char uuid[64], type[16];
    int ok = 1;
    CHECK(open_memory_db(&db) == 0);
    int64_t conversation = pcomm_db_get_or_create_group_conv(&db, "group-unit", "Test group");
    CHECK(conversation > 0);
    CHECK(pcomm_db_get_or_create_group_conv(&db, "group-unit", NULL) == conversation);
    CHECK(pcomm_db_add_participant(&db, conversation, "member-b") == 0);
    CHECK(pcomm_db_add_participant(&db, conversation, "member-a") == 0);
    CHECK(pcomm_db_add_participant(&db, conversation, "member-a") == 0);
    CHECK(pcomm_db_list_group_participants(&db, conversation, &members, &member_count) == 0);
    CHECK(member_count == 2);
    CHECK((strcmp(members[0], "member-a") == 0 && strcmp(members[1], "member-b") == 0) ||
          (strcmp(members[1], "member-a") == 0 && strcmp(members[0], "member-b") == 0));
    CHECK(pcomm_db_get_conversation_uuid(&db, conversation, uuid, sizeof(uuid), type, sizeof(type)) == 0);
    CHECK(strcmp(uuid, "group-unit") == 0 && strcmp(type, "group") == 0);
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 1);
    CHECK(count_rows(&db, "SELECT count(*) FROM participants;") == 2);
done:
    for (int i = 0; i < member_count; i++) free(members[i]);
    free(members);
    pcomm_db_close(&db);
    return ok;
}

static int test_settings_and_descriptors(void) {
    pcomm_db_t db = {0};
    char value[64];
    uint8_t key[32] = {1}, missing_key[32] = {2};
    const uint8_t first[] = {0, 0xff, 1};
    const uint8_t replacement[] = {0x42, 0, 0x80, 0};
    uint8_t *blob = NULL;
    uint32_t blob_len = 0;
    int ok = 1;
    CHECK(open_memory_db(&db) == 0);
    CHECK(pcomm_db_kv_get(&db, "missing", value, sizeof(value)) == -1);
    CHECK(pcomm_db_kv_set(&db, "test-setting", "first") == 0);
    CHECK(pcomm_db_kv_set(&db, "test-setting", "replacement") == 0);
    CHECK(pcomm_db_kv_get(&db, "test-setting", value, sizeof(value)) == 0);
    CHECK(strcmp(value, "replacement") == 0);
    CHECK(count_rows(&db, "SELECT count(*) FROM settings;") == 1);
    CHECK(pcomm_db_kv_set(&db, "test-setting", "") == 0);
    CHECK(pcomm_db_kv_get(&db, "test-setting", value, sizeof(value)) == 0 && value[0] == '\0');

    CHECK(pcomm_db_desc_put(&db, key, first, sizeof(first), INT64_MAX, 10) == 0);
    CHECK(pcomm_db_desc_get(&db, key, &blob, &blob_len) == 0);
    CHECK(blob_len == sizeof(first) && memcmp(blob, first, sizeof(first)) == 0);
    free(blob);
    blob = NULL;
    CHECK(pcomm_db_desc_put(&db, key, replacement, sizeof(replacement), INT64_MAX, 20) == 0);
    CHECK(pcomm_db_desc_get(&db, key, &blob, &blob_len) == 0);
    CHECK(blob_len == sizeof(replacement) && memcmp(blob, replacement, sizeof(replacement)) == 0);
    free(blob);
    blob = NULL;
    CHECK(pcomm_db_desc_put(&db, key, first, sizeof(first), 0, 19) == 1);
    CHECK(pcomm_db_desc_get(&db, key, &blob, &blob_len) == 0);
    CHECK(blob_len == sizeof(replacement) && memcmp(blob, replacement, sizeof(replacement)) == 0);
    free(blob);
    blob = NULL;
    CHECK(pcomm_db_desc_put(&db, key, first, sizeof(first), 0, 20) == 1);
    CHECK(pcomm_db_desc_get(&db, key, &blob, &blob_len) == 0);
    CHECK(blob_len == sizeof(replacement) && memcmp(blob, replacement, sizeof(replacement)) == 0);
    free(blob);
    blob = NULL;
    CHECK(pcomm_db_desc_put(&db, key, replacement, sizeof(replacement), INT64_MAX, 20) == 0);
    CHECK(pcomm_db_desc_get(&db, key, &blob, &blob_len) == 0);
    CHECK(blob_len == sizeof(replacement) && memcmp(blob, replacement, sizeof(replacement)) == 0);
    free(blob);
    blob = NULL;
    CHECK(count_rows(&db, "SELECT count(*) FROM descriptors WHERE ts_unix=20 AND expires_unix=9223372036854775807;") == 1);
    CHECK(count_rows(&db, "SELECT count(*) FROM descriptors;") == 1);
    CHECK(pcomm_db_desc_get(&db, missing_key, &blob, &blob_len) == -1);
    CHECK(pcomm_db_desc_put(&db, key, first, sizeof(first), 0, 30) == 0);
    CHECK(pcomm_db_desc_get(&db, key, &blob, &blob_len) == -1);
done:
    free(blob);
    pcomm_db_close(&db);
    return ok;
}

static int read_descriptor_trust(pcomm_db_t *db, const uint8_t owner[32], uint32_t epoch,
                                    uint32_t *issued, uint8_t digest[32]) {
    sqlite3_stmt *statement = NULL;
    int result = -1;
    if (sqlite3_prepare_v2(db->db, "SELECT issued,digest FROM descriptor_trust WHERE owner=? AND epoch=?;",
            -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_bind_blob(statement, 1, owner, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(statement, 2, epoch) == SQLITE_OK && sqlite3_step(statement) == SQLITE_ROW &&
        sqlite3_column_bytes(statement, 1) == 32) {
        *issued = (uint32_t)sqlite3_column_int64(statement, 0);
        memcpy(digest, sqlite3_column_blob(statement, 1), 32);
        result = 0;
    }
    sqlite3_finalize(statement);
    return result;
}

static int test_descriptor_trust_monotonicity(void) {
    pcomm_db_t db = {0};
    uint8_t owner[32] = {1}, other_owner[32] = {2};
    uint8_t first_digest[32] = {3}, second_digest[32] = {4}, fetched_digest[32];
    uint32_t issued = 0;
    int ok = 1;
    CHECK(open_memory_db(&db) == 0);
    CHECK(pcomm_db_descriptor_trust(&db, owner, 10, 100, first_digest) == 0);
    CHECK(pcomm_db_descriptor_trust(&db, owner, 10, 100, first_digest) == 0);
    CHECK(pcomm_db_descriptor_trust(&db, owner, 10, 99, second_digest) == 1);
    CHECK(pcomm_db_descriptor_trust(&db, owner, 10, 100, second_digest) == 1);
    CHECK(read_descriptor_trust(&db, owner, 10, &issued, fetched_digest) == 0);
    CHECK(issued == 100 && memcmp(fetched_digest, first_digest, 32) == 0);
    CHECK(pcomm_db_descriptor_trust(&db, owner, 10, 101, second_digest) == 0);
    CHECK(pcomm_db_descriptor_trust(&db, other_owner, 10, 1, first_digest) == 0);
    CHECK(read_descriptor_trust(&db, owner, 10, &issued, fetched_digest) == 0);
    CHECK(issued == 101 && memcmp(fetched_digest, second_digest, 32) == 0);
    CHECK(read_descriptor_trust(&db, other_owner, 10, &issued, fetched_digest) == 0);
    CHECK(issued == 1 && memcmp(fetched_digest, first_digest, 32) == 0);

    CHECK(pcomm_db_descriptor_trust(&db, owner, 11, 200, first_digest) == 0);
    CHECK(pcomm_db_descriptor_trust(&db, owner, 12, 300, first_digest) == 0);
    CHECK(read_descriptor_trust(&db, owner, 10, &issued, fetched_digest) == -1);
    CHECK(count_rows(&db, "SELECT count(*) FROM descriptor_trust;") == 3);
    CHECK(pcomm_db_descriptor_trust(&db, owner, 10, 500, second_digest) == 1);
    CHECK(count_rows(&db, "SELECT count(*) FROM descriptor_trust;") == 3);
    CHECK(read_descriptor_trust(&db, owner, 10, &issued, fetched_digest) == -1);

    CHECK(sqlite3_exec(db.db,
        "CREATE TEMP TRIGGER reject_trust_prune BEFORE DELETE ON descriptor_trust "
        "WHEN OLD.epoch=11 BEGIN SELECT RAISE(ABORT,'injected trust prune failure'); END;",
        NULL, NULL, NULL) == SQLITE_OK);
    CHECK(pcomm_db_descriptor_trust(&db, owner, 13, 400, second_digest) == -1);
    CHECK(sqlite3_get_autocommit(db.db) != 0);
    CHECK(read_descriptor_trust(&db, owner, 13, &issued, fetched_digest) == -1);
    CHECK(read_descriptor_trust(&db, owner, 11, &issued, fetched_digest) == 0);
    CHECK(count_rows(&db, "SELECT count(*) FROM descriptor_trust;") == 3);
    CHECK(sqlite3_exec(db.db, "DROP TRIGGER reject_trust_prune;", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(pcomm_db_descriptor_trust(&db, owner, 13, 400, second_digest) == 0);
    CHECK(read_descriptor_trust(&db, owner, 11, &issued, fetched_digest) == -1);
    CHECK(read_descriptor_trust(&db, owner, 13, &issued, fetched_digest) == 0);
    CHECK(issued == 400 && memcmp(fetched_digest, second_digest, 32) == 0);
    CHECK(count_rows(&db, "SELECT count(*) FROM descriptor_trust;") == 3);
    CHECK(sqlite3_next_stmt(db.db, NULL) == NULL);
done:
    pcomm_db_close(&db);
    return ok;
}

static int test_dht_node_insert_fetch_and_update(void) {
    pcomm_db_t db = {0};
    uint8_t first_id[20] = {1}, replacement_id[20] = {0xff};
    char hosts[2][64];
    uint16_t ports[2];
    uint8_t ids[2][20];
    size_t count = 0;
    int ok = 1;
    CHECK(open_memory_db(&db) == 0);
    CHECK(pcomm_db_dhtnode_load_some(&db, hosts, ports, ids, 2, &count) == -1 && count == 0);
    CHECK(pcomm_db_dhtnode_upsert(&db, first_id, "192.0.2.1", 9001, 100) == 0);
    CHECK(pcomm_db_dhtnode_upsert(&db, replacement_id, "192.0.2.1", 9001, 300) == 0);
    CHECK(pcomm_db_dhtnode_upsert(&db, first_id, "198.51.100.2", 9002, 200) == 0);
    CHECK(pcomm_db_dhtnode_load_some(&db, hosts, ports, ids, 1, &count) == 0 && count == 1);
    CHECK(strcmp(hosts[0], "192.0.2.1") == 0 && ports[0] == 9001);
    CHECK(memcmp(ids[0], replacement_id, sizeof(replacement_id)) == 0);
    CHECK(pcomm_db_dhtnode_load_some(&db, hosts, ports, ids, 2, &count) == 0 && count == 2);
    CHECK(strcmp(hosts[1], "198.51.100.2") == 0 && ports[1] == 9002);
    CHECK(memcmp(ids[1], first_id, sizeof(first_id)) == 0);
    CHECK(pcomm_db_dhtnode_upsert(&db, first_id, "192.0.2.1", 0, 400) == -1);
    CHECK(count_rows(&db, "SELECT count(*) FROM dht_nodes;") == 2);
done:
    pcomm_db_close(&db);
    return ok;
}

static int test_conversation_helpers_preserve_outer_transaction(void) {
    pcomm_db_t db = {0};
    int ok = 1;
    CHECK(open_memory_db(&db) == 0);
    CHECK(pcomm_db_get_or_create_direct_conv(&db, "existing-peer") > 0);
    CHECK(sqlite3_exec(db.db,
        "BEGIN; INSERT INTO settings(key,value) VALUES('outer','uncommitted');",
        NULL, NULL, NULL) == SQLITE_OK);
    CHECK(pcomm_db_get_or_create_direct_conv(&db, "outer-peer") > 0);
    CHECK(sqlite3_get_autocommit(db.db) == 0);
    int64_t group = pcomm_db_get_or_create_group_conv(&db, "outer-group", "Uncommitted group");
    CHECK(group > 0 && sqlite3_get_autocommit(db.db) == 0);
    CHECK(pcomm_db_add_participant(&db, group, "outer-member") == 0);
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 3);
    CHECK(sqlite3_exec(db.db, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(sqlite3_get_autocommit(db.db) != 0);
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 1);
    CHECK(count_rows(&db, "SELECT count(*) FROM participants;") == 1);
    CHECK(count_rows(&db, "SELECT count(*) FROM settings;") == 0);

    CHECK(sqlite3_exec(db.db,
        "CREATE TEMP TRIGGER reject_participant BEFORE INSERT ON participants "
        "WHEN NEW.user_id='blocked-peer' BEGIN SELECT RAISE(ABORT,'injected participant failure'); END;"
        "BEGIN; INSERT INTO settings(key,value) VALUES('outer','preserved');",
        NULL, NULL, NULL) == SQLITE_OK);
    CHECK(pcomm_db_get_or_create_direct_conv(&db, "blocked-peer") == -1);
    CHECK(sqlite3_get_autocommit(db.db) == 0);
    CHECK(count_rows(&db, "SELECT count(*) FROM settings WHERE key='outer';") == 1);
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 1);
    CHECK(pcomm_db_get_or_create_group_conv(&db, "after-failure", NULL) > 0);
    CHECK(sqlite3_get_autocommit(db.db) == 0);
    CHECK(sqlite3_exec(db.db, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 1);
    CHECK(count_rows(&db, "SELECT count(*) FROM settings;") == 0);
done:
    pcomm_db_close(&db);
    return ok;
}

typedef struct {
    pcomm_db_t *db;
    const char *peer;
    int result;
    int called;
} transaction_context_t;

static int write_transaction(void *arg) {
    transaction_context_t *context = (transaction_context_t *)arg;
    const uint8_t cipher[] = {1, 2, 3};
    char group_uuid[64];
    context->called++;
    snprintf(group_uuid, sizeof(group_uuid), "group:%s", context->peer);
    int64_t direct = pcomm_db_get_or_create_direct_conv(context->db, context->peer);
    int64_t group = pcomm_db_get_or_create_group_conv(context->db, group_uuid, "Transaction group");
    if (direct < 0 || group < 0 ||
        pcomm_db_add_participant(context->db, group, context->peer) != 0 ||
        pcomm_db_kv_set(context->db, "transaction-marker", context->peer) != 0 ||
        pcomm_db_insert_message(context->db, direct, 0, context->peer, context->peer,
                                 "transaction message", cipher, sizeof(cipher), 123) != 0) return -1;
    return context->result;
}

static int reject_commit(void *arg) {
    (void)arg;
    return 1;
}

static int test_checked_transaction_commit_and_rollback(void) {
    pcomm_db_t db = {0};
    transaction_context_t context = {&db, "committed-peer", 0, 0};
    char marker[64];
    int ok = 1;
    CHECK(open_memory_db(&db) == 0);
    CHECK(count_rows(&db, "PRAGMA secure_delete;") == 1);
    CHECK(count_rows(&db, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name LIKE 'ratchet_%';") == 5);
    CHECK(count_rows(&db, "SELECT count(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_ratchet_%';") == 2);
    CHECK(pcomm_db_transaction(&db, write_transaction, &context) == 0);
    CHECK(sqlite3_get_autocommit(db.db) != 0 && context.called == 1);
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 2);
    CHECK(count_rows(&db, "SELECT count(*) FROM participants;") == 2);
    CHECK(count_rows(&db, "SELECT count(*) FROM messages;") == 1);

    context.peer = "cancelled-peer";
    context.result = -7;
    CHECK(pcomm_db_transaction(&db, write_transaction, &context) == -7);
    CHECK(sqlite3_get_autocommit(db.db) != 0 && context.called == 2);
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 2);
    CHECK(count_rows(&db, "SELECT count(*) FROM participants;") == 2);
    CHECK(count_rows(&db, "SELECT count(*) FROM messages;") == 1);
    CHECK(pcomm_db_kv_get(&db, "transaction-marker", marker, sizeof(marker)) == 0);
    CHECK(strcmp(marker, "committed-peer") == 0);

    context.result = 1;
    CHECK(pcomm_db_transaction(&db, write_transaction, &context) == 1);
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 2);
    CHECK(sqlite3_exec(db.db, "BEGIN;", NULL, NULL, NULL) == SQLITE_OK);
    int calls_before = context.called;
    CHECK(pcomm_db_transaction(&db, write_transaction, &context) == -1);
    CHECK(context.called == calls_before && sqlite3_get_autocommit(db.db) == 0);
    CHECK(sqlite3_exec(db.db, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_OK);

    context.peer = "commit-failure-peer";
    context.result = 0;
    sqlite3_commit_hook(db.db, reject_commit, NULL);
    CHECK(pcomm_db_transaction(&db, write_transaction, &context) == -1);
    sqlite3_commit_hook(db.db, NULL, NULL);
    CHECK(sqlite3_get_autocommit(db.db) != 0);
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 2);
    CHECK(count_rows(&db, "SELECT count(*) FROM participants;") == 2);
    CHECK(count_rows(&db, "SELECT count(*) FROM messages;") == 1);
    CHECK(pcomm_db_kv_get(&db, "transaction-marker", marker, sizeof(marker)) == 0);
    CHECK(strcmp(marker, "committed-peer") == 0);
    CHECK(pcomm_db_transaction(&db, write_transaction, &context) == 0);
    CHECK(count_rows(&db, "SELECT count(*) FROM conversations;") == 4);
    CHECK(count_rows(&db, "SELECT count(*) FROM messages;") == 2);
    CHECK(sqlite3_next_stmt(db.db, NULL) == NULL);
done:
    if (db.db) sqlite3_commit_hook(db.db, NULL, NULL);
    pcomm_db_close(&db);
    return ok;
}

int main(void) {
    const struct { const char *name; int (*run)(void); } tests[] = {
        {"contact insert/fetch/update and schema idempotence", test_contact_insert_fetch_and_update},
        {"direct conversations and binary message storage", test_direct_conversation_and_message_storage},
        {"group participant storage and duplicate handling", test_group_membership_storage},
        {"settings and descriptor storage", test_settings_and_descriptors},
        {"descriptor trust monotonicity and atomic pruning", test_descriptor_trust_monotonicity},
        {"DHT node insert/fetch/update", test_dht_node_insert_fetch_and_update},
        {"conversation helpers preserve outer transactions", test_conversation_helpers_preserve_outer_transaction},
        {"checked transaction commit and rollback", test_checked_transaction_commit_and_rollback},
    };
    size_t failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int passed = tests[i].run();
        printf("%s: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if (!passed) failures++;
    }
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
