#include "db.h"
#include "mailbox_limits.h"
#include "proto.h"
#include "cell.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(PCOMM_MAILBOX_RESPONSE_MAX_BYTES + 1u + PCOMM_HDR_LEN +
               PCOMM_RELAY_HDR_LEN + 3u * 28u <= PCOMM_CELL_MAX_PAYLOAD,
               "mailbox response must fit a three-hop single-cell RPC");
_Static_assert(2u + 16u + PCOMM_MAILBOX_MAX_BLOB_LEN <= PCOMM_MAILBOX_RESPONSE_MAX_BYTES,
               "a maximum-size envelope must fit one response");

#define RECEIVED_AT INT64_C(2000000000)
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; \
        goto done; \
    } \
} while (0)

static int sql_exec(pcomm_db_t *db, const char *sql) {
    char *error = NULL;
    int rc = sqlite3_exec(db->db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) fprintf(stderr, "test SQL failed: %s\n", error);
    sqlite3_free(error);
    return rc == SQLITE_OK ? 0 : -1;
}

static int fixture_open(pcomm_db_t *db) {
    memset(db, 0, sizeof(*db));
    if (sqlite3_open_v2(":memory:", &db->db,
                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                       NULL) != SQLITE_OK) return -1;
    if (sql_exec(db, "PRAGMA foreign_keys=ON;") != 0) return -1;
    return pcomm_db_init_schema(db);
}

static void make_key(uint32_t id, uint8_t key[32]) {
    memset(key, 0, 32);
    key[0] = (uint8_t)(id >> 24);
    key[1] = (uint8_t)(id >> 16);
    key[2] = (uint8_t)(id >> 8);
    key[3] = (uint8_t)id;
    key[31] = 0x5a;
}

static sqlite3_int64 mailbox_measure(pcomm_db_t *db, const uint8_t *key, int bytes) {
    sqlite3_stmt *st = NULL;
    sqlite3_int64 value = -1;
    const char *sql = bytes ?
        "SELECT coalesce(sum(length(blob)),0) FROM mailbox_items WHERE ?1 IS NULL OR mkey=?1;" :
        "SELECT count(*) FROM mailbox_items WHERE ?1 IS NULL OR mkey=?1;";
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) goto done;
    if (key) sqlite3_bind_blob(st, 1, key, 32, SQLITE_TRANSIENT);
    else sqlite3_bind_null(st, 1);
    if (sqlite3_step(st) == SQLITE_ROW) value = sqlite3_column_int64(st, 0);
done:
    sqlite3_finalize(st);
    return value;
}

static int seed_rows(pcomm_db_t *db, uint32_t count, uint32_t blob_len,
                     const uint8_t *shared_key, int64_t received) {
    sqlite3_stmt *st = NULL;
    uint8_t key[32];
    int rc = -1;
    if (sql_exec(db, "BEGIN;") != 0) return -1;
    if (sqlite3_prepare_v2(db->db,
        "INSERT INTO mailbox_items(mkey,ts_unix,blob) VALUES(?1,?2,zeroblob(?3));",
        -1, &st, NULL) != SQLITE_OK) goto done;
    for (uint32_t i = 0; i < count; i++) {
        make_key(i, key);
        sqlite3_bind_blob(st, 1, shared_key ? shared_key : key, 32, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, received);
        sqlite3_bind_int64(st, 3, blob_len);
        if (sqlite3_step(st) != SQLITE_DONE || sqlite3_reset(st) != SQLITE_OK) goto done;
    }
    rc = 0;
done:
    sqlite3_finalize(st);
    if (rc == 0) return sql_exec(db, "COMMIT;");
    sql_exec(db, "ROLLBACK;");
    return -1;
}

static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t read_u64(const uint8_t *p) {
    return ((uint64_t)read_u32(p) << 32) | read_u32(p + 4);
}

typedef struct {
    uint64_t id;
    uint32_t received;
    const uint8_t *blob;
    uint32_t blob_len;
} record_t;

static int response_matches(const uint8_t *response, uint32_t response_len,
                            const record_t *records, uint32_t count) {
    if (!response || response_len < 2 || response_len > PCOMM_MAILBOX_RESPONSE_MAX_BYTES ||
        (((uint32_t)response[0] << 8) | response[1]) != count) return 0;
    uint32_t off = 2;
    for (uint32_t i = 0; i < count; i++) {
        if (response_len - off < 16 || read_u64(response + off) != records[i].id ||
            read_u32(response + off + 8) != records[i].received ||
            read_u32(response + off + 12) != records[i].blob_len) return 0;
        off += 16;
        if (records[i].blob_len > response_len - off ||
            memcmp(response + off, records[i].blob, records[i].blob_len) != 0) return 0;
        off += records[i].blob_len;
    }
    return off == response_len;
}

static int test_input_limits_and_receipt_timestamp(void) {
    pcomm_db_t db = {0}, unopened = {0};
    uint8_t key[32], blob[PCOMM_MAILBOX_MAX_BLOB_LEN + 1u], sentinel = 1;
    uint8_t *response = NULL;
    uint32_t response_len = 0;
    int ok = 1;
    make_key(100, key);
    for (size_t i = 0; i < sizeof(blob); i++) blob[i] = (uint8_t)(i * 13u + 5u);
    CHECK(fixture_open(&db) == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, blob, 0, RECEIVED_AT) == -1);
    CHECK(pcomm_db_mailbox_put(&db, key, blob, PCOMM_MAILBOX_MAX_BLOB_LEN + 1u, RECEIVED_AT) == -1);
    CHECK(pcomm_db_mailbox_put(&db, key, NULL, 1, RECEIVED_AT) == -1);
    CHECK(pcomm_db_mailbox_put(&db, NULL, blob, 1, RECEIVED_AT) == -1);
    CHECK(pcomm_db_mailbox_put(NULL, key, blob, 1, RECEIVED_AT) == -1);
    CHECK(pcomm_db_mailbox_put(&unopened, key, blob, 1, RECEIVED_AT) == -1);
    CHECK(pcomm_db_mailbox_put(&db, key, blob, 1, -1) == -1);
    CHECK(pcomm_db_mailbox_prune(&db, INT64_MIN) == -1);
    CHECK(pcomm_db_mailbox_prune(NULL, RECEIVED_AT) == -1);
    CHECK(mailbox_measure(&db, NULL, 0) == 0);
    response = &sentinel;
    response_len = 99;
    CHECK(pcomm_db_mailbox_get_and_delete(&db, key, -1, &response, &response_len) == -1);
    CHECK(response == NULL && response_len == 0);

    CHECK(pcomm_db_mailbox_put(&db, key, blob, PCOMM_MAILBOX_MAX_BLOB_LEN, RECEIVED_AT) == 0);
    record_t expected = {(uint64_t)sqlite3_last_insert_rowid(db.db), (uint32_t)RECEIVED_AT,
                         blob, PCOMM_MAILBOX_MAX_BLOB_LEN};
    CHECK(pcomm_db_mailbox_get_and_delete(&db, key, RECEIVED_AT, &response, &response_len) == 0);
    CHECK(response_matches(response, response_len, &expected, 1));
    CHECK(mailbox_measure(&db, key, 0) == 0);
    free(response);
    response = NULL;
    CHECK(pcomm_db_mailbox_put(&db, key, blob, 1, 0) == 0);
    expected = (record_t){(uint64_t)sqlite3_last_insert_rowid(db.db), 0, blob, 1};
    CHECK(pcomm_db_mailbox_get_and_delete(&db, key, 0, &response, &response_len) == 0);
    CHECK(response_matches(response, response_len, &expected, 1));
done:
    if (response != &sentinel) free(response);
    pcomm_db_close(&db);
    return ok;
}

static int test_per_mailbox_row_quota_and_key_isolation(void) {
    pcomm_db_t db = {0};
    uint8_t key[32], other[32], blob = 7;
    int ok = 1;
    make_key(100, key);
    make_key(101, other);
    CHECK(fixture_open(&db) == 0);
    for (uint32_t i = 0; i < PCOMM_MAILBOX_MAX_ITEMS; i++) {
        CHECK(pcomm_db_mailbox_put(&db, key, &blob, 1, RECEIVED_AT) == 0);
    }
    CHECK(pcomm_db_mailbox_put(&db, key, &blob, 1, RECEIVED_AT) == 1);
    CHECK(mailbox_measure(&db, key, 0) == PCOMM_MAILBOX_MAX_ITEMS);
    CHECK(pcomm_db_mailbox_put(&db, other, &blob, 1, RECEIVED_AT) == 0);
    CHECK(mailbox_measure(&db, other, 0) == 1);
    CHECK(mailbox_measure(&db, NULL, 0) == PCOMM_MAILBOX_MAX_ITEMS + 1u);
done:
    pcomm_db_close(&db);
    return ok;
}

static int test_per_mailbox_byte_quota(void) {
    pcomm_db_t db = {0};
    uint8_t key[32], other[32], blob[PCOMM_MAILBOX_MAX_BLOB_LEN] = {0};
    const uint32_t full_rows = PCOMM_MAILBOX_MAX_BYTES / PCOMM_MAILBOX_MAX_BLOB_LEN;
    const uint32_t tail = PCOMM_MAILBOX_MAX_BYTES % PCOMM_MAILBOX_MAX_BLOB_LEN;
    int ok = 1;
    make_key(100, key);
    make_key(101, other);
    CHECK(fixture_open(&db) == 0);
    CHECK(tail > 0 && full_rows + 1u < PCOMM_MAILBOX_MAX_ITEMS);
    for (uint32_t i = 0; i < full_rows; i++) {
        CHECK(pcomm_db_mailbox_put(&db, key, blob, sizeof(blob), RECEIVED_AT) == 0);
    }
    CHECK(pcomm_db_mailbox_put(&db, key, blob, sizeof(blob), RECEIVED_AT) == 1);
    CHECK(pcomm_db_mailbox_put(&db, key, blob, tail, RECEIVED_AT) == 0);
    CHECK(mailbox_measure(&db, key, 1) == PCOMM_MAILBOX_MAX_BYTES);
    CHECK(pcomm_db_mailbox_put(&db, key, blob, 1, RECEIVED_AT) == 1);
    CHECK(pcomm_db_mailbox_put(&db, other, blob, sizeof(blob), RECEIVED_AT) == 0);
    CHECK(mailbox_measure(&db, other, 1) == sizeof(blob));
done:
    pcomm_db_close(&db);
    return ok;
}

static int test_global_row_quota_survives_key_churn(void) {
    pcomm_db_t db = {0};
    uint8_t key[32], other[32], blob = 7;
    int ok = 1;
    make_key(UINT32_MAX, key);
    make_key(UINT32_MAX - 1u, other);
    CHECK(fixture_open(&db) == 0);
    CHECK(seed_rows(&db, PCOMM_MAILBOX_GLOBAL_MAX_ITEMS - 1u, 1, NULL, RECEIVED_AT) == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, &blob, 1, RECEIVED_AT) == 0);
    CHECK(pcomm_db_mailbox_put(&db, other, &blob, 1, RECEIVED_AT) == 1);
    CHECK(mailbox_measure(&db, NULL, 0) == PCOMM_MAILBOX_GLOBAL_MAX_ITEMS);
    CHECK(mailbox_measure(&db, other, 0) == 0);
done:
    pcomm_db_close(&db);
    return ok;
}

static int test_global_byte_quota_survives_key_churn(void) {
    pcomm_db_t db = {0};
    uint8_t key[32], other[32], blob[PCOMM_MAILBOX_MAX_BLOB_LEN] = {0};
    const uint32_t full_rows = PCOMM_MAILBOX_GLOBAL_MAX_BYTES / PCOMM_MAILBOX_MAX_BLOB_LEN;
    const uint32_t tail = PCOMM_MAILBOX_GLOBAL_MAX_BYTES % PCOMM_MAILBOX_MAX_BLOB_LEN;
    int ok = 1;
    make_key(UINT32_MAX, key);
    make_key(UINT32_MAX - 1u, other);
    CHECK(fixture_open(&db) == 0);
    CHECK(tail > 0 && full_rows + 1u < PCOMM_MAILBOX_GLOBAL_MAX_ITEMS);
    CHECK(seed_rows(&db, full_rows, sizeof(blob), NULL, RECEIVED_AT) == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, blob, tail, RECEIVED_AT) == 0);
    CHECK(mailbox_measure(&db, NULL, 1) == PCOMM_MAILBOX_GLOBAL_MAX_BYTES);
    CHECK(pcomm_db_mailbox_put(&db, other, blob, 1, RECEIVED_AT) == 1);
    make_key(UINT32_MAX - 2u, other);
    CHECK(pcomm_db_mailbox_put(&db, other, blob, 1, RECEIVED_AT) == 1);
    CHECK(mailbox_measure(&db, NULL, 0) == full_rows + 1u);
done:
    pcomm_db_close(&db);
    return ok;
}

static int test_ttl_boundaries_for_put_get_and_prune(void) {
    pcomm_db_t db = {0};
    uint8_t key[32], other[32], third[32], old = 1, fresh = 2;
    uint8_t *response = NULL;
    uint32_t response_len = 0;
    const int64_t deadline = RECEIVED_AT + PCOMM_MAILBOX_TTL_SEC;
    int ok = 1;
    make_key(100, key);
    make_key(101, other);
    make_key(102, third);
    CHECK(fixture_open(&db) == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, &old, 1, RECEIVED_AT) == 0);
    CHECK(pcomm_db_mailbox_put(&db, other, &fresh, 1, deadline - 1) == 0);
    CHECK(mailbox_measure(&db, key, 0) == 1);
    CHECK(pcomm_db_mailbox_put(&db, third, &fresh, 1, deadline) == 0);
    CHECK(mailbox_measure(&db, key, 0) == 0);
    CHECK(mailbox_measure(&db, other, 0) == 1);
    CHECK(sql_exec(&db, "DELETE FROM mailbox_items;") == 0);

    CHECK(pcomm_db_mailbox_put(&db, key, &old, 1, RECEIVED_AT) == 0);
    CHECK(pcomm_db_mailbox_prune(&db, deadline - 1) == 0);
    CHECK(mailbox_measure(&db, key, 0) == 1);
    CHECK(pcomm_db_mailbox_prune(&db, deadline) == 0);
    CHECK(mailbox_measure(&db, key, 0) == 0);

    CHECK(pcomm_db_mailbox_put(&db, key, &old, 1, RECEIVED_AT) == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, &fresh, 1, deadline - 1) == 0);
    record_t expected = {(uint64_t)sqlite3_last_insert_rowid(db.db), (uint32_t)(deadline - 1), &fresh, 1};
    CHECK(pcomm_db_mailbox_get_and_delete(&db, key, deadline, &response, &response_len) == 0);
    CHECK(response_matches(response, response_len, &expected, 1));
    CHECK(mailbox_measure(&db, key, 0) == 0);
    free(response);
    response = NULL;
    CHECK(pcomm_db_mailbox_get_and_delete(&db, key, deadline, &response, &response_len) == 0);
    CHECK(response_matches(response, response_len, NULL, 0));
done:
    free(response);
    pcomm_db_close(&db);
    return ok;
}

static int test_retrieval_copies_rows_and_batches_to_budget(void) {
    pcomm_db_t db = {0};
    uint8_t key[32], other[32], blobs[6][1000];
    const uint32_t sizes[] = {500, 700, 1000, 1000, 500, 100};
    record_t records[6];
    uint8_t *response = NULL;
    uint32_t response_len = 0;
    int ok = 1;
    make_key(100, key);
    make_key(101, other);
    CHECK(fixture_open(&db) == 0);
    for (uint32_t i = 0; i < 6; i++) {
        for (uint32_t j = 0; j < sizeof(blobs[i]); j++) blobs[i][j] = (uint8_t)(i * 29u + j * 7u);
        CHECK(pcomm_db_mailbox_put(&db, key, blobs[i], sizes[i], RECEIVED_AT + i) == 0);
        records[i] = (record_t){(uint64_t)sqlite3_last_insert_rowid(db.db),
                                (uint32_t)(RECEIVED_AT + i), blobs[i], sizes[i]};
    }
    CHECK(pcomm_db_mailbox_put(&db, other, blobs[0], sizes[0], RECEIVED_AT + 6) == 0);
    CHECK(pcomm_db_mailbox_get_and_delete(&db, key, RECEIVED_AT + 10, &response, &response_len) == 0);
    CHECK(response_matches(response, response_len, records, 5));
    CHECK(mailbox_measure(&db, key, 0) == 1);
    CHECK(mailbox_measure(&db, other, 0) == 1);
    free(response);
    response = NULL;
    CHECK(pcomm_db_mailbox_get_and_delete(&db, key, RECEIVED_AT + 10, &response, &response_len) == 0);
    CHECK(response_matches(response, response_len, records + 5, 1));
    CHECK(mailbox_measure(&db, key, 0) == 0);
    CHECK(mailbox_measure(&db, other, 0) == 1);
done:
    free(response);
    pcomm_db_close(&db);
    return ok;
}

static int test_delete_failure_rolls_back_batch_and_expiry(void) {
    pcomm_db_t db = {0};
    uint8_t key[32], old = 1, live = 2, sentinel = 7;
    uint8_t *response = NULL;
    uint32_t response_len = 0;
    const int64_t deadline = RECEIVED_AT + PCOMM_MAILBOX_TTL_SEC;
    int ok = 1;
    make_key(100, key);
    CHECK(fixture_open(&db) == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, &old, 1, RECEIVED_AT) == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, &live, 1, deadline - 1) == 0);
    record_t expected = {(uint64_t)sqlite3_last_insert_rowid(db.db), (uint32_t)(deadline - 1), &live, 1};
    CHECK(sql_exec(&db,
        "CREATE TEMP TRIGGER fail_batch_delete BEFORE DELETE ON mailbox_items "
        "WHEN OLD.id=(SELECT max(id) FROM mailbox_items) "
        "BEGIN SELECT RAISE(ABORT,'injected batch delete failure'); END;") == 0);
    response = &sentinel;
    response_len = 99;
    CHECK(pcomm_db_mailbox_get_and_delete(&db, key, deadline, &response, &response_len) == -1);
    CHECK(response == NULL && response_len == 0);
    CHECK(mailbox_measure(&db, key, 0) == 2);
    CHECK(sqlite3_get_autocommit(db.db) != 0);
    CHECK(sql_exec(&db, "DROP TRIGGER fail_batch_delete;") == 0);
    CHECK(pcomm_db_mailbox_get_and_delete(&db, key, deadline, &response, &response_len) == 0);
    CHECK(response_matches(response, response_len, &expected, 1));
    CHECK(mailbox_measure(&db, key, 0) == 0);
done:
    if (response != &sentinel) free(response);
    pcomm_db_close(&db);
    return ok;
}

static int test_sql_errors_fail_closed(void) {
    pcomm_db_t db = {0};
    uint8_t key[32], other[32], blob = 1;
    int ok = 1;
    make_key(100, key);
    make_key(101, other);
    CHECK(fixture_open(&db) == 0);
    CHECK(sql_exec(&db,
        "CREATE TEMP TRIGGER fail_put BEFORE INSERT ON mailbox_items "
        "BEGIN SELECT RAISE(ABORT,'injected put failure'); END;") == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, &blob, 1, RECEIVED_AT) == -1);
    CHECK(mailbox_measure(&db, NULL, 0) == 0);
    CHECK(sql_exec(&db, "DROP TRIGGER fail_put;") == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, &blob, 1, RECEIVED_AT) == 0);
    CHECK(sql_exec(&db,
        "CREATE TEMP TRIGGER fail_prune BEFORE DELETE ON mailbox_items "
        "BEGIN SELECT RAISE(ABORT,'injected prune failure'); END;") == 0);
    CHECK(pcomm_db_mailbox_prune(&db, RECEIVED_AT + PCOMM_MAILBOX_TTL_SEC) == -1);
    CHECK(pcomm_db_mailbox_put(&db, other, &blob, 1, RECEIVED_AT + PCOMM_MAILBOX_TTL_SEC) == -1);
    CHECK(mailbox_measure(&db, NULL, 0) == 1 && mailbox_measure(&db, other, 0) == 0);
    CHECK(sql_exec(&db, "DROP TRIGGER fail_prune;") == 0);
    CHECK(pcomm_db_mailbox_prune(&db, RECEIVED_AT + PCOMM_MAILBOX_TTL_SEC) == 0);
    CHECK(mailbox_measure(&db, NULL, 0) == 0);
    CHECK(sql_exec(&db, "DROP TABLE mailbox_items;") == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, &blob, 1, RECEIVED_AT) == -1);
    CHECK(pcomm_db_mailbox_prune(&db, RECEIVED_AT) == -1);
done:
    pcomm_db_close(&db);
    return ok;
}

static int test_get_preserves_outer_transaction(void) {
    pcomm_db_t db = {0};
    sqlite3_stmt *st = NULL;
    uint8_t key[32], blob = 1;
    uint8_t *response = NULL;
    uint32_t response_len = 0;
    int ok = 1;
    make_key(100, key);
    CHECK(fixture_open(&db) == 0);
    CHECK(pcomm_db_mailbox_put(&db, key, &blob, 1, RECEIVED_AT) == 0);
    CHECK(sql_exec(&db, "BEGIN; INSERT INTO settings(key,value) VALUES('outer','uncommitted');") == 0);
    CHECK(sqlite3_get_autocommit(db.db) == 0);
    CHECK(pcomm_db_mailbox_get_and_delete(&db, key, RECEIVED_AT, &response, &response_len) == 0);
    CHECK(sqlite3_get_autocommit(db.db) == 0);
    CHECK(mailbox_measure(&db, key, 0) == 0);
    CHECK(sql_exec(&db, "ROLLBACK;") == 0);
    CHECK(sqlite3_get_autocommit(db.db) != 0);
    CHECK(mailbox_measure(&db, key, 0) == 1);
    CHECK(sqlite3_prepare_v2(db.db, "SELECT value FROM settings WHERE key='outer';", -1, &st, NULL) == SQLITE_OK);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    st = NULL;
    CHECK(rc == SQLITE_DONE);
done:
    sqlite3_finalize(st);
    free(response);
    pcomm_db_close(&db);
    return ok;
}

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready;
    int released;
} start_gate_t;

typedef struct {
    pcomm_db_t *db;
    start_gate_t *gate;
    uint8_t key[32];
    int result;
} writer_t;

static void *concurrent_put(void *arg) {
    writer_t *writer = (writer_t *)arg;
    const uint8_t blob = 1;
    pthread_mutex_lock(&writer->gate->mutex);
    writer->gate->ready++;
    pthread_cond_broadcast(&writer->gate->condition);
    while (!writer->gate->released) pthread_cond_wait(&writer->gate->condition, &writer->gate->mutex);
    pthread_mutex_unlock(&writer->gate->mutex);
    writer->result = pcomm_db_mailbox_put(writer->db, writer->key, &blob, 1, RECEIVED_AT);
    return NULL;
}

static int concurrent_quota_case(int global) {
    enum { WORKERS = 8 };
    pcomm_db_t db = {0};
    uint8_t key[32];
    start_gate_t gate = {0};
    pthread_t threads[WORKERS];
    writer_t writers[WORKERS];
    unsigned started = 0, accepted = 0, full = 0;
    int mutex_ready = 0, condition_ready = 0;
    int ok = 1;
    make_key(UINT32_MAX, key);
    CHECK(fixture_open(&db) == 0);
    CHECK(seed_rows(&db, global ? PCOMM_MAILBOX_GLOBAL_MAX_ITEMS - 1u : PCOMM_MAILBOX_MAX_ITEMS - 1u,
                    1, global ? NULL : key, RECEIVED_AT) == 0);
    CHECK(pthread_mutex_init(&gate.mutex, NULL) == 0);
    mutex_ready = 1;
    CHECK(pthread_cond_init(&gate.condition, NULL) == 0);
    condition_ready = 1;
    for (unsigned i = 0; i < WORKERS; i++) {
        writers[i].db = &db;
        writers[i].gate = &gate;
        writers[i].result = -99;
        if (global) make_key(UINT32_MAX - i, writers[i].key);
        else memcpy(writers[i].key, key, sizeof(key));
        if (pthread_create(&threads[i], NULL, concurrent_put, &writers[i]) != 0) {
            fprintf(stderr, "could not start mailbox writer %u\n", i);
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
    for (unsigned i = 0; i < started; i++) {
        if (pthread_join(threads[i], NULL) != 0) ok = 0;
        if (writers[i].result == 0) accepted++;
        else if (writers[i].result == 1) full++;
        else ok = 0;
    }
    CHECK(started == WORKERS && accepted == 1 && full == WORKERS - 1u);
    CHECK(mailbox_measure(&db, NULL, 0) ==
          (global ? PCOMM_MAILBOX_GLOBAL_MAX_ITEMS : PCOMM_MAILBOX_MAX_ITEMS));
done:
    if (condition_ready) pthread_cond_destroy(&gate.condition);
    if (mutex_ready) pthread_mutex_destroy(&gate.mutex);
    pcomm_db_close(&db);
    return ok;
}

static int test_concurrent_writers_respect_quotas(void) {
    return concurrent_quota_case(0) && concurrent_quota_case(1);
}

int main(void) {
    const struct {
        const char *name;
        int (*run)(void);
    } tests[] = {
        {"input limits and receipt timestamp", test_input_limits_and_receipt_timestamp},
        {"per-mailbox row quota and key isolation", test_per_mailbox_row_quota_and_key_isolation},
        {"per-mailbox byte quota", test_per_mailbox_byte_quota},
        {"global row quota survives key churn", test_global_row_quota_survives_key_churn},
        {"global byte quota survives key churn", test_global_byte_quota_survives_key_churn},
        {"TTL boundaries for PUT, GET, and prune", test_ttl_boundaries_for_put_get_and_prune},
        {"retrieval copies rows and batches to budget", test_retrieval_copies_rows_and_batches_to_budget},
        {"DELETE failure rolls back batch and expiry", test_delete_failure_rolls_back_batch_and_expiry},
        {"SQL errors fail closed", test_sql_errors_fail_closed},
        {"GET preserves an outer transaction", test_get_preserves_outer_transaction},
        {"concurrent writers respect quotas", test_concurrent_writers_respect_quotas},
    };
    size_t failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int passed = tests[i].run();
        printf("%s: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if (!passed) failures++;
    }
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
