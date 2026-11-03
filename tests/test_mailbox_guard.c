#include "mailbox.h"
#include "mailbox_limits.h"
#include "pcomm.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PUT_HEADER_LEN = 1 + 20 + 32 + 4 };
#define FRAME_CAPACITY (PUT_HEADER_LEN + PCOMM_MAILBOX_MAX_BLOB_LEN + 1)
#define RECEIVED_UNIX INT64_C(1800000000)

typedef struct {
    pcomm_db_t db;
    pcomm_mailbox_guard_t *guard;
} fixture_t;

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; \
        goto done; \
    } \
} while (0)

static int fixture_open(fixture_t *fixture, size_t capacity) {
    memset(fixture, 0, sizeof(*fixture));
    if (sqlite3_open_v2(":memory:", &fixture->db.db,
                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                       NULL) != SQLITE_OK || pcomm_db_init_schema(&fixture->db) != 0) return -1;
    fixture->guard = pcomm_mailbox_guard_create(capacity);
    return fixture->guard ? 0 : -1;
}

static void fixture_close(fixture_t *fixture) {
    pcomm_mailbox_guard_destroy(fixture->guard);
    pcomm_db_close(&fixture->db);
    memset(fixture, 0, sizeof(*fixture));
}

static int sql_exec(fixture_t *fixture, const char *sql) {
    return sqlite3_exec(fixture->db.db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static sqlite3_int64 sql_value(fixture_t *fixture, const char *sql) {
    sqlite3_stmt *statement = NULL;
    sqlite3_int64 value = -1;
    if (sqlite3_prepare_v2(fixture->db.db, sql, -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW) value = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    return value;
}

static void put_u32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint32_t frame_make(uint8_t frame[FRAME_CAPACITY], uint32_t blob_len, unsigned mailbox) {
    memset(frame, 0x5a, PUT_HEADER_LEN + blob_len);
    frame[0] = (uint8_t)PCOMM_CTRL_MB_PUT;
    frame[21] = (uint8_t)mailbox;
    frame[22] = (uint8_t)(mailbox >> 8);
    put_u32(frame + 53, blob_len);
    return PUT_HEADER_LEN + blob_len;
}

static int deposit(fixture_t *fixture, const char *ip, const uint8_t *frame,
                    uint32_t frame_len, uint64_t now_ms) {
    uint8_t infohash[20], unchanged[20];
    memset(infohash, 0xa5, sizeof(infohash));
    memcpy(unchanged, infohash, sizeof(unchanged));
    int rc = pcomm_mailbox_deposit(fixture->guard, &fixture->db, ip, frame,
                                   frame_len, now_ms, RECEIVED_UNIX, infohash);
    if (rc == 0) {
        if (!frame || frame_len < 21 || memcmp(infohash, frame + 1, 20) != 0) return -2;
    } else if (memcmp(infohash, unchanged, sizeof(infohash)) != 0) {
        return -2;
    }
    return rc;
}

static int test_frame_and_source_validation(void) {
    int ok = 1;
    fixture_t fixture = {0};
    uint8_t frame[FRAME_CAPACITY];
    uint32_t frame_len;
    CHECK(pcomm_mailbox_guard_create(0) == NULL);
    CHECK(pcomm_mailbox_guard_create(SIZE_MAX) == NULL);
    pcomm_mailbox_guard_destroy(NULL);
    CHECK(fixture_open(&fixture, 16) == 0);
    frame_len = frame_make(frame, 1, 0);
    uint8_t output[20];
    pcomm_db_t closed_db = {0};
    CHECK(pcomm_mailbox_deposit(NULL, &fixture.db, "192.0.2.1", frame,
                                frame_len, 0, RECEIVED_UNIX, output) == -1);
    CHECK(pcomm_mailbox_deposit(fixture.guard, NULL, "192.0.2.1", frame,
                                frame_len, 0, RECEIVED_UNIX, output) == -1);
    CHECK(pcomm_mailbox_deposit(fixture.guard, &closed_db, "192.0.2.1", frame,
                                frame_len, 0, RECEIVED_UNIX, output) == -1);
    CHECK(pcomm_mailbox_deposit(fixture.guard, &fixture.db, NULL, frame,
                                frame_len, 0, RECEIVED_UNIX, output) == -1);
    CHECK(pcomm_mailbox_deposit(fixture.guard, &fixture.db, "192.0.2.1", frame,
                                frame_len, 0, RECEIVED_UNIX, NULL) == -1);
    CHECK(deposit(&fixture, "", frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "relay.example", frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "999.0.0.1", frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "[::1]", frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "fe80::1%2", frame, frame_len, 0) == 1);
    char long_ip[128];
    memset(long_ip, '1', sizeof(long_ip) - 1);
    long_ip[sizeof(long_ip) - 1] = '\0';
    CHECK(deposit(&fixture, long_ip, frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", NULL, 0, 0) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, 0, 0) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, PUT_HEADER_LEN - 1, 0) == 1);
    frame[0] = (uint8_t)PCOMM_CTRL_MB_GET;
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 1);
    frame_len = frame_make(frame, 0, 0);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 1);
    frame_len = frame_make(frame, 1, 0);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len - 1, 0) == 1);
    frame[frame_len] = 0;
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len + 1, 0) == 1);
    put_u32(frame + 53, UINT32_MAX);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 1);
    frame_len = frame_make(frame, PCOMM_MAILBOX_MAX_BLOB_LEN + 1, 0);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 1);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM mailbox_items;") == 0);
    frame_len = frame_make(frame, PCOMM_MAILBOX_MAX_BLOB_LEN, 0);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 0);
    CHECK(sql_value(&fixture, "SELECT ts_unix FROM mailbox_items;") == RECEIVED_UNIX);
done:
    fixture_close(&fixture);
    return ok;
}

static int test_ip_burst_and_fractional_refill(void) {
    int ok = 1;
    fixture_t fixture = {0};
    uint8_t frame[FRAME_CAPACITY];
    uint32_t frame_len = frame_make(frame, 1, 0);
    CHECK(fixture_open(&fixture, 8) == 0);
    for (unsigned i = 0; i < PCOMM_MAILBOX_IP_BURST; i++) {
        CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 0);
    }
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 999) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 1000) == 0);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 1999) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 2000) == 0);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM mailbox_items;") == PCOMM_MAILBOX_IP_BURST + 2);
done:
    fixture_close(&fixture);
    return ok;
}

static int test_ip_normalization(void) {
    int ok = 1;
    fixture_t fixture = {0};
    uint8_t frame[FRAME_CAPACITY];
    uint32_t frame_len = frame_make(frame, 1, 0);
    CHECK(fixture_open(&fixture, 8) == 0);
    for (unsigned i = 0; i < PCOMM_MAILBOX_IP_BURST; i++) {
        const char *ip = i % 2 ? "::ffff:c000:201" : "192.0.2.1";
        CHECK(deposit(&fixture, ip, frame, frame_len, 0) == 0);
    }
    CHECK(deposit(&fixture, "::ffff:192.0.2.1", frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 1);
    for (unsigned i = 0; i < PCOMM_MAILBOX_IP_BURST; i++) {
        const char *ip = i % 2 ? "2001:0db8:0:0:0:0:0:1" : "2001:db8::1";
        CHECK(deposit(&fixture, ip, frame, frame_len, 0) == 0);
    }
    CHECK(deposit(&fixture, "2001:db8::1", frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "2001:db8::2", frame, frame_len, 0) == 0);
done:
    fixture_close(&fixture);
    return ok;
}

static int test_global_budget_and_exhausted_ip_fairness(void) {
    int ok = 1;
    fixture_t fixture = {0};
    uint8_t frame[FRAME_CAPACITY];
    uint32_t frame_len;
    const char *sources[] = {"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"};
    for (int malformed = 0; malformed <= 1; malformed++) {
        CHECK(fixture_open(&fixture, 8) == 0);
        for (unsigned source = 0; source < 4; source++) {
            for (unsigned i = 0; i < PCOMM_MAILBOX_IP_BURST; i++) {
                frame_len = frame_make(frame, 1, source * PCOMM_MAILBOX_IP_BURST + i);
                CHECK(deposit(&fixture, sources[source], frame,
                              malformed ? 1 : frame_len, 0) == (malformed ? 1 : 0));
            }
            for (unsigned i = 0; i < 200; i++) {
                CHECK(deposit(&fixture, sources[source], frame, frame_len, 0) == 1);
            }
        }
        frame_len = frame_make(frame, 1, 200);
        CHECK(deposit(&fixture, "192.0.2.5", frame, frame_len, 0) == 1);
        CHECK(deposit(&fixture, "192.0.2.5", frame, frame_len, 49) == 1);
        CHECK(deposit(&fixture, "192.0.2.5", frame, frame_len, 50) == 0);
        CHECK(deposit(&fixture, "192.0.2.6", frame, frame_len, 50) == 1);
        CHECK(deposit(&fixture, "192.0.2.6", frame, frame_len, 100) == 0);
        CHECK(sql_value(&fixture, "SELECT count(*) FROM mailbox_items;") ==
              (malformed ? 2 : PCOMM_MAILBOX_GLOBAL_BURST + 2));
        fixture_close(&fixture);
    }
done:
    fixture_close(&fixture);
    return ok;
}

static int test_source_churn_cannot_reset_depleted_budget(void) {
    int ok = 1;
    fixture_t fixture = {0};
    uint8_t frame[FRAME_CAPACITY];
    uint32_t frame_len = frame_make(frame, 1, 0);
    CHECK(fixture_open(&fixture, 1) == 0);
    for (unsigned i = 0; i < PCOMM_MAILBOX_IP_BURST; i++) {
        CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 0);
    }
    CHECK(deposit(&fixture, "192.0.2.2", frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "192.0.2.3", frame, frame_len,
                  PCOMM_MAILBOX_IP_BURST * PCOMM_MAILBOX_IP_INTERVAL_MS - 1) == 1);
    CHECK(deposit(&fixture, "192.0.2.2", frame, frame_len,
                  PCOMM_MAILBOX_IP_BURST * PCOMM_MAILBOX_IP_INTERVAL_MS) == 0);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len,
                  PCOMM_MAILBOX_IP_BURST * PCOMM_MAILBOX_IP_INTERVAL_MS) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len,
                  (PCOMM_MAILBOX_IP_BURST + 1) * PCOMM_MAILBOX_IP_INTERVAL_MS) == 0);
done:
    fixture_close(&fixture);
    return ok;
}

static int test_clock_rollback_and_large_delta(void) {
    int ok = 1;
    fixture_t fixture = {0};
    uint8_t frame[FRAME_CAPACITY];
    uint32_t frame_len = frame_make(frame, 1, 0);
    CHECK(fixture_open(&fixture, 2) == 0);
    for (unsigned i = 0; i < PCOMM_MAILBOX_IP_BURST; i++) {
        CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 10000) == 0);
    }
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 9000) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 10999) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 11000) == 0);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 10000) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, UINT64_MAX) == 0);
    for (unsigned i = 1; i < PCOMM_MAILBOX_IP_BURST; i++) {
        CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 0);
    }
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, UINT64_MAX) == 1);
    CHECK(deposit(&fixture, "192.0.2.2", frame, frame_len, 0) == 0);
done:
    fixture_close(&fixture);
    return ok;
}

static int test_rejected_attempts_consume_admitted_budget(void) {
    int ok = 1;
    fixture_t fixture = {0};
    uint8_t frame[FRAME_CAPACITY];
    uint32_t frame_len = frame_make(frame, 1, 0);
    CHECK(fixture_open(&fixture, 8) == 0);
    for (unsigned i = 0; i < PCOMM_MAILBOX_IP_BURST; i++) {
        CHECK(deposit(&fixture, "192.0.2.1", frame, 1, 0) == 1);
    }
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 0) == 1);
    CHECK(deposit(&fixture, "192.0.2.1", frame, frame_len, 1000) == 0);
    CHECK(sql_exec(&fixture, "DELETE FROM mailbox_items;") == 0);

    for (unsigned i = 0; i < PCOMM_MAILBOX_MAX_ITEMS; i++) {
        CHECK(pcomm_db_mailbox_put(&fixture.db, frame + 21, frame + PUT_HEADER_LEN,
                                   1, RECEIVED_UNIX) == 0);
    }
    for (unsigned i = 0; i < PCOMM_MAILBOX_IP_BURST; i++) {
        CHECK(deposit(&fixture, "192.0.2.2", frame, frame_len, 1000) == 1);
    }
    CHECK(sql_exec(&fixture, "DELETE FROM mailbox_items;") == 0);
    CHECK(deposit(&fixture, "192.0.2.2", frame, frame_len, 1000) == 1);
    CHECK(deposit(&fixture, "192.0.2.2", frame, frame_len, 2000) == 0);

    CHECK(sql_exec(&fixture, "DROP TABLE mailbox_items;") == 0);
    CHECK(deposit(&fixture, "192.0.2.3", frame, frame_len, 2000) == -1);
done:
    fixture_close(&fixture);
    return ok;
}

enum { ADMISSION_WORKERS = 12, ADMISSION_ATTEMPTS = 16 };

typedef struct {
    fixture_t *fixture;
    atomic_uint ready;
    atomic_int start;
    atomic_int cancel;
} admission_start_t;

typedef struct {
    admission_start_t *start;
    char source[32];
    unsigned mailbox_offset;
    unsigned accepted;
    unsigned rejected;
    unsigned errors;
} admission_worker_t;

static void *admission_worker(void *arg) {
    admission_worker_t *worker = (admission_worker_t *)arg;
    atomic_fetch_add_explicit(&worker->start->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&worker->start->start, memory_order_acquire)) {

    }
    if (atomic_load_explicit(&worker->start->cancel, memory_order_acquire)) return NULL;

    uint8_t frame[FRAME_CAPACITY];
    for (unsigned i = 0; i < ADMISSION_ATTEMPTS; i++) {
        uint32_t frame_len = frame_make(frame, 1, worker->mailbox_offset + i);
        int rc = deposit(worker->start->fixture, worker->source, frame, frame_len, 0);
        if (rc == 0) worker->accepted++;
        else if (rc == 1) worker->rejected++;
        else worker->errors++;
    }
    return NULL;
}

static int test_concurrent_admission(int independent_sources) {
    int ok = 1;
    fixture_t fixture = {0};
    admission_start_t start;
    start.fixture = &fixture;
    atomic_init(&start.ready, 0);
    atomic_init(&start.start, 0);
    atomic_init(&start.cancel, 0);
    pthread_t threads[ADMISSION_WORKERS];
    admission_worker_t workers[ADMISSION_WORKERS] = {0};
    unsigned created = 0;
    unsigned accepted = 0, rejected = 0, errors = 0;
    unsigned expected = independent_sources ? PCOMM_MAILBOX_GLOBAL_BURST : PCOMM_MAILBOX_IP_BURST;
    CHECK(ADMISSION_ATTEMPTS < PCOMM_MAILBOX_IP_BURST);
    CHECK(ADMISSION_WORKERS * ADMISSION_ATTEMPTS > PCOMM_MAILBOX_GLOBAL_BURST);
    CHECK(fixture_open(&fixture, ADMISSION_WORKERS) == 0);
    for (unsigned i = 0; i < ADMISSION_WORKERS; i++) {
        workers[i].start = &start;
        workers[i].mailbox_offset = i * ADMISSION_ATTEMPTS;
        snprintf(workers[i].source, sizeof(workers[i].source), "192.0.2.%u",
                 independent_sources ? i + 1 : 1);
        if (pthread_create(&threads[i], NULL, admission_worker, &workers[i]) != 0) {
            fprintf(stderr, "Could not create admission test worker %u\n", i);
            ok = 0;
            break;
        }
        created++;
    }
    if (ok) {
        while (atomic_load_explicit(&start.ready, memory_order_acquire) < created) {

        }
    } else {
        atomic_store_explicit(&start.cancel, 1, memory_order_release);
    }
    atomic_store_explicit(&start.start, 1, memory_order_release);

    for (unsigned i = 0; i < created; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            fprintf(stderr, "Could not join admission test worker %u\n", i);
            abort();
        }
        accepted += workers[i].accepted;
        rejected += workers[i].rejected;
        errors += workers[i].errors;
    }
    CHECK(ok);
    CHECK(errors == 0);
    CHECK(accepted == expected);
    CHECK(rejected == ADMISSION_WORKERS * ADMISSION_ATTEMPTS - expected);
    CHECK(sql_value(&fixture, "SELECT count(*) FROM mailbox_items;") == expected);
done:
    fixture_close(&fixture);
    return ok;
}

int main(void) {
    if (!test_frame_and_source_validation() ||
        !test_ip_burst_and_fractional_refill() ||
        !test_ip_normalization() ||
        !test_global_budget_and_exhausted_ip_fairness() ||
        !test_source_churn_cannot_reset_depleted_budget() ||
        !test_clock_rollback_and_large_delta() ||
        !test_rejected_attempts_consume_admitted_budget() ||
        !test_concurrent_admission(0) ||
        !test_concurrent_admission(1)) return 1;
    puts("Mailbox admission checks passed.");
    return 0;
}
