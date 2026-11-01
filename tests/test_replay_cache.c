#include "replay.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return -1; \
    } \
} while (0)

typedef struct {
    int calls;
    int fail;
} callback_state_t;

static int persist(void *arg) {
    callback_state_t *state = (callback_state_t *)arg;
    state->calls++;
    return state->fail ? -1 : 0;
}

static int test_invalid_arguments_and_clock(void) {
    uint8_t tag[PCOMM_REPLAY_TAG_LEN] = {0};
    callback_state_t state = {0};
    CHECK(pcomm_replay_cache_create(0, 1) == NULL);
    CHECK(pcomm_replay_cache_create(1, 0) == NULL);
    CHECK(pcomm_replay_cache_create(SIZE_MAX, 1) == NULL);
    pcomm_replay_cache_t *cache = pcomm_replay_cache_create(1, 100);
    CHECK(cache != NULL);
    CHECK(pcomm_replay_apply(NULL, tag, 0, persist, &state) == -1);
    CHECK(pcomm_replay_apply(cache, NULL, 0, persist, &state) == -1);
    CHECK(pcomm_replay_apply(cache, tag, 0, NULL, &state) == -1);
    CHECK(state.calls == 0);
    CHECK(pcomm_replay_apply(cache, tag, 0, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, tag, 0, persist, &state) == 1);
    CHECK(state.calls == 1);
    pcomm_replay_cache_destroy(cache);
    pcomm_replay_cache_destroy(NULL);

    uint64_t before = 0, after = 0;
    CHECK(pcomm_replay_now_ms(NULL) == -1);
    CHECK(pcomm_replay_now_ms(&before) == 0);
    CHECK(pcomm_replay_now_ms(&after) == 0);
    CHECK(after >= before);
    return 0;
}

static int test_duplicates_and_independent_caches(void) {
    uint8_t first[PCOMM_REPLAY_TAG_LEN] = {0};
    uint8_t second[PCOMM_REPLAY_TAG_LEN] = {0};
    second[PCOMM_REPLAY_TAG_LEN - 1] = 1;
    callback_state_t state = {0};
    pcomm_replay_cache_t *cache = pcomm_replay_cache_create(2, 100);
    pcomm_replay_cache_t *other = pcomm_replay_cache_create(2, 100);
    CHECK(cache != NULL && other != NULL);
    CHECK(pcomm_replay_apply(cache, first, 0, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, first, 1, persist, &state) == 1);
    CHECK(pcomm_replay_apply(cache, second, 2, persist, &state) == 0);
    CHECK(pcomm_replay_apply(other, first, 3, persist, &state) == 0);
    CHECK(state.calls == 3);
    pcomm_replay_cache_destroy(cache);
    pcomm_replay_cache_destroy(other);
    return 0;
}

static int test_expiry_and_clock_rollback(void) {
    uint8_t first[PCOMM_REPLAY_TAG_LEN] = {1};
    uint8_t second[PCOMM_REPLAY_TAG_LEN] = {2};
    callback_state_t state = {0};
    pcomm_replay_cache_t *cache = pcomm_replay_cache_create(2, 100);
    CHECK(cache != NULL);
    CHECK(pcomm_replay_apply(cache, first, 1000, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, second, 1050, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, first, 900, persist, &state) == 1);
    CHECK(pcomm_replay_apply(cache, first, 1099, persist, &state) == 1);
    CHECK(pcomm_replay_apply(cache, first, 1100, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, second, 1101, persist, &state) == 1);
    CHECK(pcomm_replay_apply(cache, first, 1199, persist, &state) == 1);
    CHECK(pcomm_replay_apply(cache, first, 1200, persist, &state) == 0);
    CHECK(state.calls == 4);
    pcomm_replay_cache_destroy(cache);
    return 0;
}

static int test_lru_capacity_and_failed_persistence(void) {
    uint8_t first[PCOMM_REPLAY_TAG_LEN] = {1};
    uint8_t second[PCOMM_REPLAY_TAG_LEN] = {2};
    uint8_t third[PCOMM_REPLAY_TAG_LEN] = {3};
    callback_state_t state = {0};
    pcomm_replay_cache_t *cache = pcomm_replay_cache_create(2, 1000);
    CHECK(cache != NULL);
    CHECK(pcomm_replay_apply(cache, first, 0, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, second, 1, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, first, 2, persist, &state) == 1);
    state.fail = 1;
    CHECK(pcomm_replay_apply(cache, third, 3, persist, &state) == -1);
    CHECK(pcomm_replay_apply(cache, second, 4, persist, &state) == 1);
    CHECK(pcomm_replay_apply(cache, first, 5, persist, &state) == 1);
    state.fail = 0;
    CHECK(pcomm_replay_apply(cache, third, 6, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, first, 7, persist, &state) == 1);
    CHECK(pcomm_replay_apply(cache, second, 8, persist, &state) == 0);
    CHECK(state.calls == 5);
    pcomm_replay_cache_destroy(cache);

    cache = pcomm_replay_cache_create(1, 1000);
    CHECK(cache != NULL);
    state.calls = 0;
    state.fail = 1;
    CHECK(pcomm_replay_apply(cache, first, 0, persist, &state) == -1);
    state.fail = 0;
    CHECK(pcomm_replay_apply(cache, first, 1, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, first, 2, persist, &state) == 1);
    CHECK(state.calls == 2);
    pcomm_replay_cache_destroy(cache);
    return 0;
}

static int test_expired_slot_and_time_limit(void) {
    uint8_t first[PCOMM_REPLAY_TAG_LEN] = {1};
    uint8_t second[PCOMM_REPLAY_TAG_LEN] = {2};
    uint8_t third[PCOMM_REPLAY_TAG_LEN] = {3};
    callback_state_t state = {0};
    pcomm_replay_cache_t *cache = pcomm_replay_cache_create(2, 100);
    CHECK(cache != NULL);
    CHECK(pcomm_replay_apply(cache, first, 0, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, second, 50, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, third, 100, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, second, 101, persist, &state) == 1);
    CHECK(state.calls == 3);
    pcomm_replay_cache_destroy(cache);

    cache = pcomm_replay_cache_create(1, 100);
    CHECK(cache != NULL);
    CHECK(pcomm_replay_apply(cache, first, UINT64_MAX - 50, persist, &state) == 0);
    CHECK(pcomm_replay_apply(cache, first, UINT64_MAX, persist, &state) == 1);
    CHECK(pcomm_replay_apply(cache, first, 0, persist, &state) == 1);
    pcomm_replay_cache_destroy(cache);
    return 0;
}

enum { WORKER_COUNT = 16 };

typedef struct {
    pcomm_replay_cache_t *cache;
    uint8_t tag[PCOMM_REPLAY_TAG_LEN];
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int ready;
    int start;
    atomic_int calls;
} concurrent_state_t;

typedef struct {
    concurrent_state_t *state;
    int result;
} worker_arg_t;

static int concurrent_persist(void *arg) {
    concurrent_state_t *state = (concurrent_state_t *)arg;
    atomic_fetch_add_explicit(&state->calls, 1, memory_order_relaxed);
    return 0;
}

static void *receive_worker(void *arg) {
    worker_arg_t *worker = (worker_arg_t *)arg;
    concurrent_state_t *state = worker->state;
    if (pthread_mutex_lock(&state->mutex) != 0) return NULL;
    state->ready++;
    pthread_cond_broadcast(&state->cond);
    while (!state->start) pthread_cond_wait(&state->cond, &state->mutex);
    pthread_mutex_unlock(&state->mutex);
    worker->result = pcomm_replay_apply(state->cache, state->tag, 0,
                                         concurrent_persist, state);
    return NULL;
}

static int test_concurrent_duplicates(void) {
    concurrent_state_t state;
    memset(&state, 0, sizeof(state));
    atomic_init(&state.calls, 0);
    state.cache = pcomm_replay_cache_create(2, 100);
    CHECK(state.cache != NULL);
    CHECK(pthread_mutex_init(&state.mutex, NULL) == 0);
    CHECK(pthread_cond_init(&state.cond, NULL) == 0);
    pthread_t threads[WORKER_COUNT];
    worker_arg_t args[WORKER_COUNT];
    for (int i = 0; i < WORKER_COUNT; i++) {
        args[i].state = &state;
        args[i].result = -1;
        CHECK(pthread_create(&threads[i], NULL, receive_worker, &args[i]) == 0);
    }
    CHECK(pthread_mutex_lock(&state.mutex) == 0);
    while (state.ready < WORKER_COUNT) CHECK(pthread_cond_wait(&state.cond, &state.mutex) == 0);
    state.start = 1;
    CHECK(pthread_cond_broadcast(&state.cond) == 0);
    CHECK(pthread_mutex_unlock(&state.mutex) == 0);

    int accepted = 0, duplicates = 0;
    for (int i = 0; i < WORKER_COUNT; i++) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        accepted += args[i].result == 0;
        duplicates += args[i].result == 1;
    }
    CHECK(accepted == 1 && duplicates == WORKER_COUNT - 1);
    CHECK(atomic_load_explicit(&state.calls, memory_order_relaxed) == 1);
    CHECK(pthread_cond_destroy(&state.cond) == 0);
    CHECK(pthread_mutex_destroy(&state.mutex) == 0);
    pcomm_replay_cache_destroy(state.cache);
    return 0;
}

int main(void) {
    if (test_invalid_arguments_and_clock() != 0 ||
        test_duplicates_and_independent_caches() != 0 ||
        test_expiry_and_clock_rollback() != 0 ||
        test_lru_capacity_and_failed_persistence() != 0 ||
        test_expired_slot_and_time_limit() != 0 ||
        test_concurrent_duplicates() != 0) return 1;
    puts("Replay cache checks passed.");
    return 0;
}
