#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include "replay.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

typedef struct {
    uint8_t tag[PCOMM_REPLAY_TAG_LEN];
    uint64_t accepted_ms;
    size_t prev;
    size_t next;
    int used;
} replay_entry_t;

struct pcomm_replay_cache {
    pthread_mutex_t mutex;
    replay_entry_t *entries;
    size_t capacity;
    size_t oldest;
    size_t newest;
    uint64_t ttl_ms;
    uint64_t last_now_ms;
};

static void unlink_entry(pcomm_replay_cache_t *cache, size_t index) {
    replay_entry_t *entry = &cache->entries[index];
    if (entry->prev == SIZE_MAX) cache->oldest = entry->next;
    else cache->entries[entry->prev].next = entry->next;
    if (entry->next == SIZE_MAX) cache->newest = entry->prev;
    else cache->entries[entry->next].prev = entry->prev;
}

static void append_newest(pcomm_replay_cache_t *cache, size_t index) {
    replay_entry_t *entry = &cache->entries[index];
    entry->prev = cache->newest;
    entry->next = SIZE_MAX;
    if (cache->newest == SIZE_MAX) cache->oldest = index;
    else cache->entries[cache->newest].next = index;
    cache->newest = index;
}

pcomm_replay_cache_t *pcomm_replay_cache_create(size_t capacity, uint64_t ttl_ms) {
    if (capacity == 0 || ttl_ms == 0 || capacity > SIZE_MAX / sizeof(replay_entry_t)) return NULL;

    pcomm_replay_cache_t *cache = (pcomm_replay_cache_t *)calloc(1, sizeof(*cache));
    if (!cache) return NULL;
    cache->entries = (replay_entry_t *)calloc(capacity, sizeof(*cache->entries));
    if (!cache->entries) {
        free(cache);
        return NULL;
    }
    if (pthread_mutex_init(&cache->mutex, NULL) != 0) {
        free(cache->entries);
        free(cache);
        return NULL;
    }
    cache->capacity = capacity;
    cache->ttl_ms = ttl_ms;
    cache->oldest = SIZE_MAX;
    cache->newest = SIZE_MAX;
    return cache;
}

void pcomm_replay_cache_destroy(pcomm_replay_cache_t *cache) {
    if (!cache) return;
    pthread_mutex_destroy(&cache->mutex);
    free(cache->entries);
    free(cache);
}

int pcomm_replay_apply(pcomm_replay_cache_t *cache,
                       const uint8_t tag[PCOMM_REPLAY_TAG_LEN], uint64_t now_ms,
                       int (*apply)(void *), void *arg) {
    if (!cache || !tag || !apply) return -1;
    if (pthread_mutex_lock(&cache->mutex) != 0) return -1;

    /* A caller may have sampled the clock before another worker acquired us. */
    if (now_ms < cache->last_now_ms) now_ms = cache->last_now_ms;
    cache->last_now_ms = now_ms;

    size_t available = SIZE_MAX;
    for (size_t i = 0; i < cache->capacity; i++) {
        replay_entry_t *entry = &cache->entries[i];
        if (entry->used && now_ms - entry->accepted_ms >= cache->ttl_ms) {
            unlink_entry(cache, i);
            memset(entry, 0, sizeof(*entry));
        }
        if (!entry->used) {
            if (available == SIZE_MAX) available = i;
            continue;
        }
        if (memcmp(entry->tag, tag, PCOMM_REPLAY_TAG_LEN) == 0) {
            unlink_entry(cache, i);
            append_newest(cache, i);
            return pthread_mutex_unlock(&cache->mutex) == 0 ? 1 : -1;
        }
    }

    int result = -1;
    if (apply(arg) == 0) {
        if (available == SIZE_MAX) available = cache->oldest;
        replay_entry_t *entry = &cache->entries[available];
        if (entry->used) unlink_entry(cache, available);
        memcpy(entry->tag, tag, PCOMM_REPLAY_TAG_LEN);
        entry->accepted_ms = now_ms;
        entry->used = 1;
        append_newest(cache, available);
        result = 0;
    }
    if (pthread_mutex_unlock(&cache->mutex) != 0) return -1;
    return result;
}

int pcomm_replay_now_ms(uint64_t *out) {
    if (!out) return -1;
#ifdef _WIN32
    *out = (uint64_t)GetTickCount64();
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) return -1;
    uint64_t fraction_ms = (uint64_t)now.tv_nsec / UINT64_C(1000000);
    uint64_t seconds = (uint64_t)now.tv_sec;
    if (seconds > (UINT64_MAX - fraction_ms) / UINT64_C(1000)) return -1;
    *out = seconds * UINT64_C(1000) + fraction_ms;
#endif
    return 0;
}
