#ifndef PCOMM_REPLAY_H
#define PCOMM_REPLAY_H

#include <stddef.h>
#include <stdint.h>

#define PCOMM_REPLAY_TAG_LEN 32
#define PCOMM_REPLAY_CACHE_CAPACITY 4096u
#define PCOMM_REPLAY_CACHE_TTL_MS UINT64_C(86400000)

typedef struct pcomm_replay_cache pcomm_replay_cache_t;

pcomm_replay_cache_t *pcomm_replay_cache_create(size_t capacity, uint64_t ttl_ms);

void pcomm_replay_cache_destroy(pcomm_replay_cache_t *cache);

int pcomm_replay_apply(pcomm_replay_cache_t *cache,
                       const uint8_t tag[PCOMM_REPLAY_TAG_LEN], uint64_t now_ms,
                       int (*apply)(void *), void *arg);

int pcomm_replay_now_ms(uint64_t *out);

#endif
