#ifndef PCOMM_REPLAY_H
#define PCOMM_REPLAY_H

#include <stddef.h>
#include <stdint.h>

#define PCOMM_REPLAY_TAG_LEN 32
#define PCOMM_REPLAY_CACHE_CAPACITY 4096u
#define PCOMM_REPLAY_CACHE_TTL_MS UINT64_C(86400000)

typedef struct pcomm_replay_cache pcomm_replay_cache_t;

pcomm_replay_cache_t *pcomm_replay_cache_create(size_t capacity, uint64_t ttl_ms);

/* Call only after all users of the cache have stopped. */
void pcomm_replay_cache_destroy(pcomm_replay_cache_t *cache);

/*
 * Returns 0 after apply succeeds, 1 for a replay (without calling apply), and
 * -1 on error. Failed callbacks are not remembered. The callback runs under
 * the cache lock: use it for short persistence work, and do not reenter the
 * cache. now_ms must come from a local monotonic clock, not a message timestamp.
 *
 * Entries expire ttl_ms after successful acceptance. Hits refresh LRU order,
 * but do not extend this lifetime. State is bounded and lasts for this process
 * only; an evicted/expired tag or a tag from a previous run can be accepted.
 */
int pcomm_replay_apply(pcomm_replay_cache_t *cache,
                       const uint8_t tag[PCOMM_REPLAY_TAG_LEN], uint64_t now_ms,
                       int (*apply)(void *), void *arg);

int pcomm_replay_now_ms(uint64_t *out);

#endif
