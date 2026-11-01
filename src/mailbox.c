#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include "mailbox.h"
#include "mailbox_limits.h"
#include "pcomm.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <openssl/sha.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

enum { MAILBOX_PUT_HEADER_LEN = 1 + 20 + 32 + 4 };

typedef struct {
    uint64_t updated_ms;
    uint32_t tokens;
} token_bucket_t;

typedef struct {
    uint8_t source_hash[SHA256_DIGEST_LENGTH];
    token_bucket_t bucket;
    int used;
} source_budget_t;

struct pcomm_mailbox_guard {
    pthread_mutex_t mutex;
    source_budget_t *sources;
    size_t capacity;
    token_bucket_t global;
    uint64_t last_now_ms;
};

static void refill(token_bucket_t *bucket, uint64_t now_ms,
                   uint32_t burst, uint64_t interval_ms) {
    uint64_t elapsed = now_ms - bucket->updated_ms;
    uint64_t tokens = elapsed / interval_ms;
    uint32_t room = burst - bucket->tokens;
    if (tokens >= room) {
        bucket->tokens = burst;
        bucket->updated_ms = now_ms;
    } else {
        bucket->tokens += (uint32_t)tokens;
        bucket->updated_ms += tokens * interval_ms;
    }
}

static int source_hash(const char *peer_ip, uint8_t out[SHA256_DIGEST_LENGTH]) {
    size_t length = 0;
    while (length < INET6_ADDRSTRLEN && peer_ip[length] != '\0') length++;
    if (length == 0 || length == INET6_ADDRSTRLEN) return 1;

    uint8_t normalized[1 + 16];
    size_t normalized_len;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    static const uint8_t mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
    if (inet_pton(AF_INET, peer_ip, &ipv4) == 1) {
        normalized[0] = 4;
        memcpy(normalized + 1, &ipv4, 4);
        normalized_len = 5;
    } else if (inet_pton(AF_INET6, peer_ip, &ipv6) == 1) {
        const uint8_t *bytes = (const uint8_t *)&ipv6;
        if (memcmp(bytes, mapped_prefix, sizeof(mapped_prefix)) == 0) {
            normalized[0] = 4;
            memcpy(normalized + 1, bytes + 12, 4);
            normalized_len = 5;
        } else {
            normalized[0] = 6;
            memcpy(normalized + 1, bytes, 16);
            normalized_len = sizeof(normalized);
        }
    } else {
        return 1;
    }
    return SHA256(normalized, normalized_len, out) ? 0 : -1;
}

pcomm_mailbox_guard_t *pcomm_mailbox_guard_create(size_t source_capacity) {
    if (source_capacity == 0 || source_capacity > SIZE_MAX / sizeof(source_budget_t)) return NULL;
    pcomm_mailbox_guard_t *guard = (pcomm_mailbox_guard_t *)calloc(1, sizeof(*guard));
    if (!guard) return NULL;
    guard->sources = (source_budget_t *)calloc(source_capacity, sizeof(*guard->sources));
    if (!guard->sources) {
        free(guard);
        return NULL;
    }
    if (pthread_mutex_init(&guard->mutex, NULL) != 0) {
        free(guard->sources);
        free(guard);
        return NULL;
    }
    guard->capacity = source_capacity;
    guard->global.tokens = PCOMM_MAILBOX_GLOBAL_BURST;
    return guard;
}

void pcomm_mailbox_guard_destroy(pcomm_mailbox_guard_t *guard) {
    if (!guard) return;
    pthread_mutex_destroy(&guard->mutex);
    free(guard->sources);
    free(guard);
}

static int admit(pcomm_mailbox_guard_t *guard,
                  const uint8_t hash[SHA256_DIGEST_LENGTH], uint64_t now_ms) {
    if (pthread_mutex_lock(&guard->mutex) != 0) return -1;
    if (now_ms < guard->last_now_ms) now_ms = guard->last_now_ms;
    guard->last_now_ms = now_ms;
    refill(&guard->global, now_ms, PCOMM_MAILBOX_GLOBAL_BURST,
           PCOMM_MAILBOX_GLOBAL_INTERVAL_MS);
    if (guard->global.tokens == 0) {
        return pthread_mutex_unlock(&guard->mutex) == 0 ? 1 : -1;
    }

    size_t matching = SIZE_MAX, available = SIZE_MAX;
    for (size_t i = 0; i < guard->capacity; i++) {
        source_budget_t *source = &guard->sources[i];
        if (source->used) {
            refill(&source->bucket, now_ms, PCOMM_MAILBOX_IP_BURST,
                   PCOMM_MAILBOX_IP_INTERVAL_MS);
            /* Fully restored budgets can be recreated without granting credit. */
            if (source->bucket.tokens == PCOMM_MAILBOX_IP_BURST) {
                memset(source, 0, sizeof(*source));
            } else if (memcmp(source->source_hash, hash, SHA256_DIGEST_LENGTH) == 0) {
                matching = i;
            }
        }
        if (!source->used && available == SIZE_MAX) available = i;
    }

    int result = 1;
    if (guard->global.tokens > 0 &&
        ((matching != SIZE_MAX && guard->sources[matching].bucket.tokens > 0) ||
         (matching == SIZE_MAX && available != SIZE_MAX))) {
        if (matching == SIZE_MAX) {
            matching = available;
            source_budget_t *source = &guard->sources[matching];
            memcpy(source->source_hash, hash, SHA256_DIGEST_LENGTH);
            source->bucket.updated_ms = now_ms;
            source->bucket.tokens = PCOMM_MAILBOX_IP_BURST;
            source->used = 1;
        }
        guard->sources[matching].bucket.tokens--;
        guard->global.tokens--;
        result = 0;
    }
    if (pthread_mutex_unlock(&guard->mutex) != 0) return -1;
    return result;
}

int pcomm_mailbox_deposit(pcomm_mailbox_guard_t *guard, pcomm_db_t *db,
                          const char *peer_ip, const uint8_t *payload,
                          uint32_t payload_len, uint64_t now_ms,
                          int64_t received_unix, uint8_t infohash_out[20]) {
    if (!guard || !db || !db->db || !peer_ip || !infohash_out) return -1;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    int rc = source_hash(peer_ip, hash);
    if (rc != 0) return rc;
    rc = admit(guard, hash, now_ms);
    if (rc != 0) return rc;

    if (!payload || payload_len < MAILBOX_PUT_HEADER_LEN ||
        payload[0] != (uint8_t)PCOMM_CTRL_MB_PUT) return 1;
    uint32_t blob_len = ((uint32_t)payload[53] << 24) |
        ((uint32_t)payload[54] << 16) | ((uint32_t)payload[55] << 8) | payload[56];
    if (blob_len == 0 || blob_len > PCOMM_MAILBOX_MAX_BLOB_LEN ||
        blob_len != payload_len - MAILBOX_PUT_HEADER_LEN) return 1;

    rc = pcomm_db_mailbox_put(db, payload + 21, payload + MAILBOX_PUT_HEADER_LEN,
                              blob_len, received_unix);
    if (rc != 0) return rc > 0 ? 1 : -1;
    memcpy(infohash_out, payload + 1, 20);
    return 0;
}
