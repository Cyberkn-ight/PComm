#ifndef PCOMM_DESCRIPTOR_H
#define PCOMM_DESCRIPTOR_H

#include "pcomm.h"

#define PCOMM_DESCRIPTOR_MAX_BLOB 512u
#define PCOMM_DESCRIPTOR_MAX_SOURCES 16u
#define PCOMM_DESCRIPTOR_MAX_CANDIDATES 8u
#define PCOMM_DESCRIPTOR_MAX_TTL 43200u
#define PCOMM_DESCRIPTOR_EPOCH_SECONDS 21600u

typedef struct {
    uint8_t owner[32];
    uint32_t epoch;
    uint32_t issued;
    uint32_t expires;
    pcomm_peer_t intros[3];
    size_t intro_count;
    uint8_t digest[32];
} pcomm_descriptor_t;

typedef struct {
    pcomm_descriptor_t candidates[PCOMM_DESCRIPTOR_MAX_CANDIDATES];
    unsigned votes[PCOMM_DESCRIPTOR_MAX_CANDIDATES];
    size_t candidate_count;
    struct {
        uint8_t address[16];
        uint8_t provider[32];
        int family;
        int candidate;
    } sources[PCOMM_DESCRIPTOR_MAX_SOURCES];
    size_t source_count;
} pcomm_descriptor_quorum_t;

int pcomm_descriptor_build(const pcomm_identity_t *owner, uint32_t epoch,
                            uint32_t issued, uint32_t expires,
                            const pcomm_peer_t *intros, size_t intro_count,
                            uint8_t **out, uint32_t *out_len);
int pcomm_descriptor_parse(const uint8_t *blob, uint32_t blob_len,
                            const char *expected_owner, uint32_t expected_epoch,
                            uint32_t now, pcomm_descriptor_t *out);
int pcomm_descriptor_vote(pcomm_descriptor_quorum_t *quorum, const char *source_ip,
                           const uint8_t provider[32],
                           const pcomm_descriptor_t *descriptor);
int pcomm_descriptor_consensus(const pcomm_descriptor_quorum_t *quorum,
                                pcomm_descriptor_t *out);
int pcomm_descriptor_keys(const uint8_t owner[32], uint32_t epoch,
                           uint8_t dkey[32], uint8_t infohash[20]);

#endif
