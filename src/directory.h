#ifndef PCOMM_DIRECTORY_H
#define PCOMM_DIRECTORY_H

#include "pcomm.h"

int pcomm_directory_request(const uint8_t infohash[20], const uint8_t dkey[32],
                              const uint8_t nonce[32], uint8_t **out, uint32_t *out_len);
int pcomm_directory_parse_request(const uint8_t *payload, uint32_t length,
                                    uint8_t infohash[20], uint8_t dkey[32], uint8_t nonce[32]);
int pcomm_directory_response(const pcomm_identity_t *provider, const uint8_t nonce[32],
                               const uint8_t dkey[32], const uint8_t *blob, uint32_t blob_len,
                               uint8_t **out, uint32_t *out_len);
int pcomm_directory_parse_response(const uint8_t *payload, uint32_t length,
                                     const uint8_t expected_provider[32], const uint8_t nonce[32],
                                     const uint8_t dkey[32], uint8_t **blob, uint32_t *blob_len);

#endif
