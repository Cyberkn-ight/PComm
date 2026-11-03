#include "directory.h"
#include "descriptor.h"
#include "sign.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

enum { REQUEST_LENGTH = 89, RESPONSE_HEADER = 106, SIGNATURE_LENGTH = 64 };

static void put32(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)(value >> 24); bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8); bytes[3] = (uint8_t)value;
}

static uint32_t get32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 |
        (uint32_t)bytes[2] << 8 | bytes[3];
}

int pcomm_directory_request(const uint8_t infohash[20], const uint8_t dkey[32],
                              const uint8_t nonce[32], uint8_t **out, uint32_t *out_len) {
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!infohash || !dkey || !nonce || !out || !out_len) return -1;
    uint8_t *packet = malloc(REQUEST_LENGTH);
    if (!packet) return -1;
    packet[0] = PCOMM_CTRL_DESC_GET;
    memcpy(packet+1, "PDQ2", 4);
    memcpy(packet+5, infohash, 20);
    memcpy(packet+25, dkey, 32);
    memcpy(packet+57, nonce, 32);
    *out = packet; *out_len = REQUEST_LENGTH;
    return 0;
}

int pcomm_directory_parse_request(const uint8_t *payload, uint32_t length,
                                    uint8_t infohash[20], uint8_t dkey[32], uint8_t nonce[32]) {
    if (!payload || !infohash || !dkey || !nonce || length != REQUEST_LENGTH ||
        payload[0] != PCOMM_CTRL_DESC_GET || memcmp(payload+1, "PDQ2", 4)) return -1;
    memcpy(infohash, payload+5, 20);
    memcpy(dkey, payload+25, 32);
    memcpy(nonce, payload+57, 32);
    return 0;
}

int pcomm_directory_response(const pcomm_identity_t *provider, const uint8_t nonce[32],
                               const uint8_t dkey[32], const uint8_t *blob, uint32_t blob_len,
                               uint8_t **out, uint32_t *out_len) {
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!provider || !nonce || !dkey || !out || !out_len || (!blob && blob_len) ||
        blob_len > PCOMM_DESCRIPTOR_MAX_BLOB) return -1;
    uint32_t length = RESPONSE_HEADER + blob_len + SIGNATURE_LENGTH;
    uint8_t *packet = malloc(length);
    if (!packet) return -1;
    packet[0] = PCOMM_CTRL_DESC_RESP;
    memcpy(packet+1, "PDR2", 4);
    packet[5] = blob_len ? 1 : 0;
    memcpy(packet+6, provider->pubkey, 32);
    memcpy(packet+38, nonce, 32);
    memcpy(packet+70, dkey, 32);
    put32(packet+102, blob_len);
    if (blob_len) memcpy(packet+RESPONSE_HEADER, blob, blob_len);
    if (pcomm_sign(provider->privkey, packet, length-SIGNATURE_LENGTH, packet+length-SIGNATURE_LENGTH) ||
        pcomm_verify(provider->pubkey, packet, length-SIGNATURE_LENGTH, packet+length-SIGNATURE_LENGTH)) {
        free(packet);
        return -1;
    }
    *out = packet; *out_len = length;
    return 0;
}

int pcomm_directory_parse_response(const uint8_t *payload, uint32_t length,
                                     const uint8_t expected_provider[32], const uint8_t nonce[32],
                                     const uint8_t dkey[32], uint8_t **blob, uint32_t *blob_len) {
    if (blob) *blob = NULL;
    if (blob_len) *blob_len = 0;
    if (!payload || !expected_provider || !nonce || !dkey || !blob || !blob_len ||
        length < RESPONSE_HEADER+SIGNATURE_LENGTH ||
        length > RESPONSE_HEADER+PCOMM_DESCRIPTOR_MAX_BLOB+SIGNATURE_LENGTH ||
        payload[0] != PCOMM_CTRL_DESC_RESP || memcmp(payload+1, "PDR2", 4) ||
        CRYPTO_memcmp(payload+6, expected_provider, 32) ||
        CRYPTO_memcmp(payload+38, nonce, 32) || CRYPTO_memcmp(payload+70, dkey, 32)) return -1;
    uint32_t found_length = get32(payload+102);
    if (found_length > PCOMM_DESCRIPTOR_MAX_BLOB || payload[5] > 1 ||
        (payload[5] == 0) != (found_length == 0) ||
        length != RESPONSE_HEADER+found_length+SIGNATURE_LENGTH ||
        pcomm_verify(expected_provider, payload, length-SIGNATURE_LENGTH, payload+length-SIGNATURE_LENGTH)) return -1;
    if (!found_length) return 1;
    uint8_t *copy = malloc(found_length);
    if (!copy) return -1;
    memcpy(copy, payload+RESPONSE_HEADER, found_length);
    *blob = copy; *blob_len = found_length;
    return 0;
}
