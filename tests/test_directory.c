#include "directory.h"
#include "descriptor.h"
#include "sign.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; goto done; \
    } \
} while (0)

typedef struct {
    pcomm_identity_t provider, other;
    uint8_t infohash[20], key[32], nonce[32], body[PCOMM_DESCRIPTOR_MAX_BLOB+1];
} fixture_t;

static int make_identity(pcomm_identity_t *identity) {
    memset(identity, 0, sizeof(*identity));
    if (RAND_bytes(identity->privkey, 32) != 1) return -1;
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, identity->privkey, 32);
    size_t length = 32;
    int rc = key && EVP_PKEY_get_raw_public_key(key, identity->pubkey, &length) == 1 && length == 32 ? 0 : -1;
    EVP_PKEY_free(key);
    return rc;
}

static int fixture_open(fixture_t *fixture) {
    memset(fixture, 0, sizeof(*fixture));
    for (unsigned i = 0; i < sizeof(fixture->infohash); i++) fixture->infohash[i] = (uint8_t)i;
    for (unsigned i = 0; i < sizeof(fixture->key); i++) {
        fixture->key[i] = (uint8_t)(0x40+i); fixture->nonce[i] = (uint8_t)(0x80+i);
    }
    for (size_t i = 0; i < sizeof(fixture->body); i++) fixture->body[i] = (uint8_t)i;
    return make_identity(&fixture->provider) || make_identity(&fixture->other) ? -1 : 0;
}

static int rejects(const fixture_t *fixture, const uint8_t *packet, uint32_t length) {
    uint8_t *blob = (uint8_t *)(uintptr_t)1;
    uint32_t blob_len = 99;
    int rc = pcomm_directory_parse_response(packet, length, fixture->provider.pubkey,
        fixture->nonce, fixture->key, &blob, &blob_len);
    if (rc == 0) free(blob);
    return rc == -1 && !blob && blob_len == 0;
}

static int resign(const fixture_t *fixture, uint8_t *packet, uint32_t length) {
    return length < 64 ? -1 : pcomm_sign(fixture->provider.privkey, packet, length-64, packet+length-64);
}

static int test_request_golden_and_framing(void) {
    fixture_t fixture;
    uint8_t *request = NULL, infohash[20], key[32], nonce[32], expected[90] = {0};
    uint32_t length = 0;
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    expected[0] = 5;
    memcpy(expected+1, "PDQ2", 4);
    for (size_t i = 0; i < 20; i++) expected[5+i] = (uint8_t)i;
    for (size_t i = 0; i < 32; i++) {
        expected[25+i] = (uint8_t)(0x40+i); expected[57+i] = (uint8_t)(0x80+i);
    }
    CHECK(pcomm_directory_request(fixture.infohash, fixture.key, fixture.nonce, &request, &length) == 0);
    CHECK(length == 89 && memcmp(request, expected, 89) == 0);
    CHECK(pcomm_directory_parse_request(expected, 89, infohash, key, nonce) == 0);
    CHECK(memcmp(infohash, fixture.infohash, 20) == 0 && memcmp(key, fixture.key, 32) == 0 &&
        memcmp(nonce, fixture.nonce, 32) == 0);
    for (uint32_t i = 0; i < 89; i++) CHECK(pcomm_directory_parse_request(expected, i, infohash, key, nonce) == -1);
    CHECK(pcomm_directory_parse_request(expected, 90, infohash, key, nonce) == -1);
    expected[0] = 6;
    CHECK(pcomm_directory_parse_request(expected, 89, infohash, key, nonce) == -1);
    expected[0] = 5; expected[4] = '1';
    CHECK(pcomm_directory_parse_request(expected, 89, infohash, key, nonce) == -1);
    CHECK(pcomm_directory_parse_request(NULL, 89, infohash, key, nonce) == -1);
done:
    free(request); OPENSSL_cleanse(&fixture, sizeof(fixture));
    return ok;
}

static int test_response_golden_and_independent_fixture(void) {
    fixture_t fixture;
    uint8_t *packet = NULL, *blob = NULL;
    uint8_t expected[106+PCOMM_DESCRIPTOR_MAX_BLOB+64] = {0};
    uint32_t length = 0, blob_len = 0;
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    expected[0] = 6; memcpy(expected+1, "PDR2", 4); expected[5] = 1;
    memcpy(expected+6, fixture.provider.pubkey, 32); memcpy(expected+38, fixture.nonce, 32);
    memcpy(expected+70, fixture.key, 32); expected[104] = 2;
    memcpy(expected+106, fixture.body, PCOMM_DESCRIPTOR_MAX_BLOB);
    CHECK(pcomm_sign(fixture.provider.privkey, expected, sizeof(expected)-64, expected+sizeof(expected)-64) == 0);
    CHECK(pcomm_directory_parse_response(expected, sizeof(expected), fixture.provider.pubkey,
        fixture.nonce, fixture.key, &blob, &blob_len) == 0);
    CHECK(blob_len == PCOMM_DESCRIPTOR_MAX_BLOB && memcmp(blob, fixture.body, blob_len) == 0);
    blob[0] ^= 1;
    CHECK(expected[106] == fixture.body[0]);
    free(blob); blob = NULL;
    CHECK(pcomm_directory_response(&fixture.provider, fixture.nonce, fixture.key,
        fixture.body, PCOMM_DESCRIPTOR_MAX_BLOB, &packet, &length) == 0);
    CHECK(length == sizeof(expected) && memcmp(packet, expected, sizeof(expected)-64) == 0);
    CHECK(pcomm_verify(fixture.provider.pubkey, packet, length-64, packet+length-64) == 0);
    CHECK(pcomm_directory_parse_response(packet, length, fixture.provider.pubkey,
        fixture.nonce, fixture.key, &blob, &blob_len) == 0);
    CHECK(blob_len == PCOMM_DESCRIPTOR_MAX_BLOB && memcmp(blob, fixture.body, blob_len) == 0);
done:
    free(packet); free(blob); OPENSSL_cleanse(&fixture, sizeof(fixture));
    return ok;
}

static int test_response_binding_and_tampering(void) {
    fixture_t fixture;
    uint8_t *packet = NULL, *blob = NULL, *forged = NULL;
    uint8_t altered[106+PCOMM_DESCRIPTOR_MAX_BLOB+65], changed_nonce[32], changed_key[32];
    uint32_t length = 0, blob_len = 0, forged_len = 0;
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    CHECK(pcomm_directory_response(&fixture.provider, fixture.nonce, fixture.key, fixture.body,
        PCOMM_DESCRIPTOR_MAX_BLOB, &packet, &length) == 0);
    memcpy(changed_nonce, fixture.nonce, 32); changed_nonce[0] ^= 1;
    memcpy(changed_key, fixture.key, 32); changed_key[31] ^= 1;
    CHECK(pcomm_directory_parse_response(packet, length, fixture.other.pubkey,
        fixture.nonce, fixture.key, &blob, &blob_len) == -1 && !blob && !blob_len);
    CHECK(pcomm_directory_parse_response(packet, length, fixture.provider.pubkey,
        changed_nonce, fixture.key, &blob, &blob_len) == -1 && !blob && !blob_len);
    CHECK(pcomm_directory_parse_response(packet, length, fixture.provider.pubkey,
        fixture.nonce, changed_key, &blob, &blob_len) == -1 && !blob && !blob_len);
    CHECK(pcomm_directory_response(&fixture.other, fixture.nonce, fixture.key, fixture.body,
        17, &forged, &forged_len) == 0);
    CHECK(rejects(&fixture, forged, forged_len));
    memcpy(forged+6, fixture.provider.pubkey, 32);
    CHECK(rejects(&fixture, forged, forged_len));
    for (uint32_t i = 0; i < length; i++) {
        memcpy(altered, packet, length); altered[i] ^= 1;
        CHECK(rejects(&fixture, altered, length));
    }
    for (uint32_t i = 0; i < length; i++) CHECK(rejects(&fixture, packet, i));
    memcpy(altered, packet, length); altered[length] = 0;
    CHECK(rejects(&fixture, altered, length+1));
    memset(altered, 0, 170); altered[0] = PCOMM_CTRL_DESC_RESP; altered[1] = 1;
    CHECK(rejects(&fixture, altered, 170));
    CHECK(rejects(&fixture, NULL, length));
done:
    free(packet); free(blob); free(forged); OPENSSL_cleanse(&fixture, sizeof(fixture));
    return ok;
}

static int test_authenticated_notfound_and_status(void) {
    fixture_t fixture;
    uint8_t *packet = NULL, *found = NULL, *blob = NULL, malformed[171];
    uint32_t length = 0, found_len = 0, blob_len = 0;
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    CHECK(pcomm_directory_response(&fixture.provider, fixture.nonce, fixture.key, NULL, 0, &packet, &length) == 0);
    CHECK(length == 170 && packet[5] == 0);
    CHECK(pcomm_directory_parse_response(packet, length, fixture.provider.pubkey,
        fixture.nonce, fixture.key, &blob, &blob_len) == 1 && !blob && !blob_len);
    CHECK(pcomm_verify(fixture.provider.pubkey, packet, length-64, packet+length-64) == 0);
    memcpy(malformed, packet, length); malformed[5] = 1;
    CHECK(resign(&fixture, malformed, length) == 0 && rejects(&fixture, malformed, length));
    memcpy(malformed, packet, length); malformed[5] = 2;
    CHECK(resign(&fixture, malformed, length) == 0 && rejects(&fixture, malformed, length));
    CHECK(pcomm_directory_response(&fixture.provider, fixture.nonce, fixture.key, fixture.body, 1, &found, &found_len) == 0);
    CHECK(found_len == sizeof(malformed));
    memcpy(malformed, found, found_len); malformed[5] = 0;
    CHECK(resign(&fixture, malformed, found_len) == 0 && rejects(&fixture, malformed, found_len));
    memcpy(malformed, found, found_len); malformed[102] = 0xff;
    CHECK(resign(&fixture, malformed, found_len) == 0 && rejects(&fixture, malformed, found_len));
    packet[169] ^= 1;
    CHECK(rejects(&fixture, packet, length));
done:
    free(packet); free(found); free(blob); OPENSSL_cleanse(&fixture, sizeof(fixture));
    return ok;
}

static int test_input_admission_and_key_consistency(void) {
    fixture_t fixture;
    uint8_t *packet = NULL, infohash[20], key[32], nonce[32];
    uint32_t length = 0;
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    CHECK(pcomm_directory_request(NULL, fixture.key, fixture.nonce, &packet, &length) == -1 && !packet && !length);
    CHECK(pcomm_directory_request(fixture.infohash, NULL, fixture.nonce, &packet, &length) == -1);
    CHECK(pcomm_directory_request(fixture.infohash, fixture.key, NULL, &packet, &length) == -1);
    CHECK(pcomm_directory_request(fixture.infohash, fixture.key, fixture.nonce, NULL, &length) == -1);
    CHECK(pcomm_directory_response(&fixture.provider, fixture.nonce, fixture.key, fixture.body,
        PCOMM_DESCRIPTOR_MAX_BLOB+1, &packet, &length) == -1 && !packet && !length);
    CHECK(pcomm_directory_response(&fixture.provider, fixture.nonce, fixture.key, NULL, 1, &packet, &length) == -1);
    CHECK(pcomm_directory_response(NULL, fixture.nonce, fixture.key, NULL, 0, &packet, &length) == -1);
    CHECK(pcomm_directory_response(&fixture.provider, fixture.nonce, fixture.key, NULL, 0, NULL, &length) == -1);
    CHECK(pcomm_directory_parse_request(NULL, 89, infohash, key, nonce) == -1);
    memcpy(fixture.provider.pubkey, fixture.other.pubkey, 32);
    CHECK(pcomm_directory_response(&fixture.provider, fixture.nonce, fixture.key, fixture.body, 1,
        &packet, &length) == -1 && !packet && !length);
done:
    free(packet); OPENSSL_cleanse(&fixture, sizeof(fixture));
    return ok;
}

int main(void) {
    const struct { const char *name; int (*run)(void); } tests[] = {
        {"request golden wire and exact framing", test_request_golden_and_framing},
        {"response golden header and independent signed fixture", test_response_golden_and_independent_fixture},
        {"provider/request binding, tampering, and unsigned rejection", test_response_binding_and_tampering},
        {"authenticated notfound and malformed status", test_authenticated_notfound_and_status},
        {"input admission and provider key consistency", test_input_admission_and_key_consistency}
    };
    unsigned failed = 0;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        int ok = tests[i].run();
        printf("%s: %s\n", ok ? "PASS" : "FAIL", tests[i].name);
        if (!ok) failed++;
    }
    return failed ? 1 : 0;
}
