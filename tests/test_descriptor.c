#include "descriptor.h"
#include "identity.h"
#include "sign.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; goto done; \
    } \
} while (0)

#define TEST_NOW (PCOMM_DESCRIPTOR_EPOCH_SECONDS * 80000u + 1000u)
#define TEST_EPOCH (TEST_NOW / PCOMM_DESCRIPTOR_EPOCH_SECONDS)

typedef struct {
    pcomm_identity_t owner;
    pcomm_identity_t other;
    pcomm_peer_t intros[3];
    uint8_t *blob;
    uint32_t length;
    pcomm_descriptor_t descriptor;
} fixture_t;

static void put_u32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static int identity(pcomm_identity_t *out, unsigned seed) {
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < sizeof(out->privkey); ++i) out->privkey[i] = (uint8_t)(seed + 7u*i);
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, out->privkey, 32);
    size_t length = 32;
    int rc = key && EVP_PKEY_get_raw_public_key(key, out->pubkey, &length) == 1 && length == 32 &&
        pcomm_user_id_from_pubkey(out->pubkey, out->user_id) == 0 ? 0 : -1;
    EVP_PKEY_free(key);
    return rc;
}

static void fixture_close(fixture_t *fixture) {
    free(fixture->blob);
    OPENSSL_cleanse(fixture, sizeof(*fixture));
}

static int fixture_open(fixture_t *fixture) {
    memset(fixture, 0, sizeof(*fixture));
    if (identity(&fixture->owner, 1) || identity(&fixture->other, 51)) return -1;
    for (size_t i = 0; i < 3; ++i) {
        pcomm_identity_t intro;
        if (identity(&intro, 101u + (unsigned)i*10u)) return -1;
        memcpy(fixture->intros[i].pubkey, intro.pubkey, 32);
        memcpy(fixture->intros[i].user_id, intro.user_id, sizeof(intro.user_id));
        snprintf(fixture->intros[i].host, sizeof(fixture->intros[i].host), "198.51.100.%zu", 10 + i);
        fixture->intros[i].port = (uint16_t)(9001 + i);
        OPENSSL_cleanse(&intro, sizeof(intro));
    }
    return pcomm_descriptor_build(&fixture->owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
               fixture->intros, 3, &fixture->blob, &fixture->length) == 0 &&
        pcomm_descriptor_parse(fixture->blob, fixture->length, fixture->owner.user_id, TEST_EPOCH,
            TEST_NOW, &fixture->descriptor) == 0 ? 0 : -1;
}

static int resign(const fixture_t *fixture, uint8_t *blob, uint32_t length) {
    return length >= 64 ? pcomm_sign(fixture->owner.privkey, blob, length - 64, blob + length - 64) : -1;
}

static int parse_rejected(const fixture_t *fixture, const uint8_t *blob, uint32_t length) {
    pcomm_descriptor_t descriptor;
    return pcomm_descriptor_parse(blob, length, fixture->owner.user_id, TEST_EPOCH,
        TEST_NOW, &descriptor) != 0;
}

static int variant(const fixture_t *fixture, unsigned serial, pcomm_descriptor_t *out) {
    pcomm_peer_t intros[3];
    memcpy(intros, fixture->intros, sizeof(intros));
    intros[0].port = (uint16_t)(9100 + serial);
    uint8_t *blob = NULL;
    uint32_t length = 0;
    int rc = pcomm_descriptor_build(&fixture->owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        intros, 3, &blob, &length);
    if (!rc) rc = pcomm_descriptor_parse(blob, length, fixture->owner.user_id,
        TEST_EPOCH, TEST_NOW, out);
    free(blob);
    return rc;
}

static int vote(pcomm_descriptor_quorum_t *quorum, const char *source, unsigned provider,
                    const pcomm_descriptor_t *descriptor) {
    uint8_t public_key[32] = {0x42};
    put_u32(public_key + 1, provider + 1);
    return pcomm_descriptor_vote(quorum, source, public_key, descriptor);
}

static int test_roundtrip(void) {
    fixture_t fixture;
    uint8_t *second = NULL;
    uint32_t second_length = 0;
    pcomm_descriptor_t parsed;
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    CHECK(fixture.length <= PCOMM_DESCRIPTOR_MAX_BLOB && fixture.length > 64);
    CHECK(memcmp(fixture.blob, "PCD2", 4) == 0);
    CHECK(memcmp(fixture.descriptor.owner, fixture.owner.pubkey, 32) == 0);
    CHECK(fixture.descriptor.epoch == TEST_EPOCH);
    CHECK(fixture.descriptor.issued == TEST_NOW && fixture.descriptor.expires == TEST_NOW + 3600);
    CHECK(fixture.descriptor.intro_count == 3);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(memcmp(fixture.descriptor.intros[i].pubkey, fixture.intros[i].pubkey, 32) == 0);
        CHECK(strcmp(fixture.descriptor.intros[i].user_id, fixture.intros[i].user_id) == 0);
        CHECK(strcmp(fixture.descriptor.intros[i].host, fixture.intros[i].host) == 0);
        CHECK(fixture.descriptor.intros[i].port == fixture.intros[i].port);
    }
    CHECK(pcomm_descriptor_parse(fixture.blob, fixture.length, NULL, UINT32_MAX, TEST_NOW, &parsed) == 0);
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        fixture.intros, 3, &second, &second_length) == 0);
    CHECK(second_length == fixture.length);
    CHECK(pcomm_descriptor_parse(second, second_length, fixture.owner.user_id, TEST_EPOCH, TEST_NOW, &parsed) == 0);
    CHECK(memcmp(parsed.digest, fixture.descriptor.digest, 32) == 0);
    free(second); second = NULL;
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        fixture.intros, 1, &second, &second_length) == 0);
    CHECK(pcomm_descriptor_parse(second, second_length, fixture.owner.user_id, TEST_EPOCH, TEST_NOW, &parsed) == 0);
    CHECK(parsed.intro_count == 1);
done:
    free(second);
    fixture_close(&fixture);
    return ok;
}

static int test_authentication_and_framing(void) {
    fixture_t fixture;
    pcomm_descriptor_t parsed;
    uint8_t changed[PCOMM_DESCRIPTOR_MAX_BLOB + 1];
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    CHECK(fixture.length > 64 && fixture.length <= PCOMM_DESCRIPTOR_MAX_BLOB);
    CHECK(pcomm_descriptor_parse(fixture.blob, fixture.length, fixture.other.user_id,
        TEST_EPOCH, TEST_NOW, &parsed) != 0);
    CHECK(pcomm_descriptor_parse(fixture.blob, fixture.length, "invalid-owner",
        TEST_EPOCH, TEST_NOW, &parsed) != 0);
    CHECK(pcomm_descriptor_parse(fixture.blob, fixture.length, fixture.owner.user_id,
        TEST_EPOCH + 1, TEST_NOW, &parsed) != 0);
    for (uint32_t i = 0; i < fixture.length; ++i) {
        memcpy(changed, fixture.blob, fixture.length);
        changed[i] ^= 1;
        CHECK(parse_rejected(&fixture, changed, fixture.length));
    }
    for (uint32_t length = 0; length < fixture.length; ++length)
        CHECK(parse_rejected(&fixture, fixture.blob, length));
    size_t body_length = fixture.length;
    CHECK(body_length > 64 && body_length <= PCOMM_DESCRIPTOR_MAX_BLOB);
    body_length -= 64;
    memcpy(changed, fixture.blob, body_length);
    changed[body_length] = 0x42;
    CHECK(resign(&fixture, changed, (uint32_t)body_length + 65) == 0);
    CHECK(parse_rejected(&fixture, changed, (uint32_t)body_length + 65));
    memset(changed, 0, sizeof(changed));
    CHECK(parse_rejected(&fixture, changed, sizeof(changed)));
    memcpy(changed, fixture.blob, fixture.length);
    changed[35] |= 0x80;
    CHECK(resign(&fixture, changed, fixture.length) == 0);
    CHECK(parse_rejected(&fixture, changed, fixture.length));

    uint8_t legacy[256] = {1};
    put_u32(legacy + 1, TEST_EPOCH);
    legacy[5] = 1;
    size_t uid_length = strlen(fixture.intros[0].user_id);
    size_t host_length = strlen(fixture.intros[0].host);
    legacy[6] = (uint8_t)(uid_length >> 8); legacy[7] = (uint8_t)uid_length;
    memcpy(legacy + 8, fixture.intros[0].user_id, uid_length);
    size_t offset = 8 + uid_length;
    legacy[offset++] = (uint8_t)host_length;
    memcpy(legacy + offset, fixture.intros[0].host, host_length); offset += host_length;
    legacy[offset++] = (uint8_t)(fixture.intros[0].port >> 8);
    legacy[offset++] = (uint8_t)fixture.intros[0].port;
    memcpy(legacy + offset, fixture.intros[0].pubkey, 32); offset += 32;
    CHECK(parse_rejected(&fixture, legacy, (uint32_t)offset));
done:
    fixture_close(&fixture);
    return ok;
}

static int test_time_bounds(void) {
    fixture_t fixture;
    pcomm_descriptor_t parsed;
    uint8_t changed[PCOMM_DESCRIPTOR_MAX_BLOB];
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    CHECK(pcomm_descriptor_parse(fixture.blob, fixture.length, NULL, UINT32_MAX,
        TEST_NOW - 120, &parsed) == 0);
    CHECK(pcomm_descriptor_parse(fixture.blob, fixture.length, NULL, UINT32_MAX,
        TEST_NOW - 121, &parsed) != 0);
    CHECK(pcomm_descriptor_parse(fixture.blob, fixture.length, NULL, UINT32_MAX,
        TEST_NOW + 3600, &parsed) != 0);

    const struct { uint32_t epoch, issued, expires; int valid; } cases[] = {
        {TEST_EPOCH, TEST_NOW, TEST_NOW + PCOMM_DESCRIPTOR_MAX_TTL, 1},
        {TEST_EPOCH, TEST_NOW, TEST_NOW + PCOMM_DESCRIPTOR_MAX_TTL + 1, 0},
        {TEST_EPOCH, TEST_NOW, TEST_NOW, 0},
        {TEST_EPOCH, TEST_NOW, TEST_NOW - 1, 0},
        {TEST_EPOCH + 1, TEST_NOW, TEST_NOW + 3600, 0},
        {TEST_EPOCH, TEST_NOW + 120, TEST_NOW + 3600, 1},
        {TEST_EPOCH, TEST_NOW + 121, TEST_NOW + 3600, 0}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        memcpy(changed, fixture.blob, fixture.length);
        put_u32(changed + 36, cases[i].epoch);
        put_u32(changed + 40, cases[i].issued);
        put_u32(changed + 44, cases[i].expires);
        CHECK(resign(&fixture, changed, fixture.length) == 0);
        int accepted = pcomm_descriptor_parse(changed, fixture.length, NULL, UINT32_MAX,
            TEST_NOW, &parsed) == 0;
        CHECK(accepted == cases[i].valid);
    }
done:
    fixture_close(&fixture);
    return ok;
}

static int test_intro_validation(void) {
    fixture_t fixture;
    pcomm_peer_t intros[3];
    uint8_t changed[PCOMM_DESCRIPTOR_MAX_BLOB];
    uint8_t *blob = NULL;
    uint32_t length = 0;
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        fixture.intros, 0, &blob, &length) != 0);
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        fixture.intros, 4, &blob, &length) != 0);

    memcpy(intros, fixture.intros, sizeof(intros));
    intros[1] = intros[0];
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        intros, 3, &blob, &length) != 0);
    memcpy(intros, fixture.intros, sizeof(intros));
    memcpy(intros[1].host, intros[0].host, sizeof(intros[1].host));
    intros[1].port = intros[0].port;
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        intros, 3, &blob, &length) != 0);

    const struct { const char *first, *second; } aliases[] = {
        {"RELAY.EXAMPLE", "relay.example"},
        {"relay.example", "relay.example."},
        {"2001:db8::1", "2001:0db8:0:0:0:0:0:1"},
        {"198.51.100.10", "::ffff:198.51.100.10"}
    };
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); ++i) {
        memcpy(intros, fixture.intros, sizeof(intros));
        snprintf(intros[0].host, sizeof(intros[0].host), "%s", aliases[i].first);
        snprintf(intros[1].host, sizeof(intros[1].host), "%s", aliases[i].second);
        intros[1].port = intros[0].port;
        CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
            intros, 3, &blob, &length) != 0);
    }

    const char *invalid_hosts[] = {"", "bad host", "bad\nhost", "bad\x80host"};
    for (size_t i = 0; i < sizeof(invalid_hosts) / sizeof(invalid_hosts[0]); ++i) {
        memcpy(intros, fixture.intros, sizeof(intros));
        snprintf(intros[0].host, sizeof(intros[0].host), "%s", invalid_hosts[i]);
        CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
            intros, 3, &blob, &length) != 0);
    }
    memcpy(intros, fixture.intros, sizeof(intros));
    memset(intros[0].host, 'a', sizeof(intros[0].host));
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        intros, 3, &blob, &length) != 0);
    memcpy(intros, fixture.intros, sizeof(intros));
    intros[0].port = 0;
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        intros, 3, &blob, &length) != 0);
    memcpy(intros, fixture.intros, sizeof(intros));
    memset(intros[0].pubkey, 0, sizeof(intros[0].pubkey));
    CHECK(pcomm_user_id_from_pubkey(intros[0].pubkey, intros[0].user_id) == 0);
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        intros, 3, &blob, &length) != 0);
    memcpy(intros, fixture.intros, sizeof(intros));
    intros[0].pubkey[31] |= 0x80;
    CHECK(pcomm_user_id_from_pubkey(intros[0].pubkey, intros[0].user_id) == 0);
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        intros, 3, &blob, &length) != 0);
    memcpy(intros, fixture.intros, sizeof(intros));
    memcpy(intros[0].user_id, fixture.other.user_id, sizeof(intros[0].user_id));
    CHECK(pcomm_descriptor_build(&fixture.owner, TEST_EPOCH, TEST_NOW, TEST_NOW + 3600,
        intros, 3, &blob, &length) != 0);

    const size_t first_host = 82;
    const size_t first_port = first_host + strlen(fixture.intros[0].host);
    const size_t second_intro = first_port + 2;
    memcpy(changed, fixture.blob, fixture.length); changed[48] = 0;
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
    memcpy(changed, fixture.blob, fixture.length); changed[48] = 4;
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
    memcpy(changed, fixture.blob, fixture.length); changed[81] = 0;
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
    memcpy(changed, fixture.blob, fixture.length); changed[first_host] = '\0';
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
    memcpy(changed, fixture.blob, fixture.length); changed[first_host] = 0x80;
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
    memcpy(changed, fixture.blob, fixture.length); changed[first_port] = 0; changed[first_port + 1] = 0;
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
    memcpy(changed, fixture.blob, fixture.length); memcpy(changed + second_intro, changed + 49, 32);
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
    memcpy(changed, fixture.blob, fixture.length); memset(changed + 49, 0, 32);
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
    memcpy(changed, fixture.blob, fixture.length); changed[80] |= 0x80;
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
    memcpy(changed, fixture.blob, fixture.length);
    memcpy(changed + second_intro + 33, changed + first_host, strlen(fixture.intros[0].host) + 2);
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
    memcpy(changed, fixture.blob, fixture.length);
    CHECK(strlen(fixture.intros[0].host) == strlen("RELAY.EXAMPLE"));
    memcpy(changed + first_host, "RELAY.EXAMPLE", strlen("RELAY.EXAMPLE"));
    memcpy(changed + second_intro + 33, "relay.example", strlen("relay.example"));
    changed[second_intro + 33 + strlen("relay.example")] = changed[first_port];
    changed[second_intro + 34 + strlen("relay.example")] = changed[first_port + 1];
    CHECK(resign(&fixture, changed, fixture.length) == 0 && parse_rejected(&fixture, changed, fixture.length));
done:
    free(blob);
    fixture_close(&fixture);
    return ok;
}

static int test_majority_and_equivocation(void) {
    fixture_t fixture;
    pcomm_descriptor_t alternative, output;
    pcomm_descriptor_quorum_t quorum = {0};
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0 && variant(&fixture, 1, &alternative) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
    CHECK(vote(&quorum, "198.51.100.1", 1, &fixture.descriptor) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
    CHECK(vote(&quorum, "198.51.100.2", 2, &fixture.descriptor) == 0);
    CHECK(vote(&quorum, "198.51.100.3", 3, &alternative) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);
    CHECK(memcmp(output.digest, fixture.descriptor.digest, 32) == 0);
    CHECK(vote(&quorum, "198.51.100.4", 4, &alternative) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
    CHECK(vote(&quorum, "198.51.100.5", 5, &fixture.descriptor) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);

    memset(&quorum, 0, sizeof(quorum));
    CHECK(vote(&quorum, "198.51.100.1", 1, &fixture.descriptor) == 0);
    vote(&quorum, "198.51.100.1", 1, &alternative);
    vote(&quorum, "198.51.100.1", 1, &fixture.descriptor);
    CHECK(vote(&quorum, "198.51.100.2", 2, &fixture.descriptor) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
    CHECK(vote(&quorum, "198.51.100.3", 3, &fixture.descriptor) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);
    CHECK(memcmp(output.digest, fixture.descriptor.digest, 32) == 0);

    memset(&quorum, 0, sizeof(quorum));
    CHECK(vote(&quorum, "198.51.100.1", 1, &fixture.descriptor) == 0);
    CHECK(vote(&quorum, "198.51.100.2", 2, &fixture.descriptor) == 0);
    vote(&quorum, "198.51.100.1", 1, &alternative);
    vote(&quorum, "198.51.100.2", 2, &alternative);
    CHECK(vote(&quorum, "198.51.100.3", 3, &fixture.descriptor) == 0);
    CHECK(vote(&quorum, "198.51.100.4", 4, &fixture.descriptor) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
    vote(&quorum, "198.51.100.1", 1, &fixture.descriptor);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
    CHECK(vote(&quorum, "198.51.100.5", 5, &fixture.descriptor) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);
done:
    fixture_close(&fixture);
    return ok;
}

static int test_source_aliases(void) {
    fixture_t fixture;
    pcomm_descriptor_t output, resigned;
    pcomm_descriptor_quorum_t quorum = {0};
    uint8_t copy[PCOMM_DESCRIPTOR_MAX_BLOB];
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    memcpy(copy, fixture.blob, fixture.length);
    CHECK(resign(&fixture, copy, fixture.length) == 0);
    CHECK(pcomm_descriptor_parse(copy, fixture.length, fixture.owner.user_id, TEST_EPOCH,
        TEST_NOW, &resigned) == 0);
    CHECK(memcmp(resigned.digest, fixture.descriptor.digest, 32) == 0);
    CHECK(vote(&quorum, "198.51.100.1", 1, &fixture.descriptor) == 0);
    vote(&quorum, "198.51.100.1", 1, &resigned);
    vote(&quorum, "::ffff:198.51.100.1", 1, &resigned);
    vote(&quorum, "::ffff:c633:6401", 1, &fixture.descriptor);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
    CHECK(quorum.source_count == 1);
    CHECK(vote(&quorum, "seed.example", 2, &fixture.descriptor) != 0);
    CHECK(vote(&quorum, "198.51.100.1:9001", 2, &fixture.descriptor) != 0);
    CHECK(vote(&quorum, "[2001:db8::1]", 2, &fixture.descriptor) != 0);
    CHECK(quorum.source_count == 1);
    CHECK(vote(&quorum, "198.51.100.2", 2, &resigned) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);

    memset(&quorum, 0, sizeof(quorum));
    CHECK(vote(&quorum, "2001:db8::1", 1, &fixture.descriptor) == 0);
    vote(&quorum, "2001:0db8:0000:0000:0000:0000:0000:0001", 1, &fixture.descriptor);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0 && quorum.source_count == 1);
    CHECK(vote(&quorum, "2001:db8::2", 2, &fixture.descriptor) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);
done:
    fixture_close(&fixture);
    return ok;
}

static int test_provider_aliases(void) {
    fixture_t fixture;
    pcomm_descriptor_t output, alternative;
    pcomm_descriptor_quorum_t quorum = {0};
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0 && variant(&fixture, 1, &alternative) == 0);
    CHECK(vote(&quorum, "198.51.100.1", 1, &fixture.descriptor) == 0);
    vote(&quorum, "198.51.100.2", 1, &fixture.descriptor);
    vote(&quorum, "2001:db8::1", 1, &fixture.descriptor);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
    CHECK(vote(&quorum, "198.51.100.3", 2, &fixture.descriptor) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);

    memset(&quorum, 0, sizeof(quorum));
    CHECK(vote(&quorum, "198.51.100.1", 1, &fixture.descriptor) == 0);
    vote(&quorum, "198.51.100.1", 2, &fixture.descriptor);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
    CHECK(vote(&quorum, "198.51.100.2", 3, &fixture.descriptor) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);

    memset(&quorum, 0, sizeof(quorum));
    CHECK(vote(&quorum, "198.51.100.1", 1, &fixture.descriptor) == 0);
    vote(&quorum, "198.51.100.2", 1, &alternative);
    vote(&quorum, "198.51.100.3", 1, &fixture.descriptor);
    CHECK(vote(&quorum, "198.51.100.4", 2, &fixture.descriptor) == 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
done:
    fixture_close(&fixture);
    return ok;
}

static int test_quorum_capacity(void) {
    fixture_t fixture;
    pcomm_descriptor_t candidates[PCOMM_DESCRIPTOR_MAX_CANDIDATES + 1], output;
    pcomm_descriptor_quorum_t quorum = {0};
    char source[64];
    int ok = 1;
    CHECK(fixture_open(&fixture) == 0);
    for (size_t i = 0; i < PCOMM_DESCRIPTOR_MAX_SOURCES; ++i) {
        snprintf(source, sizeof(source), "198.51.100.%zu", i + 1);
        CHECK(vote(&quorum, source, (unsigned)i + 1, &fixture.descriptor) == 0);
    }
    CHECK(quorum.source_count == PCOMM_DESCRIPTOR_MAX_SOURCES);
    CHECK(vote(&quorum, "203.0.113.1", 100, &fixture.descriptor) != 0);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);
    CHECK(variant(&fixture, 1, &candidates[0]) == 0);
    vote(&quorum, "198.51.100.1", 1, &candidates[0]);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);

    memset(&quorum, 0, sizeof(quorum));
    for (size_t i = 0; i <= PCOMM_DESCRIPTOR_MAX_CANDIDATES; ++i)
        CHECK(variant(&fixture, (unsigned)i, &candidates[i]) == 0);
    for (size_t i = 0; i < PCOMM_DESCRIPTOR_MAX_CANDIDATES; ++i) {
        snprintf(source, sizeof(source), "198.51.100.%zu", i + 1);
        CHECK(vote(&quorum, source, (unsigned)i + 1, &candidates[i]) == 0);
    }
    CHECK(quorum.candidate_count == PCOMM_DESCRIPTOR_MAX_CANDIDATES);
    CHECK(pcomm_descriptor_consensus(&quorum, &output) != 0);
    CHECK(vote(&quorum, "203.0.113.1", 100, &candidates[PCOMM_DESCRIPTOR_MAX_CANDIDATES]) != 0);
    for (size_t i = PCOMM_DESCRIPTOR_MAX_CANDIDATES; i < PCOMM_DESCRIPTOR_MAX_SOURCES; ++i) {
        snprintf(source, sizeof(source), "198.51.100.%zu", i + 1);
        CHECK(vote(&quorum, source, (unsigned)i + 1, &candidates[0]) == 0);
    }
    CHECK(pcomm_descriptor_consensus(&quorum, &output) == 0);
    CHECK(memcmp(output.digest, candidates[0].digest, 32) == 0);
done:
    fixture_close(&fixture);
    return ok;
}

int main(void) {
    const struct { const char *name; int (*run)(void); } tests[] = {
        {"roundtrip", test_roundtrip},
        {"authentication and framing", test_authentication_and_framing},
        {"time bounds", test_time_bounds},
        {"intro validation", test_intro_validation},
        {"majority and equivocation", test_majority_and_equivocation},
        {"source aliases", test_source_aliases},
        {"provider aliases", test_provider_aliases},
        {"quorum capacity", test_quorum_capacity}
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        int passed = tests[i].run();
        printf("%s: %s\n", tests[i].name, passed ? "PASS" : "FAIL");
        failed += !passed;
    }
    return failed ? 1 : 0;
}
