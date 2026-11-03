#include "ratchet_crypto.h"
#include "crypto.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; \
        goto done; \
    } \
} while (0)

static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int from_hex(const char *hex, uint8_t *output, size_t length) {
    if (strlen(hex) != length * 2) return -1;
    for (size_t i = 0; i < length; i++) {
        int high = nibble(hex[i * 2]), low = nibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0) return -1;
        output[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int is_zero(const uint8_t *bytes, size_t length) {
    uint8_t combined = 0;
    for (size_t i = 0; i < length; i++) combined |= bytes[i];
    return combined == 0;
}

static int test_mac_known_answer(void) {
    int ok = 1;
    uint8_t key[32] = {0}, expected[32], output[32], changed[32];
    uint8_t binary[] = {0x50, 0, 1, 2, 0xff};
    static const uint8_t message[] = "Hi There";

    memset(key, 0x0b, 20);
    CHECK(from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                   expected, sizeof(expected)) == 0);
    CHECK(pcomm_ratchet_mac(key, message, sizeof(message) - 1, output) == 0);
    CHECK(memcmp(output, expected, sizeof(output)) == 0);
    CHECK(pcomm_ratchet_mac(key, message, sizeof(message) - 1, changed) == 0);
    CHECK(memcmp(output, changed, sizeof(output)) == 0);
    key[0] ^= 1;
    CHECK(pcomm_ratchet_mac(key, message, sizeof(message) - 1, changed) == 0);
    CHECK(memcmp(output, changed, sizeof(output)) != 0);
    CHECK(pcomm_ratchet_mac(key, NULL, 0, output) == 0);
    CHECK(pcomm_ratchet_mac(key, message, 0, changed) == 0);
    CHECK(memcmp(output, changed, sizeof(output)) == 0);
    CHECK(pcomm_ratchet_mac(key, binary, sizeof(binary), output) == 0);
    binary[sizeof(binary) - 1] ^= 1;
    CHECK(pcomm_ratchet_mac(key, binary, sizeof(binary), changed) == 0);
    CHECK(memcmp(output, changed, sizeof(output)) != 0);
done:
    return ok;
}

static int test_chain_vectors_and_in_place_advance(void) {
    int ok = 1;
    uint8_t chain[32], next[32], message[32], expected_next[32], expected_message[32];
    uint8_t second_next[32], second_message[32], in_place[32], in_place_message[32];
    for (size_t i = 0; i < sizeof(chain); i++) chain[i] = (uint8_t)i;

    CHECK(from_hex("38e965664f8b6b18d7c5e4a5080e0686427cb7fa6b8c83f7909b739b14eaed9a",
                   expected_next, sizeof(expected_next)) == 0);
    CHECK(from_hex("63a2736c3918b88ee8357445f34ae7822b9ff02b7e9f6d07ab8755824f753427",
                   expected_message, sizeof(expected_message)) == 0);
    CHECK(from_hex("fbcefaed8ac1b02d9323cb4d07bec239ca8c4fb7e7d874aa1c9296cb24700268",
                   second_next, sizeof(second_next)) == 0);
    CHECK(from_hex("95da0978850e275d3e9cc8890c99991ed1fa002ab1eb3b552f85fce4c1e6c7af",
                   second_message, sizeof(second_message)) == 0);
    CHECK(pcomm_ratchet_chain_step(chain, next, message) == 0);
    CHECK(memcmp(next, expected_next, sizeof(next)) == 0);
    CHECK(memcmp(message, expected_message, sizeof(message)) == 0);
    CHECK(memcmp(next, message, sizeof(next)) != 0);
    for (size_t i = 0; i < sizeof(chain); i++) CHECK(chain[i] == (uint8_t)i);
    memcpy(in_place, chain, sizeof(in_place));
    CHECK(pcomm_ratchet_chain_step(in_place, in_place, in_place_message) == 0);
    CHECK(memcmp(in_place, expected_next, sizeof(in_place)) == 0);
    CHECK(memcmp(in_place_message, expected_message, sizeof(in_place_message)) == 0);
    CHECK(pcomm_ratchet_chain_step(in_place, in_place, in_place_message) == 0);
    CHECK(memcmp(in_place, second_next, sizeof(in_place)) == 0);
    CHECK(memcmp(in_place_message, second_message, sizeof(in_place_message)) == 0);
    memcpy(in_place, chain, sizeof(in_place));
    CHECK(pcomm_ratchet_chain_step(in_place, next, in_place) == 0);
    CHECK(memcmp(next, expected_next, sizeof(next)) == 0);
    CHECK(memcmp(in_place, expected_message, sizeof(in_place)) == 0);
done:
    return ok;
}

static int test_session_vector_and_transcript_binding(void) {
    int ok = 1;
    uint8_t shared[32], expected[96], output[96], repeated[96], changed[96];
    uint8_t transcript[] = {0x50, 0x43, 0x4f, 0x4d, 0, 1, 0, 2, 0, 0xff};
    for (size_t i = 0; i < sizeof(shared); i++) shared[i] = (uint8_t)i;

    CHECK(from_hex("4085b06d3784ed66cebb488e18082eb8b301120b82569dcfd498f5f2d6ad06c30"
                   "d99ee4044054e9044f4fef8e21795f2a968672a8db16c01cbdfa293d8faefdc9"
                   "835e9e7c6e5bfba33f2d0d39aa528667647c6597d67db45b8c44793b38e6879",
                   expected, sizeof(expected)) == 0);
    CHECK(pcomm_ratchet_derive(shared, transcript, sizeof(transcript),
                               output, output + 32, output + 64) == 0);
    CHECK(memcmp(output, expected, sizeof(output)) == 0);
    CHECK(pcomm_ratchet_derive(shared, transcript, sizeof(transcript),
                               repeated, repeated + 32, repeated + 64) == 0);
    CHECK(memcmp(output, repeated, sizeof(output)) == 0);
    CHECK(memcmp(output, output + 32, 32) != 0);
    CHECK(memcmp(output, output + 64, 32) != 0);
    CHECK(memcmp(output + 32, output + 64, 32) != 0);
    transcript[sizeof(transcript) - 1] ^= 1;
    CHECK(pcomm_ratchet_derive(shared, transcript, sizeof(transcript),
                               changed, changed + 32, changed + 64) == 0);
    for (size_t i = 0; i < sizeof(output); i += 32) {
        CHECK(memcmp(output + i, changed + i, 32) != 0);
    }
    transcript[sizeof(transcript) - 1] ^= 1;
    CHECK(pcomm_ratchet_derive(shared, transcript, 4,
                               changed, changed + 32, changed + 64) == 0);
    CHECK(memcmp(output, changed, sizeof(output)) != 0);
    CHECK(pcomm_ratchet_derive(shared, NULL, 0,
                               changed, changed + 32, changed + 64) == 0);
    CHECK(memcmp(output, changed, sizeof(output)) != 0);
done:
    return ok;
}

static int test_generated_key_agreement(void) {
    int ok = 1;
    uint8_t alice_private[32] = {0}, alice_public[32], bob_private[32] = {0}, bob_public[32];
    uint8_t alice_shared[32] = {0}, bob_shared[32] = {0};
    uint8_t alice_output[96] = {0}, bob_output[96] = {0}, control_mac[32], peer_mac[32];
    uint8_t derived_public[32], basepoint[32] = {9}, transcript[1 + 32 + 32];
    CHECK(pcomm_ratchet_keygen(alice_private, alice_public) == 0);
    CHECK(pcomm_ratchet_keygen(bob_private, bob_public) == 0);
    CHECK(pcomm_x25519_derive(alice_private, basepoint, derived_public) == 0);
    CHECK(memcmp(derived_public, alice_public, sizeof(derived_public)) == 0);
    CHECK(pcomm_x25519_derive(alice_private, bob_public, alice_shared) == 0);
    CHECK(pcomm_x25519_derive(bob_private, alice_public, bob_shared) == 0);
    CHECK(memcmp(alice_shared, bob_shared, sizeof(alice_shared)) == 0);
    CHECK(!is_zero(alice_shared, sizeof(alice_shared)));
    transcript[0] = 1;
    memcpy(transcript + 1, alice_public, 32);
    memcpy(transcript + 33, bob_public, 32);
    CHECK(pcomm_ratchet_derive(alice_shared, transcript, sizeof(transcript),
                               alice_output, alice_output + 32, alice_output + 64) == 0);
    CHECK(pcomm_ratchet_derive(bob_shared, transcript, sizeof(transcript),
                               bob_output, bob_output + 32, bob_output + 64) == 0);

    CHECK(memcmp(alice_output, bob_output, sizeof(alice_output)) == 0);
    CHECK(memcmp(alice_output + 32, alice_output + 64, 32) != 0);
    CHECK(pcomm_ratchet_mac(alice_output, transcript, sizeof(transcript), control_mac) == 0);
    CHECK(pcomm_ratchet_mac(bob_output, transcript, sizeof(transcript), peer_mac) == 0);
    CHECK(memcmp(control_mac, peer_mac, sizeof(control_mac)) == 0);
done:
    OPENSSL_cleanse(alice_private, sizeof(alice_private));
    OPENSSL_cleanse(bob_private, sizeof(bob_private));
    OPENSSL_cleanse(alice_shared, sizeof(alice_shared));
    OPENSSL_cleanse(bob_shared, sizeof(bob_shared));
    OPENSSL_cleanse(alice_output, sizeof(alice_output));
    OPENSSL_cleanse(bob_output, sizeof(bob_output));
    return ok;
}

static int test_invalid_outputs_fail_closed(void) {
    int ok = 1;
    uint8_t chain[32] = {1}, outputs[96], private_key[32], public_key[32];
    memset(outputs, 0xa5, sizeof(outputs));
    CHECK(pcomm_ratchet_chain_step(chain, outputs, outputs + 1) == -1);
    CHECK(pcomm_ratchet_derive(chain, NULL, 1, outputs, outputs + 32, outputs + 64) == -1);
    CHECK(pcomm_ratchet_derive(chain, NULL, 0, outputs, outputs + 16, outputs + 64) == -1);
    CHECK(pcomm_ratchet_mac(chain, NULL, 1, outputs) == -1);
    for (size_t i = 0; i < sizeof(outputs); i++) CHECK(outputs[i] == 0xa5);
    memset(private_key, 0xa5, sizeof(private_key));
    CHECK(pcomm_ratchet_keygen(private_key, NULL) == -1);
    CHECK(is_zero(private_key, sizeof(private_key)));
    memset(public_key, 0xa5, sizeof(public_key));
    CHECK(pcomm_ratchet_keygen(NULL, public_key) == -1);
    CHECK(is_zero(public_key, sizeof(public_key)));
    memset(private_key, 0xa5, sizeof(private_key));
    CHECK(pcomm_ratchet_keygen(private_key, private_key) == -1);
    CHECK(is_zero(private_key, sizeof(private_key)));
done:
    return ok;
}

int main(void) {
    if (!test_mac_known_answer() || !test_chain_vectors_and_in_place_advance() ||
        !test_session_vector_and_transcript_binding() || !test_generated_key_agreement() ||
        !test_invalid_outputs_fail_closed()) return 1;
    puts("Ratchet crypto checks passed.");
    return 0;
}
