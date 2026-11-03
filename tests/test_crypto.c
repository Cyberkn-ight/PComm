#include "crypto.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; \
        goto done; \
    } \
} while (0)

static int hex_nibble(char digit) {
    if (digit >= '0' && digit <= '9') return digit - '0';
    if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
    return -1;
}

static int from_hex(const char *hex, uint8_t *bytes, size_t length) {
    if (strlen(hex) != length * 2) return -1;
    for (size_t i = 0; i < length; i++) {
        int high = hex_nibble(hex[i * 2]), low = hex_nibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0) return -1;
        bytes[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int key_pair(uint8_t private_key[32], uint8_t public_key[32]) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    size_t private_len = 32, public_len = 32;
    int ok = context && EVP_PKEY_keygen_init(context) == 1 &&
        EVP_PKEY_keygen(context, &key) == 1 &&
        EVP_PKEY_get_raw_private_key(key, private_key, &private_len) == 1 &&
        EVP_PKEY_get_raw_public_key(key, public_key, &public_len) == 1 &&
        private_len == 32 && public_len == 32;
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    return ok ? 0 : -1;
}

static int test_x25519_agreement(void) {
    int ok = 1;
    uint8_t alice_private[32], alice_public[32], bob_private[32], bob_public[32];
    uint8_t expected[32], from_alice[32], from_bob[32], basepoint[32] = {9};
    uint8_t equivalent_public[32];
    uint8_t zero_public[32] = {0};

    CHECK(from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                   alice_private, sizeof(alice_private)) == 0);
    CHECK(from_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                   alice_public, sizeof(alice_public)) == 0);
    CHECK(from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
                   bob_private, sizeof(bob_private)) == 0);
    CHECK(from_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                   bob_public, sizeof(bob_public)) == 0);
    CHECK(from_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                   expected, sizeof(expected)) == 0);
    CHECK(pcomm_x25519_derive(alice_private, bob_public, from_alice) == 0);
    CHECK(pcomm_x25519_derive(bob_private, alice_public, from_bob) == 0);
    CHECK(memcmp(from_alice, from_bob, sizeof(from_alice)) == 0);
    CHECK(memcmp(from_alice, expected, sizeof(expected)) == 0);

    memcpy(equivalent_public, bob_public, sizeof(equivalent_public));
    equivalent_public[31] ^= 0x80;
    CHECK(pcomm_x25519_derive(alice_private, equivalent_public, from_alice) == 0);
    CHECK(memcmp(from_alice, expected, sizeof(expected)) == 0);
    CHECK(pcomm_x25519_derive(alice_private, basepoint, from_alice) == 0);
    CHECK(memcmp(from_alice, alice_public, sizeof(alice_public)) == 0);
    CHECK(pcomm_x25519_derive(alice_private, zero_public, from_alice) != 0);
done:
    return ok;
}

static int test_hkdf_vectors_and_separation(void) {
    int ok = 1;
    uint8_t input[22], salt[13], info[10], expected[42], output[42], repeated[42];
    uint8_t changed[42], without_salt[42], zero_salt[32] = {0};
    memset(input, 0x0b, sizeof(input));
    for (size_t i = 0; i < sizeof(salt); i++) salt[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(info); i++) info[i] = (uint8_t)(0xf0 + i);

    CHECK(from_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                   "34007208d5b887185865", expected, sizeof(expected)) == 0);
    CHECK(pcomm_hkdf_sha256(input, sizeof(input), salt, sizeof(salt), info, sizeof(info),
                            output, sizeof(output)) == 0);
    CHECK(memcmp(output, expected, sizeof(output)) == 0);
    CHECK(pcomm_hkdf_sha256(input, sizeof(input), salt, sizeof(salt), info, sizeof(info),
                            repeated, sizeof(repeated)) == 0);
    CHECK(memcmp(output, repeated, sizeof(output)) == 0);
    info[0] ^= 1;
    CHECK(pcomm_hkdf_sha256(input, sizeof(input), salt, sizeof(salt), info, sizeof(info),
                            changed, sizeof(changed)) == 0);
    CHECK(memcmp(output, changed, sizeof(output)) != 0);
    info[0] ^= 1;
    salt[0] ^= 1;
    CHECK(pcomm_hkdf_sha256(input, sizeof(input), salt, sizeof(salt), info, sizeof(info),
                            changed, sizeof(changed)) == 0);
    CHECK(memcmp(output, changed, sizeof(output)) != 0);

    CHECK(from_hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                   "9d201395faa4b61a96c8", expected, sizeof(expected)) == 0);
    CHECK(pcomm_hkdf_sha256(input, sizeof(input), NULL, 0, NULL, 0,
                            without_salt, sizeof(without_salt)) == 0);
    CHECK(memcmp(without_salt, expected, sizeof(expected)) == 0);
    CHECK(pcomm_hkdf_sha256(input, sizeof(input), zero_salt, sizeof(zero_salt), NULL, 0,
                            output, sizeof(output)) == 0);
    CHECK(memcmp(output, without_salt, sizeof(output)) == 0);
done:
    return ok;
}

static int test_aead_vector_and_authentication(void) {
    int ok = 1;
    static const uint8_t plain[] = "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";
    enum { PLAIN_LEN = sizeof(plain) - 1, CIPHER_LEN = PLAIN_LEN + 16 };
    uint8_t key[32], nonce[12], aad[12], expected[CIPHER_LEN];
    uint8_t cipher[CIPHER_LEN], opened[PLAIN_LEN + 1], altered[CIPHER_LEN];
    uint8_t short_buffer[CIPHER_LEN + 1];
    size_t cipher_len = sizeof(cipher), opened_len = PLAIN_LEN;

    CHECK(from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                   key, sizeof(key)) == 0);
    CHECK(from_hex("070000004041424344454647", nonce, sizeof(nonce)) == 0);
    CHECK(from_hex("50515253c0c1c2c3c4c5c6c7", aad, sizeof(aad)) == 0);
    CHECK(from_hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                   "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                   "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                   "3ff4def08e4b7a9de576d26586cec64b6116"
                   "1ae10b594f09e26a7e902ecbd0600691", expected, sizeof(expected)) == 0);
    CHECK(pcomm_aead_encrypt(key, nonce, aad, sizeof(aad), plain, PLAIN_LEN,
                             cipher, &cipher_len) == 0);
    CHECK(cipher_len == sizeof(expected) && memcmp(cipher, expected, sizeof(expected)) == 0);
    CHECK(pcomm_aead_decrypt(key, nonce, aad, sizeof(aad), expected, sizeof(expected),
                             opened, &opened_len) == 0);
    CHECK(opened_len == PLAIN_LEN && memcmp(opened, plain, PLAIN_LEN) == 0);

    aad[0] ^= 1;
    opened_len = sizeof(opened);
    CHECK(pcomm_aead_decrypt(key, nonce, aad, sizeof(aad), cipher, cipher_len,
                             opened, &opened_len) != 0);
    aad[0] ^= 1;
    nonce[0] ^= 1;
    opened_len = sizeof(opened);
    CHECK(pcomm_aead_decrypt(key, nonce, aad, sizeof(aad), cipher, cipher_len,
                             opened, &opened_len) != 0);
    nonce[0] ^= 1;
    key[0] ^= 1;
    opened_len = sizeof(opened);
    CHECK(pcomm_aead_decrypt(key, nonce, aad, sizeof(aad), cipher, cipher_len,
                             opened, &opened_len) != 0);
    key[0] ^= 1;
    memcpy(altered, cipher, sizeof(altered));
    altered[0] ^= 1;
    opened_len = sizeof(opened);
    CHECK(pcomm_aead_decrypt(key, nonce, aad, sizeof(aad), altered, sizeof(altered),
                             opened, &opened_len) != 0);
    memcpy(altered, cipher, sizeof(altered));
    altered[sizeof(altered) - 1] ^= 1;
    opened_len = sizeof(opened);
    CHECK(pcomm_aead_decrypt(key, nonce, aad, sizeof(aad), altered, sizeof(altered),
                             opened, &opened_len) != 0);
    for (size_t length = 0; length < 16; length++) {
        opened_len = sizeof(opened);
        CHECK(pcomm_aead_decrypt(key, nonce, aad, sizeof(aad), cipher, length,
                                 opened, &opened_len) != 0);
    }

    memset(short_buffer, 0xa5, sizeof(short_buffer));
    cipher_len = CIPHER_LEN - 1;
    CHECK(pcomm_aead_encrypt(key, nonce, aad, sizeof(aad), plain, PLAIN_LEN,
                             short_buffer, &cipher_len) != 0);
    CHECK(short_buffer[CIPHER_LEN - 1] == 0xa5 && short_buffer[CIPHER_LEN] == 0xa5);
    memset(opened, 0xa5, sizeof(opened));
    opened_len = PLAIN_LEN - 1;
    CHECK(pcomm_aead_decrypt(key, nonce, aad, sizeof(aad), expected, sizeof(expected),
                             opened, &opened_len) != 0);
    CHECK(opened[PLAIN_LEN - 1] == 0xa5 && opened[PLAIN_LEN] == 0xa5);
done:
    return ok;
}

static int test_seal_round_trips(void) {
    int ok = 1;
    static const size_t lengths[] = {0, 1, 15, 16, 31, 32, 63, 64, 65, 255, 256, 3072, 4096};
    uint8_t private_key[32], public_key[32], input[4096];
    uint8_t *sealed = NULL, *opened = NULL;
    size_t sealed_len = 0, opened_len = 0;
    CHECK(key_pair(private_key, public_key) == 0);
    for (size_t i = 0; i < sizeof(input); i++) input[i] = (uint8_t)(i * 37);
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        size_t length = lengths[i];
        CHECK(pcomm_seal_for_recipient(public_key, input, length, &sealed, &sealed_len) == 0);
        CHECK(sealed_len == length + 32 + 12 + 16);
        CHECK(pcomm_open_seal(private_key, sealed, sealed_len, &opened, &opened_len) == 0);
        CHECK(opened_len == length);
        CHECK(length == 0 || (opened && memcmp(opened, input, length) == 0));
        free(sealed);
        free(opened);
        sealed = NULL;
        opened = NULL;
    }
done:
    free(sealed);
    free(opened);
    return ok;
}

static int seal_rejected(const uint8_t private_key[32], const uint8_t *sealed, size_t length) {
    uint8_t *opened = NULL;
    size_t opened_len = 0;
    int rc = pcomm_open_seal(private_key, sealed, length, &opened, &opened_len);
    if (rc == 0) free(opened);
    return rc != 0;
}

static int test_randomized_seals_and_rejection(void) {
    int ok = 1;
    uint8_t private_key[32], public_key[32], wrong_private[32], wrong_public[32];
    static const uint8_t input[] = {0, 0xff, 0x80, 'P', 'C', 'o', 'm', 'm', 0, 0x10};
    uint8_t *first = NULL, *second = NULL, *altered = NULL, *opened = NULL;
    size_t first_len = 0, second_len = 0, opened_len = 0;
    CHECK(key_pair(private_key, public_key) == 0);
    CHECK(key_pair(wrong_private, wrong_public) == 0);
    CHECK(pcomm_seal_for_recipient(public_key, input, sizeof(input), &first, &first_len) == 0);
    CHECK(pcomm_seal_for_recipient(public_key, input, sizeof(input), &second, &second_len) == 0);
    CHECK(first_len == second_len && memcmp(first, second, first_len) != 0);
    CHECK(pcomm_open_seal(private_key, first, first_len, &opened, &opened_len) == 0);
    CHECK(opened_len == sizeof(input) && memcmp(opened, input, sizeof(input)) == 0);
    free(opened);
    opened = NULL;
    CHECK(pcomm_open_seal(private_key, second, second_len, &opened, &opened_len) == 0);
    CHECK(opened_len == sizeof(input) && memcmp(opened, input, sizeof(input)) == 0);
    free(opened);
    opened = NULL;
    CHECK(seal_rejected(wrong_private, first, first_len));
    altered = (uint8_t *)malloc(first_len);
    CHECK(altered != NULL);
    memcpy(altered, first, first_len);
    memset(altered, 0, 32);
    CHECK(seal_rejected(private_key, altered, first_len));
    const size_t altered_offsets[] = {32, 44, first_len - 1};
    for (size_t i = 0; i < sizeof(altered_offsets) / sizeof(altered_offsets[0]); i++) {
        memcpy(altered, first, first_len);
        altered[altered_offsets[i]] ^= 1;
        CHECK(seal_rejected(private_key, altered, first_len));
    }
    for (size_t length = 0; length < first_len; length++) {
        CHECK(seal_rejected(private_key, first, length));
    }
done:
    free(first);
    free(second);
    free(altered);
    free(opened);
    return ok;
}

int main(void) {
    if (!test_x25519_agreement() || !test_hkdf_vectors_and_separation() ||
        !test_aead_vector_and_authentication() || !test_seal_round_trips() ||
        !test_randomized_seals_and_rejection()) return 1;
    puts("Core crypto checks passed.");
    return 0;
}
