#include "sign.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sodium.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; goto done; \
    } \
} while (0)

static int random_mode = 0;

int pcomm_random(uint8_t *buffer, size_t length) {
    if (random_mode < 0) return -1;
    if (random_mode > 0) { memset(buffer, 0, length); return 0; }
    return length <= INT_MAX && RAND_bytes(buffer, (int)length) == 1 ? 0 : -1;
}

static int decode(const char *text, uint8_t *bytes, size_t length) {
    if (strlen(text) != length*2) return -1;
    for (size_t i = 0; i < length; i++) {
        unsigned value;
        if (sscanf(text+2*i, "%2x", &value) != 1) return -1;
        bytes[i] = (uint8_t)value;
    }
    return 0;
}

static int derive_public(int type, const uint8_t private_key[32], uint8_t public_key[32]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(type, NULL, private_key, 32);
    size_t length = 32;
    int rc = key && EVP_PKEY_get_raw_public_key(key, public_key, &length) == 1 && length == 32 ? 0 : -1;
    EVP_PKEY_free(key);
    return rc;
}

static int oracle_public(const uint8_t private_key[32], uint8_t public_key[32], int *sign_bit) {
    uint8_t extended[64] = {0}, scalar[32];
    memcpy(extended, private_key, 32);
    extended[0] &= 248; extended[31] &= 127; extended[31] |= 64;
    crypto_core_ed25519_scalar_reduce(scalar, extended);
    int rc = crypto_scalarmult_ed25519_base_noclamp(public_key, scalar);
    if (!rc) {
        if (sign_bit) *sign_bit = public_key[31] >> 7;
        public_key[31] &= 127;
    }
    OPENSSL_cleanse(extended, sizeof(extended)); OPENSSL_cleanse(scalar, sizeof(scalar));
    return rc;
}

static int oracle_verify(const uint8_t public_key[32], const uint8_t *message, size_t length,
                            const uint8_t signature[64]) {
    static const uint8_t empty = 0;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int rc = key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestVerify(ctx, signature, 64, message ? message : &empty, length) == 1 ? 0 : -1;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    return rc;
}

static int test_signal_70fae57d_vector(void) {
    uint8_t private_key[32] = {0}, public_key[32], edwards[32], signature[64], expected[64], message[200] = {0};
    int ok = 1;
    private_key[8] = 189;
    CHECK(decode("11c7f3e6c4df9e8a5150e1db3b30f92de3a3b3aa438656545fa7390f4bcc7bb2"
                 "6c431d9e90643e4f0eaa0e9c557766fa69ada576d63dcaf2ac326c11d0b97702", expected, 64) == 0);
    random_mode = 1;
    CHECK(pcomm_sign(private_key, message, sizeof(message), signature) == 0);
    CHECK(memcmp(signature, expected, sizeof(expected)) == 0);
    CHECK(derive_public(EVP_PKEY_X25519, private_key, public_key) == 0);
    CHECK(pcomm_verify(public_key, message, sizeof(message), expected) == 0);
    CHECK(oracle_public(private_key, edwards, NULL) == 0);
    CHECK(oracle_verify(edwards, message, sizeof(message), signature) == 0);
    signature[0] ^= 1;
    CHECK(pcomm_verify(public_key, message, sizeof(message), signature) == -1);
done:
    random_mode = 0;
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return ok;
}

static int test_rfc8032_vectors(void) {
    const struct { const char *seed, *edwards, *message, *signature; } vectors[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
         "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
        {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"}
    };
    uint8_t seed[32], expected[32], edwards[32], hashed[64], public_key[32], signature[64], message[2];
    int ok = 1;
    for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
        size_t length = strlen(vectors[i].message)/2;
        unsigned hash_length = 0;
        CHECK(decode(vectors[i].seed, seed, 32) == 0 && decode(vectors[i].edwards, expected, 32) == 0);
        CHECK(decode(vectors[i].signature, signature, 64) == 0 && decode(vectors[i].message, message, length) == 0);
        CHECK(derive_public(EVP_PKEY_ED25519, seed, edwards) == 0 && memcmp(edwards, expected, 32) == 0);
        CHECK(EVP_Digest(seed, 32, hashed, &hash_length, EVP_sha512(), NULL) == 1 && hash_length == 64);
        CHECK(derive_public(EVP_PKEY_X25519, hashed, public_key) == 0);
        int verified = pcomm_verify(public_key, length ? message : NULL, length, signature);
        int oracle = oracle_verify(edwards, length ? message : NULL, length, signature);
        if (verified || oracle) fprintf(stderr, "RFC vector %zu: verifier=%d oracle=%d\n", i+1, verified, oracle);
        CHECK(verified == 0 && oracle == 0);
        signature[63] ^= 1;
        CHECK(pcomm_verify(public_key, length ? message : NULL, length, signature) == -1);
    }
done:
    OPENSSL_cleanse(seed, sizeof(seed)); OPENSSL_cleanse(hashed, sizeof(hashed));
    return ok;
}

static int test_signatures_match_openssl(void) {
    uint8_t private_key[32], public_key[32], edwards[32], message[4096], signature[64], second[64];
    int observed_signs = 0, ok = 1;
    const size_t sizes[] = {0, 1, 257, sizeof(message)};
    for (unsigned round = 0; round < 32; round++) {
        CHECK(RAND_bytes(private_key, 32) == 1 && RAND_bytes(message, sizeof(message)) == 1);
        int sign = 0;
        CHECK(derive_public(EVP_PKEY_X25519, private_key, public_key) == 0);
        CHECK(oracle_public(private_key, edwards, &sign) == 0);
        observed_signs |= 1 << sign;
        for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
            CHECK(pcomm_sign(private_key, sizes[i] ? message : NULL, sizes[i], signature) == 0);
            CHECK(pcomm_verify(public_key, sizes[i] ? message : NULL, sizes[i], signature) == 0);
            CHECK(oracle_verify(edwards, sizes[i] ? message : NULL, sizes[i], signature) == 0);
            CHECK(pcomm_sign(private_key, sizes[i] ? message : NULL, sizes[i], second) == 0);
            CHECK(memcmp(signature, second, 64) != 0);
        }
    }
    CHECK(observed_signs == 3);
done:
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return ok;
}

static int test_invalid_encodings_and_tampering(void) {
    static const uint8_t order[32] = {
        0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
    };
    uint8_t private_key[32] = {7}, public_key[32], other[32], bad[64], signature[64];
    uint8_t message[] = {'b', 0, 'o', 'u', 'n', 'd'};
    int ok = 1;
    CHECK(derive_public(EVP_PKEY_X25519, private_key, public_key) == 0);
    CHECK(pcomm_sign(private_key, message, sizeof(message), signature) == 0);
    CHECK(pcomm_verify(public_key, message, sizeof(message), signature) == 0);
    message[2] ^= 1;
    CHECK(pcomm_verify(public_key, message, sizeof(message), signature) == -1);
    message[2] ^= 1;
    private_key[8] = 3;
    CHECK(derive_public(EVP_PKEY_X25519, private_key, other) == 0);
    CHECK(pcomm_verify(other, message, sizeof(message), signature) == -1);
    memcpy(other, public_key, 32); other[31] |= 128;
    CHECK(pcomm_verify(other, message, sizeof(message), signature) == -1);
    memset(other, 0, 32);
    CHECK(pcomm_verify(other, message, sizeof(message), signature) == -1);
    other[0] = 1;
    CHECK(pcomm_verify(other, message, sizeof(message), signature) == -1);
    memset(other, 0xff, 32); other[0] = 0xec; other[31] = 0x7f;
    CHECK(pcomm_verify(other, message, sizeof(message), signature) == -1);
    other[0] = 0xed;
    CHECK(pcomm_verify(other, message, sizeof(message), signature) == -1);
    memset(other, 0xff, 32);
    CHECK(pcomm_verify(other, message, sizeof(message), signature) == -1);
    memcpy(bad, signature, 64);
    unsigned carry = 0;
    for (size_t i = 0; i < 32; i++) {
        unsigned sum = (unsigned)bad[32+i]+order[i]+carry;
        bad[32+i] = (uint8_t)sum; carry = sum >> 8;
    }
    CHECK(pcomm_verify(public_key, message, sizeof(message), bad) == -1);
    memcpy(bad, signature, 64); memset(bad, 0, 32); bad[0] = 1;
    CHECK(pcomm_verify(public_key, message, sizeof(message), bad) == -1);
    memcpy(bad, signature, 64); memset(bad+32, 0xff, 32);
    CHECK(pcomm_verify(public_key, message, sizeof(message), bad) == -1);
done:
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return ok;
}

static int test_failure_cleanup(void) {
    uint8_t private_key[32] = {9}, signature[64], zero[64] = {0};
    const uint8_t message[] = "failure";
    int ok = 1;
    memset(signature, 0xa5, 64);
    random_mode = -1;
    CHECK(pcomm_sign(private_key, message, sizeof(message)-1, signature) == -1 && memcmp(signature, zero, 64) == 0);
    random_mode = 0;
    memset(signature, 0xa5, 64);
    CHECK(pcomm_sign(NULL, message, sizeof(message)-1, signature) == -1 && memcmp(signature, zero, 64) == 0);
    CHECK(pcomm_sign(private_key, NULL, 1, signature) == -1);
    CHECK(pcomm_sign(private_key, message, sizeof(message)-1, NULL) == -1);
    CHECK(pcomm_verify(NULL, message, sizeof(message)-1, signature) == -1);
    CHECK(pcomm_verify(private_key, NULL, 1, signature) == -1);
    CHECK(pcomm_verify(private_key, message, sizeof(message)-1, NULL) == -1);
done:
    random_mode = 0;
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return ok;
}

int main(void) {
    const struct { const char *name; int (*run)(void); } tests[] = {
        {"Signal XEdDSA known-answer vector", test_signal_70fae57d_vector},
        {"RFC 8032 signature verification vectors", test_rfc8032_vectors},
        {"generated signatures verified independently by OpenSSL", test_signatures_match_openssl},
        {"tampering and noncanonical/low-order encodings", test_invalid_encodings_and_tampering},
        {"failure output cleanup", test_failure_cleanup}
    };
    unsigned failures = 0;
    if (sodium_init() < 0) return 1;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        int ok = tests[i].run();
        printf("%s: %s\n", ok ? "PASS" : "FAIL", tests[i].name);
        if (!ok) failures++;
    }
    return failures ? 1 : 0;
}
