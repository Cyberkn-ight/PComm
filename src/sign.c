#include "sign.h"
#include "crypto.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int signing_ready(void) {
    unsigned major = 0, minor = 0, patch = 0;
    if (sodium_init() < 0 || sscanf(sodium_version_string(), "%u.%u.%u", &major, &minor, &patch) != 3) return -1;
    return major > 1 || (major == 1 && (minor > 0 || patch >= 21)) ? 0 : -1;
}

static int edwards_public(const uint8_t montgomery[32], uint8_t edwards[32]) {
    BN_CTX *ctx = BN_CTX_new();
    int rc = -1;
    if (!ctx) return -1;
    BN_CTX_start(ctx);
    BIGNUM *prime = BN_CTX_get(ctx), *u = BN_CTX_get(ctx), *one = BN_CTX_get(ctx);
    BIGNUM *numerator = BN_CTX_get(ctx), *denominator = BN_CTX_get(ctx);
    BIGNUM *inverse = BN_CTX_get(ctx), *y = BN_CTX_get(ctx);
    if (!y || BN_one(prime) != 1 || BN_lshift(prime, prime, 255) != 1 ||
        BN_sub_word(prime, 19) != 1 || !BN_lebin2bn(montgomery, 32, u) ||
        BN_ucmp(u, prime) >= 0 || BN_one(one) != 1 ||
        BN_mod_sub(numerator, u, one, prime, ctx) != 1 ||
        BN_mod_add(denominator, u, one, prime, ctx) != 1 || BN_is_zero(denominator) ||
        !BN_mod_inverse(inverse, denominator, prime, ctx) ||
        BN_mod_mul(y, numerator, inverse, prime, ctx) != 1 ||
        BN_bn2lebinpad(y, edwards, 32) != 32 || crypto_core_ed25519_is_valid_point(edwards) != 1) goto done;
    rc = 0;
done:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return rc;
}

static int hash_nonce(const uint8_t scalar[32], const uint8_t *message, size_t length,
                        const uint8_t random[64], uint8_t hash[64]) {
    uint8_t padding[32];
    memset(padding, 0xff, sizeof(padding));
    padding[0] = 0xfe;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned written = 0;
    int rc = -1;
    if (!ctx) return -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, padding, sizeof(padding)) == 1 &&
        EVP_DigestUpdate(ctx, scalar, 32) == 1 &&
        (!length || EVP_DigestUpdate(ctx, message, length) == 1) &&
        EVP_DigestUpdate(ctx, random, 64) == 1 &&
        EVP_DigestFinal_ex(ctx, hash, &written) == 1 && written == 64) rc = 0;
    EVP_MD_CTX_free(ctx);
    return rc;
}

static int hash_challenge(const uint8_t point[32], const uint8_t public_key[32],
                            const uint8_t *message, size_t length, uint8_t hash[64]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned written = 0;
    int rc = -1;
    if (!ctx) return -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, point, 32) == 1 && EVP_DigestUpdate(ctx, public_key, 32) == 1 &&
        (!length || EVP_DigestUpdate(ctx, message, length) == 1) &&
        EVP_DigestFinal_ex(ctx, hash, &written) == 1 && written == 64) rc = 0;
    EVP_MD_CTX_free(ctx);
    return rc;
}

int pcomm_sign(const uint8_t private_key[32], const uint8_t *message, size_t length,
                 uint8_t signature[64]) {
    uint8_t raw[32] = {0}, extended[64] = {0}, scalar[32] = {0}, negative[32] = {0};
    uint8_t public_key[32] = {0}, random[64] = {0}, digest[64] = {0};
    uint8_t nonce[32] = {0}, challenge[32] = {0}, product[32] = {0}, temporary[64] = {0};
    int rc = -1;
    if (!private_key || !signature || (!message && length) || signing_ready()) goto done;
    memcpy(raw, private_key, 32);
    raw[0] &= 248;
    raw[31] &= 127;
    raw[31] |= 64;
    memcpy(extended, raw, 32);
    crypto_core_ed25519_scalar_reduce(scalar, extended);
    if (crypto_scalarmult_ed25519_base_noclamp(public_key, scalar) != 0) goto done;
    crypto_core_ed25519_scalar_negate(negative, scalar);
    uint8_t mask = (uint8_t)(0u-(unsigned)(public_key[31] >> 7));
    for (size_t i = 0; i < 32; i++) {
        raw[i] = (uint8_t)((raw[i] & (uint8_t)~mask) | (negative[i] & mask));
        scalar[i] = (uint8_t)((scalar[i] & (uint8_t)~mask) | (negative[i] & mask));
    }
    public_key[31] &= 127;
    if (pcomm_random(random, sizeof(random)) || hash_nonce(raw, message, length, random, digest)) goto done;
    crypto_core_ed25519_scalar_reduce(nonce, digest);
    if (crypto_scalarmult_ed25519_base_noclamp(temporary, nonce) != 0 ||
        hash_challenge(temporary, public_key, message, length, digest)) goto done;
    crypto_core_ed25519_scalar_reduce(challenge, digest);
    crypto_core_ed25519_scalar_mul(product, challenge, scalar);
    crypto_core_ed25519_scalar_add(temporary+32, nonce, product);
    memcpy(signature, temporary, 64);
    rc = 0;
done:
    OPENSSL_cleanse(raw, sizeof(raw));
    OPENSSL_cleanse(extended, sizeof(extended));
    OPENSSL_cleanse(scalar, sizeof(scalar));
    OPENSSL_cleanse(negative, sizeof(negative));
    OPENSSL_cleanse(random, sizeof(random));
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(challenge, sizeof(challenge));
    OPENSSL_cleanse(product, sizeof(product));
    OPENSSL_cleanse(temporary, sizeof(temporary));
    if (rc && signature) OPENSSL_cleanse(signature, 64);
    return rc;
}

int pcomm_verify(const uint8_t public_key[32], const uint8_t *message, size_t length,
                   const uint8_t signature[64]) {
    static const uint8_t empty = 0;
    uint8_t edwards[32];
    if (!public_key || !signature || (!message && length) || signing_ready() ||
        edwards_public(public_key, edwards) || crypto_core_ed25519_is_valid_point(signature) != 1) return -1;
    return crypto_sign_verify_detached(signature, message ? message : &empty,
                                       (unsigned long long)length, edwards) == 0 ? 0 : -1;
}
