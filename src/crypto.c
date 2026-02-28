#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

#include <string.h>
#include <stdlib.h>

int pcomm_random(uint8_t *buf, size_t len) {
    return (RAND_bytes(buf, (int)len) == 1) ? 0 : -1;
}

int pcomm_x25519_derive(const uint8_t priv[32], const uint8_t pub[32], uint8_t out_shared[32]) {
    int ok = -1;
    EVP_PKEY *p_priv = NULL;
    EVP_PKEY *p_pub = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    p_priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    p_pub  = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, 32);
    if (!p_priv || !p_pub) goto cleanup;

    ctx = EVP_PKEY_CTX_new(p_priv, NULL);
    if (!ctx) goto cleanup;
    if (EVP_PKEY_derive_init(ctx) != 1) goto cleanup;
    if (EVP_PKEY_derive_set_peer(ctx, p_pub) != 1) goto cleanup;

    size_t out_len = 32;
    if (EVP_PKEY_derive(ctx, out_shared, &out_len) != 1) goto cleanup;
    if (out_len != 32) goto cleanup;
    ok = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(p_priv);
    EVP_PKEY_free(p_pub);
    return ok;
}

int pcomm_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *salt, size_t salt_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out, size_t out_len) {
    int ok = -1;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) goto cleanup;
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) goto cleanup;

    OSSL_PARAM params[6];
    size_t p = 0;
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA256", 0);
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm, ikm_len);
    if (salt && salt_len > 0)
        params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt, salt_len);
    if (info && info_len > 0)
        params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info, info_len);
    params[p++] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, out_len, params) != 1) goto cleanup;
    ok = 0;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ok;
}

static int aead_crypt(int enc,
                      const uint8_t key[32], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t *out_len_inout) {
    int ok = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher = EVP_chacha20_poly1305();

    int len = 0;
    int out_len = 0;

    if (enc) {
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto cleanup;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) goto cleanup;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto cleanup;

        if (aad && aad_len > 0) {
            if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto cleanup;
        }

        if (*out_len_inout < in_len + 16) goto cleanup;

        if (EVP_EncryptUpdate(ctx, out, &len, in, (int)in_len) != 1) goto cleanup;
        out_len = len;

        if (EVP_EncryptFinal_ex(ctx, out + out_len, &len) != 1) goto cleanup;
        out_len += len;

        // tag appended
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out + out_len) != 1) goto cleanup;
        out_len += 16;
        *out_len_inout = (size_t)out_len;
        ok = 0;
    } else {
        if (in_len < 16) goto cleanup;
        size_t ct_len = in_len - 16;
        const uint8_t *tag = in + ct_len;

        if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto cleanup;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) goto cleanup;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto cleanup;

        if (aad && aad_len > 0) {
            if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto cleanup;
        }

        if (*out_len_inout < ct_len) goto cleanup;
        if (EVP_DecryptUpdate(ctx, out, &len, in, (int)ct_len) != 1) goto cleanup;
        out_len = len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag) != 1) goto cleanup;

        if (EVP_DecryptFinal_ex(ctx, out + out_len, &len) != 1) goto cleanup;
        out_len += len;
        *out_len_inout = (size_t)out_len;
        ok = 0;
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int pcomm_aead_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct_out, size_t *ct_len_inout) {
    return aead_crypt(1, key, nonce, aad, aad_len, pt, pt_len, ct_out, ct_len_inout);
}

int pcomm_aead_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt_out, size_t *pt_len_inout) {
    return aead_crypt(0, key, nonce, aad, aad_len, ct, ct_len, pt_out, pt_len_inout);
}

static int x25519_keygen(uint8_t priv[32], uint8_t pub[32]) {
    int ok = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx) goto cleanup;
    if (EVP_PKEY_keygen_init(ctx) != 1) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) goto cleanup;

    size_t priv_len = 32, pub_len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) != 1) goto cleanup;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) != 1) goto cleanup;
    if (priv_len != 32 || pub_len != 32) goto cleanup;

    ok = 0;
cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

int pcomm_seal_for_recipient(const uint8_t recipient_pub[32],
                             const uint8_t *msg, size_t msg_len,
                             uint8_t **out, size_t *out_len) {
    if (!recipient_pub || !msg || !out || !out_len) return -1;

    uint8_t eph_priv[32], eph_pub[32];
    if (x25519_keygen(eph_priv, eph_pub) != 0) return -1;

    uint8_t shared[32];
    if (pcomm_x25519_derive(eph_priv, recipient_pub, shared) != 0) return -1;

    uint8_t key[32];
    const uint8_t info[] = "pcomm-seal-v1";
    if (pcomm_hkdf_sha256(shared, sizeof(shared), NULL, 0, info, sizeof(info)-1, key, sizeof(key)) != 0) return -1;

    uint8_t nonce[12];
    if (pcomm_random(nonce, sizeof(nonce)) != 0) return -1;

    size_t ct_cap = msg_len + 16;
    size_t total = 32 + 12 + ct_cap;
    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) return -1;

    memcpy(buf, eph_pub, 32);
    memcpy(buf + 32, nonce, 12);

    size_t ct_len = ct_cap;
    if (pcomm_aead_encrypt(key, nonce, NULL, 0, msg, msg_len, buf + 32 + 12, &ct_len) != 0) {
        free(buf);
        return -1;
    }

    *out = buf;
    *out_len = 32 + 12 + ct_len;
    return 0;
}

int pcomm_open_seal(const uint8_t recipient_priv[32],
                    const uint8_t *sealed, size_t sealed_len,
                    uint8_t **out_msg, size_t *out_msg_len) {
    if (!recipient_priv || !sealed || !out_msg || !out_msg_len) return -1;
    if (sealed_len < 32 + 12 + 16) return -1;

    const uint8_t *eph_pub = sealed;
    const uint8_t *nonce = sealed + 32;
    const uint8_t *ct = sealed + 32 + 12;
    size_t ct_len = sealed_len - 32 - 12;

    uint8_t shared[32];
    if (pcomm_x25519_derive(recipient_priv, eph_pub, shared) != 0) return -1;

    uint8_t key[32];
    const uint8_t info[] = "pcomm-seal-v1";
    if (pcomm_hkdf_sha256(shared, sizeof(shared), NULL, 0, info, sizeof(info)-1, key, sizeof(key)) != 0) return -1;

    uint8_t *pt = (uint8_t*)malloc(ct_len);
    if (!pt) return -1;
    size_t pt_len = ct_len;

    if (pcomm_aead_decrypt(key, nonce, NULL, 0, ct, ct_len, pt, &pt_len) != 0) {
        free(pt);
        return -1;
    }

    *out_msg = pt;
    *out_msg_len = pt_len;
    return 0;
}
