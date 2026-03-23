#include "identity.h"
#include "base32.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir_p(path) _mkdir(path)
#else
#include <unistd.h>
#define mkdir_p(path) mkdir(path, 0700)
#endif

static int file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

static int read_file_all(const char *path, uint8_t *buf, size_t need) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, need, f);
    fclose(f);
    return (n == need) ? 0 : -1;
}

static int write_file_all_600(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(buf, 1, len, f);
    fclose(f);
#ifndef _WIN32
    chmod(path, 0600);
#endif
    return (n == len) ? 0 : -1;
}

int pcomm_user_id_from_pubkey(const uint8_t pubkey[32], char out[96]) {
    if (!pubkey || !out) return -1;

    uint8_t payload[1 + 32 + 4];
    payload[0] = 0x01;
    memcpy(payload + 1, pubkey, 32);

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(payload, 1 + 32, digest);
    memcpy(payload + 1 + 32, digest, 4);

    char b32[128];
    int b32len = base32_encode_no_pad(payload, sizeof(payload), b32, sizeof(b32));
    if (b32len < 0) return -1;

    snprintf(out, 96, "pcomm1_%s", b32);
    return 0;
}

int pcomm_pubkey_from_user_id(const char *user_id, uint8_t pubkey_out[32]) {
    if (!user_id || !pubkey_out) return -1;
    const char *p = user_id;
    const char *prefix = "pcomm1_";
    if (strncmp(p, prefix, strlen(prefix)) == 0) p += strlen(prefix);

    uint8_t payload[1 + 32 + 4];
    int n = base32_decode_no_pad(p, payload, sizeof(payload));
    if (n != (int)sizeof(payload)) return -1;
    if (payload[0] != 0x01) return -1;

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(payload, 1 + 32, digest);
    if (memcmp(payload + 1 + 32, digest, 4) != 0) return -1;

    memcpy(pubkey_out, payload + 1, 32);
    return 0;
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

int pcomm_identity_load_or_create(pcomm_identity_t *id, const char *data_dir) {
    if (!id || !data_dir) return -1;
    memset(id, 0, sizeof(*id));

    mkdir_p(data_dir);

    char key_path[1024];
    snprintf(key_path, sizeof(key_path), "%s/identity.key", data_dir);

    if (!file_exists(key_path)) {
        uint8_t priv[32], pub[32];
        if (x25519_keygen(priv, pub) != 0) return -1;
        if (write_file_all_600(key_path, priv, 32) != 0) return -1;
    }

    if (read_file_all(key_path, id->privkey, 32) != 0) return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, id->privkey, 32);
    if (!pkey) return -1;
    size_t pub_len = 32;
    int rc = EVP_PKEY_get_raw_public_key(pkey, id->pubkey, &pub_len);
    EVP_PKEY_free(pkey);
    if (rc != 1 || pub_len != 32) return -1;

    if (pcomm_user_id_from_pubkey(id->pubkey, id->user_id) != 0) return -1;
    return 0;
}
