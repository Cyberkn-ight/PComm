#include "ratchet_crypto.h"
#include "crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>

static int overlaps_key(const uint8_t *first, const uint8_t *second) {
    uintptr_t a = (uintptr_t)first, b = (uintptr_t)second;
    return a >= b ? a - b < 32 : b - a < 32;
}

int pcomm_ratchet_mac(const uint8_t key[32], const uint8_t *data, size_t len,
                      uint8_t mac[32]) {
    if (!key || !mac || (!data && len)) return -1;
    static const uint8_t empty = 0;
    uint8_t temporary[32];
    unsigned int written = 0;
    int result = -1;
    if (HMAC(EVP_sha256(), key, 32, data ? data : &empty, len,
             temporary, &written) && written == sizeof(temporary)) {
        memcpy(mac, temporary, sizeof(temporary));
        result = 0;
    }
    OPENSSL_cleanse(temporary, sizeof(temporary));
    return result;
}

int pcomm_ratchet_chain_step(const uint8_t chain[32], uint8_t next[32],
                             uint8_t message_key[32]) {
    if (!chain || !next || !message_key || overlaps_key(next, message_key)) return -1;
    static const uint8_t chain_label[] = "pcomm-ratchet-chain-v1";
    static const uint8_t message_label[] = "pcomm-ratchet-message-v1";
    uint8_t next_temporary[32], message_temporary[32];
    int result = -1;
    if (pcomm_ratchet_mac(chain, chain_label, sizeof(chain_label) - 1, next_temporary) == 0 &&
        pcomm_ratchet_mac(chain, message_label, sizeof(message_label) - 1, message_temporary) == 0) {
        memcpy(next, next_temporary, sizeof(next_temporary));
        memcpy(message_key, message_temporary, sizeof(message_temporary));
        result = 0;
    }
    OPENSSL_cleanse(next_temporary, sizeof(next_temporary));
    OPENSSL_cleanse(message_temporary, sizeof(message_temporary));
    return result;
}

int pcomm_ratchet_derive(const uint8_t shared[32], const uint8_t *transcript,
                         size_t len, uint8_t root[32], uint8_t initiator_chain[32],
                         uint8_t responder_chain[32]) {
    if (!shared || !root || !initiator_chain || !responder_chain || (!transcript && len) ||
        overlaps_key(root, initiator_chain) || overlaps_key(root, responder_chain) ||
        overlaps_key(initiator_chain, responder_chain)) return -1;
    static const uint8_t info[] = "pcomm-ratchet-session-v1";
    static const uint8_t empty = 0;
    uint8_t salt[SHA256_DIGEST_LENGTH], output[96];
    int result = -1;
    if (SHA256(transcript ? transcript : &empty, len, salt) &&
        pcomm_hkdf_sha256(shared, 32, salt, sizeof(salt), info, sizeof(info) - 1,
                          output, sizeof(output)) == 0) {
        memcpy(root, output, 32);
        memcpy(initiator_chain, output + 32, 32);
        memcpy(responder_chain, output + 64, 32);
        result = 0;
    }
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(output, sizeof(output));
    return result;
}

int pcomm_ratchet_keygen(uint8_t priv[32], uint8_t pub[32]) {
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    size_t private_len = 32, public_len = 32;
    int result = -1;
    if (!priv || !pub || overlaps_key(priv, pub)) goto done;
    context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!context || EVP_PKEY_keygen_init(context) != 1 ||
        EVP_PKEY_keygen(context, &key) != 1 ||
        EVP_PKEY_get_raw_private_key(key, priv, &private_len) != 1 || private_len != 32 ||
        EVP_PKEY_get_raw_public_key(key, pub, &public_len) != 1 || public_len != 32) goto done;
    result = 0;
done:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    if (result != 0) {
        if (priv) OPENSSL_cleanse(priv, 32);
        if (pub) OPENSSL_cleanse(pub, 32);
    }
    return result;
}
