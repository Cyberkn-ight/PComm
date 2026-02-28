#ifndef PCOMM_CRYPTO_H
#define PCOMM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int pcomm_x25519_derive(const uint8_t priv[32], const uint8_t pub[32], uint8_t out_shared[32]);
int pcomm_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *salt, size_t salt_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out, size_t out_len);
int pcomm_aead_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct_out, size_t *ct_len_inout);

int pcomm_aead_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt_out, size_t *pt_len_inout);

int pcomm_random(uint8_t *buf, size_t len);
int pcomm_seal_for_recipient(const uint8_t recipient_pub[32],
                             const uint8_t *msg, size_t msg_len,
                             uint8_t **out, size_t *out_len);

int pcomm_open_seal(const uint8_t recipient_priv[32],
                    const uint8_t *sealed, size_t sealed_len,
                    uint8_t **out_msg, size_t *out_msg_len);

#endif