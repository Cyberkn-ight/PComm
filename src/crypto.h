#ifndef PCOMM_CRYPTO_H
#define PCOMM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

// Derive shared secret: X25519(priv(32), pub(32)) -> out(32). Returns 0 on success.
int pcomm_x25519_derive(const uint8_t priv[32], const uint8_t pub[32], uint8_t out_shared[32]);

// HKDF-SHA256 to derive key material.
int pcomm_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *salt, size_t salt_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out, size_t out_len);

// AEAD ChaCha20-Poly1305 (IETF 96-bit nonce). Tag is appended to ciphertext.
int pcomm_aead_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct_out, size_t *ct_len_inout);

int pcomm_aead_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt_out, size_t *pt_len_inout);

// Random bytes
int pcomm_random(uint8_t *buf, size_t len);

// Sealed-box style: encrypt for recipient pubkey.
// Output format: eph_pub(32) || nonce(12) || ciphertext||tag
int pcomm_seal_for_recipient(const uint8_t recipient_pub[32],
                             const uint8_t *msg, size_t msg_len,
                             uint8_t **out, size_t *out_len);

// Decrypt sealed box using recipient priv.
int pcomm_open_seal(const uint8_t recipient_priv[32],
                    const uint8_t *sealed, size_t sealed_len,
                    uint8_t **out_msg, size_t *out_msg_len);

#endif
