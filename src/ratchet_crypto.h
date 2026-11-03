#ifndef PCOMM_RATCHET_CRYPTO_H
#define PCOMM_RATCHET_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int pcomm_ratchet_mac(const uint8_t key[32], const uint8_t *data, size_t len,
                      uint8_t mac[32]);

int pcomm_ratchet_chain_step(const uint8_t chain[32], uint8_t next[32],
                             uint8_t message_key[32]);

int pcomm_ratchet_derive(const uint8_t shared[32], const uint8_t *transcript,
                         size_t len, uint8_t root[32], uint8_t initiator_chain[32],
                         uint8_t responder_chain[32]);

int pcomm_ratchet_keygen(uint8_t priv[32], uint8_t pub[32]);

#endif
