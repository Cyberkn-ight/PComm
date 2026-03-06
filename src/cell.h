#ifndef PCOMM_CELL_H
#define PCOMM_CELL_H

#include "pcomm.h"
#include <stdint.h>
#include <stddef.h>

// Link-level cell header (unencrypted)
// circ_id(4) cmd(1) flags(1) len(2)  => 8 bytes total
#define PCOMM_CELL_HDR_LEN 8
#define PCOMM_CELL_MAX_PAYLOAD 4096u

// Build/parse link cells
int pcomm_cell_pack(uint32_t circ_id, uint8_t cmd, uint8_t flags, const uint8_t *payload, uint16_t payload_len,
                    uint8_t **out, uint32_t *out_len);

int pcomm_cell_unpack(const uint8_t *buf, uint32_t buf_len, uint32_t *circ_id, uint8_t *cmd, uint8_t *flags,
                      const uint8_t **payload, uint16_t *payload_len);

// RELAY plaintext format (after full decryption at the exit):
// relay_cmd(1) stream_id(2) rsv(1) body_len(2) body(...)
#define PCOMM_RELAY_HDR_LEN 6

int pcomm_relay_plain_pack(uint8_t relay_cmd, uint16_t stream_id, const uint8_t *body, uint16_t body_len,
                           uint8_t **out, uint16_t *out_len);

int pcomm_relay_plain_unpack(const uint8_t *buf, uint32_t buf_len, uint8_t *relay_cmd, uint16_t *stream_id,
                             const uint8_t **body, uint16_t *body_len);

// Onion-style layering for RELAY payloads.
// Each layer: nonce(12) || AEAD(ct||tag) using ChaCha20-Poly1305 with aad.
//
// Forward direction (client -> exit): client wraps from last hop to first.
int pcomm_relay_wrap_forward(const uint8_t (*keys_fwd)[32], size_t nhops, uint32_t circ_id,
                             const uint8_t *plain, uint16_t plain_len,
                             uint8_t **out, uint16_t *out_len);

// Relay decrypts exactly one forward layer
int pcomm_relay_unwrap_one_forward(const uint8_t key_fwd[32], uint32_t circ_id,
                                  const uint8_t *in, uint16_t in_len,
                                  uint8_t **out, uint16_t *out_len);

// Return direction (exit -> client): each hop adds one layer with its bwd key.
int pcomm_relay_wrap_one_backward(const uint8_t key_bwd[32], uint32_t circ_id,
                                 const uint8_t *in, uint16_t in_len,
                                 uint8_t **out, uint16_t *out_len);

// Client unwraps all backward layers (first hop to last)
int pcomm_relay_unwrap_backward_all(const uint8_t (*keys_bwd)[32], size_t nhops, uint32_t circ_id,
                                   const uint8_t *in, uint16_t in_len,
                                   uint8_t **plain, uint16_t *plain_len);

#endif
