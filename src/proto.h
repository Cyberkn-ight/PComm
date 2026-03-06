#ifndef PCOMM_PROTO_H
#define PCOMM_PROTO_H

#include "pcomm.h"
#include <stddef.h>
#include <stdint.h>

#define PCOMM_EPH_PUB_LEN 32

// Header: magic(4) version(1) type(1) rsv(2) payload_len(4) eph_pub(32)
#define PCOMM_HDR_LEN (4+1+1+2+4+32)

int pcomm_send_packet(int fd, pcomm_msg_type_t type, const uint8_t eph_pub[32], const uint8_t *payload, uint32_t payload_len);

// Allocates payload; caller frees.
int pcomm_recv_packet(int fd, pcomm_msg_type_t *type_out, uint8_t eph_pub_out[32], uint8_t **payload_out, uint32_t *payload_len_out);

// Helpers for stream-multiplexing: build a complete packet into a buffer.
// Allocates *out; caller frees.
int pcomm_pack_packet(pcomm_msg_type_t type, const uint8_t eph_pub[32], const uint8_t *payload, uint32_t payload_len,
                      uint8_t **out, uint32_t *out_len);

// Parse a complete packet from a buffer. Allocates *payload_out; caller frees.
int pcomm_unpack_packet(const uint8_t *buf, uint32_t buf_len, pcomm_msg_type_t *type_out, uint8_t eph_pub_out[32],
                        uint8_t **payload_out, uint32_t *payload_len_out);

#endif
