#ifndef PCOMM_PROTO_H
#define PCOMM_PROTO_H

#include "pcomm.h"
#include <stddef.h>
#include <stdint.h>

#define PCOMM_EPH_PUB_LEN 32
#define PCOMM_HDR_LEN (4+1+1+2+4+32)
#define PCOMM_MAX_PACKET_PAYLOAD 65536u
#define PCOMM_MAX_PACKET_LEN (PCOMM_HDR_LEN + PCOMM_MAX_PACKET_PAYLOAD)

int pcomm_send_packet(int fd, pcomm_msg_type_t type, const uint8_t eph_pub[32], const uint8_t *payload, uint32_t payload_len);
int pcomm_recv_packet(int fd, pcomm_msg_type_t *type_out, uint8_t eph_pub_out[32], uint8_t **payload_out, uint32_t *payload_len_out);
int pcomm_pack_packet(pcomm_msg_type_t type, const uint8_t eph_pub[32], const uint8_t *payload, uint32_t payload_len,
                      uint8_t **out, uint32_t *out_len);
int pcomm_unpack_packet(const uint8_t *buf, uint32_t buf_len, pcomm_msg_type_t *type_out, uint8_t eph_pub_out[32],
                        uint8_t **payload_out, uint32_t *payload_len_out);

/* Append one fragment without exceeding the maximum framed packet size.
 * Failure leaves the buffer and length unchanged. data may overlap the current
 * buffer; a zero-length append is a no-op and may use NULL data.
 */
int pcomm_packet_append(uint8_t **buffer, uint32_t *length,
                         const uint8_t *data, uint32_t data_len);

#endif
