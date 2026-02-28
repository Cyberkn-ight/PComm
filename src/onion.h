#ifndef PCOMM_ONION_H
#define PCOMM_ONION_H

#include "pcomm.h"
#include <stddef.h>
#include <stdint.h>

int pcomm_onion_build_v1(const pcomm_peer_t *path, size_t path_len,
                         const char *dest_host, uint16_t dest_port,
                         pcomm_msg_type_t deliver_type,
                         const uint8_t *deliver_payload, size_t deliver_len,
                         int roundtrip,
                         uint8_t eph_pub_out[32],
                         uint8_t **onion_payload_out, uint32_t *onion_payload_len_out);

int pcomm_onion_unwrap_v1(const uint8_t relay_priv[32], const uint8_t eph_pub[32],
                          const uint8_t *payload, uint32_t payload_len,
                          pcomm_inst_t *inst_out,
                          char *next_host_out, size_t next_host_cap, uint16_t *next_port_out,
                          uint8_t **next_payload_out, uint32_t *next_payload_len_out,
                          char *dest_host_out, size_t dest_host_cap, uint16_t *dest_port_out,
                          pcomm_msg_type_t *deliver_type_out,
                          uint8_t *deliver_flags_out,
                          uint8_t **deliver_payload_out, uint32_t *deliver_len_out);

#endif
