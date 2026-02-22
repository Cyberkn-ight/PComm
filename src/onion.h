#ifndef PCOMM_ONION_H
#define PCOMM_ONION_H

#include "pcomm.h"
#include <stddef.h>
#include <stdint.h>

int pcomm_onion_build(const pcomm_peer_t *path, size_t path_len,
                      const char *dest_host, uint16_t dest_port,
                      const char *recipient_id,
                      const uint8_t *sealed, size_t sealed_len,
                      uint8_t eph_pub_out[32],
                      uint8_t **onion_payload_out, uint32_t *onion_payload_len_out);

int pcomm_onion_unwrap(const uint8_t relay_priv[32], const uint8_t eph_pub[32],
                       const uint8_t *payload, uint32_t payload_len,
                       pcomm_inst_t *inst_out,
                       char *next_host_out, size_t next_host_cap, uint16_t *next_port_out,
                       uint8_t **next_payload_out, uint32_t *next_payload_len_out,
                       char *recipient_id_out, size_t recipient_id_cap,
                       uint8_t **sealed_out, uint32_t *sealed_len_out,
                       char *dest_host_out, size_t dest_host_cap, uint16_t *dest_port_out);

#endif
