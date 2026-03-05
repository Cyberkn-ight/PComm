#ifndef PCOMM_CIRCUIT_H
#define PCOMM_CIRCUIT_H

#include "pcomm.h"
#include "db.h"
#include <stdint.h>
#include <stddef.h>

typedef struct pcomm_circuit pcomm_circuit_t;

// Start global circuit manager. It will keep at least one 3-hop circuit alive for onion-routed RPCs.
int pcomm_circuits_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db);

// Get current circuit (may be NULL if not ready).
pcomm_circuit_t *pcomm_circuit_get(void);

// Perform a single RPC over the circuit using stream multiplexing.
// It opens a stream to dest_host:dest_port, sends one packed PComm packet (inner_type/payload),
// optionally waits for one response packet, then closes the stream.
int pcomm_circuit_rpc(pcomm_circuit_t *c,
                      const char *dest_host, uint16_t dest_port,
                      pcomm_msg_type_t inner_type,
                      const uint8_t *inner_payload, uint32_t inner_payload_len,
                      int expect_resp,
                      pcomm_msg_type_t *resp_type_out,
                      uint8_t **resp_payload_out, uint32_t *resp_payload_len_out);

#endif
