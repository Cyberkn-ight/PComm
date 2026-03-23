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


typedef void (*pcomm_relay_event_cb)(void *arg, pcomm_circuit_t *c,
                                     uint8_t relay_cmd, uint16_t stream_id,
                                     const uint8_t *body, uint16_t body_len);

// Create a dedicated circuit whose exit hop is (exit_host:exit_port). Useful for hidden-service
// intro/rendezvous circuits. The circuit runs its own RX thread.
// Returns owned pointer; free with pcomm_circuit_close().
pcomm_circuit_t *pcomm_circuit_create_to_exit(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db,
                                              const char *exit_host, uint16_t exit_port,
                                              const char *exclude_uid);

// Close and free a dedicated circuit created with pcomm_circuit_create_to_exit.
void pcomm_circuit_close(pcomm_circuit_t *c);

// Set an optional callback invoked for RELAY cells that are not consumed by an RPC waiter.
int pcomm_circuit_set_event_cb(pcomm_circuit_t *c, pcomm_relay_event_cb cb, void *arg);

// Send a raw RELAY command over the circuit (stream_id is caller-chosen; 0 recommended for control).
int pcomm_circuit_send_relay(pcomm_circuit_t *c, uint8_t relay_cmd, uint16_t stream_id,
                            const uint8_t *body, uint16_t body_len);

// Allocate a new stream id (for custom uses like rendezvous data streams).
int pcomm_circuit_alloc_stream(pcomm_circuit_t *c, uint16_t *stream_id_out);

#endif
