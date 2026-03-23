#ifndef PCOMM_CIRCUIT_H
#define PCOMM_CIRCUIT_H

#include "pcomm.h"
#include "db.h"
#include <stdint.h>
#include <stddef.h>

typedef struct pcomm_circuit pcomm_circuit_t;

int pcomm_circuits_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db);

pcomm_circuit_t *pcomm_circuit_get(void);

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

pcomm_circuit_t *pcomm_circuit_create_to_exit(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db,
                                              const char *exit_host, uint16_t exit_port,
                                              const char *exclude_uid);

void pcomm_circuit_close(pcomm_circuit_t *c);
int pcomm_circuit_set_event_cb(pcomm_circuit_t *c, pcomm_relay_event_cb cb, void *arg);
int pcomm_circuit_send_relay(pcomm_circuit_t *c, uint8_t relay_cmd, uint16_t stream_id,
                            const uint8_t *body, uint16_t body_len);
int pcomm_circuit_alloc_stream(pcomm_circuit_t *c, uint16_t *stream_id_out);

#endif
