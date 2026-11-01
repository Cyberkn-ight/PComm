#ifndef PCOMM_MAILBOX_H
#define PCOMM_MAILBOX_H

#include "db.h"
#include <stddef.h>
#include <stdint.h>

typedef struct pcomm_mailbox_guard pcomm_mailbox_guard_t;

pcomm_mailbox_guard_t *pcomm_mailbox_guard_create(size_t source_capacity);
/* Call after all deposit workers have stopped. */
void pcomm_mailbox_guard_destroy(pcomm_mailbox_guard_t *guard);

/*
 * Admit a complete CTRL_MB_PUT frame using the kernel-observed numeric peer IP.
 * Returns 0 when stored, 1 when rejected, and -1 on an internal error. Only a
 * successful store writes infohash_out. Source addresses are hashed in bounded
 * RAM state and are never passed to storage. now_ms is local monotonic time;
 * received_unix is the relay's receive time, not a value from the message.
 * Malformed/quota-rejected deposits consume an admitted attempt's rate budget.
 */
int pcomm_mailbox_deposit(pcomm_mailbox_guard_t *guard, pcomm_db_t *db,
                          const char *peer_ip, const uint8_t *payload,
                          uint32_t payload_len, uint64_t now_ms,
                          int64_t received_unix, uint8_t infohash_out[20]);

#endif
