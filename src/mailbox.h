#ifndef PCOMM_MAILBOX_H
#define PCOMM_MAILBOX_H

#include "db.h"
#include <stddef.h>
#include <stdint.h>

typedef struct pcomm_mailbox_guard pcomm_mailbox_guard_t;

pcomm_mailbox_guard_t *pcomm_mailbox_guard_create(size_t source_capacity);

void pcomm_mailbox_guard_destroy(pcomm_mailbox_guard_t *guard);

int pcomm_mailbox_deposit(pcomm_mailbox_guard_t *guard, pcomm_db_t *db,
                          const char *peer_ip, const uint8_t *payload,
                          uint32_t payload_len, uint64_t now_ms,
                          int64_t received_unix, uint8_t infohash_out[20]);

#endif
