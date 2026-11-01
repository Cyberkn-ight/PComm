#ifndef PCOMM_RECEIVE_H
#define PCOMM_RECEIVE_H

#include "db.h"
#include "pcomm.h"

/* Shared by mailbox, rendezvous, and legacy direct delivery. Returns 0 after
 * storage, 1 for a silently ignored replay, and -1 on validation/storage error.
 * Replay state is bounded and local to this database's current process lifetime.
 */
int pcomm_receive_sealed(pcomm_db_t *db, const pcomm_identity_t *recipient,
                         const uint8_t *sealed, size_t sealed_len,
                         uint32_t fallback_ts);

#endif
