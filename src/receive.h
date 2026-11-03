#ifndef PCOMM_RECEIVE_H
#define PCOMM_RECEIVE_H

#include "db.h"
#include "pcomm.h"

int pcomm_receive_sealed(pcomm_db_t *db, const pcomm_identity_t *recipient,
                         const uint8_t *sealed, size_t sealed_len,
                         uint32_t fallback_ts);

#endif
