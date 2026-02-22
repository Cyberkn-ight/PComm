#ifndef PCOMM_RELAY_H
#define PCOMM_RELAY_H

#include "pcomm.h"
#include "db.h"

int pcomm_relay_start(const pcomm_config_t *cfg, const pcomm_identity_t *id, pcomm_db_t *db);

#endif
