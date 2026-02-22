#ifndef PCOMM_HTTP_H
#define PCOMM_HTTP_H

#include "pcomm.h"
#include "db.h"

int pcomm_http_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db);

#endif
