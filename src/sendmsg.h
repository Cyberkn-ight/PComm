#ifndef PCOMM_SENDMSG_H
#define PCOMM_SENDMSG_H

#include "pcomm.h"
#include "db.h"

int pcomm_send_text(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                    const char *to_user_id, const char *text);

#endif
