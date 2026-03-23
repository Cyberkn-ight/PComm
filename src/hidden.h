#ifndef PCOMM_HIDDEN_H
#define PCOMM_HIDDEN_H

#include "pcomm.h"
#include "db.h"

int pcomm_hidden_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db);

int pcomm_hidden_mailbox_send(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                              const char *recipient_id,
                              const uint8_t *sealed, size_t sealed_len);

int pcomm_hidden_send_direct_text(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                                  const char *to_user_id, const char *text);
int pcomm_hidden_send_group_invite(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                                   const char *member_id,
                                   const char *group_uuid, const char *title,
                                   char **members, int member_count);
int pcomm_hidden_send_group_text(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                                 const char *member_id,
                                 const char *group_uuid, const char *text);

#endif
