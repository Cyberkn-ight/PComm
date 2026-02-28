#include "sendmsg.h"
#include "hidden.h"

int pcomm_send_text(pcomm_db_t *db, const pcomm_config_t *cfg, const pcomm_identity_t *me,
                    const char *to_user_id, const char *text) {
    return pcomm_hidden_send_direct_text(db, cfg, me, to_user_id, text);
}
