#ifndef PCOMM_IDENTITY_H
#define PCOMM_IDENTITY_H

#include "pcomm.h"

int pcomm_identity_load_or_create(pcomm_identity_t *id, const char *data_dir);

int pcomm_user_id_from_pubkey(const uint8_t pubkey[32], char out[96]);

int pcomm_pubkey_from_user_id(const char *user_id, uint8_t pubkey_out[32]);

#endif
