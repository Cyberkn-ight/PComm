#ifndef PCOMM_IDENTITY_H
#define PCOMM_IDENTITY_H

#include "pcomm.h"

// Loads identity from data_dir/identity.key, or creates a new one.
// Fills id->privkey/pubkey/user_id.
int pcomm_identity_load_or_create(pcomm_identity_t *id, const char *data_dir);

// Converts pubkey to user ID string.
int pcomm_user_id_from_pubkey(const uint8_t pubkey[32], char out[96]);

// Extracts pubkey from user ID (verifies checksum). Returns 0 on success.
int pcomm_pubkey_from_user_id(const char *user_id, uint8_t pubkey_out[32]);

#endif
