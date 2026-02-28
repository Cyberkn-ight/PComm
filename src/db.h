#ifndef PCOMM_DB_H
#define PCOMM_DB_H

#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    sqlite3 *db;
} pcomm_db_t;

int pcomm_db_open(pcomm_db_t *pdb, const char *data_dir);
void pcomm_db_close(pcomm_db_t *pdb);

int pcomm_db_init_schema(pcomm_db_t *pdb);

int pcomm_db_upsert_contact(pcomm_db_t *pdb, const char *user_id, const char *host, uint16_t port, const uint8_t pubkey[32], int is_relay);
int pcomm_db_get_contact(pcomm_db_t *pdb, const char *user_id, char *host_out, size_t host_cap, uint16_t *port_out, uint8_t pubkey_out[32], int *is_relay_out);

int64_t pcomm_db_get_or_create_direct_conv(pcomm_db_t *pdb, const char *peer_user_id);

int pcomm_db_insert_message(pcomm_db_t *pdb, int64_t conv_id, int direction, const char *peer_user_id,
                            const char *sender_user_id, const char *body_utf8,
                            const uint8_t *cipher, size_t cipher_len,
                            int64_t ts_unix);

int64_t pcomm_db_get_or_create_group_conv(pcomm_db_t *pdb, const char *uuid, const char *title);
int pcomm_db_add_participant(pcomm_db_t *pdb, int64_t conv_id, const char *user_id);
int pcomm_db_get_conversation_uuid(pcomm_db_t *pdb, int64_t conv_id, char *uuid_out, size_t uuid_cap, char *type_out, size_t type_cap);
int pcomm_db_list_group_participants(pcomm_db_t *pdb, int64_t conv_id, char ***ids_out, int *count_out);

int pcomm_db_mailbox_put(pcomm_db_t *pdb, const uint8_t key[32], const uint8_t *blob, uint32_t blob_len, int64_t ts_unix);
int pcomm_db_mailbox_get_and_delete(pcomm_db_t *pdb, const uint8_t key[32], uint8_t **out, uint32_t *out_len);
int pcomm_db_desc_put(pcomm_db_t *pdb, const uint8_t key[32], const uint8_t *blob, uint32_t blob_len, int64_t expires_unix, int64_t ts_unix);
int pcomm_db_desc_get(pcomm_db_t *pdb, const uint8_t key[32], uint8_t **blob_out, uint32_t *blob_len_out);

#endif
