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

#endif
