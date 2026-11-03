#ifndef PCOMM_RATCHET_H
#define PCOMM_RATCHET_H

#include "db.h"
#include "pcomm.h"

#define PCOMM_RATCHET_MAX_SKIP 128u
#define PCOMM_RATCHET_MAX_PENDING 64u
#define PCOMM_RATCHET_MAX_OUTBOX 4096u
#define PCOMM_RATCHET_MAX_SESSIONS 4096u

typedef struct {
    int64_t id;
    char peer[96];
    uint8_t *sealed;
    size_t sealed_len;
} pcomm_ratchet_outgoing_t;

typedef int (*pcomm_ratchet_store_fn)(void *arg, const char *sender,
                                      const char *context,
                                      const uint8_t *plain, size_t plain_len);

int pcomm_ratchet_send(pcomm_db_t *db, const pcomm_identity_t *me,
                       const char *peer, const char *context,
                       const uint8_t *plain, size_t plain_len);

int pcomm_ratchet_is_packet(const uint8_t *plain, size_t plain_len);
int pcomm_ratchet_has_session(pcomm_db_t *db, const pcomm_identity_t *me,
                              const char *peer, const char *context);

int pcomm_ratchet_receive(pcomm_db_t *db, const pcomm_identity_t *me,
                          const uint8_t *packet, size_t packet_len,
                          pcomm_ratchet_store_fn store, void *arg);

int pcomm_ratchet_outbox_next(pcomm_db_t *db, int64_t now_unix,
                              pcomm_ratchet_outgoing_t *out);
int pcomm_ratchet_outbox_sent(pcomm_db_t *db, int64_t id, int transport_ok);
void pcomm_ratchet_outgoing_free(pcomm_ratchet_outgoing_t *out);

#endif
