#ifndef PCOMM_MSG_H
#define PCOMM_MSG_H

#include <stdint.h>
#include <stddef.h>


int pcomm_msg_pack_plain(uint32_t ts_unix, const char *sender_id, const char *text,
                         uint8_t **out, size_t *out_len);

int pcomm_msg_unpack_plain(const uint8_t *buf, size_t len,
                           uint32_t *ts_unix_out,
                           char *sender_id_out, size_t sender_id_cap,
                           char **text_out_malloc);

#endif
