#ifndef PCOMM_MSG_H
#define PCOMM_MSG_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    PCOMM_PLAIN_DIRECT_TEXT = 1,
    PCOMM_PLAIN_GROUP_INVITE = 2,
    PCOMM_PLAIN_GROUP_TEXT = 3,
} pcomm_plain_kind_t;

int pcomm_msg_pack_direct_text(uint32_t ts_unix, const char *sender_id, const char *text,
                               uint8_t **out, size_t *out_len);

int pcomm_msg_pack_group_invite(uint32_t ts_unix, const char *sender_id,
                                const char *group_uuid, const char *title,
                                char **members, int member_count,
                                uint8_t **out, size_t *out_len);

int pcomm_msg_pack_group_text(uint32_t ts_unix, const char *sender_id,
                              const char *group_uuid, const char *text,
                              uint8_t **out, size_t *out_len);

int pcomm_msg_unpack_any(const uint8_t *buf, size_t len,
                         pcomm_plain_kind_t *kind_out,
                         uint32_t *ts_unix_out,
                         char *sender_id_out, size_t sender_id_cap,
                         char *group_uuid_out, size_t group_uuid_cap,
                         char **title_out_malloc,
                         char ***members_out_malloc, int *member_count_out,
                         char **text_out_malloc);

// Why does VSC auto format de code like this
void pcomm_msg_free_members(char **members, int count);

#endif
