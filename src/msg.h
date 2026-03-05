#ifndef PCOMM_MSG_H
#define PCOMM_MSG_H

#include <stdint.h>
#include <stddef.h>

// Plaintext format (sealed end-to-end):
// v2:
//   ver(u8=2) kind(u8) ts(u32)
//   sender_len(u16) sender
//   ... kind-specific
// v1 (legacy):
//   ver(u8=1) ts(u32) sender_len(u16) sender text_len(u32) text

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

// Unpack any supported version.
// For DIRECT_TEXT: text_out_malloc is set.
// For GROUP_INVITE: group_uuid_out, title_out_malloc, members_out_malloc/member_count_out are set.
// For GROUP_TEXT: group_uuid_out and text_out_malloc are set.
int pcomm_msg_unpack_any(const uint8_t *buf, size_t len,
                         pcomm_plain_kind_t *kind_out,
                         uint32_t *ts_unix_out,
                         char *sender_id_out, size_t sender_id_cap,
                         char *group_uuid_out, size_t group_uuid_cap,
                         char **title_out_malloc,
                         char ***members_out_malloc, int *member_count_out,
                         char **text_out_malloc);

// helpers to free arrays from unpack
void pcomm_msg_free_members(char **members, int count);

#endif
