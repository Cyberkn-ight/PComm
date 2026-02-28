#include "msg.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

static void put_u16(uint8_t *p, uint16_t v) { uint16_t n = htons(v); memcpy(p,&n,2); }
static void put_u32(uint8_t *p, uint32_t v) { uint32_t n = htonl(v); memcpy(p,&n,4); }
static uint16_t get_u16(const uint8_t *p) { uint16_t n; memcpy(&n,p,2); return ntohs(n); }
static uint32_t get_u32(const uint8_t *p) { uint32_t n; memcpy(&n,p,4); return ntohl(n); }

int pcomm_msg_pack_direct_text(uint32_t ts_unix, const char *sender_id, const char *text,
                               uint8_t **out, size_t *out_len) {
    if (!sender_id || !text || !out || !out_len) return -1;
    size_t sid_len = strlen(sender_id);
    size_t tlen = strlen(text);
    if (sid_len > 90) return -1;
    size_t len = 1 + 1 + 4 + 2 + sid_len + 4 + tlen;
    uint8_t *buf = (uint8_t*)malloc(len);
    if (!buf) return -1;

    size_t off = 0;
    buf[off++] = 2;
    buf[off++] = (uint8_t)PCOMM_PLAIN_DIRECT_TEXT;
    put_u32(buf + off, ts_unix); off += 4;
    put_u16(buf + off, (uint16_t)sid_len); off += 2;
    memcpy(buf + off, sender_id, sid_len); off += sid_len;
    put_u32(buf + off, (uint32_t)tlen); off += 4;
    memcpy(buf + off, text, tlen); off += tlen;

    if (off != len) { free(buf); return -1; }
    *out = buf; *out_len = len;
    return 0;
}

int pcomm_msg_pack_group_invite(uint32_t ts_unix, const char *sender_id,
                                const char *group_uuid, const char *title,
                                char **members, int member_count,
                                uint8_t **out, size_t *out_len) {
    if (!sender_id || !group_uuid || !out || !out_len) return -1;
    if (member_count < 0) return -1;
    size_t sid_len = strlen(sender_id);
    size_t uuid_len = strlen(group_uuid);
    size_t title_len = title ? strlen(title) : 0;
    if (sid_len > 90 || uuid_len > 63 || title_len > 1024) return -1;

    size_t members_bytes = 0;
    for (int i = 0; i < member_count; i++) {
        if (!members[i]) continue;
        size_t ml = strlen(members[i]);
        if (ml > 90) return -1;
        members_bytes += 2 + ml;
    }

    // ver kind ts sid uuid title member_count(u16) members... bro wtf am I doing
    size_t len = 1 + 1 + 4 + 2 + sid_len + 1 + uuid_len + 2 + title_len + 2 + members_bytes;
    uint8_t *buf = (uint8_t*)malloc(len);
    if (!buf) return -1;

    size_t off = 0;
    buf[off++] = 2;
    buf[off++] = (uint8_t)PCOMM_PLAIN_GROUP_INVITE;
    put_u32(buf + off, ts_unix); off += 4;
    put_u16(buf + off, (uint16_t)sid_len); off += 2;
    memcpy(buf + off, sender_id, sid_len); off += sid_len;

    buf[off++] = (uint8_t)uuid_len;
    memcpy(buf + off, group_uuid, uuid_len); off += uuid_len;

    put_u16(buf + off, (uint16_t)title_len); off += 2;
    if (title_len) { memcpy(buf + off, title, title_len); off += title_len; }

    put_u16(buf + off, (uint16_t)member_count); off += 2;
    for (int i = 0; i < member_count; i++) {
        size_t ml = members[i] ? strlen(members[i]) : 0;
        put_u16(buf + off, (uint16_t)ml); off += 2;
        if (ml) { memcpy(buf + off, members[i], ml); off += ml; }
    }

    if (off != len) { free(buf); return -1; }
    *out = buf; *out_len = len;
    return 0;
}

int pcomm_msg_pack_group_text(uint32_t ts_unix, const char *sender_id,
                              const char *group_uuid, const char *text,
                              uint8_t **out, size_t *out_len) {
    if (!sender_id || !group_uuid || !text || !out || !out_len) return -1;
    size_t sid_len = strlen(sender_id);
    size_t uuid_len = strlen(group_uuid);
    size_t tlen = strlen(text);
    if (sid_len > 90 || uuid_len > 63) return -1;

    size_t len = 1 + 1 + 4 + 2 + sid_len + 1 + uuid_len + 4 + tlen;
    uint8_t *buf = (uint8_t*)malloc(len);
    if (!buf) return -1;

    size_t off = 0;
    buf[off++] = 2;
    buf[off++] = (uint8_t)PCOMM_PLAIN_GROUP_TEXT;
    put_u32(buf + off, ts_unix); off += 4;
    put_u16(buf + off, (uint16_t)sid_len); off += 2;
    memcpy(buf + off, sender_id, sid_len); off += sid_len;

    buf[off++] = (uint8_t)uuid_len;
    memcpy(buf + off, group_uuid, uuid_len); off += uuid_len;

    put_u32(buf + off, (uint32_t)tlen); off += 4;
    memcpy(buf + off, text, tlen); off += tlen;

    if (off != len) { free(buf); return -1; }
    *out = buf; *out_len = len;
    return 0;
}

static int unpack_v1(const uint8_t *buf, size_t len,
                     uint32_t *ts_unix_out,
                     char *sender_id_out, size_t sender_id_cap,
                     char **text_out_malloc) {
    if (!buf || len < 1 + 4 + 2 + 4 || !ts_unix_out || !sender_id_out || !text_out_malloc) return -1;
    size_t off = 0;
    uint8_t ver = buf[off++];
    if (ver != 1) return -1;

    *ts_unix_out = get_u32(buf + off); off += 4;
    uint16_t sid_len = get_u16(buf + off); off += 2;
    if (sid_len >= sender_id_cap) return -1;
    if (len < off + sid_len + 4) return -1;
    memcpy(sender_id_out, buf + off, sid_len);
    sender_id_out[sid_len] = '\0';
    off += sid_len;

    uint32_t tlen = get_u32(buf + off); off += 4;
    if (len < off + tlen) return -1;
    char *txt = (char*)malloc((size_t)tlen + 1);
    if (!txt) return -1;
    memcpy(txt, buf + off, tlen);
    txt[tlen] = '\0';
    *text_out_malloc = txt;
    return 0;
}

int pcomm_msg_unpack_any(const uint8_t *buf, size_t len,
                         pcomm_plain_kind_t *kind_out,
                         uint32_t *ts_unix_out,
                         char *sender_id_out, size_t sender_id_cap,
                         char *group_uuid_out, size_t group_uuid_cap,
                         char **title_out_malloc,
                         char ***members_out_malloc, int *member_count_out,
                         char **text_out_malloc) {
    if (!buf || len < 1 || !kind_out || !ts_unix_out || !sender_id_out) return -1;
    if (group_uuid_out && group_uuid_cap) group_uuid_out[0] = '\0';
    if (title_out_malloc) *title_out_malloc = NULL;
    if (members_out_malloc) *members_out_malloc = NULL;
    if (member_count_out) *member_count_out = 0;
    if (text_out_malloc) *text_out_malloc = NULL;

    uint8_t ver = buf[0];
    if (ver == 1) {
        *kind_out = PCOMM_PLAIN_DIRECT_TEXT;
        return unpack_v1(buf, len, ts_unix_out, sender_id_out, sender_id_cap, text_out_malloc);
    }
    if (ver != 2) return -1;
    if (len < 1 + 1 + 4 + 2) return -1;

    size_t off = 0;
    off++;
    uint8_t kind = buf[off++];
    *kind_out = (pcomm_plain_kind_t)kind;

    *ts_unix_out = get_u32(buf + off); off += 4;
    uint16_t sid_len = get_u16(buf + off); off += 2;
    if (sid_len >= sender_id_cap) return -1;
    if (len < off + sid_len) return -1;
    memcpy(sender_id_out, buf + off, sid_len);
    sender_id_out[sid_len] = '\0';
    off += sid_len;

    if (kind == PCOMM_PLAIN_DIRECT_TEXT) {
        if (len < off + 4) return -1;
        uint32_t tlen = get_u32(buf + off); off += 4;
        if (len < off + tlen) return -1;
        char *txt = (char*)malloc((size_t)tlen + 1);
        if (!txt) return -1;
        memcpy(txt, buf + off, tlen);
        txt[tlen] = '\0';
        if (text_out_malloc) *text_out_malloc = txt; else free(txt);
        return 0;
    }

    if (kind == PCOMM_PLAIN_GROUP_INVITE) {
        if (len < off + 1) return -1;
        uint8_t uuid_len = buf[off++];
        if (uuid_len >= group_uuid_cap) return -1;
        if (len < off + uuid_len + 2) return -1;
        if (group_uuid_out) {
            memcpy(group_uuid_out, buf + off, uuid_len);
            group_uuid_out[uuid_len] = '\0';
        }
        off += uuid_len;

        uint16_t title_len = get_u16(buf + off); off += 2;
        if (len < off + title_len + 2) return -1;
        if (title_out_malloc) {
            char *t = (char*)malloc((size_t)title_len + 1);
            if (!t) return -1;
            memcpy(t, buf + off, title_len);
            t[title_len] = '\0';
            *title_out_malloc = t;
        }
        off += title_len;

        uint16_t mcount = get_u16(buf + off); off += 2;
        if (members_out_malloc && member_count_out) {
            char **arr = (char**)calloc((size_t)mcount, sizeof(char*));
            if (!arr) return -1;
            for (uint16_t i = 0; i < mcount; i++) {
                if (len < off + 2) { pcomm_msg_free_members(arr, i); return -1; }
                uint16_t ml = get_u16(buf + off); off += 2;
                if (len < off + ml) { pcomm_msg_free_members(arr, i); return -1; }
                arr[i] = (char*)malloc((size_t)ml + 1);
                if (!arr[i]) { pcomm_msg_free_members(arr, i); return -1; }
                memcpy(arr[i], buf + off, ml);
                arr[i][ml] = '\0';
                off += ml;
            }
            *members_out_malloc = arr;
            *member_count_out = (int)mcount;
        } else {
            for (uint16_t i = 0; i < mcount; i++) {
                if (len < off + 2) return -1;
                uint16_t ml = get_u16(buf + off); off += 2;
                if (len < off + ml) return -1;
                off += ml;
            }
        }
        return 0;
    }

    if (kind == PCOMM_PLAIN_GROUP_TEXT) {
        if (len < off + 1) return -1;
        uint8_t uuid_len = buf[off++];
        if (uuid_len >= group_uuid_cap) return -1;
        if (len < off + uuid_len + 4) return -1;
        if (group_uuid_out) {
            memcpy(group_uuid_out, buf + off, uuid_len);
            group_uuid_out[uuid_len] = '\0';
        }
        off += uuid_len;

        uint32_t tlen = get_u32(buf + off); off += 4;
        if (len < off + tlen) return -1;
        char *txt = (char*)malloc((size_t)tlen + 1);
        if (!txt) return -1;
        memcpy(txt, buf + off, tlen);
        txt[tlen] = '\0';
        if (text_out_malloc) *text_out_malloc = txt; else free(txt);
        return 0;
    }

    return -1;
}

void pcomm_msg_free_members(char **members, int count) {
    if (!members) return;
    for (int i = 0; i < count; i++) free(members[i]);
    free(members);
}
