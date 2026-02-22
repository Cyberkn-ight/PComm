#include "msg.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

static void put_u16(uint8_t *p, uint16_t v) { uint16_t n = htons(v); memcpy(p,&n,2); }
static void put_u32(uint8_t *p, uint32_t v) { uint32_t n = htonl(v); memcpy(p,&n,4); }
static uint16_t get_u16(const uint8_t *p) { uint16_t n; memcpy(&n,p,2); return ntohs(n); }
static uint32_t get_u32(const uint8_t *p) { uint32_t n; memcpy(&n,p,4); return ntohl(n); }

int pcomm_msg_pack_plain(uint32_t ts_unix, const char *sender_id, const char *text,
                         uint8_t **out, size_t *out_len) {
    if (!sender_id || !text || !out || !out_len) return -1;
    size_t sid_len = strlen(sender_id);
    size_t tlen = strlen(text);
    if (sid_len > 90) return -1;

    size_t len = 1 + 4 + 2 + sid_len + 4 + tlen;
    uint8_t *buf = (uint8_t*)malloc(len);
    if (!buf) return -1;

    size_t off = 0;
    buf[off++] = 1;
    put_u32(buf + off, ts_unix); off += 4;
    put_u16(buf + off, (uint16_t)sid_len); off += 2;
    memcpy(buf + off, sender_id, sid_len); off += sid_len;
    put_u32(buf + off, (uint32_t)tlen); off += 4;
    memcpy(buf + off, text, tlen); off += tlen;

    if (off != len) { free(buf); return -1; }
    *out = buf;
    *out_len = len;
    return 0;
}

int pcomm_msg_unpack_plain(const uint8_t *buf, size_t len,
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
