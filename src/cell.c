#include "cell.h"
#include "crypto.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static void put_u16(uint8_t *p, uint16_t v){ uint16_t n=htons(v); memcpy(p,&n,2); }
static void put_u32(uint8_t *p, uint32_t v){ uint32_t n=htonl(v); memcpy(p,&n,4); }
static uint16_t get_u16(const uint8_t *p){ uint16_t n; memcpy(&n,p,2); return ntohs(n); }
static uint32_t get_u32(const uint8_t *p){ uint32_t n; memcpy(&n,p,4); return ntohl(n); }

int pcomm_cell_pack(uint32_t circ_id, uint8_t cmd, uint8_t flags, const uint8_t *payload, uint16_t payload_len,
                    uint8_t **out, uint32_t *out_len) {
    if (!out || !out_len) return -1;
    *out = NULL; *out_len = 0;
    if (payload_len > PCOMM_CELL_MAX_PAYLOAD) return -1;

    uint32_t total = PCOMM_CELL_HDR_LEN + payload_len;
    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) return -1;

    put_u32(buf, circ_id);
    buf[4] = cmd;
    buf[5] = flags;
    put_u16(buf + 6, payload_len);
    if (payload_len && payload) memcpy(buf + PCOMM_CELL_HDR_LEN, payload, payload_len);

    *out = buf;
    *out_len = total;
    return 0;
}

int pcomm_cell_unpack(const uint8_t *buf, uint32_t buf_len, uint32_t *circ_id, uint8_t *cmd, uint8_t *flags,
                      const uint8_t **payload, uint16_t *payload_len) {
    if (!buf || buf_len < PCOMM_CELL_HDR_LEN || !circ_id || !cmd || !flags || !payload || !payload_len) return -1;

    *circ_id = get_u32(buf);
    *cmd = buf[4];
    *flags = buf[5];
    uint16_t pl = get_u16(buf + 6);
    if (PCOMM_CELL_HDR_LEN + pl != buf_len) return -1;
    *payload_len = pl;
    *payload = buf + PCOMM_CELL_HDR_LEN;
    return 0;
}

int pcomm_relay_plain_pack(uint8_t relay_cmd, uint16_t stream_id, const uint8_t *body, uint16_t body_len,
                           uint8_t **out, uint16_t *out_len) {
    if (!out || !out_len) return -1;
    *out = NULL; *out_len = 0;
    uint32_t total = PCOMM_RELAY_HDR_LEN + body_len;
    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) return -1;
    buf[0] = relay_cmd;
    put_u16(buf + 1, stream_id);
    buf[3] = 0;
    put_u16(buf + 4, body_len);
    if (body_len && body) memcpy(buf + PCOMM_RELAY_HDR_LEN, body, body_len);
    *out = buf;
    *out_len = (uint16_t)total;
    return 0;
}

int pcomm_relay_plain_unpack(const uint8_t *buf, uint32_t buf_len, uint8_t *relay_cmd, uint16_t *stream_id,
                             const uint8_t **body, uint16_t *body_len) {
    if (!buf || buf_len < PCOMM_RELAY_HDR_LEN || !relay_cmd || !stream_id || !body || !body_len) return -1;
    *relay_cmd = buf[0];
    *stream_id = get_u16(buf + 1);
    uint16_t bl = get_u16(buf + 4);
    if (PCOMM_RELAY_HDR_LEN + bl != buf_len) return -1;
    *body_len = bl;
    *body = buf + PCOMM_RELAY_HDR_LEN;
    return 0;
}

static int layer_encrypt(const uint8_t key[32], uint32_t circ_id,
                         const uint8_t *in, uint16_t in_len,
                         uint8_t **out, uint16_t *out_len) {
    uint8_t nonce[12];
    if (pcomm_random(nonce, sizeof(nonce)) != 0) return -1;

    // aad = "pcomm-relay" || circ_id_be
    uint8_t aad[16];
    memset(aad, 0, sizeof(aad));
    memcpy(aad, "pcomm-relay", 10);
    uint32_t cid = htonl(circ_id);
    memcpy(aad + 12, &cid, 4);

    size_t ct_cap = (size_t)in_len + 16;
    uint8_t *ct = (uint8_t*)malloc(ct_cap);
    if (!ct) return -1;
    size_t ct_len = ct_cap;
    if (pcomm_aead_encrypt(key, nonce, aad, sizeof(aad), in, in_len, ct, &ct_len) != 0) {
        free(ct);
        return -1;
    }

    uint32_t total = 12 + (uint32_t)ct_len;
    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) { free(ct); return -1; }
    memcpy(buf, nonce, 12);
    memcpy(buf + 12, ct, ct_len);
    free(ct);

    *out = buf;
    *out_len = (uint16_t)total;
    return 0;
}

static int layer_decrypt(const uint8_t key[32], uint32_t circ_id,
                         const uint8_t *in, uint16_t in_len,
                         uint8_t **out, uint16_t *out_len) {
    if (in_len < 12 + 16) return -1;
    const uint8_t *nonce = in;
    const uint8_t *ct = in + 12;
    size_t ct_len = (size_t)in_len - 12;

    uint8_t aad[16];
    memset(aad, 0, sizeof(aad));
    memcpy(aad, "pcomm-relay", 10);
    uint32_t cid = htonl(circ_id);
    memcpy(aad + 12, &cid, 4);

    uint8_t *pt = (uint8_t*)malloc(ct_len); // upper bound
    if (!pt) return -1;
    size_t pt_len = ct_len;
    if (pcomm_aead_decrypt(key, nonce, aad, sizeof(aad), ct, ct_len, pt, &pt_len) != 0) {
        free(pt);
        return -1;
    }
    *out = pt;
    *out_len = (uint16_t)pt_len;
    return 0;
}

int pcomm_relay_wrap_forward(const uint8_t (*keys_fwd)[32], size_t nhops, uint32_t circ_id,
                             const uint8_t *plain, uint16_t plain_len,
                             uint8_t **out, uint16_t *out_len) {
    if (!out || !out_len) return -1;
    *out = NULL; *out_len = 0;
    if (!keys_fwd || nhops == 0) return -1;

    uint8_t *cur = (uint8_t*)malloc(plain_len);
    if (!cur) return -1;
    memcpy(cur, plain, plain_len);
    uint16_t cur_len = plain_len;

    for (size_t i = nhops; i-- > 0;) {
        uint8_t *next = NULL; uint16_t next_len = 0;
        if (layer_encrypt(keys_fwd[i], circ_id, cur, cur_len, &next, &next_len) != 0) {
            free(cur);
            return -1;
        }
        free(cur);
        cur = next;
        cur_len = next_len;
    }

    *out = cur;
    *out_len = cur_len;
    return 0;
}

int pcomm_relay_unwrap_one_forward(const uint8_t key_fwd[32], uint32_t circ_id,
                                  const uint8_t *in, uint16_t in_len,
                                  uint8_t **out, uint16_t *out_len) {
    return layer_decrypt(key_fwd, circ_id, in, in_len, out, out_len);
}

int pcomm_relay_wrap_one_backward(const uint8_t key_bwd[32], uint32_t circ_id,
                                 const uint8_t *in, uint16_t in_len,
                                 uint8_t **out, uint16_t *out_len) {
    return layer_encrypt(key_bwd, circ_id, in, in_len, out, out_len);
}

int pcomm_relay_unwrap_backward_all(const uint8_t (*keys_bwd)[32], size_t nhops, uint32_t circ_id,
                                   const uint8_t *in, uint16_t in_len,
                                   uint8_t **plain, uint16_t *plain_len) {
    if (!plain || !plain_len) return -1;
    *plain = NULL; *plain_len = 0;
    if (!keys_bwd || nhops == 0) return -1;

    uint8_t *cur = (uint8_t*)malloc(in_len);
    if (!cur) return -1;
    memcpy(cur, in, in_len);
    uint16_t cur_len = in_len;

    for (size_t i = 0; i < nhops; i++) {
        uint8_t *next = NULL; uint16_t next_len = 0;
        if (layer_decrypt(keys_bwd[i], circ_id, cur, cur_len, &next, &next_len) != 0) {
            free(cur);
            return -1;
        }
        free(cur);
        cur = next;
        cur_len = next_len;
    }

    *plain = cur;
    *plain_len = cur_len;
    return 0;
}
