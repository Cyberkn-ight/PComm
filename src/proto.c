#include "proto.h"
#include "net.h"

#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

int pcomm_send_packet(int fd, pcomm_msg_type_t type, const uint8_t eph_pub[32], const uint8_t *payload, uint32_t payload_len) {
    if (payload_len > PCOMM_MAX_PACKET_PAYLOAD || (payload_len > 0 && !payload)) return -1;

    uint8_t hdr[PCOMM_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));

    memcpy(hdr, PCOMM_MAGIC, 4);
    hdr[4] = PCOMM_VERSION;
    hdr[5] = (uint8_t)type;

    uint32_t nlen = htonl(payload_len);
    memcpy(hdr + 8, &nlen, 4);

    if (eph_pub) memcpy(hdr + 12, eph_pub, 32);

    if (net_sendall(fd, hdr, sizeof(hdr)) != 0) return -1;
    if (payload_len > 0) {
        if (net_sendall(fd, payload, payload_len) != 0) return -1;
    }
    return 0;
}

int pcomm_recv_packet(int fd, pcomm_msg_type_t *type_out, uint8_t eph_pub_out[32], uint8_t **payload_out, uint32_t *payload_len_out) {
    if (payload_out) *payload_out = NULL;
    if (payload_len_out) *payload_len_out = 0;
    if (!type_out || !payload_out || !payload_len_out) return -1;

    uint8_t hdr[PCOMM_HDR_LEN];
    if (net_recvall(fd, hdr, sizeof(hdr)) != 0) return -1;

    if (memcmp(hdr, PCOMM_MAGIC, 4) != 0) return -1;
    if (hdr[4] != PCOMM_VERSION) return -1;

    uint32_t nlen;
    memcpy(&nlen, hdr + 8, 4);
    uint32_t payload_len = ntohl(nlen);
    if (payload_len > PCOMM_MAX_PACKET_PAYLOAD) return -1;

    uint8_t *payload = NULL;
    if (payload_len > 0) {
        payload = (uint8_t*)malloc(payload_len);
        if (!payload) return -1;
        if (net_recvall(fd, payload, payload_len) != 0) {
            free(payload);
            return -1;
        }
    }

    *type_out = (pcomm_msg_type_t)hdr[5];
    if (eph_pub_out) memcpy(eph_pub_out, hdr + 12, 32);
    *payload_out = payload;
    *payload_len_out = payload_len;
    return 0;
}

int pcomm_pack_packet(pcomm_msg_type_t type, const uint8_t eph_pub[32], const uint8_t *payload, uint32_t payload_len,
                      uint8_t **out, uint32_t *out_len) {
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!out || !out_len || payload_len > PCOMM_MAX_PACKET_PAYLOAD ||
        (payload_len > 0 && !payload)) return -1;

    uint32_t total = PCOMM_HDR_LEN + payload_len;
    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) return -1;

    memset(buf, 0, PCOMM_HDR_LEN);
    memcpy(buf, PCOMM_MAGIC, 4);
    buf[4] = PCOMM_VERSION;
    buf[5] = (uint8_t)type;
    uint32_t nlen = htonl(payload_len);
    memcpy(buf + 8, &nlen, 4);
    if (eph_pub) memcpy(buf + 12, eph_pub, 32);
    if (payload_len > 0) memcpy(buf + PCOMM_HDR_LEN, payload, payload_len);

    *out = buf;
    *out_len = total;
    return 0;
}

int pcomm_unpack_packet(const uint8_t *buf, uint32_t buf_len, pcomm_msg_type_t *type_out, uint8_t eph_pub_out[32],
                        uint8_t **payload_out, uint32_t *payload_len_out) {
    if (payload_out) *payload_out = NULL;
    if (payload_len_out) *payload_len_out = 0;
    if (!buf || buf_len < PCOMM_HDR_LEN || buf_len > PCOMM_MAX_PACKET_LEN ||
        !type_out || !payload_out || !payload_len_out) return -1;

    if (memcmp(buf, PCOMM_MAGIC, 4) != 0) return -1;
    if (buf[4] != PCOMM_VERSION) return -1;
    uint32_t nlen;
    memcpy(&nlen, buf + 8, 4);
    uint32_t pl = ntohl(nlen);
    if (pl > PCOMM_MAX_PACKET_PAYLOAD || pl != buf_len - PCOMM_HDR_LEN) return -1;
    uint8_t *payload = NULL;
    if (pl > 0) {
        payload = (uint8_t*)malloc(pl);
        if (!payload) return -1;
        memcpy(payload, buf + PCOMM_HDR_LEN, pl);
    }
    *type_out = (pcomm_msg_type_t)buf[5];
    if (eph_pub_out) memcpy(eph_pub_out, buf + 12, 32);
    *payload_out = payload;
    *payload_len_out = pl;
    return 0;
}

int pcomm_packet_append(uint8_t **buffer, uint32_t *length,
                         const uint8_t *data, uint32_t data_len) {
    if (!buffer || !length || *length > PCOMM_MAX_PACKET_LEN ||
        (*length > 0 && !*buffer)) return -1;
    if (data_len == 0) return 0;
    if (!data || data_len > PCOMM_MAX_PACKET_LEN - *length) return -1;

    uint32_t total = *length + data_len;
    uint8_t *grown = (uint8_t *)malloc(total);
    if (!grown) return -1;
    if (*length > 0) memcpy(grown, *buffer, *length);
    memcpy(grown + *length, data, data_len);
    free(*buffer);
    *buffer = grown;
    *length = total;
    return 0;
}
