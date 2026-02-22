#include "proto.h"
#include "net.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

int pcomm_send_packet(int fd, pcomm_msg_type_t type, const uint8_t eph_pub[32], const uint8_t *payload, uint32_t payload_len) {
    uint8_t hdr[PCOMM_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));

    memcpy(hdr, PCOMM_MAGIC, 4);
    hdr[4] = PCOMM_VERSION;
    hdr[5] = (uint8_t)type;

    uint32_t nlen = htonl(payload_len);
    memcpy(hdr + 8, &nlen, 4);

    if (eph_pub) memcpy(hdr + 12, eph_pub, 32);

    if (net_sendall(fd, hdr, sizeof(hdr)) != 0) return -1;
    if (payload_len > 0 && payload) {
        if (net_sendall(fd, payload, payload_len) != 0) return -1;
    }
    return 0;
}

int pcomm_recv_packet(int fd, pcomm_msg_type_t *type_out, uint8_t eph_pub_out[32], uint8_t **payload_out, uint32_t *payload_len_out) {
    if (!type_out || !payload_out || !payload_len_out) return -1;

    uint8_t hdr[PCOMM_HDR_LEN];
    if (net_recvall(fd, hdr, sizeof(hdr)) != 0) return -1;

    if (memcmp(hdr, PCOMM_MAGIC, 4) != 0) return -1;
    if (hdr[4] != PCOMM_VERSION) return -1;

    *type_out = (pcomm_msg_type_t)hdr[5];

    uint32_t nlen;
    memcpy(&nlen, hdr + 8, 4);
    uint32_t payload_len = ntohl(nlen);
    *payload_len_out = payload_len;

    if (eph_pub_out) memcpy(eph_pub_out, hdr + 12, 32);

    uint8_t *payload = NULL;
    if (payload_len > 0) {
        payload = (uint8_t*)malloc(payload_len);
        if (!payload) return -1;
        if (net_recvall(fd, payload, payload_len) != 0) {
            free(payload);
            return -1;
        }
    }

    *payload_out = payload;
    return 0;
}
