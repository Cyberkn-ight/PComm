#include "onion.h"
#include "crypto.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

static void put_u16(uint8_t *p, uint16_t v) {
    uint16_t n = htons(v);
    memcpy(p, &n, 2);
}
static void put_u32(uint8_t *p, uint32_t v) {
    uint32_t n = htonl(v);
    memcpy(p, &n, 4);
}
static uint16_t get_u16(const uint8_t *p) {
    uint16_t n; memcpy(&n, p, 2); return ntohs(n);
}
static uint32_t get_u32(const uint8_t *p) {
    uint32_t n; memcpy(&n, p, 4); return ntohl(n);
}

static int x25519_keygen(uint8_t priv[32], uint8_t pub[32]) {
    int ok = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx) goto cleanup;
    if (EVP_PKEY_keygen_init(ctx) != 1) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) goto cleanup;

    size_t priv_len = 32, pub_len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) != 1) goto cleanup;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) != 1) goto cleanup;
    if (priv_len != 32 || pub_len != 32) goto cleanup;

    ok = 0;
cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int derive_hop_key(const uint8_t eph_priv[32], const uint8_t hop_pub[32], uint8_t out_key[32]) {
    uint8_t shared[32];
    if (pcomm_x25519_derive(eph_priv, hop_pub, shared) != 0) return -1;
    const uint8_t info[] = "pcomm-onion-v1";
    if (pcomm_hkdf_sha256(shared, sizeof(shared), NULL, 0, info, sizeof(info)-1, out_key, 32) != 0) return -1;
    return 0;
}

int pcomm_onion_build_v1(const pcomm_peer_t *path, size_t path_len,
                         const char *dest_host, uint16_t dest_port,
                         pcomm_msg_type_t deliver_type,
                         const uint8_t *deliver_payload, size_t deliver_len,
                         int roundtrip,
                         uint8_t eph_pub_out[32],
                         uint8_t **onion_payload_out, uint32_t *onion_payload_len_out) {
    if (!path || path_len < 1 || !dest_host || !deliver_payload || !onion_payload_out || !onion_payload_len_out) return -1;

    uint8_t eph_priv[32], eph_pub[32];
    if (x25519_keygen(eph_priv, eph_pub) != 0) return -1;
    memcpy(eph_pub_out, eph_pub, 32);

    size_t dest_host_len = strlen(dest_host);
    if (dest_host_len > 63) return -1;
    uint8_t flags = (roundtrip != 0) ? 0x01 : 0x00;
    size_t pt0_len = 1 + 1 + 1 + dest_host_len + 2 + 1 + 4 + deliver_len;
    uint8_t *pt0 = (uint8_t*)malloc(pt0_len);
    if (!pt0) return -1;

    size_t off = 0;
    pt0[off++] = (uint8_t)PCOMM_INST_DELIVER;
    pt0[off++] = flags;
    pt0[off++] = (uint8_t)dest_host_len;
    memcpy(pt0 + off, dest_host, dest_host_len); off += dest_host_len;
    put_u16(pt0 + off, dest_port); off += 2;
    pt0[off++] = (uint8_t)deliver_type;
    put_u32(pt0 + off, (uint32_t)deliver_len); off += 4;
    memcpy(pt0 + off, deliver_payload, deliver_len); off += deliver_len;
    if (off != pt0_len) { free(pt0); return -1; }

    uint8_t *inner_blob = NULL;
    uint32_t inner_len = 0;
    {
        uint8_t key[32];
        if (derive_hop_key(eph_priv, path[path_len-1].pubkey, key) != 0) { free(pt0); return -1; }
        uint8_t nonce[12];
        if (pcomm_random(nonce, sizeof(nonce)) != 0) { free(pt0); return -1; }

        size_t ct_cap = pt0_len + 16;
        size_t blob_cap = 12 + ct_cap;
        uint8_t *blob = (uint8_t*)malloc(blob_cap);
        if (!blob) { free(pt0); return -1; }
        memcpy(blob, nonce, 12);

        size_t ct_len = ct_cap;
        if (pcomm_aead_encrypt(key, nonce, NULL, 0, pt0, pt0_len, blob + 12, &ct_len) != 0) {
            free(pt0); free(blob); return -1;
        }

        inner_blob = blob;
        inner_len = (uint32_t)(12 + ct_len);
    }
    free(pt0);

    for (ssize_t i = (ssize_t)path_len - 2; i >= 0; i--) {
        const char *next_host = path[i+1].host;
        uint16_t next_port = path[i+1].port;
        size_t next_host_len = strlen(next_host);
        if (next_host_len > 63) { free(inner_blob); return -1; }
        uint8_t inst = (roundtrip != 0) ? (uint8_t)PCOMM_INST_FORWARD_RR : (uint8_t)PCOMM_INST_FORWARD;
        size_t pt_len = 1 + 1 + next_host_len + 2 + 4 + inner_len;
        uint8_t *pt = (uint8_t*)malloc(pt_len);
        if (!pt) { free(inner_blob); return -1; }

        size_t off2 = 0;
        pt[off2++] = inst;
        pt[off2++] = (uint8_t)next_host_len;
        memcpy(pt + off2, next_host, next_host_len); off2 += next_host_len;
        put_u16(pt + off2, next_port); off2 += 2;
        put_u32(pt + off2, inner_len); off2 += 4;
        memcpy(pt + off2, inner_blob, inner_len); off2 += inner_len;
        if (off2 != pt_len) { free(pt); free(inner_blob); return -1; }

        uint8_t key[32];
        if (derive_hop_key(eph_priv, path[i].pubkey, key) != 0) {
            free(pt); free(inner_blob); return -1;
        }
        uint8_t nonce[12];
        if (pcomm_random(nonce, sizeof(nonce)) != 0) {
            free(pt); free(inner_blob); return -1;
        }

        size_t ct_cap = pt_len + 16;
        size_t blob_cap = 12 + ct_cap;
        uint8_t *blob = (uint8_t*)malloc(blob_cap);
        if (!blob) { free(pt); free(inner_blob); return -1; }
        memcpy(blob, nonce, 12);

        size_t ct_len = ct_cap;
        if (pcomm_aead_encrypt(key, nonce, NULL, 0, pt, pt_len, blob + 12, &ct_len) != 0) {
            free(pt); free(inner_blob); free(blob); return -1;
        }

        free(pt);
        free(inner_blob);
        inner_blob = blob;
        inner_len = (uint32_t)(12 + ct_len);
    }

    *onion_payload_out = inner_blob;
    *onion_payload_len_out = inner_len;
    return 0;
}

int pcomm_onion_unwrap_v1(const uint8_t relay_priv[32], const uint8_t eph_pub[32],
                          const uint8_t *payload, uint32_t payload_len,
                          pcomm_inst_t *inst_out,
                          char *next_host_out, size_t next_host_cap, uint16_t *next_port_out,
                          uint8_t **next_payload_out, uint32_t *next_payload_len_out,
                          char *dest_host_out, size_t dest_host_cap, uint16_t *dest_port_out,
                          pcomm_msg_type_t *deliver_type_out,
                          uint8_t *deliver_flags_out,
                          uint8_t **deliver_payload_out, uint32_t *deliver_len_out) {
    if (!relay_priv || !eph_pub || !payload || payload_len < 12 + 16 || !inst_out) return -1;

    const uint8_t *nonce = payload;
    const uint8_t *ct = payload + 12;
    uint32_t ct_len = payload_len - 12;

    uint8_t shared[32];
    if (pcomm_x25519_derive(relay_priv, eph_pub, shared) != 0) return -1;
    uint8_t key[32];
    const uint8_t info[] = "pcomm-onion-v1";
    if (pcomm_hkdf_sha256(shared, sizeof(shared), NULL, 0, info, sizeof(info)-1, key, 32) != 0) return -1;

    uint8_t *pt = (uint8_t*)malloc(ct_len);
    if (!pt) return -1;
    size_t pt_len = ct_len;
    if (pcomm_aead_decrypt(key, nonce, NULL, 0, ct, ct_len, pt, &pt_len) != 0) {
        free(pt);
        return -1;
    }

    if (pt_len < 1) { free(pt); return -1; }
    size_t off = 0;
    uint8_t inst = pt[off++];
    *inst_out = (pcomm_inst_t)inst;

    if (inst == PCOMM_INST_FORWARD || inst == PCOMM_INST_FORWARD_RR) {
        if (pt_len < off + 1) { free(pt); return -1; }
        uint8_t hlen = pt[off++];
        if (pt_len < off + hlen + 2 + 4) { free(pt); return -1; }
        if (hlen >= next_host_cap) { free(pt); return -1; }
        memcpy(next_host_out, pt + off, hlen);
        next_host_out[hlen] = '\0';
        off += hlen;
        *next_port_out = get_u16(pt + off); off += 2;
        uint32_t inner_len = get_u32(pt + off); off += 4;
        if (pt_len < off + inner_len) { free(pt); return -1; }

        uint8_t *inner = (uint8_t*)malloc(inner_len);
        if (!inner) { free(pt); return -1; }
        memcpy(inner, pt + off, inner_len);

        *next_payload_out = inner;
        *next_payload_len_out = inner_len;
        free(pt);
        return 0;
    }

    if (inst == PCOMM_INST_DELIVER) {
        if (pt_len < off + 2) { free(pt); return -1; }
        uint8_t flags = pt[off++];
        if (deliver_flags_out) *deliver_flags_out = flags;

        uint8_t hlen = pt[off++];
        if (pt_len < off + hlen + 2 + 1 + 4) { free(pt); return -1; }
        if (hlen >= dest_host_cap) { free(pt); return -1; }
        memcpy(dest_host_out, pt + off, hlen);
        dest_host_out[hlen] = '\0';
        off += hlen;
        *dest_port_out = get_u16(pt + off); off += 2;

        uint8_t dtyp = pt[off++];
        if (deliver_type_out) *deliver_type_out = (pcomm_msg_type_t)dtyp;

        uint32_t dlen = get_u32(pt + off); off += 4;
        if (pt_len < off + dlen) { free(pt); return -1; }

        uint8_t *d = (uint8_t*)malloc(dlen);
        if (!d) { free(pt); return -1; }
        memcpy(d, pt + off, dlen);

        if (deliver_payload_out) *deliver_payload_out = d;
        if (deliver_len_out) *deliver_len_out = dlen;
        free(pt);
        return 0;
    }

    free(pt);
    return -1;
}
