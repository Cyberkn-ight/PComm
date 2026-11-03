#include "descriptor.h"
#include "identity.h"
#include "crypto.h"
#include "sign.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

static void put32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
}
static int canonical_host(const char *host, size_t len, char out[64]) {
    if (!len || len > 63 || memchr(host, 0, len)) return -1;
    char text[64];
    memcpy(text, host, len); text[len] = 0;
    if (strchr(text, ':')) {
        struct in6_addr address;
        if (inet_pton(AF_INET6, text, &address) != 1) return -1;
        static const uint8_t mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (!memcmp(&address, mapped, 12)) return inet_ntop(AF_INET, (uint8_t *)&address+12, out, 64) ? 0 : -1;
        return inet_ntop(AF_INET6, &address, out, 64) ? 0 : -1;
    }
    if (text[0] == '.' || strstr(text, "..")) return -1;
    int numeric = 1;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_')) return -1;
        if (!((c >= '0' && c <= '9') || c == '.')) numeric = 0;
        if (c >= 'A' && c <= 'Z') text[i] = (char)(c-'A'+'a');
    }
    if (numeric) {
        struct in_addr address;
        if (inet_pton(AF_INET, text, &address) != 1) return -1;
        return inet_ntop(AF_INET, &address, out, 64) ? 0 : -1;
    }
    if (text[len-1] == '.') text[--len] = 0;
    const char *label = text;
    while (*label) {
        const char *end = strchr(label, '.');
        if (!end) end = label+strlen(label);
        if (*label == '-' || end == label || end[-1] == '-') return -1;
        if (!*end) break;
        label = end+1;
    }
    memcpy(out, text, len+1);
    return 0;
}
static int valid_host(const char *host, size_t len) {
    char normalized[64];
    return canonical_host(host, len, normalized) == 0;
}
static int valid_intro(const pcomm_peer_t *peer) {
    uint8_t shared[32] = {0};
    static const uint8_t probe[32] = {0xa8,0x34,0x71,0x98,0x36,0x53,0x21,0xf4,
        0x18,0x2b,0xca,0xe6,0x31,0x55,0x49,0x7a,0xb5,0x81,0x42,0x16,0x20,0xb3,0x65,0xca,
        0x41,0x67,0x20,0xda,0x72,0x39,0x6c,0x7f};
    static const uint8_t prime[32] = {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f};
    int canonical = 0;
    for (int i = 31; i >= 0; i--) {
        if (peer->pubkey[i] < prime[i]) { canonical = 1; break; }
        if (peer->pubkey[i] > prime[i]) break;
    }
    size_t host_len = 0;
    while (host_len < sizeof(peer->host) && peer->host[host_len]) host_len++;
    char derived[96];
    if (!canonical || !peer->port || !valid_host(peer->host, host_len) ||
        pcomm_user_id_from_pubkey(peer->pubkey, derived) ||
        strncmp(derived, peer->user_id, sizeof(peer->user_id)) ||
        pcomm_x25519_derive(probe, peer->pubkey, shared)) return 0;
    OPENSSL_cleanse(shared, sizeof(shared));
    return 1;
}
static int repeated_intro(const pcomm_peer_t *peers, size_t index) {
    char current[64];
    if (canonical_host(peers[index].host, strlen(peers[index].host), current)) return 1;
    for (size_t i = 0; i < index; i++) {
        char previous[64];
        if (canonical_host(peers[i].host, strlen(peers[i].host), previous)) return 1;
        if (!CRYPTO_memcmp(peers[i].pubkey, peers[index].pubkey, 32) ||
            (peers[i].port == peers[index].port && !strcmp(previous, current))) return 1;
    }
    return 0;
}
int pcomm_descriptor_build(const pcomm_identity_t *owner, uint32_t epoch,
                            uint32_t issued, uint32_t expires,
                            const pcomm_peer_t *intros, size_t intro_count,
                            uint8_t **out, uint32_t *out_len) {
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!owner || !intros || !out || !out_len || !intro_count || intro_count > 3 ||
        epoch != issued/PCOMM_DESCRIPTOR_EPOCH_SECONDS || expires <= issued ||
        expires-issued > PCOMM_DESCRIPTOR_MAX_TTL) return -1;
    uint8_t buffer[PCOMM_DESCRIPTOR_MAX_BLOB];
    memcpy(buffer, "PCD2", 4); memcpy(buffer+4, owner->pubkey, 32);
    put32(buffer+36, epoch); put32(buffer+40, issued); put32(buffer+44, expires);
    buffer[48] = (uint8_t)intro_count;
    size_t offset = 49;
    for (size_t i = 0; i < intro_count; i++) {
        if (!valid_intro(&intros[i]) || repeated_intro(intros, i)) return -1;
        size_t len = strlen(intros[i].host);
        memcpy(buffer+offset, intros[i].pubkey, 32); offset += 32;
        buffer[offset++] = (uint8_t)len;
        memcpy(buffer+offset, intros[i].host, len); offset += len;
        buffer[offset++] = (uint8_t)(intros[i].port >> 8);
        buffer[offset++] = (uint8_t)intros[i].port;
    }
    if (offset+64 > sizeof(buffer) || pcomm_sign(owner->privkey, buffer, offset, buffer+offset) ||
        pcomm_verify(owner->pubkey, buffer, offset, buffer+offset)) return -1;
    uint8_t *result = malloc(offset+64);
    if (!result) return -1;
    memcpy(result, buffer, offset+64);
    *out = result; *out_len = (uint32_t)(offset+64);
    return 0;
}
int pcomm_descriptor_parse(const uint8_t *blob, uint32_t blob_len,
                            const char *expected_owner, uint32_t expected_epoch,
                            uint32_t now, pcomm_descriptor_t *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!blob || !out || blob_len < 49+35+1+64 || blob_len > PCOMM_DESCRIPTOR_MAX_BLOB ||
        memcmp(blob, "PCD2", 4)) return -1;
    pcomm_descriptor_t parsed = {0};
    memcpy(parsed.owner, blob+4, 32);
    parsed.epoch = get32(blob+36); parsed.issued = get32(blob+40); parsed.expires = get32(blob+44);
    parsed.intro_count = blob[48];
    uint8_t expected[32];
    if ((expected_owner && (pcomm_pubkey_from_user_id(expected_owner, expected) ||
                           CRYPTO_memcmp(expected, parsed.owner, 32))) ||
        (expected_epoch != UINT32_MAX && expected_epoch != parsed.epoch) ||
        parsed.epoch != parsed.issued/PCOMM_DESCRIPTOR_EPOCH_SECONDS ||
        (uint64_t)parsed.issued > (uint64_t)now+120 || parsed.expires <= now ||
        parsed.expires <= parsed.issued || parsed.expires-parsed.issued > PCOMM_DESCRIPTOR_MAX_TTL ||
        !parsed.intro_count || parsed.intro_count > 3 ||
        pcomm_verify(parsed.owner, blob, blob_len-64, blob+blob_len-64)) return -1;
    size_t offset = 49, body_len = blob_len-64;
    for (size_t i = 0; i < parsed.intro_count; i++) {
        if (body_len-offset < 35) return -1;
        pcomm_peer_t *peer = &parsed.intros[i];
        memcpy(peer->pubkey, blob+offset, 32); offset += 32;
        size_t len = blob[offset++];
        if (!len || len > 63 || body_len-offset < len+2 || !valid_host((const char *)blob+offset, len)) return -1;
        memcpy(peer->host, blob+offset, len); offset += len;
        peer->port = (uint16_t)((unsigned)blob[offset]<<8 | blob[offset+1]); offset += 2;
        if (pcomm_user_id_from_pubkey(peer->pubkey, peer->user_id) ||
            !valid_intro(peer) || repeated_intro(parsed.intros, i)) return -1;
    }
    if (offset != body_len || !SHA256(blob, body_len, parsed.digest)) return -1;
    *out = parsed;
    return 0;
}
static int source_address(const char *text, uint8_t address[16], int *family) {
    if (!text) return -1;
    memset(address, 0, 16);
    if (inet_pton(AF_INET, text, address) == 1) { *family = 4; return 0; }
    if (inet_pton(AF_INET6, text, address) != 1) return -1;
    static const uint8_t mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (!memcmp(address, mapped, 12)) {
        memmove(address, address+12, 4); memset(address+4, 0, 12); *family = 4;
    } else *family = 6;
    return 0;
}
int pcomm_descriptor_vote(pcomm_descriptor_quorum_t *quorum, const char *source_ip,
                           const uint8_t provider[32],
                           const pcomm_descriptor_t *descriptor) {
    if (!quorum || !descriptor || !provider || quorum->source_count > PCOMM_DESCRIPTOR_MAX_SOURCES ||
        quorum->candidate_count > PCOMM_DESCRIPTOR_MAX_CANDIDATES) return -1;
    uint8_t address[16]; int family;
    if (source_address(source_ip, address, &family)) return -1;
    for (size_t i = 0; i < quorum->source_count; i++) {
        if ((quorum->sources[i].family == family && !memcmp(quorum->sources[i].address, address, 16)) ||
            !CRYPTO_memcmp(quorum->sources[i].provider, provider, 32)) {
            int candidate = quorum->sources[i].candidate;
            if (candidate >= 0 && CRYPTO_memcmp(quorum->candidates[candidate].digest, descriptor->digest, 32)) {
                quorum->votes[candidate]--;
                quorum->sources[i].candidate = -1;
            }
            return 0;
        }
    }
    size_t candidate;
    for (candidate = 0; candidate < quorum->candidate_count; candidate++) {
        if (!CRYPTO_memcmp(quorum->candidates[candidate].digest, descriptor->digest, 32)) break;
    }
    if (quorum->source_count == PCOMM_DESCRIPTOR_MAX_SOURCES || candidate == PCOMM_DESCRIPTOR_MAX_CANDIDATES) return -1;
    if (candidate == quorum->candidate_count) {
        quorum->candidates[candidate] = *descriptor;
        quorum->candidate_count++;
    }
    size_t index = quorum->source_count++;
    memcpy(quorum->sources[index].address, address, 16);
    memcpy(quorum->sources[index].provider, provider, 32);
    quorum->sources[index].family = family;
    quorum->sources[index].candidate = (int)candidate;
    quorum->votes[candidate]++;
    return 0;
}
int pcomm_descriptor_consensus(const pcomm_descriptor_quorum_t *quorum,
                                pcomm_descriptor_t *out) {
    if (!quorum || !out || quorum->candidate_count > PCOMM_DESCRIPTOR_MAX_CANDIDATES ||
        quorum->source_count > PCOMM_DESCRIPTOR_MAX_SOURCES) return -1;
    for (size_t i = 0; i < quorum->candidate_count; i++) {
        if (quorum->votes[i] >= 2 && quorum->votes[i] > quorum->source_count/2) { *out = quorum->candidates[i]; return 0; }
    }
    return -1;
}
int pcomm_descriptor_keys(const uint8_t owner[32], uint32_t epoch,
                           uint8_t dkey[32], uint8_t infohash[20]) {
    if (!owner || !dkey || !infohash) return -1;
    char identity[96]; uint8_t buffer[160];
    if (pcomm_user_id_from_pubkey(owner, identity)) return -1;
    const char prefix[] = "pcomm-desc-v1";
    size_t offset = sizeof(prefix);
    memcpy(buffer, prefix, offset);
    size_t len = strlen(identity);
    memcpy(buffer+offset, identity, len); offset += len;
    buffer[offset++] = 0; put32(buffer+offset, epoch); offset += 4;
    if (!SHA256(buffer, offset, dkey)) return -1;
    const char lookup[] = "pcomm-desc:";
    memcpy(buffer, lookup, sizeof(lookup)-1);
    memcpy(buffer+sizeof(lookup)-1, identity, len);
    return SHA1(buffer, sizeof(lookup)-1+len, infohash) ? 0 : -1;
}
