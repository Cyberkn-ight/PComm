#include "base32.h"
#include <string.h>
#include <ctype.h>

static const char *B32_ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int base32_encode_no_pad(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    if (!in || !out) return -1;
    size_t out_len = (in_len * 8 + 4) / 5;
    if (out_cap < out_len + 1) return -1;

    size_t i = 0, o = 0;
    uint32_t buffer = 0;
    int bits_left = 0;

    while (i < in_len) {
        buffer = (buffer << 8) | in[i++];
        bits_left += 8;
        while (bits_left >= 5) {
            int idx = (buffer >> (bits_left - 5)) & 0x1F;
            bits_left -= 5;
            out[o++] = B32_ALPH[idx];
        }
    }

    if (bits_left > 0) {
        int idx = (buffer << (5 - bits_left)) & 0x1F;
        out[o++] = B32_ALPH[idx];
    }

    out[o] = '\0';
    return (int)o;
}

static int b32_val(char c) {
    c = (char)toupper((unsigned char)c);
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return 26 + (c - '2');
    return -1;
}

int base32_decode_no_pad(const char *in, uint8_t *out, size_t out_cap) {
    if (!in || !out) return -1;

    uint32_t buffer = 0;
    int bits_left = 0;
    size_t o = 0;

    for (size_t i = 0; in[i] != '\0'; i++) {
        char c = in[i];
        if (c == '=' || isspace((unsigned char)c)) continue;
        int v = b32_val(c);
        if (v < 0) return -1;
        buffer = (buffer << 5) | (uint32_t)v;
        bits_left += 5;
        if (bits_left >= 8) {
            if (o >= out_cap) return -1;
            out[o++] = (uint8_t)((buffer >> (bits_left - 8)) & 0xFF);
            bits_left -= 8;
        }
    }

    return (int)o;
}
