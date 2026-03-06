#ifndef PCOMM_BASE32_H
#define PCOMM_BASE32_H

#include <stddef.h>
#include <stdint.h>

// RFC4648 Base32 without padding.
// Returns number of chars written (excluding NUL) or -1 on error.
int base32_encode_no_pad(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

// Decodes RFC4648 Base32 (accepts upper/lowercase, ignores '='). Returns bytes written or -1.
int base32_decode_no_pad(const char *in, uint8_t *out, size_t out_cap);

#endif
