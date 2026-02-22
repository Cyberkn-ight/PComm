#ifndef PCOMM_BASE32_H
#define PCOMM_BASE32_H

#include <stddef.h>
#include <stdint.h>

int base32_encode_no_pad(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

int base32_decode_no_pad(const char *in, uint8_t *out, size_t out_cap);

#endif
