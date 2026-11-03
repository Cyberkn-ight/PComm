#ifndef PCOMM_SIGN_H
#define PCOMM_SIGN_H

#include <stddef.h>
#include <stdint.h>

int pcomm_sign(const uint8_t private_key[32], const uint8_t *message, size_t length,
                 uint8_t signature[64]);
int pcomm_verify(const uint8_t public_key[32], const uint8_t *message, size_t length,
                   const uint8_t signature[64]);

#endif
