#ifndef PCOMM_HTTP_UTIL_H
#define PCOMM_HTTP_UTIL_H

#include <stddef.h>

size_t url_decode_inplace(char *s);

int form_get_field(const char *body, const char *key, char *out, size_t out_cap);

#include "sb.h"
int sb_append_json_escaped(sb_t *sb, const char *s);

#endif
