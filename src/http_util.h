#ifndef PCOMM_HTTP_UTIL_H
#define PCOMM_HTTP_UTIL_H

#include <stddef.h>

// Decodes percent-encoding in-place. Returns length.
size_t url_decode_inplace(char *s);

// Gets a form field from x-www-form-urlencoded body.
// Writes decoded value into out. Returns 0 if found.
int form_get_field(const char *body, const char *key, char *out, size_t out_cap);

// Appends JSON-escaped version of s into sb (without surrounding quotes).
#include "sb.h"
int sb_append_json_escaped(sb_t *sb, const char *s);

#endif
