#include "http_util.h"
#include <ctype.h>
#include <string.h>

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

size_t url_decode_inplace(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '+') {
            *w++ = ' ';
        } else if (*r == '%' && r[1] && r[2]) {
            int a = hexv(r[1]);
            int b = hexv(r[2]);
            if (a >= 0 && b >= 0) {
                *w++ = (char)((a << 4) | b);
                r += 2;
            } else {
                *w++ = *r;
            }
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
    return (size_t)(w - s);
}

int form_get_field(const char *body, const char *key, char *out, size_t out_cap) {
    if (!body || !key || !out || out_cap == 0) return -1;
    size_t klen = strlen(key);

    const char *p = body;
    while (*p) {
        const char *eq = strchr(p, '=');
        if (!eq) break;
        const char *amp = strchr(p, '&');
        if (!amp) amp = p + strlen(p);

        if ((size_t)(eq - p) == klen && strncmp(p, key, klen) == 0) {
            size_t vlen = (size_t)(amp - (eq + 1));
            if (vlen >= out_cap) vlen = out_cap - 1;
            memcpy(out, eq + 1, vlen);
            out[vlen] = '\0';
            url_decode_inplace(out);
            return 0;
        }

        p = (*amp == '&') ? amp + 1 : amp;
    }

    return -1;
}

int sb_append_json_escaped(sb_t *sb, const char *s) {
    for (const unsigned char *p = (const unsigned char*)s; p && *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '"': if (sb_append(sb, "\\\"")!=0) return -1; break;
            case '\\': if (sb_append(sb, "\\\\")!=0) return -1; break;
            case '\b': if (sb_append(sb, "\\b")!=0) return -1; break;
            case '\f': if (sb_append(sb, "\\f")!=0) return -1; break;
            case '\n': if (sb_append(sb, "\\n")!=0) return -1; break;
            case '\r': if (sb_append(sb, "\\r")!=0) return -1; break;
            case '\t': if (sb_append(sb, "\\t")!=0) return -1; break;
            default:
                if (c < 0x20) {
                    if (sb_appendf(sb, "\\u%04x", (unsigned)c)!=0) return -1;
                } else {
                    char tmp[2] = {(char)c, 0};
                    if (sb_append(sb, tmp)!=0) return -1;
                }
        }
    }
    return 0;
}
