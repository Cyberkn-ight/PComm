#include "sb.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

void sb_init(sb_t *sb) {
    sb->buf = NULL;
    sb->len = 0;
    sb->cap = 0;
}

void sb_free(sb_t *sb) {
    if (sb->buf) free(sb->buf);
    sb->buf = NULL;
    sb->len = 0;
    sb->cap = 0;
}

static int sb_grow(sb_t *sb, size_t need) {
    size_t want = sb->len + need + 1;
    if (want <= sb->cap) return 0;
    size_t ncap = sb->cap ? sb->cap * 2 : 1024;
    while (ncap < want) ncap *= 2;
    char *nb = (char*)realloc(sb->buf, ncap);
    if (!nb) return -1;
    sb->buf = nb;
    sb->cap = ncap;
    return 0;
}

int sb_append(sb_t *sb, const char *s) {
    if (!s) return 0;
    size_t n = strlen(s);
    if (sb_grow(sb, n) != 0) return -1;
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
    return 0;
}

int sb_appendf(sb_t *sb, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char tmp[2048];
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n >= sizeof(tmp)) {
        char *big = (char*)malloc((size_t)n + 1);
        if (!big) return -1;
        va_start(ap, fmt);
        vsnprintf(big, (size_t)n + 1, fmt, ap);
        va_end(ap);
        int rc = sb_append(sb, big);
        free(big);
        return rc;
    }
    return sb_append(sb, tmp);
}
