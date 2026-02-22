#ifndef PCOMM_SB_H
#define PCOMM_SB_H

#include <stddef.h>

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} sb_t;

void sb_init(sb_t *sb);
void sb_free(sb_t *sb);
int sb_append(sb_t *sb, const char *s);
int sb_appendf(sb_t *sb, const char *fmt, ...);

#endif
