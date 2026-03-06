#include "bencode.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static benc_t *alloc_node(benc_type_t t) {
    benc_t *n = (benc_t*)calloc(1, sizeof(benc_t));
    if (!n) return NULL;
    n->t = t;
    return n;
}

benc_t *benc_new_int(int64_t v) {
    benc_t *n = alloc_node(BENC_INT);
    if (!n) return NULL;
    n->i = v;
    return n;
}

benc_t *benc_new_str(const uint8_t *s, size_t slen) {
    benc_t *n = alloc_node(BENC_STR);
    if (!n) return NULL;
    if (slen) {
        n->s = (uint8_t*)malloc(slen);
        if (!n->s) { free(n); return NULL; }
        memcpy(n->s, s, slen);
    }
    n->slen = slen;
    return n;
}

benc_t *benc_new_list(void) {
    return alloc_node(BENC_LIST);
}

benc_t *benc_new_dict(void) {
    return alloc_node(BENC_DICT);
}

int benc_list_add(benc_t *l, benc_t *item) {
    if (!l || l->t != BENC_LIST || !item) return -1;
    benc_t **nl = (benc_t**)realloc(l->list, (l->list_len + 1) * sizeof(benc_t*));
    if (!nl) return -1;
    l->list = nl;
    l->list[l->list_len++] = item;
    return 0;
}

int benc_dict_set(benc_t *d, const char *key, benc_t *val) {
    if (!d || d->t != BENC_DICT || !key || !val) return -1;
    size_t klen = strlen(key);
    // replace if exists
    for (size_t i=0;i<d->dict_len;i++) {
        if (d->dict[i].klen == klen && memcmp(d->dict[i].k, key, klen) == 0) {
            benc_free(d->dict[i].v);
            d->dict[i].v = val;
            return 0;
        }
    }
    benc_kv_t *nd = (benc_kv_t*)realloc(d->dict, (d->dict_len + 1) * sizeof(benc_kv_t));
    if (!nd) return -1;
    d->dict = nd;
    char *kcopy = (char*)malloc(klen);
    if (!kcopy) return -1;
    memcpy(kcopy, key, klen);
    d->dict[d->dict_len].k = kcopy;
    d->dict[d->dict_len].klen = klen;
    d->dict[d->dict_len].v = val;
    d->dict_len++;
    return 0;
}

void benc_free(benc_t *n) {
    if (!n) return;
    if (n->t == BENC_STR) {
        free(n->s);
    } else if (n->t == BENC_LIST) {
        for (size_t i=0;i<n->list_len;i++) benc_free(n->list[i]);
        free(n->list);
    } else if (n->t == BENC_DICT) {
        for (size_t i=0;i<n->dict_len;i++) {
            free((void*)n->dict[i].k);
            benc_free(n->dict[i].v);
        }
        free(n->dict);
    }
    free(n);
}

benc_t *benc_dict_get(benc_t *d, const char *key) {
    if (!d || d->t != BENC_DICT || !key) return NULL;
    size_t klen = strlen(key);
    for (size_t i=0;i<d->dict_len;i++) {
        if (d->dict[i].klen == klen && memcmp(d->dict[i].k, key, klen) == 0) return d->dict[i].v;
    }
    return NULL;
}

static int parse_int(const uint8_t *buf, size_t len, size_t *pos, benc_t **out) {
    // i<digits>e
    if (*pos >= len || buf[*pos] != 'i') return -1;
    (*pos)++;
    if (*pos >= len) return -1;
    int neg = 0;
    if (buf[*pos] == '-') { neg = 1; (*pos)++; }
    if (*pos >= len || !isdigit(buf[*pos])) return -1;
    int64_t v = 0;
    while (*pos < len && isdigit(buf[*pos])) {
        v = v * 10 + (buf[*pos] - '0');
        (*pos)++;
    }
    if (*pos >= len || buf[*pos] != 'e') return -1;
    (*pos)++;
    if (neg) v = -v;
    *out = benc_new_int(v);
    return *out ? 0 : -1;
}

static int parse_str(const uint8_t *buf, size_t len, size_t *pos, benc_t **out) {
    // <len>:<bytes>
    if (*pos >= len || !isdigit(buf[*pos])) return -1;
    size_t n = 0;
    while (*pos < len && isdigit(buf[*pos])) {
        n = n*10 + (size_t)(buf[*pos]-'0');
        (*pos)++;
        if (n > 1024*1024) return -1;
    }
    if (*pos >= len || buf[*pos] != ':') return -1;
    (*pos)++;
    if (*pos + n > len) return -1;
    *out = benc_new_str(buf + *pos, n);
    if (!*out) return -1;
    *pos += n;
    return 0;
}

static int parse_list(const uint8_t *buf, size_t len, size_t *pos, benc_t **out);
static int parse_dict(const uint8_t *buf, size_t len, size_t *pos, benc_t **out);

static int parse_any(const uint8_t *buf, size_t len, size_t *pos, benc_t **out) {
    if (*pos >= len) return -1;
    uint8_t c = buf[*pos];
    if (c == 'i') return parse_int(buf, len, pos, out);
    if (c == 'l') return parse_list(buf, len, pos, out);
    if (c == 'd') return parse_dict(buf, len, pos, out);
    if (isdigit(c)) return parse_str(buf, len, pos, out);
    return -1;
}

static int parse_list(const uint8_t *buf, size_t len, size_t *pos, benc_t **out) {
    if (*pos >= len || buf[*pos] != 'l') return -1;
    (*pos)++;
    benc_t *l = benc_new_list();
    if (!l) return -1;
    while (*pos < len && buf[*pos] != 'e') {
        benc_t *item = NULL;
        if (parse_any(buf, len, pos, &item) != 0) { benc_free(l); return -1; }
        if (benc_list_add(l, item) != 0) { benc_free(item); benc_free(l); return -1; }
    }
    if (*pos >= len || buf[*pos] != 'e') { benc_free(l); return -1; }
    (*pos)++;
    *out = l;
    return 0;
}

static int parse_dict(const uint8_t *buf, size_t len, size_t *pos, benc_t **out) {
    if (*pos >= len || buf[*pos] != 'd') return -1;
    (*pos)++;
    benc_t *d = benc_new_dict();
    if (!d) return -1;
    while (*pos < len && buf[*pos] != 'e') {
        benc_t *k = NULL;
        if (parse_str(buf, len, pos, &k) != 0) { benc_free(d); return -1; }
        benc_t *v = NULL;
        if (parse_any(buf, len, pos, &v) != 0) { benc_free(k); benc_free(d); return -1; }
        // key bytes are not NUL-terminated; copy into C string
        char *ks = (char*)malloc(k->slen + 1);
        if (!ks) { benc_free(k); benc_free(v); benc_free(d); return -1; }
        memcpy(ks, k->s, k->slen);
        ks[k->slen] = '\0';
        benc_free(k);
        if (benc_dict_set(d, ks, v) != 0) { free(ks); benc_free(v); benc_free(d); return -1; }
        free(ks);
    }
    if (*pos >= len || buf[*pos] != 'e') { benc_free(d); return -1; }
    (*pos)++;
    *out = d;
    return 0;
}

int benc_parse(const uint8_t *buf, size_t len, benc_t **out, size_t *used) {
    if (!buf || !out) return -1;
    *out = NULL;
    size_t pos = 0;
    benc_t *n = NULL;
    if (parse_any(buf, len, &pos, &n) != 0) return -1;
    if (used) *used = pos;
    *out = n;
    return 0;
}

// --- encoding ---

typedef struct {
    uint8_t *b;
    size_t len;
    size_t cap;
} wbuf_t;

static int wb_grow(wbuf_t *w, size_t add) {
    if (w->len + add <= w->cap) return 0;
    size_t nc = w->cap ? w->cap*2 : 256;
    while (nc < w->len + add) nc *= 2;
    uint8_t *nb = (uint8_t*)realloc(w->b, nc);
    if (!nb) return -1;
    w->b = nb;
    w->cap = nc;
    return 0;
}

static int wb_put(wbuf_t *w, const void *p, size_t n) {
    if (wb_grow(w, n) != 0) return -1;
    memcpy(w->b + w->len, p, n);
    w->len += n;
    return 0;
}

static int enc_any(wbuf_t *w, const benc_t *n);

static int enc_int(wbuf_t *w, int64_t v) {
    char tmp[64];
    int m = snprintf(tmp, sizeof(tmp), "i%llde", (long long)v);
    if (m <= 0) return -1;
    return wb_put(w, tmp, (size_t)m);
}

static int enc_str(wbuf_t *w, const uint8_t *s, size_t slen) {
    char tmp[64];
    int m = snprintf(tmp, sizeof(tmp), "%zu:", slen);
    if (m <= 0) return -1;
    if (wb_put(w, tmp, (size_t)m) != 0) return -1;
    if (slen) return wb_put(w, s, slen);
    return 0;
}

static int enc_list(wbuf_t *w, const benc_t *n) {
    if (wb_put(w, "l", 1) != 0) return -1;
    for (size_t i=0;i<n->list_len;i++) if (enc_any(w, n->list[i]) != 0) return -1;
    return wb_put(w, "e", 1);
}

static int kv_cmp(const void *a, const void *b) {
    const benc_kv_t *ka = (const benc_kv_t*)a;
    const benc_kv_t *kb = (const benc_kv_t*)b;
    size_t ml = ka->klen < kb->klen ? ka->klen : kb->klen;
    int c = memcmp(ka->k, kb->k, ml);
    if (c != 0) return c;
    if (ka->klen < kb->klen) return -1;
    if (ka->klen > kb->klen) return 1;
    return 0;
}

static int enc_dict(wbuf_t *w, const benc_t *n) {
    if (wb_put(w, "d", 1) != 0) return -1;
    // spec requires lexicographic order; sort a copy
    benc_kv_t *tmp = NULL;
    if (n->dict_len) {
        tmp = (benc_kv_t*)malloc(n->dict_len * sizeof(benc_kv_t));
        if (!tmp) return -1;
        memcpy(tmp, n->dict, n->dict_len * sizeof(benc_kv_t));
        qsort(tmp, n->dict_len, sizeof(benc_kv_t), kv_cmp);
    }
    for (size_t i=0;i<n->dict_len;i++) {
        if (enc_str(w, (const uint8_t*)tmp[i].k, tmp[i].klen) != 0) { free(tmp); return -1; }
        if (enc_any(w, tmp[i].v) != 0) { free(tmp); return -1; }
    }
    free(tmp);
    return wb_put(w, "e", 1);
}

static int enc_any(wbuf_t *w, const benc_t *n) {
    if (!n) return -1;
    switch (n->t) {
        case BENC_INT: return enc_int(w, n->i);
        case BENC_STR: return enc_str(w, n->s, n->slen);
        case BENC_LIST: return enc_list(w, n);
        case BENC_DICT: return enc_dict(w, n);
        default: return -1;
    }
}

int benc_encode(const benc_t *n, uint8_t **out, size_t *out_len) {
    if (!n || !out || !out_len) return -1;
    *out = NULL; *out_len = 0;
    wbuf_t w = {0};
    if (enc_any(&w, n) != 0) { free(w.b); return -1; }
    *out = w.b;
    *out_len = w.len;
    return 0;
}
