#ifndef PCOMM_BENCODE_H
#define PCOMM_BENCODE_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    BENC_INT,
    BENC_STR,
    BENC_LIST,
    BENC_DICT,
} benc_type_t;

typedef struct benc benc_t;

typedef struct {
    const char *k;
    size_t klen;
    benc_t *v;
} benc_kv_t;

struct benc {
    benc_type_t t;
    int64_t i;
    uint8_t *s;
    size_t slen;
    benc_t **list;
    size_t list_len;
    benc_kv_t *dict;
    size_t dict_len;
};

// Parse bencode. Returns 0 on success.
int benc_parse(const uint8_t *buf, size_t len, benc_t **out, size_t *used);
void benc_free(benc_t *n);

// Dict helpers
benc_t *benc_dict_get(benc_t *d, const char *key);

// Encode bencode. Allocates *out; caller frees.
int benc_encode(const benc_t *n, uint8_t **out, size_t *out_len);

// Convenience constructors (allocated nodes)
benc_t *benc_new_int(int64_t v);
benc_t *benc_new_str(const uint8_t *s, size_t slen);
benc_t *benc_new_list(void);
benc_t *benc_new_dict(void);
int benc_list_add(benc_t *l, benc_t *item);
int benc_dict_set(benc_t *d, const char *key, benc_t *val);

#endif
