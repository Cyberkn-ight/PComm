#include "bencode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ok = 0; \
        goto done; \
    } \
} while (0)

static int nodes_equal(const benc_t *left, const benc_t *right) {
    if (!left || !right || left->t != right->t) return 0;
    switch (left->t) {
        case BENC_INT:
            return left->i == right->i;
        case BENC_STR:
            return left->slen == right->slen &&
                (left->slen == 0 || memcmp(left->s, right->s, left->slen) == 0);
        case BENC_LIST:
            if (left->list_len != right->list_len) return 0;
            for (size_t i = 0; i < left->list_len; i++) {
                if (!nodes_equal(left->list[i], right->list[i])) return 0;
            }
            return 1;
        case BENC_DICT:
            if (left->dict_len != right->dict_len) return 0;
            for (size_t i = 0; i < left->dict_len; i++) {
                const benc_kv_t *entry = &left->dict[i];
                size_t j;
                for (j = 0; j < right->dict_len; j++) {
                    const benc_kv_t *other = &right->dict[j];
                    if (entry->klen == other->klen &&
                        (entry->klen == 0 || memcmp(entry->k, other->k, entry->klen) == 0)) break;
                }
                if (j == right->dict_len || !nodes_equal(entry->v, right->dict[j].v)) return 0;
            }
            return 1;
        default:
            return 0;
    }
}

static int parse_exact(const uint8_t *bytes, size_t len, benc_t **out) {
    size_t used = SIZE_MAX;
    *out = NULL;
    if (benc_parse(bytes, len, out, &used) == 0 && used == len) return 1;
    benc_free(*out);
    *out = NULL;
    return 0;
}

static int encoded_is(const benc_t *node, const uint8_t *expected, size_t expected_len) {
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    int ok = benc_encode(node, &encoded, &encoded_len) == 0 &&
        encoded_len == expected_len &&
        (expected_len == 0 || memcmp(encoded, expected, expected_len) == 0);
    free(encoded);
    return ok;
}

/* Transfer a newly created node on success; free it on an add/set failure. */
static int add_new(benc_t *list, benc_t *node) {
    if (node && benc_list_add(list, node) == 0) return 1;
    benc_free(node);
    return 0;
}

static int set_new(benc_t *dict, const char *key, benc_t *node) {
    if (node && benc_dict_set(dict, key, node) == 0) return 1;
    benc_free(node);
    return 0;
}

static int test_integer_golden_vectors(void) {
    static const struct {
        int64_t value;
        const char *wire;
    } vectors[] = {
        {0, "i0e"},
        {1, "i1e"},
        {-1, "i-1e"},
        {42, "i42e"},
        {-123456789, "i-123456789e"},
        {INT64_MAX, "i9223372036854775807e"},
        {INT64_MIN, "i-9223372036854775808e"}
    };
    benc_t *created = NULL, *parsed = NULL;
    int ok = 1;
    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        const uint8_t *wire = (const uint8_t *)vectors[i].wire;
        size_t len = strlen(vectors[i].wire);
        created = benc_new_int(vectors[i].value);
        CHECK(created != NULL);
        CHECK(encoded_is(created, wire, len));
        CHECK(parse_exact(wire, len, &parsed));
        CHECK(parsed->t == BENC_INT && parsed->i == vectors[i].value);
        CHECK(nodes_equal(created, parsed));
        benc_free(created);
        benc_free(parsed);
        created = parsed = NULL;
    }
done:
    benc_free(created);
    benc_free(parsed);
    return ok;
}

static int test_empty_and_binary_strings(void) {
    static const uint8_t binary[] = {0, 'A', 255, ':'};
    static const uint8_t binary_wire[] = {'4', ':', 0, 'A', 255, ':'};
    uint8_t all_bytes[256], all_wire[4 + 256];
    benc_t *created = NULL, *parsed = NULL;
    int ok = 1;

    created = benc_new_str(NULL, 0);
    CHECK(created != NULL);
    CHECK(encoded_is(created, (const uint8_t *)"0:", 2));
    CHECK(parse_exact((const uint8_t *)"0:", 2, &parsed));
    CHECK(parsed->t == BENC_STR && parsed->slen == 0);
    CHECK(nodes_equal(created, parsed));
    benc_free(created);
    benc_free(parsed);
    created = parsed = NULL;

    created = benc_new_str(binary, sizeof(binary));
    CHECK(created != NULL);
    CHECK(encoded_is(created, binary_wire, sizeof(binary_wire)));
    CHECK(parse_exact(binary_wire, sizeof(binary_wire), &parsed));
    CHECK(nodes_equal(created, parsed));
    benc_free(created);
    benc_free(parsed);
    created = parsed = NULL;

    for (size_t i = 0; i < sizeof(all_bytes); i++) all_bytes[i] = (uint8_t)i;
    memcpy(all_wire, "256:", 4);
    memcpy(all_wire + 4, all_bytes, sizeof(all_bytes));
    created = benc_new_str(all_bytes, sizeof(all_bytes));
    CHECK(created != NULL);
    CHECK(encoded_is(created, all_wire, sizeof(all_wire)));
    CHECK(parse_exact(all_wire, sizeof(all_wire), &parsed));
    CHECK(nodes_equal(created, parsed));
done:
    benc_free(created);
    benc_free(parsed);
    return ok;
}

static int test_empty_containers(void) {
    benc_t *list = NULL, *dict = NULL, *parsed = NULL;
    int ok = 1;
    list = benc_new_list();
    dict = benc_new_dict();
    CHECK(list != NULL && dict != NULL);
    CHECK(encoded_is(list, (const uint8_t *)"le", 2));
    CHECK(encoded_is(dict, (const uint8_t *)"de", 2));
    CHECK(parse_exact((const uint8_t *)"le", 2, &parsed));
    CHECK(nodes_equal(list, parsed));
    benc_free(parsed);
    parsed = NULL;
    CHECK(parse_exact((const uint8_t *)"de", 2, &parsed));
    CHECK(nodes_equal(dict, parsed));
done:
    benc_free(list);
    benc_free(dict);
    benc_free(parsed);
    return ok;
}

static int test_nested_golden_roundtrip(void) {
    static const uint8_t binary[] = {'A', 0, 'B'};
    static const uint8_t wire[] =
        "d5:counti4e5:itemsli-7e3:A\0Bd1:xle1:ydee0:ee";
    benc_t *root = NULL, *items = NULL, *nested = NULL, *parsed = NULL;
    int ok = 1;
    root = benc_new_dict();
    items = benc_new_list();
    nested = benc_new_dict();
    CHECK(root != NULL && items != NULL && nested != NULL);
    CHECK(set_new(nested, "y", benc_new_dict()));
    CHECK(set_new(nested, "x", benc_new_list()));
    CHECK(add_new(items, benc_new_int(-7)));
    CHECK(add_new(items, benc_new_str(binary, sizeof(binary))));
    CHECK(benc_list_add(items, nested) == 0);
    nested = NULL;
    CHECK(add_new(items, benc_new_str(NULL, 0)));
    CHECK(benc_dict_set(root, "items", items) == 0);
    items = NULL;
    CHECK(set_new(root, "count", benc_new_int(4)));
    CHECK(encoded_is(root, wire, sizeof(wire) - 1));
    CHECK(parse_exact(wire, sizeof(wire) - 1, &parsed));
    CHECK(nodes_equal(root, parsed));
    CHECK(encoded_is(parsed, wire, sizeof(wire) - 1));
done:
    benc_free(root);
    benc_free(items);
    benc_free(nested);
    benc_free(parsed);
    return ok;
}

static int test_dictionary_order_and_replacement(void) {
    static const uint8_t wire[] =
        "d0:i5e1:Ai4e1:ai7e2:abi2e1:zi1e1:\x80" "i6ee";
    benc_t *dict = NULL, *parsed = NULL;
    int ok = 1;
    dict = benc_new_dict();
    CHECK(dict != NULL);
    CHECK(set_new(dict, "z", benc_new_int(1)));
    CHECK(set_new(dict, "ab", benc_new_int(2)));
    CHECK(set_new(dict, "a", benc_new_int(3)));
    CHECK(set_new(dict, "A", benc_new_int(4)));
    CHECK(set_new(dict, "", benc_new_int(5)));
    CHECK(set_new(dict, "\x80", benc_new_int(6)));
    CHECK(set_new(dict, "a", benc_new_int(7)));
    CHECK(dict->dict_len == 6);
    CHECK(benc_dict_get(dict, "a") != NULL && benc_dict_get(dict, "a")->i == 7);
    CHECK(benc_dict_get(dict, "z") != NULL && benc_dict_get(dict, "z")->i == 1);
    CHECK(benc_dict_get(dict, "missing") == NULL);
    CHECK(encoded_is(dict, wire, sizeof(wire) - 1));
    CHECK(parse_exact(wire, sizeof(wire) - 1, &parsed));
    CHECK(nodes_equal(dict, parsed));
done:
    benc_free(dict);
    benc_free(parsed);
    return ok;
}

static int test_binary_dictionary_keys_roundtrip(void) {
    static const uint8_t wire[] = "d0:i1e1:ai2e3:a\0bi3e1:bi4ee";
    static const uint8_t binary_key[] = {'a', 0, 'b'};
    benc_t *parsed = NULL;
    size_t binary_keys = 0;
    int ok = 1;
    CHECK(parse_exact(wire, sizeof(wire) - 1, &parsed));
    CHECK(parsed->t == BENC_DICT && parsed->dict_len == 4);
    CHECK(benc_dict_get(parsed, "") != NULL && benc_dict_get(parsed, "")->i == 1);
    CHECK(benc_dict_get(parsed, "a") != NULL && benc_dict_get(parsed, "a")->i == 2);
    for (size_t i = 0; i < parsed->dict_len; i++) {
        const benc_kv_t *entry = &parsed->dict[i];
        if (entry->klen == sizeof(binary_key) &&
            memcmp(entry->k, binary_key, sizeof(binary_key)) == 0) {
            CHECK(entry->v->t == BENC_INT && entry->v->i == 3);
            binary_keys++;
        }
    }
    CHECK(binary_keys == 1);
    CHECK(encoded_is(parsed, wire, sizeof(wire) - 1));
done:
    benc_free(parsed);
    return ok;
}

static int test_malformed_and_truncated_input(void) {
    static const char *const malformed[] = {
        "", "x", "e", "i", "ie", "i-e", "i+1e", "i1", "i1.0e", "i1xe",
        "i-0e", "i00e", "i01e", "i-01e",
        "i9223372036854775808e", "i-9223372036854775809e", "i18446744073709551616e",
        ":", "1", "1a", "2:a", "3:ab", "-1:a",
        "l", "li1e", "li1exe", "d", "d1:a", "di1ei2ee", "d1:ai1e", "d1:ae", "d1:al"
    };
    static const uint8_t nested[] = "d1:ali-2e3:A\0Bee";
    benc_t *parsed = NULL;
    int ok = 1;
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
        size_t used = SIZE_MAX;
        int rc = benc_parse((const uint8_t *)malformed[i], strlen(malformed[i]), &parsed, &used);
        if (rc == 0) fprintf(stderr, "malformed vector accepted: %s\n", malformed[i]);
        CHECK(rc != 0);
        benc_free(parsed);
        parsed = NULL;
    }
    CHECK(parse_exact(nested, sizeof(nested) - 1, &parsed));
    benc_free(parsed);
    parsed = NULL;
    for (size_t len = 0; len < sizeof(nested) - 1; len++) {
        CHECK(benc_parse(nested, len, &parsed, NULL) != 0);
        benc_free(parsed);
        parsed = NULL;
    }
done:
    benc_free(parsed);
    return ok;
}

static int test_used_count_for_adjacent_values(void) {
    static const uint8_t wire[] = "i7e3:food1:ai1ee";
    static const size_t expected_used[] = {3, 5, 8};
    benc_t *parsed = NULL;
    size_t offset = 0;
    int ok = 1;
    for (size_t i = 0; i < sizeof(expected_used) / sizeof(expected_used[0]); i++) {
        size_t used = SIZE_MAX;
        CHECK(benc_parse(wire + offset, sizeof(wire) - 1 - offset, &parsed, &used) == 0);
        CHECK(used == expected_used[i]);
        if (i == 0) CHECK(parsed->t == BENC_INT && parsed->i == 7);
        if (i == 1) {
            CHECK(parsed->t == BENC_STR && parsed->slen == 3);
            CHECK(memcmp(parsed->s, "foo", 3) == 0);
        }
        if (i == 2) {
            CHECK(parsed->t == BENC_DICT && parsed->dict_len == 1);
            benc_t *value = benc_dict_get(parsed, "a");
            CHECK(value != NULL && value->t == BENC_INT && value->i == 1);
        }
        offset += used;
        benc_free(parsed);
        parsed = NULL;
    }
    CHECK(offset == sizeof(wire) - 1);
    CHECK(benc_parse((const uint8_t *)"i9ex", 4, &parsed, NULL) == 0);
    CHECK(parsed->t == BENC_INT && parsed->i == 9);
done:
    benc_free(parsed);
    return ok;
}

int main(void) {
    static const struct {
        const char *name;
        int (*run)(void);
    } tests[] = {
        {"integer golden vectors and int64 boundaries", test_integer_golden_vectors},
        {"empty and binary strings", test_empty_and_binary_strings},
        {"empty containers", test_empty_containers},
        {"nested golden roundtrip", test_nested_golden_roundtrip},
        {"dictionary ordering and replacement", test_dictionary_order_and_replacement},
        {"binary dictionary keys", test_binary_dictionary_keys_roundtrip},
        {"malformed and truncated input", test_malformed_and_truncated_input},
        {"used count for adjacent values", test_used_count_for_adjacent_values}
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (!tests[i].run()) {
            fprintf(stderr, "Bencode check failed: %s\n", tests[i].name);
            failed = 1;
        }
    }
    if (failed) return 1;
    puts("Bencode checks passed.");
    return 0;
}
