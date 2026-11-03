#include "msg.h"

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

typedef struct {
    pcomm_plain_kind_t kind;
    uint32_t timestamp;
    char sender[96];
    char group[64];
    char *title;
    char **members;
    int member_count;
    char *text;
} decoded_t;

static void decoded_free(decoded_t *decoded) {
    free(decoded->title);
    pcomm_msg_free_members(decoded->members, decoded->member_count);
    free(decoded->text);
    memset(decoded, 0, sizeof(*decoded));
}

static int decode(const uint8_t *wire, size_t len, decoded_t *decoded,
                   size_t sender_cap, size_t group_cap) {
    return pcomm_msg_unpack_any(wire, len, &decoded->kind, &decoded->timestamp,
                                decoded->sender, sender_cap, decoded->group, group_cap,
                                &decoded->title, &decoded->members,
                                &decoded->member_count, &decoded->text);
}

static int unpack(const uint8_t *wire, size_t len, decoded_t *decoded) {
    return decode(wire, len, decoded, sizeof(decoded->sender), sizeof(decoded->group));
}

static int rejected(const uint8_t *wire, size_t len) {
    decoded_t decoded = {0};
    int rc = unpack(wire, len, &decoded);
    decoded_free(&decoded);
    return rc == -1;
}

static int all_truncated_prefixes_rejected(const uint8_t *wire, size_t len) {
    for (size_t prefix = 0; prefix < len; prefix++) {
        if (!rejected(wire, prefix)) {
            fprintf(stderr, "accepted truncated prefix of %zu/%zu bytes\n", prefix, len);
            return 0;
        }
    }
    return 1;
}

static void repeated(char *text, size_t len, char value) {
    memset(text, value, len);
    text[len] = '\0';
}

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static int test_direct_roundtrips_and_wire_format(void) {
    const uint8_t expected[] = {2, 1, 1, 2, 3, 4, 0, 1, 'a', 0, 0, 0, 1, 'B'};
    const char *texts[] = {"", "ordinary text", "caf\xc3\xa9 \xf0\x9f\x94\x92"};
    const uint32_t timestamps[] = {0, UINT32_MAX, UINT32_C(0x01020304)};
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    decoded_t decoded = {0};
    int ok = 1;
    CHECK(pcomm_msg_pack_direct_text(UINT32_C(0x01020304), "a", "B", &wire, &wire_len) == 0);
    CHECK(wire_len == sizeof(expected) && memcmp(wire, expected, sizeof(expected)) == 0);
    CHECK(all_truncated_prefixes_rejected(wire, wire_len));
    free(wire);
    wire = NULL;

    for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++) {
        CHECK(pcomm_msg_pack_direct_text(timestamps[i], "sender-id", texts[i], &wire, &wire_len) == 0);
        CHECK(unpack(wire, wire_len, &decoded) == 0);
        CHECK(decoded.kind == PCOMM_PLAIN_DIRECT_TEXT && decoded.timestamp == timestamps[i]);
        CHECK(strcmp(decoded.sender, "sender-id") == 0 && strcmp(decoded.text, texts[i]) == 0);
        CHECK(decoded.group[0] == '\0' && decoded.title == NULL && decoded.members == NULL);
        decoded_free(&decoded);
        free(wire);
        wire = NULL;
    }
done:
    decoded_free(&decoded);
    free(wire);
    return ok;
}

static int test_group_invite_roundtrip(void) {
    char *members[] = {"sender-id", "member-two", "membre-\xc3\xa9"};
    const char *title = "Salon priv\xc3\xa9";
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    decoded_t decoded = {0};
    int ok = 1;
    CHECK(pcomm_msg_pack_group_invite(UINT32_C(0xfedcba98), "sender-id", "group-uuid", title,
                                      members, 3, &wire, &wire_len) == 0);
    CHECK(wire[0] == 2 && wire[1] == PCOMM_PLAIN_GROUP_INVITE);
    CHECK(read_u32(wire + 2) == UINT32_C(0xfedcba98));
    CHECK(read_u16(wire + 6) == strlen("sender-id"));
    size_t group_offset = 8 + strlen("sender-id");
    size_t title_offset = group_offset + 1 + strlen("group-uuid");
    CHECK(wire[group_offset] == strlen("group-uuid"));
    CHECK(read_u16(wire + title_offset) == strlen(title));
    CHECK(read_u16(wire + title_offset + 2 + strlen(title)) == 3);
    CHECK(unpack(wire, wire_len, &decoded) == 0);
    CHECK(decoded.kind == PCOMM_PLAIN_GROUP_INVITE && decoded.timestamp == UINT32_C(0xfedcba98));
    CHECK(strcmp(decoded.sender, "sender-id") == 0 && strcmp(decoded.group, "group-uuid") == 0);
    CHECK(strcmp(decoded.title, title) == 0 && decoded.member_count == 3 && decoded.text == NULL);
    for (int i = 0; i < decoded.member_count; i++) CHECK(strcmp(decoded.members[i], members[i]) == 0);
    CHECK(all_truncated_prefixes_rejected(wire, wire_len));
done:
    decoded_free(&decoded);
    free(wire);
    return ok;
}

static int test_empty_invite_and_group_text(void) {
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    decoded_t decoded = {0};
    const char *texts[] = {"", "groupe \xe2\x9c\x93"};
    int ok = 1;
    CHECK(pcomm_msg_pack_group_invite(0, "s", "g", "", NULL, 0, &wire, &wire_len) == 0);
    CHECK(wire_len == 15 && wire[0] == 2 && wire[1] == PCOMM_PLAIN_GROUP_INVITE);
    CHECK(read_u16(wire + 11) == 0 && read_u16(wire + 13) == 0);
    CHECK(unpack(wire, wire_len, &decoded) == 0);
    CHECK(decoded.kind == PCOMM_PLAIN_GROUP_INVITE && decoded.timestamp == 0);
    CHECK(strcmp(decoded.sender, "s") == 0 && strcmp(decoded.group, "g") == 0);
    CHECK(decoded.title != NULL && decoded.title[0] == '\0' && decoded.member_count == 0);

    CHECK(decoded.text == NULL);
    decoded_free(&decoded);
    free(wire);
    wire = NULL;

    for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++) {
        CHECK(pcomm_msg_pack_group_text(123456, "sender", "group", texts[i], &wire, &wire_len) == 0);
        CHECK(wire[0] == 2 && wire[1] == PCOMM_PLAIN_GROUP_TEXT);
        CHECK(unpack(wire, wire_len, &decoded) == 0);
        CHECK(decoded.kind == PCOMM_PLAIN_GROUP_TEXT && decoded.timestamp == 123456);
        CHECK(strcmp(decoded.sender, "sender") == 0 && strcmp(decoded.group, "group") == 0);
        CHECK(strcmp(decoded.text, texts[i]) == 0 && decoded.title == NULL && decoded.members == NULL);
        CHECK(all_truncated_prefixes_rejected(wire, wire_len));
        decoded_free(&decoded);
        free(wire);
        wire = NULL;
    }
done:
    decoded_free(&decoded);
    free(wire);
    return ok;
}

static int test_legacy_v1_decode(void) {
    uint8_t wire[] = {1, 0x89, 0xab, 0xcd, 0xef, 0, 3, 'o', 'l', 'd',
                      0, 0, 0, 4, 't', 'e', 'x', 't'};
    decoded_t decoded = {0};
    int ok = 1;
    CHECK(unpack(wire, sizeof(wire), &decoded) == 0);
    CHECK(decoded.kind == PCOMM_PLAIN_DIRECT_TEXT && decoded.timestamp == UINT32_C(0x89abcdef));
    CHECK(strcmp(decoded.sender, "old") == 0 && strcmp(decoded.text, "text") == 0);
    CHECK(decoded.group[0] == '\0' && decoded.title == NULL && decoded.members == NULL);
    CHECK(all_truncated_prefixes_rejected(wire, sizeof(wire)));
    wire[5] = wire[6] = 0xff;
    CHECK(rejected(wire, sizeof(wire)));
    wire[5] = 0;
    wire[6] = 3;
    memset(wire + 10, 0xff, 4);
    CHECK(rejected(wire, sizeof(wire)));
done:
    decoded_free(&decoded);
    return ok;
}

static int test_field_length_boundaries(void) {
    char sender[92], group[65], title[1026], member[92];
    char *members[] = {member};
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    decoded_t decoded = {0};
    int ok = 1;
    repeated(sender, 90, 's');
    repeated(group, 63, 'g');
    repeated(title, 1024, 't');
    repeated(member, 90, 'm');
    CHECK(pcomm_msg_pack_direct_text(1, sender, "text", &wire, &wire_len) == 0);
    CHECK(decode(wire, wire_len, &decoded, 91, sizeof(decoded.group)) == 0);
    CHECK(strcmp(decoded.sender, sender) == 0);
    decoded_free(&decoded);
    CHECK(decode(wire, wire_len, &decoded, 90, sizeof(decoded.group)) == -1);
    decoded_free(&decoded);
    free(wire);
    wire = NULL;

    CHECK(pcomm_msg_pack_group_invite(2, sender, group, title, members, 1, &wire, &wire_len) == 0);
    CHECK(decode(wire, wire_len, &decoded, 91, 64) == 0);
    CHECK(strcmp(decoded.sender, sender) == 0 && strcmp(decoded.group, group) == 0);
    CHECK(strcmp(decoded.title, title) == 0 && decoded.member_count == 1);
    CHECK(strcmp(decoded.members[0], member) == 0);
    decoded_free(&decoded);
    CHECK(decode(wire, wire_len, &decoded, 91, 63) == -1);
    decoded_free(&decoded);
    free(wire);
    wire = NULL;

    CHECK(pcomm_msg_pack_group_text(3, sender, group, "text", &wire, &wire_len) == 0);
    CHECK(unpack(wire, wire_len, &decoded) == 0);
    CHECK(strcmp(decoded.sender, sender) == 0 && strcmp(decoded.group, group) == 0);
    decoded_free(&decoded);
    free(wire);
    wire = NULL;

    repeated(sender, 91, 's');
    CHECK(pcomm_msg_pack_direct_text(1, sender, "text", &wire, &wire_len) == -1);
    CHECK(pcomm_msg_pack_group_invite(1, sender, group, title, members, 1, &wire, &wire_len) == -1);
    CHECK(pcomm_msg_pack_group_text(1, sender, group, "text", &wire, &wire_len) == -1);
    repeated(sender, 90, 's');
    repeated(group, 64, 'g');
    CHECK(pcomm_msg_pack_group_invite(1, sender, group, title, members, 1, &wire, &wire_len) == -1);
    CHECK(pcomm_msg_pack_group_text(1, sender, group, "text", &wire, &wire_len) == -1);
    repeated(group, 63, 'g');
    repeated(title, 1025, 't');
    CHECK(pcomm_msg_pack_group_invite(1, sender, group, title, members, 1, &wire, &wire_len) == -1);
    repeated(title, 1024, 't');
    repeated(member, 91, 'm');
    CHECK(pcomm_msg_pack_group_invite(1, sender, group, title, members, 1, &wire, &wire_len) == -1);
done:
    decoded_free(&decoded);
    free(wire);
    return ok;
}

static int test_unknown_types_and_bogus_lengths(void) {
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    char *members[] = {"m"};
    int ok = 1;
    CHECK(pcomm_msg_pack_direct_text(1, "s", "text", &wire, &wire_len) == 0);
    wire[0] = 0;
    CHECK(rejected(wire, wire_len));
    wire[0] = 3;
    CHECK(rejected(wire, wire_len));
    wire[0] = 2;
    wire[1] = 0xff;
    CHECK(rejected(wire, wire_len));
    wire[1] = PCOMM_PLAIN_DIRECT_TEXT;
    wire[6] = wire[7] = 0xff;
    CHECK(rejected(wire, wire_len));
    wire[6] = 0;
    wire[7] = 1;
    memset(wire + 9, 0xff, 4);
    CHECK(rejected(wire, wire_len));
    free(wire);
    wire = NULL;

    CHECK(pcomm_msg_pack_group_invite(1, "s", "g", "t", members, 1, &wire, &wire_len) == 0);

    wire[9] = 0xff;
    CHECK(rejected(wire, wire_len));
    wire[9] = 1;
    wire[11] = wire[12] = 0xff;
    CHECK(rejected(wire, wire_len));
    wire[11] = 0;
    wire[12] = 1;
    wire[14] = 0;
    wire[15] = 2;
    CHECK(rejected(wire, wire_len));
    wire[15] = 1;
    wire[16] = wire[17] = 0xff;
    CHECK(rejected(wire, wire_len));
    free(wire);
    wire = NULL;

    CHECK(pcomm_msg_pack_group_text(1, "s", "g", "text", &wire, &wire_len) == 0);
    wire[9] = 0xff;
    CHECK(rejected(wire, wire_len));
    wire[9] = 1;
    memset(wire + 11, 0xff, 4);
    CHECK(rejected(wire, wire_len));
done:
    free(wire);
    return ok;
}

int main(void) {
    const struct {
        const char *name;
        int (*run)(void);
    } tests[] = {
        {"direct roundtrips and independent wire format", test_direct_roundtrips_and_wire_format},
        {"group invite roundtrip", test_group_invite_roundtrip},
        {"empty invite and group text", test_empty_invite_and_group_text},
        {"legacy v1 decode", test_legacy_v1_decode},
        {"field length boundaries", test_field_length_boundaries},
        {"unknown types and bogus lengths", test_unknown_types_and_bogus_lengths},
    };
    size_t failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int passed = tests[i].run();
        printf("%s: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if (!passed) failures++;
    }
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
