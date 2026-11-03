#include "proto.h"
#include "net.h"

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

static const uint8_t *input;
static size_t input_size, input_offset;
static size_t recv_sizes[4];
static unsigned recv_calls, send_calls, fail_recv_call, fail_send_call;
static uint8_t output[PCOMM_MAX_PACKET_LEN];
static size_t output_size;

static void reset_io(const uint8_t *bytes, size_t size) {
    input = bytes;
    input_size = size;
    input_offset = output_size = 0;
    recv_calls = send_calls = fail_recv_call = fail_send_call = 0;
    memset(recv_sizes, 0, sizeof(recv_sizes));
}

int net_recvall(int fd, void *buf, size_t len) {
    size_t available = input_size - input_offset;
    size_t copied = len < available ? len : available;
    (void)fd;
    recv_calls++;
    if (recv_calls <= sizeof(recv_sizes) / sizeof(recv_sizes[0])) recv_sizes[recv_calls - 1] = len;
    if (recv_calls == fail_recv_call) return -1;
    if (copied > 0) memcpy(buf, input + input_offset, copied);
    input_offset += copied;
    return copied == len ? 0 : -1;
}

int net_sendall(int fd, const void *buf, size_t len) {
    (void)fd;
    send_calls++;
    if (send_calls == fail_send_call || len > sizeof(output) - output_size) return -1;
    if (len > 0) memcpy(output + output_size, buf, len);
    output_size += len;
    return 0;
}

static void header(uint8_t bytes[PCOMM_HDR_LEN], uint32_t payload_len) {
    memset(bytes, 0, PCOMM_HDR_LEN);
    memcpy(bytes, PCOMM_MAGIC, 4);
    bytes[4] = PCOMM_VERSION;
    bytes[5] = PCOMM_MSG_DELIVER;
    bytes[8] = (uint8_t)(payload_len >> 24);
    bytes[9] = (uint8_t)(payload_len >> 16);
    bytes[10] = (uint8_t)(payload_len >> 8);
    bytes[11] = (uint8_t)payload_len;
}

static int test_roundtrips(void) {
    const uint32_t sizes[] = {0, 1, 4096, PCOMM_MAX_PACKET_PAYLOAD};
    uint8_t *payload = NULL, *packed = NULL, *unpacked = NULL;
    uint8_t eph[32], received_eph[32];
    uint32_t packed_len = 0, unpacked_len = 0;
    pcomm_msg_type_t type = 0;
    int ok = 1;
    payload = (uint8_t *)malloc(PCOMM_MAX_PACKET_PAYLOAD);
    CHECK(payload != NULL);
    for (uint32_t i = 0; i < PCOMM_MAX_PACKET_PAYLOAD; i++) payload[i] = (uint8_t)(i * 37u + 3u);
    for (size_t i = 0; i < sizeof(eph); i++) eph[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        const uint8_t *body = sizes[i] ? payload : NULL;
        CHECK(pcomm_pack_packet(PCOMM_MSG_DELIVER, eph, body, sizes[i], &packed, &packed_len) == 0);
        CHECK(packed_len == PCOMM_HDR_LEN + sizes[i]);
        CHECK(pcomm_unpack_packet(packed, packed_len, &type, received_eph, &unpacked, &unpacked_len) == 0);
        CHECK(type == PCOMM_MSG_DELIVER && unpacked_len == sizes[i]);
        CHECK(memcmp(eph, received_eph, sizeof(eph)) == 0);
        CHECK(sizes[i] == 0 ? unpacked == NULL : memcmp(payload, unpacked, sizes[i]) == 0);
        free(unpacked);
        unpacked = NULL;

        reset_io(NULL, 0);
        CHECK(pcomm_send_packet(1, PCOMM_MSG_DELIVER, eph, body, sizes[i]) == 0);
        CHECK(output_size == packed_len && memcmp(output, packed, packed_len) == 0);
        CHECK(send_calls == (sizes[i] ? 2u : 1u));
        reset_io(packed, packed_len);
        CHECK(pcomm_recv_packet(1, &type, received_eph, &unpacked, &unpacked_len) == 0);
        CHECK(type == PCOMM_MSG_DELIVER && unpacked_len == sizes[i]);
        CHECK(memcmp(eph, received_eph, sizeof(eph)) == 0);
        CHECK(sizes[i] == 0 ? unpacked == NULL : memcmp(payload, unpacked, sizes[i]) == 0);
        CHECK(input_offset == packed_len && recv_calls == (sizes[i] ? 2u : 1u));
        free(unpacked);
        unpacked = NULL;
        free(packed);
        packed = NULL;
    }
done:
    free(payload);
    free(packed);
    free(unpacked);
    return ok;
}

static int test_send_and_pack_reject_invalid_payloads(void) {
    const uint32_t invalid_sizes[] = {PCOMM_MAX_PACKET_PAYLOAD + 1u, UINT32_MAX};
    uint8_t byte = 9;
    uint8_t *packed = NULL;
    uint32_t packed_len = 0;
    int ok = 1;
    for (size_t i = 0; i < sizeof(invalid_sizes) / sizeof(invalid_sizes[0]); i++) {
        reset_io(NULL, 0);
        CHECK(pcomm_send_packet(1, PCOMM_MSG_DELIVER, NULL, &byte, invalid_sizes[i]) == -1);
        CHECK(send_calls == 0 && output_size == 0);
        packed = &byte;
        packed_len = 99;
        CHECK(pcomm_pack_packet(PCOMM_MSG_DELIVER, NULL, &byte, invalid_sizes[i], &packed, &packed_len) == -1);
        CHECK(packed == NULL && packed_len == 0);
    }
    reset_io(NULL, 0);
    CHECK(pcomm_send_packet(1, PCOMM_MSG_DELIVER, NULL, NULL, 1) == -1);
    CHECK(send_calls == 0);
    packed = &byte;
    packed_len = 99;
    CHECK(pcomm_pack_packet(PCOMM_MSG_DELIVER, NULL, NULL, 1, &packed, &packed_len) == -1);
    CHECK(packed == NULL && packed_len == 0);
    packed = &byte;
    CHECK(pcomm_pack_packet(PCOMM_MSG_DELIVER, NULL, &byte, 1, &packed, NULL) == -1);
    CHECK(packed == NULL);
    packed_len = 99;
    CHECK(pcomm_pack_packet(PCOMM_MSG_DELIVER, NULL, &byte, 1, NULL, &packed_len) == -1);
    CHECK(packed_len == 0);
    for (unsigned failed_call = 1; failed_call <= 2; failed_call++) {
        reset_io(NULL, 0);
        fail_send_call = failed_call;
        CHECK(pcomm_send_packet(1, PCOMM_MSG_DELIVER, NULL, &byte, 1) == -1);
        CHECK(send_calls == failed_call);
    }
done:
    return ok;
}

static int test_oversized_receive_never_reads_body(void) {
    const uint32_t sizes[] = {PCOMM_MAX_PACKET_PAYLOAD + 1u, UINT32_MAX};
    uint8_t bytes[PCOMM_HDR_LEN], sentinel = 1;
    uint8_t *payload;
    uint32_t payload_len;
    pcomm_msg_type_t type = 0;
    int ok = 1;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        header(bytes, sizes[i]);
        reset_io(bytes, sizeof(bytes));
        payload = &sentinel;
        payload_len = 99;
        CHECK(pcomm_recv_packet(1, &type, NULL, &payload, &payload_len) == -1);
        CHECK(payload == NULL && payload_len == 0);
        CHECK(recv_calls == 1 && recv_sizes[0] == PCOMM_HDR_LEN && input_offset == PCOMM_HDR_LEN);
    }
done:
    return ok;
}

static int test_receive_failures_and_stream_boundary(void) {
    uint8_t bytes[PCOMM_HDR_LEN + 4], sentinel = 1;
    uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    pcomm_msg_type_t type = 0;
    int ok = 1;
    header(bytes, 3);
    memset(bytes + PCOMM_HDR_LEN, 7, 4);
    for (unsigned failure = 0; failure < 4; failure++) {
        reset_io(bytes, failure == 0 ? PCOMM_HDR_LEN - 1 : failure == 1 ? PCOMM_HDR_LEN + 2 : sizeof(bytes));
        if (failure >= 2) fail_recv_call = failure - 1;
        payload = &sentinel;
        payload_len = 99;
        CHECK(pcomm_recv_packet(1, &type, NULL, &payload, &payload_len) == -1);
        CHECK(payload == NULL && payload_len == 0);
    }
    for (unsigned bad_field = 0; bad_field < 2; bad_field++) {
        header(bytes, 3);
        bytes[bad_field ? 4 : 0] ^= 0x80;
        reset_io(bytes, sizeof(bytes));
        payload = &sentinel;
        payload_len = 99;
        CHECK(pcomm_recv_packet(1, &type, NULL, &payload, &payload_len) == -1);
        CHECK(payload == NULL && payload_len == 0 && recv_calls == 1);
    }
    header(bytes, 3);
    reset_io(bytes, sizeof(bytes));
    payload = &sentinel;
    payload_len = 99;
    CHECK(pcomm_recv_packet(1, NULL, NULL, &payload, &payload_len) == -1);
    CHECK(payload == NULL && payload_len == 0 && recv_calls == 0);
    payload = &sentinel;
    CHECK(pcomm_recv_packet(1, &type, NULL, &payload, NULL) == -1);
    CHECK(payload == NULL && recv_calls == 0);
    payload_len = 99;
    CHECK(pcomm_recv_packet(1, &type, NULL, NULL, &payload_len) == -1);
    CHECK(payload_len == 0 && recv_calls == 0);

    CHECK(pcomm_recv_packet(1, &type, NULL, &payload, &payload_len) == 0);
    CHECK(payload_len == 3 && input_offset == PCOMM_HDR_LEN + 3);
    CHECK(input_size - input_offset == 1);
done:
    if (payload != &sentinel) free(payload);
    return ok;
}

static int test_unpack_rejects_bad_lengths_and_headers(void) {
    uint8_t bytes[PCOMM_HDR_LEN + 4], sentinel = 1;
    uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    pcomm_msg_type_t type = 0;
    int ok = 1;
    const uint32_t bad_lengths[] = {0, PCOMM_HDR_LEN - 1, PCOMM_HDR_LEN + 2, PCOMM_HDR_LEN + 4, UINT32_MAX};
    header(bytes, 3);
    memset(bytes + PCOMM_HDR_LEN, 7, 4);
    for (size_t i = 0; i < sizeof(bad_lengths) / sizeof(bad_lengths[0]); i++) {
        payload = &sentinel;
        payload_len = 99;
        CHECK(pcomm_unpack_packet(bytes, bad_lengths[i], &type, NULL, &payload, &payload_len) == -1);
        CHECK(payload == NULL && payload_len == 0);
    }
    header(bytes, PCOMM_MAX_PACKET_PAYLOAD + 1u);
    payload = &sentinel;
    payload_len = 99;
    CHECK(pcomm_unpack_packet(bytes, PCOMM_HDR_LEN, &type, NULL, &payload, &payload_len) == -1);
    CHECK(payload == NULL && payload_len == 0);
    header(bytes, UINT32_MAX);
    payload = &sentinel;
    payload_len = 99;
    CHECK(pcomm_unpack_packet(bytes, PCOMM_HDR_LEN, &type, NULL, &payload, &payload_len) == -1);
    CHECK(payload == NULL && payload_len == 0);
    for (unsigned bad_field = 0; bad_field < 2; bad_field++) {
        header(bytes, 3);
        bytes[bad_field ? 4 : 0] ^= 0x80;
        payload = &sentinel;
        payload_len = 99;
        CHECK(pcomm_unpack_packet(bytes, PCOMM_HDR_LEN + 3, &type, NULL, &payload, &payload_len) == -1);
        CHECK(payload == NULL && payload_len == 0);
    }
    header(bytes, 3);
    payload = &sentinel;
    payload_len = 99;
    CHECK(pcomm_unpack_packet(NULL, PCOMM_HDR_LEN + 3, &type, NULL, &payload, &payload_len) == -1);
    CHECK(payload == NULL && payload_len == 0);
    payload = &sentinel;
    payload_len = 99;
    CHECK(pcomm_unpack_packet(bytes, PCOMM_HDR_LEN + 3, NULL, NULL, &payload, &payload_len) == -1);
    CHECK(payload == NULL && payload_len == 0);
    payload = &sentinel;
    CHECK(pcomm_unpack_packet(bytes, PCOMM_HDR_LEN + 3, &type, NULL, &payload, NULL) == -1);
    CHECK(payload == NULL);
    payload_len = 99;
    CHECK(pcomm_unpack_packet(bytes, PCOMM_HDR_LEN + 3, &type, NULL, NULL, &payload_len) == -1);
    CHECK(payload_len == 0);
done:
    if (payload != &sentinel) free(payload);
    return ok;
}

static int test_fragment_append_is_bounded_and_preserves_state(void) {
    uint8_t *buffer = NULL, *expected = NULL;
    uint32_t length = 0;
    int ok = 1;
    CHECK(pcomm_packet_append(&buffer, &length, NULL, 0) == 0);
    CHECK(buffer == NULL && length == 0);
    expected = (uint8_t *)malloc(PCOMM_MAX_PACKET_LEN);
    CHECK(expected != NULL);
    for (uint32_t i = 0; i < PCOMM_MAX_PACKET_LEN; i++) expected[i] = (uint8_t)(i * 13u + 7u);
    while (length < PCOMM_MAX_PACKET_LEN) {
        uint32_t remaining = PCOMM_MAX_PACKET_LEN - length;
        uint32_t fragment = remaining < 257u ? remaining : 257u;
        CHECK(pcomm_packet_append(&buffer, &length, expected + length, fragment) == 0);
    }
    CHECK(length == PCOMM_MAX_PACKET_LEN && memcmp(buffer, expected, length) == 0);
    uint8_t *original = buffer;
    CHECK(pcomm_packet_append(&buffer, &length, expected, 1) == -1);
    CHECK(pcomm_packet_append(&buffer, &length, expected, UINT32_MAX) == -1);
    CHECK(pcomm_packet_append(&buffer, &length, NULL, 1) == -1);
    CHECK(pcomm_packet_append(&buffer, &length, NULL, 0) == 0);
    CHECK(buffer == original && length == PCOMM_MAX_PACKET_LEN && memcmp(buffer, expected, length) == 0);
    uint32_t invalid_length = PCOMM_MAX_PACKET_LEN + 1u;
    uint8_t *invalid_buffer = buffer;
    CHECK(pcomm_packet_append(&invalid_buffer, &invalid_length, NULL, 0) == -1);
    CHECK(invalid_buffer == buffer && invalid_length == PCOMM_MAX_PACKET_LEN + 1u);
    invalid_length = 1;
    invalid_buffer = NULL;
    CHECK(pcomm_packet_append(&invalid_buffer, &invalid_length, expected, 1) == -1);
    CHECK(invalid_buffer == NULL && invalid_length == 1);
    CHECK(pcomm_packet_append(NULL, &length, expected, 1) == -1);
    CHECK(pcomm_packet_append(&buffer, NULL, expected, 1) == -1);
done:
    free(buffer);
    free(expected);
    return ok;
}

static int test_append_allows_overlapping_fragment(void) {
    uint8_t *buffer = NULL;
    uint32_t length = 0;
    int ok = 1;
    CHECK(pcomm_packet_append(&buffer, &length, (const uint8_t *)"abc", 3) == 0);
    CHECK(pcomm_packet_append(&buffer, &length, buffer, length) == 0);
    CHECK(length == 6 && memcmp(buffer, "abcabc", 6) == 0);
done:
    free(buffer);
    return ok;
}

int main(void) {
    const struct {
        const char *name;
        int (*run)(void);
    } tests[] = {
        {"roundtrips at zero, ordinary, and maximum lengths", test_roundtrips},
        {"send and pack reject invalid payloads", test_send_and_pack_reject_invalid_payloads},
        {"oversized receive never reads a body", test_oversized_receive_never_reads_body},
        {"receive failures and stream boundary", test_receive_failures_and_stream_boundary},
        {"unpack rejects malformed framing", test_unpack_rejects_bad_lengths_and_headers},
        {"fragment append is bounded and preserves state", test_fragment_append_is_bounded_and_preserves_state},
        {"fragment append supports overlapping source", test_append_allows_overlapping_fragment},
    };
    size_t failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int passed = tests[i].run();
        printf("%s: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if (!passed) failures++;
    }
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
