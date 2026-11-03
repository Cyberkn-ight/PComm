#include "config.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 0; \
    } \
} while (0)

static int parse(pcomm_config_t *cfg, size_t argc, const char *const *args) {
    char *argv[64];
    if (argc >= sizeof(argv) / sizeof(argv[0])) return -1;
    for (size_t i = 0; i < argc; ++i) argv[i] = (char *)args[i];
    argv[argc] = NULL;
    return pcomm_config_from_argv(cfg, (int)argc, argv);
}

static int parse_value(pcomm_config_t *cfg, const char *option, const char *value) {
    const char *args[] = {"pcomm", option, value};
    return parse(cfg, sizeof(args) / sizeof(args[0]), args);
}

static int test_defaults(void) {
    pcomm_config_t cfg;
    memset(&cfg, 0xa5, sizeof(cfg));
    pcomm_config_defaults(&cfg);
    CHECK(cfg.bootstrap_count == 0);
    CHECK(strcmp(cfg.relay_host, "0.0.0.0") == 0 && cfg.relay_port == 9001);
    CHECK(strcmp(cfg.http_host, "127.0.0.1") == 0 && cfg.http_port == 8080);
    CHECK(cfg.advertise_host[0] == '\0' && cfg.advertise_port == 0);
    CHECK(strcmp(cfg.peers_path, "./peers.txt") == 0);
    CHECK(!cfg.allow_private_addrs && !cfg.allow_private_exit);
    CHECK(parse_value(&cfg, "--bootstrap", "seed.example:9001") == 0);
    const char *args[] = {"pcomm"};
    CHECK(parse(&cfg, 1, args) == 0);
    CHECK(cfg.bootstrap_count == 0);
    return 1;
}

static int test_bootstrap_values(void) {
    pcomm_config_t cfg;
    CHECK(parse_value(&cfg, "--bootstrap", "seed.example:9001") == 0);
    CHECK(cfg.bootstrap_count == 1);
    CHECK(strcmp(cfg.bootstrap[0].host, "seed.example") == 0);
    CHECK(cfg.bootstrap[0].port == 9001);

    CHECK(parse_value(&cfg, "--bootstrap", "  seed-one.example:1,\t192.0.2.10:65535 \t, seed-two.example:00080  ") == 0);
    CHECK(cfg.bootstrap_count == 3);
    CHECK(strcmp(cfg.bootstrap[0].host, "seed-one.example") == 0 && cfg.bootstrap[0].port == 1);
    CHECK(strcmp(cfg.bootstrap[1].host, "192.0.2.10") == 0 && cfg.bootstrap[1].port == 65535);
    CHECK(strcmp(cfg.bootstrap[2].host, "seed-two.example") == 0 && cfg.bootstrap[2].port == 80);

    const char *args[] = {
        "pcomm", "--bootstrap", "Seed.Example:9001,192.0.2.10:9002",
        "--bootstrap", "seed.example:9001,192.0.2.10:09002,seed.example:9003",
        "--bootstrap", "SEED.EXAMPLE:9001"
    };
    CHECK(parse(&cfg, sizeof(args) / sizeof(args[0]), args) == 0);
    CHECK(cfg.bootstrap_count == 3);
    CHECK(strcmp(cfg.bootstrap[1].host, "192.0.2.10") == 0 && cfg.bootstrap[1].port == 9002);
    CHECK(cfg.bootstrap[2].port == 9003);
    return 1;
}

static int test_bootstrap_capacity(void) {
    pcomm_config_t cfg;
    char list[2048];
    size_t used = 0;
    for (size_t i = 0; i < PCOMM_MAX_BOOTSTRAP; ++i) {
        int written = snprintf(list + used, sizeof(list) - used, "%sseed%zu.example:%zu",
            i ? "," : "", i, 9001 + i);
        CHECK(written > 0 && (size_t)written < sizeof(list) - used);
        used += (size_t)written;
    }
    CHECK(parse_value(&cfg, "--bootstrap", list) == 0);
    CHECK(cfg.bootstrap_count == PCOMM_MAX_BOOTSTRAP);
    for (size_t i = 0; i < PCOMM_MAX_BOOTSTRAP; ++i) CHECK(cfg.bootstrap[i].port == 9001 + i);

    const char *duplicates[] = {"pcomm", "--bootstrap", list, "--bootstrap", "SEED0.EXAMPLE:9001,seed15.example:9016"};
    CHECK(parse(&cfg, sizeof(duplicates) / sizeof(duplicates[0]), duplicates) == 0);
    CHECK(cfg.bootstrap_count == PCOMM_MAX_BOOTSTRAP);
    const char *overflow[] = {"pcomm", "--bootstrap", list, "--bootstrap", "another.example:9020"};
    CHECK(parse(&cfg, sizeof(overflow) / sizeof(overflow[0]), overflow) != 0);

    CHECK(snprintf(list + used, sizeof(list) - used, ",another.example:9020") > 0);
    CHECK(parse_value(&cfg, "--bootstrap", list) != 0);
    return 1;
}

static int test_malformed_bootstrap(void) {
    pcomm_config_t cfg;
    const char *invalid[] = {
        "", " ", ",", ",seed.example:9001", "seed.example:9001,",
        "seed.example:9001,,other.example:9001", "seed.example:9001, ,other.example:9001",
        "seed.example", ":9001", "seed.example:", "seed.example:0", "seed.example:65536",
        "seed.example:99999999999999999999999999999999999999", "seed.example:-1", "seed.example:+1",
        "seed.example:1x", "seed.example:1.0", "seed.example:0x20", "seed.example: 1",
        "seed.example:1 2", "seed.example:9001:9002", "seed example:9001", "seed\texample:9001",
        "https://seed.example:9001", "seed.example/path:9001", "-seed.example:9001", "seed-.example:9001",
        ".example:9001", "seed..example:9001", "999.0.0.1:9001", "192.0.2:9001", "192.0.2.1.2:9001",
        "[::1]:9001", "::1:9001", "[2001:db8::1]:9001", "[seed.example]:9001",
        "[seed.example:9001", "seed.example]:9001"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        if (parse_value(&cfg, "--bootstrap", invalid[i]) == 0) {
            fprintf(stderr, "Accepted invalid bootstrap: <%s>\n", invalid[i]);
            return 0;
        }
    }
    char overlong[80];
    memset(overlong, 'a', 64);
    memcpy(overlong + 64, ":9001", 6);
    CHECK(parse_value(&cfg, "--bootstrap", overlong) != 0);
    return 1;
}

static int test_listener_values(void) {
    pcomm_config_t cfg;
    const char *args[] = {
        "pcomm", "--relay", "[::1]:1", "--http", "[2001:db8::1]:65535",
        "--advertise", "relay.example:9001", "--bootstrap", "seed.example:9002",
        "--peers", "custom-peers.txt", "--allow-private-addrs", "--allow-private-exit"
    };
    CHECK(parse(&cfg, sizeof(args) / sizeof(args[0]), args) == 0);
    CHECK(strcmp(cfg.relay_host, "::1") == 0 && cfg.relay_port == 1);
    CHECK(strcmp(cfg.http_host, "2001:db8::1") == 0 && cfg.http_port == 65535);
    CHECK(strcmp(cfg.advertise_host, "relay.example") == 0 && cfg.advertise_port == 9001);
    CHECK(strcmp(cfg.peers_path, "custom-peers.txt") == 0);
    CHECK(cfg.allow_private_addrs && cfg.allow_private_exit);
    CHECK(cfg.bootstrap_count == 1 && cfg.bootstrap[0].port == 9002);

    const char *options[] = {"--relay", "--http", "--advertise"};
    const char *invalid[] = {
        "", ":9001", "host", "host:", "host:0", "host:65536", "host:+1", "host:-1", "host:1x",
        "host:9999999999999999999999999999", "host: 1", "bad host:9001", "::1:9001",
        "[::1:9001", "[::1]9001", "[host]:9001", "host:9001,other:9002"
    };
    for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
        CHECK(parse_value(&cfg, options[i], "[::1]:9001") == 0);
        for (size_t j = 0; j < sizeof(invalid) / sizeof(invalid[0]); ++j) {
            if (parse_value(&cfg, options[i], invalid[j]) == 0) {
                fprintf(stderr, "Accepted invalid %s: <%s>\n", options[i], invalid[j]);
                return 0;
            }
        }
    }
    return 1;
}

static int test_missing_value(void) {
    pcomm_config_t cfg;
    const char *options[] = {"--bootstrap", "--relay", "--http", "--advertise"};
    for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
        const char *args[] = {"pcomm", options[i]};
        CHECK(parse(&cfg, sizeof(args) / sizeof(args[0]), args) != 0);
        const char *next_flag[] = {"pcomm", options[i], "--allow-private-addrs"};
        CHECK(parse(&cfg, sizeof(next_flag) / sizeof(next_flag[0]), next_flag) != 0);
    }
    return 1;
}

int main(void) {
    const struct { const char *name; int (*run)(void); } tests[] = {
        {"defaults", test_defaults},
        {"bootstrap values", test_bootstrap_values},
        {"bootstrap capacity", test_bootstrap_capacity},
        {"malformed bootstrap", test_malformed_bootstrap},
        {"listener values", test_listener_values},
        {"missing value", test_missing_value}
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        int passed = tests[i].run();
        printf("%s: %s\n", tests[i].name, passed ? "PASS" : "FAIL");
        failed += !passed;
    }
    return failed ? 1 : 0;
}
