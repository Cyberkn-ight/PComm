#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

static int parse_hostport(const char *s, char *host_out, size_t host_cap, uint16_t *port_out) {
    if (!s || !host_out || !port_out) return -1;
    const char *host = s, *colon;
    int ipv6 = s[0] == '[';
    size_t hlen;
    if (ipv6) {
        const char *closing = strchr(s+1, ']');
        if (!closing || closing[1] != ':') return -1;
        host = s+1;
        hlen = (size_t)(closing-host);
        colon = closing+1;
    } else {
        colon = strchr(s, ':');
        if (!colon || strchr(colon+1, ':')) return -1;
        hlen = (size_t)(colon-host);
    }
    if (!hlen || hlen >= host_cap || !colon[1]) return -1;
    memcpy(host_out, host, hlen);
    host_out[hlen] = '\0';
    if (ipv6) {
        struct in6_addr address;
        if (inet_pton(AF_INET6, host_out, &address) != 1) return -1;
    } else {
        int numeric = 1;
        for (size_t i = 0; i < hlen; i++) {
            unsigned char c = (unsigned char)host_out[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_')) return -1;
            if (!(c >= '0' && c <= '9') && c != '.') numeric = 0;
        }
        if (numeric) {
            struct in_addr address;
            if (inet_pton(AF_INET, host_out, &address) != 1) return -1;
        } else {
            if (host_out[0] == '.' || strstr(host_out, "..")) return -1;
            const char *label = host_out;
            while (*label) {
                const char *end = strchr(label, '.');
                if (!end) end = label+strlen(label);
                if (*label == '-' || end == label || end[-1] == '-') return -1;
                if (!*end) break;
                label = end+1;
            }
        }
    }
    unsigned port = 0;
    for (const char *p = colon+1; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        port = port*10u+(unsigned)(*p-'0');
        if (port > 65535) return -1;
    }
    if (!port) return -1;
    *port_out = (uint16_t)port;
    return 0;
}

static int add_bootstrap(pcomm_config_t *cfg, const char *value) {
    if (!value || !*value) return -1;
    const char *cursor = value;
    for (;;) {
        const char *end = strchr(cursor, ',');
        if (!end) end = cursor+strlen(cursor);
        while (cursor < end && isspace((unsigned char)*cursor)) cursor++;
        while (end > cursor && isspace((unsigned char)end[-1])) end--;
        size_t len = (size_t)(end-cursor);
        char endpoint[80];
        pcomm_bootstrap_t seed = {0};
        if (!len || len >= sizeof(endpoint)) return -1;
        memcpy(endpoint, cursor, len); endpoint[len] = '\0';
        if (parse_hostport(endpoint, seed.host, sizeof(seed.host), &seed.port) || strchr(seed.host, ':')) return -1;
        size_t host_len = strlen(seed.host);
        if (host_len && seed.host[host_len-1] == '.') seed.host[--host_len] = '\0';
        for (size_t i = 0; i < host_len; i++) seed.host[i] = (char)tolower((unsigned char)seed.host[i]);
        size_t i;
        for (i = 0; i < cfg->bootstrap_count; i++) {
            if (cfg->bootstrap[i].port == seed.port && strcmp(cfg->bootstrap[i].host, seed.host) == 0) break;
        }
        if (i == cfg->bootstrap_count) {
            if (i >= PCOMM_MAX_BOOTSTRAP) return -1;
            cfg->bootstrap[cfg->bootstrap_count++] = seed;
        }
        const char *comma = strchr(cursor, ',');
        if (!comma) return 0;
        cursor = comma+1;
    }
}

void pcomm_config_defaults(pcomm_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    snprintf(cfg->data_dir, sizeof(cfg->data_dir), "./pcomm_data");
    snprintf(cfg->ui_dir, sizeof(cfg->ui_dir), "./ui");

    snprintf(cfg->relay_host, sizeof(cfg->relay_host), "0.0.0.0");
    cfg->relay_port = 9001;

    cfg->advertise_host[0] = '\0';
    cfg->advertise_port = 0;

    snprintf(cfg->http_host, sizeof(cfg->http_host), "127.0.0.1");
    cfg->http_port = 8080;

    snprintf(cfg->peers_path, sizeof(cfg->peers_path), "./peers.txt");
    cfg->allow_private_addrs = false;
    cfg->allow_private_exit = false;

    cfg->circuit_pool_size = 2;
    cfg->circuit_max_age_sec = 30 * 60;
    cfg->circuit_keepalive_idle_ms = 12000;
    cfg->dedicated_circuit_idle_sec = 10 * 60;

    cfg->hs_max_intros = 4096;
    cfg->hs_max_rdv = 4096;
    cfg->hs_intro_ttl_sec = 15 * 60;
    cfg->hs_rdv_ttl_sec = 2 * 60;

    cfg->relay_upqueue_cap = 256;

    cfg->mesh_gossip_base_sec = 8;
    cfg->mailbox_poll_base_ms = 3500;
    cfg->dht_maint_interval_sec = 30;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "PComm - onion-relay messenger (prototype evolving toward production)\n\n"
        "Usage: %s [options]\n\n"
        "Options:\n"
        "  --data-dir PATH         Data directory (default ./pcomm_data)\n"
        "  --ui-dir PATH           UI directory (default ./ui)\n"
        "  --relay HOST:PORT       Relay listen address (default 0.0.0.0:9001)\n"
        "  --http HOST:PORT        HTTP listen address (default 127.0.0.1:8080)\n"
        "  --advertise HOST:PORT   Public relay address advertised to the mesh (default: use --relay)\n"
        "  --peers PATH            Peers file (default ./peers.txt)\n"
        "  --bootstrap HOST:PORT[,HOST:PORT...]  PComm seeds; repeatable, IPv4/DNS\n"
        "  --allow-private-addrs   Allow private/loopback addresses in peer discovery (dev/local testing)\n"
        "  --allow-private-exit    Allow exit connections to private/loopback destinations (unsafe)\n"
        "\nPeers file format (one per line):\n"
        "  <user_id> <host> <port>\n"
        "Lines starting with # are ignored.\n",
        argv0);
}

int pcomm_config_from_argv(pcomm_config_t *cfg, int argc, char **argv) {
    pcomm_config_defaults(cfg);

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(argv[0]);
            return -1;
        } else if (strcmp(a, "--data-dir") == 0 && i + 1 < argc) {
            snprintf(cfg->data_dir, sizeof(cfg->data_dir), "%s", argv[++i]);
        } else if (strcmp(a, "--ui-dir") == 0 && i + 1 < argc) {
            snprintf(cfg->ui_dir, sizeof(cfg->ui_dir), "%s", argv[++i]);
        } else if (strcmp(a, "--relay") == 0 && i + 1 < argc) {
            char host[64]; uint16_t port;
            if (parse_hostport(argv[++i], host, sizeof(host), &port) != 0) {
                fprintf(stderr, "Bad --relay value\n");
                return -1;
            }
            snprintf(cfg->relay_host, sizeof(cfg->relay_host), "%s", host);
            cfg->relay_port = port;
        } else if (strcmp(a, "--http") == 0 && i + 1 < argc) {
            char host[64]; uint16_t port;
            if (parse_hostport(argv[++i], host, sizeof(host), &port) != 0) {
                fprintf(stderr, "Bad --http value\n");
                return -1;
            }
            snprintf(cfg->http_host, sizeof(cfg->http_host), "%s", host);
            cfg->http_port = port;
        } else if (strcmp(a, "--advertise") == 0 && i + 1 < argc) {
            char host[64]; uint16_t port;
            if (parse_hostport(argv[++i], host, sizeof(host), &port) != 0) {
                fprintf(stderr, "Bad --advertise value\n");
                return -1;
            }
            snprintf(cfg->advertise_host, sizeof(cfg->advertise_host), "%s", host);
            cfg->advertise_port = port;
        } else if (strcmp(a, "--peers") == 0 && i + 1 < argc) {
            snprintf(cfg->peers_path, sizeof(cfg->peers_path), "%s", argv[++i]);
        } else if (strcmp(a, "--bootstrap") == 0 && i + 1 < argc) {
            if (add_bootstrap(cfg, argv[++i]) != 0) {
                fprintf(stderr, "Bad --bootstrap value (up to %u unique IPv4/DNS host:port entries)\n", PCOMM_MAX_BOOTSTRAP);
                return -1;
            }
        } else if (strcmp(a, "--allow-private-addrs") == 0) {
            cfg->allow_private_addrs = true;
        } else if (strcmp(a, "--allow-private-exit") == 0) {
            cfg->allow_private_exit = true;
        } else {
            fprintf(stderr, "Unknown option: %s\n", a);
            usage(argv[0]);
            return -1;
        }
    }

    return 0;
}
