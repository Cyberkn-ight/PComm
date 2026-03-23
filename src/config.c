#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int parse_hostport(const char *s, char *host_out, size_t host_cap, uint16_t *port_out) {
    const char *colon = strrchr(s, ':');
    if (!colon) return -1;
    size_t hlen = (size_t)(colon - s);
    if (hlen == 0 || hlen >= host_cap) return -1;
    memcpy(host_out, s, hlen);
    host_out[hlen] = '\0';
    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) return -1;
    *port_out = (uint16_t)port;
    return 0;
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

    // Hardening defaults (safe-by-default).
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
