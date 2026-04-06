#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

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

static char *skip_whitespace(char *p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static void read_config_section(FILE *config, const char *section_line, pcomm_config_t *cfg) {
    char line[1024];
    fgets(line, sizeof(line), config);
    char *p = skip_whitespace(line);
    if (*p == ';' || *p == '\n' || *p == '\r' || *p == '#') return;
    
    char *key, *val;
    char host[64];
    uint16_t port, default_port = 9001;
    
    if (strstr(p, "data-dir") || strstr(p, "data_dir")) {
        char buf[256];
        char *eq = strchr(p, '=');
        if (eq) {
            size_t len = (size_t)(eq - p);
            if (len < sizeof(buf)) memcpy(buf, p, len);
            buf[len] = '\0';
            size_t vlen = strlen(buf);
            if (vlen < sizeof(cfg->data_dir)) {
                strcpy(cfg->data_dir, buf);
            }
        }
    } else if (strstr(p, "ui-dir") || strstr(p, "ui_dir")) {
        size_t len = strlen(p + 7);
        if (len < sizeof(cfg->ui_dir)) {
            strcpy(cfg->ui_dir, p + 7);
        }
    } else if (strstr(p, "relay-host") || strstr(p, "relay_host")) {
        char *eq = strchr(p, '=');
        if (eq) {
            *eq = '\0';
            char *eq_pos = strchr(p, '=');
            if (eq_pos) {
                eq_pos++;
                host[0] = '\0';
                cfg->relay_port = parse_hostport(p, host, sizeof(host), &cfg->relay_port);
                if (cfg->relay_port == default_port) cfg->relay_port = 9001;
            }
        }
    } else if (strstr(p, "http-host") || strstr(p, "http_host")) {
        char *eq = strchr(p, '=');
        if (eq) {
            *eq = '\0';
            size_t len = strlen(p);
            if (len < sizeof(cfg->http_host)) {
                strcpy(cfg->http_host, p + 10);
            }
            cfg->http_port = 8080;
        }
    } else if (strstr(p, "allow-private-addrs") || strstr(p, "allow_private_addrs")) {
        char *eq = strchr(p, '=');
        if (eq) cfg->allow_private_addrs = !strcmp(p, "allow-private-addrs=yes") || strcmp(eq + 1, "yes") == 0;
    } else if (strstr(p, "allow-private-exit") || strstr(p, "allow_private_exit")) {
        char *eq = strchr(p, '=');
        if (eq) cfg->allow_private_exit = !strcmp(p, "allow-private-exit=yes") || strcmp(eq + 1, "yes") == 0;
    } else if (strstr(p, "circuit-pool-size") || strstr(p, "circuit_pool_size")) {
        char *eq = strchr(p, '=');
        if (eq) cfg->circuit_pool_size = atoi(eq + 1);
    } else if (strstr(p, "relay-upqueue-cap") || strstr(p, "relay_upqueue_cap")) {
        char *eq = strchr(p, '=');
        if (eq) cfg->relay_upqueue_cap = atoi(eq + 1);
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

int pcomm_config_from_file(pcomm_config_t *cfg, const char *config_path) {
    FILE *config = fopen(config_path, "r");
    if (!config) {
        fprintf(stderr, "Config file not found: %s\n", config_path);
        return -1;
    }

    char *section = NULL;
    char line[1024];

    while (fgets(line, sizeof(line), config)) {
        char *p = skip_whitespace(line);
        if (*p == ';' || *p == '\n' || *p == '\r' || *p == '#') continue;
        pcomm_config_defaults(cfg);

        char *key, *val;
        char host[64];
        uint16_t port, default_port = 9001;
        
        key = p;
        val = strchr(key, '=');
        
        if (!val) {
            continue;
        }
        
        *val = '\0';
        val++;
        
        if (strstr(key, "data-dir") || strstr(key, "data_dir")) {
            size_t len = strlen(key + 8);
            if (len < sizeof(cfg->data_dir)) {
                strcpy(cfg->data_dir, key + 8);
            }
        } else if (strstr(key, "ui-dir") || strstr(key, "ui_dir")) {
            size_t len = strlen(key + 6);
            if (len < sizeof(cfg->ui_dir)) {
                strcpy(cfg->ui_dir, key + 6);
            }
        } else if (strstr(key, "relay-host") || strstr(key, "relay_host")) {
            char *eq = strchr(key, '=');
            if (eq) {
                *eq = '\0';
                cfg->relay_host[0] = '\0';
                cfg->relay_port = atoi(key + 12);
                cfg->relay_port = atoi(eq + 1);
                strcpy(cfg->relay_host, key + 12);
                cfg->relay_port = atoi(eq + 1);
                if (cfg->relay_port == default_port) cfg->relay_port = 9001;
            }
        } else if (strstr(key, "http-host") || strstr(key, "http_host")) {
            char *eq = strchr(key, '=');
            if (eq) {
                *eq = '\0';
                size_t len = strlen(key);
                if (len < sizeof(cfg->http_host)) {
                    strcpy(cfg->http_host, key + 10);
                }
                cfg->http_port = atoi(eq + 1);
            }
        } else if (strstr(key, "allow-private-addrs") || strstr(key, "allow_private_addrs")) {
            cfg->allow_private_addrs = !strcmp(key + 21, "yes") || strcmp(val, "yes") == 0;
        } else if (strstr(key, "allow-private-exit") || strstr(key, "allow_private_exit")) {
            cfg->allow_private_exit = !strcmp(key + 22, "yes") || strcmp(val, "yes") == 0;
        } else if (strstr(key, "circuit-pool-size") || strstr(key, "circuit_pool_size")) {
            cfg->circuit_pool_size = atoi(val);
        } else if (strstr(key, "relay-upqueue-cap") || strstr(key, "relay_upqueue_cap")) {
            cfg->relay_upqueue_cap = atoi(val);
        } else if (strstr(key, "mesh-gossip-base-sec") || strstr(key, "mesh_gossip_base_sec")) {
            cfg->mesh_gossip_base_sec = atoi(val);
        } else if (strstr(key, "mailbox-poll-base-ms") || strstr(key, "mailbox_poll_base_ms")) {
            cfg->mailbox_poll_base_ms = atoi(val);
        } else if (strstr(key, "hs-max-intros") || strstr(key, "hs_max_intros")) {
            cfg->hs_max_intros = atoi(val);
        } else if (strstr(key, "hs-max-rdv") || strstr(key, "hs_max_rdv")) {
            cfg->hs_max_rdv = atoi(val);
        } else if (strstr(key, "hs-intro-ttl-sec") || strstr(key, "hs_intro_ttl_sec")) {
            cfg->hs_intro_ttl_sec = atoi(val);
        }
    }

    fclose(config);
    return 0;
}
