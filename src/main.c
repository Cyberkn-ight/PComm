#include "config.h"
#include "identity.h"
#include "db.h"
#include "peers.h"
#include "relay.h"
#include "http.h"

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

static volatile int g_running = 1;
static void on_sig(int s) {
    (void)s;
    g_running = 0;
}

int main(int argc, char **argv) {
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    pcomm_config_t cfg;
    if (pcomm_config_from_argv(&cfg, argc, argv) != 0) return 1;

    pcomm_identity_t me;
    if (pcomm_identity_load_or_create(&me, cfg.data_dir) != 0) {
        fprintf(stderr, "Failed to load/create identity\n");
        return 1;
    }

    pcomm_db_t db;
    if (pcomm_db_open(&db, cfg.data_dir) != 0) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    if (pcomm_db_init_schema(&db) != 0) {
        fprintf(stderr, "Failed to init schema\n");
        return 1;
    }

    int loaded = pcomm_load_peers_file(&db, cfg.peers_path);
    if (loaded > 0) {
        fprintf(stderr, "Loaded %d relay peers from %s\n", loaded, cfg.peers_path);
    }

    fprintf(stderr, "Your PComm ID: %s\n", me.user_id);
    fprintf(stderr, "Data dir: %s\n", cfg.data_dir);

    if (pcomm_relay_start(&cfg, &me, &db) != 0) {
        fprintf(stderr, "Failed to start relay\n");
        return 1;
    }

    if (pcomm_http_start(&cfg, &me, &db) != 0) {
        fprintf(stderr, "Failed to start HTTP server\n");
        return 1;
    }

    while (g_running) {
        sleep(1);
    }

    pcomm_db_close(&db);
    fprintf(stderr, "Bye\n");
    return 0;
}
