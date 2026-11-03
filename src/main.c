#include "config.h"
#include "identity.h"
#include "db.h"
#include "peers.h"
#include "relay.h"
#include "http.h"
#include "mesh.h"
#include "hidden.h"
#include "dht.h"
#include "circuit.h"
#include "lifecycle.h"
#include "net.h"

#include <stdio.h>
#include <signal.h>
#include <string.h>

static volatile sig_atomic_t g_signal = 0;
static void on_sig(int s) {

    g_signal = s;
}

int main(int argc, char **argv) {
    pcomm_shutdown_reset();
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    pcomm_config_t cfg;
    if (pcomm_config_from_argv(&cfg, argc, argv) != 0) return 1;

    pcomm_identity_t me;
    if (pcomm_identity_load_or_create(&me, cfg.data_dir) != 0) {
        fprintf(stderr, "Failed to load/create identity\n");
        return 1;
    }

    pcomm_db_t db = {0};
    if (pcomm_db_open(&db, cfg.data_dir) != 0) {
        fprintf(stderr, "Failed to open database\n");
        pcomm_db_close(&db);
        return 1;
    }
    int result = 1;
    if (pcomm_db_init_schema(&db) != 0) {
        fprintf(stderr, "Failed to init schema\n");
        goto shutdown;
    }

    int loaded = pcomm_load_peers_file(&db, cfg.peers_path);
    if (loaded > 0) {
        fprintf(stderr, "Loaded %d relay peers from %s\n", loaded, cfg.peers_path);
    }

    fprintf(stderr, "Your PComm ID: %s\n", me.user_id);
    fprintf(stderr, "Data dir: %s\n", cfg.data_dir);

    const struct {
        const char *name;
        int (*start)(const pcomm_config_t *, const pcomm_identity_t *, pcomm_db_t *);
    } services[] = {
        {"relay", pcomm_relay_start},
        {"HTTP server", pcomm_http_start},
        {"mesh", pcomm_mesh_start},
        {"DHT", pcomm_dht_start},
        {"circuits", pcomm_circuits_start},
        {"hidden services", pcomm_hidden_start},
    };
    for (size_t i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
        if (g_signal || pcomm_shutdown_requested()) { result = 0; goto shutdown; }
        if (services[i].start(&cfg, &me, &db) != 0) {
            fprintf(stderr, "Failed to start %s\n", services[i].name);
            goto shutdown;
        }
    }

    result = 0;
    while (!g_signal && !pcomm_shutdown_requested()) {
        if (pcomm_shutdown_wait(100) < 0) { result = 1; break; }
    }

shutdown:

    pcomm_shutdown_request();
    net_shutdown_all();
    pcomm_dht_request_stop();
    pcomm_hidden_request_stop();
    pcomm_circuits_request_stop();
    pcomm_http_stop();
    pcomm_mesh_stop();
    pcomm_hidden_stop();
    pcomm_circuits_stop();
    pcomm_relay_stop();
    pcomm_dht_stop();
    pcomm_db_close(&db);
    fprintf(stderr, "Bye\n");
    return result;
}
