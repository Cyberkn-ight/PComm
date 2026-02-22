#include "peers.h"
#include "identity.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int pcomm_load_peers_file(pcomm_db_t *db, const char *peers_path) {
    if (!db || !peers_path) return -1;
    FILE *f = fopen(peers_path, "r");
    if (!f) return -1;

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;

        char uid[128], host[128];
        int port = 0;
        if (sscanf(line, "%127s %127s %d", uid, host, &port) != 3) continue;
        if (port <= 0 || port > 65535) continue;

        uint8_t pubkey[32];
        if (pcomm_pubkey_from_user_id(uid, pubkey) != 0) continue;

        if (pcomm_db_upsert_contact(db, uid, host, (uint16_t)port, pubkey, 1) == 0) {
            count++;
        }
    }

    fclose(f);
    return count;
}
