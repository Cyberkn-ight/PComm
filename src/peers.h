#ifndef PCOMM_PEERS_H
#define PCOMM_PEERS_H

#include "db.h"

// Loads peers from text file and inserts/updates them as contacts with is_relay=1.
int pcomm_load_peers_file(pcomm_db_t *db, const char *peers_path);

#endif
