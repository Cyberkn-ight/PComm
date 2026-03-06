#ifndef PCOMM_MESH_H
#define PCOMM_MESH_H

#include "pcomm.h"
#include "db.h"

// Starts a background thread that gossips relay peers (HELLO + PEERS_REQ)
// to help new nodes join and maintain a dense mesh.
int pcomm_mesh_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db);

#endif
