#ifndef PCOMM_DHT_H
#define PCOMM_DHT_H

#include "pcomm.h"
#include "db.h"
#include <stdint.h>
#include <stddef.h>

// Start a minimal BEP-5 DHT node on UDP port = cfg->relay_port.
// The DHT routing table is bootstrapped from the relay contacts database and peers.txt.
int pcomm_dht_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db);

// Compute infohashes used by PComm for descriptor/mailbox discovery.
void pcomm_dht_infohash_desc(const char *user_id, uint8_t out20[20]);
void pcomm_dht_infohash_mb(const char *user_id, uint8_t out20[20]);

// Announce ourselves for the given infohash (announce_peer). Port is the TCP relay port.
int pcomm_dht_announce(const uint8_t infohash20[20], uint16_t port);

// Lookup peers for the given infohash. Returns (host,port) pairs (IPv4 only).
int pcomm_dht_get_peers_hosts(const uint8_t infohash20[20],
                             char (*hosts)[64], uint16_t *ports,
                             size_t cap, size_t *out_len);

#endif
