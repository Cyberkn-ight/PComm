#ifndef PCOMM_H
#define PCOMM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCOMM_MAGIC "PCOM"
#define PCOMM_VERSION 1

// Network message types
typedef enum {
    PCOMM_MSG_ONION   = 1,
    PCOMM_MSG_DELIVER = 2,
    PCOMM_MSG_CTRL    = 3,
    // Long-lived circuit cells (Tor-like relay cells + control)
    PCOMM_MSG_CELL    = 4,
} pcomm_msg_type_t;

// CELL commands (unencrypted; payload depends on cmd)
typedef enum {
    PCOMM_CELL_CREATE  = 1,
    PCOMM_CELL_CREATED = 2,
    PCOMM_CELL_RELAY   = 3,
    PCOMM_CELL_DESTROY = 4,
    PCOMM_CELL_PADDING = 5,
} pcomm_cell_cmd_t;

// RELAY commands (encrypted end-to-end to the current exit)
typedef enum {
    PCOMM_RELAY_EXTEND    = 1,
    PCOMM_RELAY_EXTENDED  = 2,
    PCOMM_RELAY_BEGIN     = 3,
    PCOMM_RELAY_CONNECTED = 4,
    PCOMM_RELAY_DATA      = 5,
    PCOMM_RELAY_END       = 6,

    // Hidden-service style rendezvous/intro (Tor-inspired)
    PCOMM_RELAY_ESTABLISH_INTRO      = 7,
    PCOMM_RELAY_INTRO_ESTABLISHED    = 8,
    PCOMM_RELAY_INTRODUCE1           = 9,
    PCOMM_RELAY_INTRODUCE_ACK        = 10,
    PCOMM_RELAY_INTRODUCE2           = 11,
    PCOMM_RELAY_ESTABLISH_RENDEZVOUS = 12,
    PCOMM_RELAY_RENDEZVOUS1          = 13,
    PCOMM_RELAY_RENDEZVOUS2          = 14,

    // Lightweight circuit keepalive + liveness check.
    // Exit replies with PONG (same body) unless the exit is in rendezvous-forwarding mode,
    // in which case the rendezvous point itself replies.
    PCOMM_RELAY_PING = 15,
    PCOMM_RELAY_PONG = 16,
} pcomm_relay_cmd_t;

// Onion instruction
typedef enum {
    PCOMM_INST_FORWARD = 1,
    PCOMM_INST_DELIVER = 2,
    // Like FORWARD but relays a single response packet back to the previous hop.
    PCOMM_INST_FORWARD_RR = 3,
} pcomm_inst_t;

// CTRL commands (payload[0])
typedef enum {
    PCOMM_CTRL_HELLO       = 1,
    PCOMM_CTRL_PEERS_REQ   = 2,
    PCOMM_CTRL_PEERS_RESP  = 3,

    // DESC/MB payloads include a 20-byte BEP-5 infohash prefix so storage nodes can announce themselves.
    PCOMM_CTRL_DESC_PUT    = 4,
    PCOMM_CTRL_DESC_GET    = 5,
    PCOMM_CTRL_DESC_RESP   = 6,
    PCOMM_CTRL_MB_PUT      = 7,
    PCOMM_CTRL_MB_GET      = 8,
    PCOMM_CTRL_MB_RESP     = 9,
    PCOMM_CTRL_NOOP        = 10,
} pcomm_ctrl_cmd_t;

typedef struct {
    char user_id[96];       // printable identifier
    uint8_t pubkey[32];
    char host[64];
    uint16_t port;
} pcomm_peer_t;

typedef struct {
    char data_dir[512];
    char ui_dir[512];

    char relay_host[64];
    uint16_t relay_port;

    // Publicly advertised relay address for mesh discovery (HELLO).
    // If empty, relay_host/relay_port is used.
    char advertise_host[64];
    uint16_t advertise_port;

    char http_host[64];
    uint16_t http_port;

    char peers_path[512];

    // ---- Hardening / operational knobs (safe defaults in config.c) ----

    // Allow private/loopback peers to be learned/used (useful for local testing). Default false.
    bool allow_private_addrs;

    // Allow the relay exit to connect to private/loopback destinations (SSRF risk). Default false.
    bool allow_private_exit;

    // Circuit pool size (primary + spare). Default 2.
    uint8_t circuit_pool_size;

    // Rebuild circuits after this age (seconds). Default 1800.
    uint32_t circuit_max_age_sec;

    // Send circuit keepalives if no circuit activity for this long (milliseconds). Default 12000.
    uint32_t circuit_keepalive_idle_ms;

    // Dedicated circuits (intro/rendezvous) idle timeout (seconds). Default 600.
    uint32_t dedicated_circuit_idle_sec;

    // Hidden service registry limits on relays.
    uint32_t hs_max_intros;
    uint32_t hs_max_rdv;
    uint32_t hs_intro_ttl_sec;
    uint32_t hs_rdv_ttl_sec;

    // Max cross-thread upstream queue depth (per circuit connection on relays). Default 256.
    uint32_t relay_upqueue_cap;

    // Mesh gossip base interval (seconds). Default 8.
    uint32_t mesh_gossip_base_sec;

    // Mailbox poll base interval (milliseconds) with jitter. Default 3500.
    uint32_t mailbox_poll_base_ms;

    // DHT maintenance interval (seconds). Default 30.
    uint32_t dht_maint_interval_sec;

} pcomm_config_t;

typedef struct {
    uint8_t privkey[32];
    uint8_t pubkey[32];
    char user_id[96];
} pcomm_identity_t;

#ifdef __cplusplus
}
#endif

#endif
