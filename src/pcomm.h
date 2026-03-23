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

typedef enum {
    PCOMM_MSG_ONION = 1,
    PCOMM_MSG_DELIVER = 2,
    PCOMM_MSG_CTRL = 3,
    PCOMM_MSG_CELL = 4,
} pcomm_msg_type_t;

typedef enum {
    PCOMM_CELL_CREATE = 1,
    PCOMM_CELL_CREATED = 2,
    PCOMM_CELL_RELAY  = 3,
    PCOMM_CELL_DESTROY = 4,
    PCOMM_CELL_PADDING = 5,
} pcomm_cell_cmd_t;

typedef enum {
    PCOMM_RELAY_EXTEND = 1,
    PCOMM_RELAY_EXTENDED  = 2,
    PCOMM_RELAY_BEGIN = 3,
    PCOMM_RELAY_CONNECTED = 4,
    PCOMM_RELAY_DATA = 5,
    PCOMM_RELAY_END = 6,
    PCOMM_RELAY_ESTABLISH_INTRO = 7,
    PCOMM_RELAY_INTRO_ESTABLISHED = 8,
    PCOMM_RELAY_INTRODUCE1 = 9,
    PCOMM_RELAY_INTRODUCE_ACK = 10,
    PCOMM_RELAY_INTRODUCE2 = 11,
    PCOMM_RELAY_ESTABLISH_RENDEZVOUS = 12,
    PCOMM_RELAY_RENDEZVOUS1 = 13,
    PCOMM_RELAY_RENDEZVOUS2 = 14,
    PCOMM_RELAY_PING = 15,
    PCOMM_RELAY_PONG = 16,
} pcomm_relay_cmd_t;

typedef enum {
    PCOMM_INST_FORWARD = 1,
    PCOMM_INST_DELIVER = 2,
    PCOMM_INST_FORWARD_RR = 3,
} pcomm_inst_t;

typedef enum {
    PCOMM_CTRL_HELLO = 1,
    PCOMM_CTRL_PEERS_REQ  = 2,
    PCOMM_CTRL_PEERS_RESP = 3,
    PCOMM_CTRL_DESC_PUT = 4,
    PCOMM_CTRL_DESC_GET = 5,
    PCOMM_CTRL_DESC_RESP = 6,
    PCOMM_CTRL_MB_PUT = 7,
    PCOMM_CTRL_MB_GET = 8,
    PCOMM_CTRL_MB_RESP = 9,
    PCOMM_CTRL_NOOP = 10,
} pcomm_ctrl_cmd_t;

typedef struct {
    char user_id[96];
    uint8_t pubkey[32];
    char host[64];
    uint16_t port;
} pcomm_peer_t;

typedef struct {
    char data_dir[512];
    char ui_dir[512];

    char relay_host[64];
    uint16_t relay_port;

    char advertise_host[64];
    uint16_t advertise_port;

    char http_host[64];
    uint16_t http_port;

    char peers_path[512];

    bool allow_private_addrs;

    bool allow_private_exit;
    uint8_t circuit_pool_size;
    uint32_t circuit_max_age_sec;
    uint32_t circuit_keepalive_idle_ms;
    uint32_t dedicated_circuit_idle_sec;
    uint32_t hs_max_intros;
    uint32_t hs_max_rdv;
    uint32_t hs_intro_ttl_sec;
    uint32_t hs_rdv_ttl_sec;
    uint32_t relay_upqueue_cap;
    uint32_t mesh_gossip_base_sec;
    uint32_t mailbox_poll_base_ms;
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
