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
    PCOMM_MSG_ONION  = 1,
    PCOMM_MSG_DELIVER = 2,
} pcomm_msg_type_t;

typedef enum {
    PCOMM_INST_FORWARD = 1,
    PCOMM_INST_DELIVER = 2,
} pcomm_inst_t;

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
    char http_host[64];
    uint16_t http_port;
    char peers_path[512];
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
