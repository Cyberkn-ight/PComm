#ifndef PCOMM_NET_H
#define PCOMM_NET_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

int net_listen_tcp(const char *host, uint16_t port, int backlog);
int net_accept(int listen_fd, char *peer_ip, size_t peer_ip_cap, uint16_t *peer_port);
int net_connect_tcp(const char *host, uint16_t port);
int net_connect_tcp_policy(const char *host, uint16_t port, bool allow_private);
int net_sendall(int fd, const void *buf, size_t len);
int net_recvall(int fd, void *buf, size_t len);
bool net_addr_is_private(const void *addr, int family);

#endif
