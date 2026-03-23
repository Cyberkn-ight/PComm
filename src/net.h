#ifndef PCOMM_NET_H
#define PCOMM_NET_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

int net_listen_tcp(const char *host, uint16_t port, int backlog);
int net_accept(int listen_fd, char *peer_ip, size_t peer_ip_cap, uint16_t *peer_port);

// Connect to host:port (DNS allowed). Returns fd or -1.
int net_connect_tcp(const char *host, uint16_t port);

// Like net_connect_tcp but applies a basic destination policy:
// if allow_private is false, private/loopback/link-local destinations are rejected.
int net_connect_tcp_policy(const char *host, uint16_t port, bool allow_private);

int net_sendall(int fd, const void *buf, size_t len);
int net_recvall(int fd, void *buf, size_t len);

// Best-effort check for whether an IPv4/IPv6 address is private/loopback/link-local.
// Returns true if the address should be treated as private.
bool net_addr_is_private(const void *addr, int family);

#endif
