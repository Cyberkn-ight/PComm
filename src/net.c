#include "net.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

int net_sendall(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t*)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

int net_recvall(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t*)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

static int resolve_bind_addr(const char *host, uint16_t port, struct sockaddr_storage *out, socklen_t *outlen) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo((host && host[0]) ? host : NULL, portstr, &hints, &res);
    if (rc != 0 || !res) return -1;

    memcpy(out, res->ai_addr, res->ai_addrlen);
    *outlen = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

int net_listen_tcp(const char *host, uint16_t port, int backlog) {
    struct sockaddr_storage ss;
    socklen_t slen;
    if (resolve_bind_addr(host, port, &ss, &slen) != 0) return -1;

    int fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(fd, (struct sockaddr*)&ss, slen) != 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int net_accept(int listen_fd, char *peer_ip, size_t peer_ip_cap, uint16_t *peer_port) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listen_fd, (struct sockaddr*)&ss, &slen);
    if (fd < 0) return -1;

    if (peer_ip && peer_ip_cap > 0) {
        void *addr = NULL;
        uint16_t port = 0;
        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in*)&ss;
            addr = &sin->sin_addr;
            port = ntohs(sin->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&ss;
            addr = &sin6->sin6_addr;
            port = ntohs(sin6->sin6_port);
        }
        if (addr) {
            inet_ntop(ss.ss_family, addr, peer_ip, (socklen_t)peer_ip_cap);
            if (peer_port) *peer_port = port;
        }
    }

    return fd;
}

bool net_addr_is_private(const void *addr, int family) {
    if (!addr) return true;

    if (family == AF_INET) {
        const uint8_t *a = (const uint8_t*)addr;
        // 0.0.0.0/8
        if (a[0] == 0) return true;
        // 127.0.0.0/8
        if (a[0] == 127) return true;
        // 10.0.0.0/8
        if (a[0] == 10) return true;
        // 172.16.0.0/12
        if (a[0] == 172 && (a[1] >= 16 && a[1] <= 31)) return true;
        // 192.168.0.0/16
        if (a[0] == 192 && a[1] == 168) return true;
        // 169.254.0.0/16 link-local
        if (a[0] == 169 && a[1] == 254) return true;
        // 100.64.0.0/10 CGNAT
        if (a[0] == 100 && (a[1] >= 64 && a[1] <= 127)) return true;
        // multicast/broadcast/reserved
        if (a[0] >= 224) return true;
        return false;
    }

    if (family == AF_INET6) {
        const uint8_t *a = (const uint8_t*)addr;
        // ::/128
        static const uint8_t z16[16] = {0};
        if (memcmp(a, z16, 16) == 0) return true;
        // ::1 loopback
        static const uint8_t l16[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (memcmp(a, l16, 16) == 0) return true;
        // fc00::/7 unique local
        if ((a[0] & 0xFE) == 0xFC) return true;
        // fe80::/10 link-local
        if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) return true;
        // ff00::/8 multicast
        if (a[0] == 0xFF) return true;
        return false;
    }

    return true;
}

static int net_connect_tcp_internal(const char *host, uint16_t port, bool apply_policy, bool allow_private) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (apply_policy && !allow_private) {
            if (ai->ai_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)ai->ai_addr;
                if (net_addr_is_private(&sin->sin_addr, AF_INET)) continue;
            } else if (ai->ai_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)ai->ai_addr;
                if (net_addr_is_private(&sin6->sin6_addr, AF_INET6)) continue;
            }
        }

        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

int net_connect_tcp(const char *host, uint16_t port) {
    return net_connect_tcp_internal(host, port, false, true);
}

int net_connect_tcp_policy(const char *host, uint16_t port, bool allow_private) {
    return net_connect_tcp_internal(host, port, true, allow_private);
}
