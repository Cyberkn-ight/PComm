#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "net.h"
#include "lifecycle.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>

typedef struct tracked_socket {
    int fd;
    struct tracked_socket *next;
} tracked_socket_t;

static pthread_mutex_t g_socket_mutex = PTHREAD_MUTEX_INITIALIZER;
static tracked_socket_t *g_sockets = NULL;

static int track_socket(int fd) {
    tracked_socket_t *entry = (tracked_socket_t *)malloc(sizeof(*entry));
    if (!entry) { close(fd); return -1; }
    pthread_mutex_lock(&g_socket_mutex);
    if (pcomm_shutdown_requested()) {
        pthread_mutex_unlock(&g_socket_mutex);
        free(entry);
        close(fd);
        errno = ECANCELED;
        return -1;
    }
    entry->fd = fd;
    entry->next = g_sockets;
    g_sockets = entry;
    pthread_mutex_unlock(&g_socket_mutex);
    return 0;
}

void net_close(int fd) {
    if (fd < 0) return;
    pthread_mutex_lock(&g_socket_mutex);
    tracked_socket_t **entry = &g_sockets;
    while (*entry && (*entry)->fd != fd) entry = &(*entry)->next;
    if (*entry) {
        tracked_socket_t *owned = *entry;
        *entry = owned->next;
        close(fd);
        free(owned);
    }
    pthread_mutex_unlock(&g_socket_mutex);
}

void net_shutdown(int fd) {
    pthread_mutex_lock(&g_socket_mutex);
    for (tracked_socket_t *entry = g_sockets; entry; entry = entry->next) {
        if (entry->fd == fd) { shutdown(fd, SHUT_RDWR); break; }
    }
    pthread_mutex_unlock(&g_socket_mutex);
}

void net_shutdown_all(void) {
    pthread_mutex_lock(&g_socket_mutex);
    for (tracked_socket_t *entry = g_sockets; entry; entry = entry->next) {
        shutdown(entry->fd, SHUT_RDWR);
    }
    pthread_mutex_unlock(&g_socket_mutex);
}

size_t net_tracked_socket_count(void) {
    size_t count = 0;
    pthread_mutex_lock(&g_socket_mutex);
    for (tracked_socket_t *entry = g_sockets; entry; entry = entry->next) count++;
    pthread_mutex_unlock(&g_socket_mutex);
    return count;
}

int net_sendall(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t*)buf;
    size_t sent = 0;
    while (sent < len) {
        if (pcomm_shutdown_requested()) return -1;
#ifdef MSG_NOSIGNAL
        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
#else
        ssize_t n = send(fd, p + sent, len - sent, 0);
#endif
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

int net_recvall(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t*)buf;
    size_t got = 0;
    while (got < len) {
        if (pcomm_shutdown_requested()) return -1;
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n < 0 && errno == EINTR) continue;
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
    if (pcomm_shutdown_requested()) return -1;
    struct sockaddr_storage ss;
    socklen_t slen;
    if (resolve_bind_addr(host, port, &ss, &slen) != 0) return -1;

    int fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (track_socket(fd) != 0) return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(fd, (struct sockaddr*)&ss, slen) != 0) {
        net_close(fd);
        return -1;
    }

    if (listen(fd, backlog) != 0) {
        net_close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        net_close(fd);
        return -1;
    }
    if (pcomm_shutdown_requested()) { net_close(fd); return -1; }
    return fd;
}

int net_accept(int listen_fd, char *peer_ip, size_t peer_ip_cap, uint16_t *peer_port) {
    if (pcomm_shutdown_requested()) { errno = ECANCELED; return -1; }
    struct pollfd ready = {listen_fd, POLLIN, 0};
    int rc = poll(&ready, 1, 100);
    if (rc == 0) { errno = EAGAIN; return -1; }
    if (rc < 0) return -1;
    if (ready.revents & POLLNVAL) { errno = EBADF; return -1; }
    if (!(ready.revents & POLLIN)) { errno = ECONNABORTED; return -1; }
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listen_fd, (struct sockaddr*)&ss, &slen);
    if (fd < 0) return -1;
    if (track_socket(fd) != 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
        net_close(fd);
        return -1;
    }

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
        if (a[0] == 0) return true;
        if (a[0] == 127) return true;
        if (a[0] == 10) return true;
        if (a[0] == 172 && (a[1] >= 16 && a[1] <= 31)) return true;
        if (a[0] == 192 && a[1] == 168) return true;
        if (a[0] == 169 && a[1] == 254) return true;
        if (a[0] == 100 && (a[1] >= 64 && a[1] <= 127)) return true;
        if (a[0] >= 224) return true;
        return false;
    }

    if (family == AF_INET6) {
        const uint8_t *a = (const uint8_t*)addr;
        static const uint8_t z16[16] = {0};
        if (memcmp(a, z16, 16) == 0) return true;
        static const uint8_t l16[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (memcmp(a, l16, 16) == 0) return true;
        if ((a[0] & 0xFE) == 0xFC) return true;
        if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) return true;
        if (a[0] == 0xFF) return true;
        return false;
    }

    return true;
}

static int net_connect_tcp_internal(const char *host, uint16_t port, bool apply_policy, bool allow_private) {
    if (pcomm_shutdown_requested()) return -1;
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
        if (pcomm_shutdown_requested()) break;
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
        if (track_socket(fd) != 0) { fd = -1; break; }

        int flags = fcntl(fd, F_GETFL, 0);
        int connected = 0;
        if (flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0) {
            if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) connected = 1;
            else if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
                for (unsigned attempt = 0; attempt < 50 && !pcomm_shutdown_requested(); attempt++) {
                    struct pollfd ready = {fd, POLLOUT, 0};
                    int rc = poll(&ready, 1, 100);
                    if (rc == 0 || (rc < 0 && errno == EINTR)) continue;
                    if (rc > 0) {
                        int error = 0;
                        socklen_t error_len = sizeof(error);
                        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 && error == 0) connected = 1;
                    }
                    break;
                }
            }
        }
        if (connected && !pcomm_shutdown_requested() && fcntl(fd, F_SETFL, flags) == 0) break;
        net_close(fd);
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
