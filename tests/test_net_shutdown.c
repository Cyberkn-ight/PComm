#define _POSIX_C_SOURCE 200809L
#include "net.h"
#include "lifecycle.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int fd;
    atomic_int started;
    int result;
} io_wait_t;

static uint64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static void delay_ms(unsigned milliseconds) {
    struct timespec delay = {milliseconds / 1000, (long)(milliseconds % 1000) * 1000000};
    nanosleep(&delay, NULL);
}

static void *accept_until_stopped(void *arg) {
    io_wait_t *waiter = (io_wait_t *)arg;
    atomic_store(&waiter->started, 1);
    while (!pcomm_shutdown_requested()) {
        int fd = net_accept(waiter->fd, NULL, 0, NULL);
        if (fd >= 0) net_close(fd);
    }
    waiter->result = 1;
    return NULL;
}

static void *receive_two_bytes(void *arg) {
    io_wait_t *waiter = (io_wait_t *)arg;
    unsigned char bytes[2];
    atomic_store(&waiter->started, 1);
    waiter->result = net_recvall(waiter->fd, bytes, sizeof(bytes));
    return NULL;
}

static int bound_port(int fd, uint16_t *port) {
    struct sockaddr_in address;
    socklen_t size = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &size) != 0) return -1;
    *port = ntohs(address.sin_port);
    return 0;
}

static int test_accept_and_shutdown(void) {
    int listener = -1, started = 0, ok = 0;
    pthread_t thread;
    io_wait_t waiter;
    pcomm_shutdown_reset();
    listener = net_listen_tcp("127.0.0.1", 0, 8);
    if (listener < 0 || net_tracked_socket_count() != 1) goto done;
    waiter.fd = listener;
    waiter.result = -99;
    atomic_init(&waiter.started, 0);
    if (pthread_create(&thread, NULL, accept_until_stopped, &waiter) != 0) goto done;
    started = 1;
    while (!atomic_load(&waiter.started)) delay_ms(1);
    uint64_t before = now_ms();
    pcomm_shutdown_request();
    net_shutdown_all();
    if (pthread_join(thread, NULL) != 0) abort();
    started = 0;
    if (waiter.result != 1 || now_ms() - before > 2000) goto done;
    if (net_connect_tcp("127.0.0.1", 1) >= 0 || net_listen_tcp("127.0.0.1", 0, 8) >= 0) goto done;
    ok = 1;
done:
    if (started) {
        pcomm_shutdown_request();
        net_shutdown_all();
        if (pthread_join(thread, NULL) != 0) abort();
    }
    net_close(listener);
    if (net_tracked_socket_count() != 0) ok = 0;
    return ok;
}

static int test_blocked_receive_and_owner_close(void) {
    int listener = -1, client = -1, accepted = -1, started = 0, ok = 0;
    pthread_t thread;
    io_wait_t waiter;
    uint16_t port = 0;
    pcomm_shutdown_reset();
    listener = net_listen_tcp("127.0.0.1", 0, 8);
    if (listener < 0 || bound_port(listener, &port) != 0) goto done;
    if (net_connect_tcp_policy("127.0.0.1", port, false) >= 0) goto done;
    if (net_tracked_socket_count() != 1) goto done;
    client = net_connect_tcp("127.0.0.1", port);
    if (client < 0) goto done;
    for (unsigned i = 0; i < 20 && accepted < 0; i++) accepted = net_accept(listener, NULL, 0, NULL);
    if (accepted < 0 || net_tracked_socket_count() != 3) goto done;
    if (net_sendall(client, "x", 1) != 0) goto done;
    waiter.fd = accepted;
    waiter.result = -99;
    atomic_init(&waiter.started, 0);
    if (pthread_create(&thread, NULL, receive_two_bytes, &waiter) != 0) goto done;
    started = 1;
    while (!atomic_load(&waiter.started)) delay_ms(1);
    delay_ms(20);
    uint64_t before = now_ms();

    net_shutdown(accepted);
    if (pthread_join(thread, NULL) != 0) abort();
    started = 0;
    if (waiter.result != -1 || now_ms() - before > 2000) goto done;
    if (pcomm_shutdown_requested()) goto done;
    if (net_tracked_socket_count() != 3) goto done;
    ok = 1;
done:
    if (started) {
        pcomm_shutdown_request();
        net_shutdown_all();
        if (pthread_join(thread, NULL) != 0) abort();
    }
    net_close(accepted);
    net_close(client);
    net_close(listener);
    if (net_tracked_socket_count() != 0) ok = 0;
    return ok;
}

int main(void) {
    alarm(10);
    int ok = test_accept_and_shutdown() && test_blocked_receive_and_owner_close();
    pcomm_shutdown_reset();
    alarm(0);
    if (!ok) {
        fputs("Managed socket shutdown checks failed.\n", stderr);
        return EXIT_FAILURE;
    }
    puts("Idle accept, blocked receive, shutdown admission, and owner-close checks passed.");
    return EXIT_SUCCESS;
}
