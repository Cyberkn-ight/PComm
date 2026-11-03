#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static void delay_ms(unsigned milliseconds) {
    struct timespec delay = {milliseconds / 1000, (long)(milliseconds % 1000) * 1000000};
    nanosleep(&delay, NULL);
}

static int bound_socket(int type, uint16_t requested_port, uint16_t *port) {
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) return -1;
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(requested_port);
    socklen_t length = sizeof(address);
    if (bind(fd, (struct sockaddr *)&address, length) != 0 ||
        (type == SOCK_STREAM && listen(fd, 32) != 0) ||
        getsockname(fd, (struct sockaddr *)&address, &length) != 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(address.sin_port);
    return fd;
}

static int connect_loopback(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    struct timeval timeout = {0, 200000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) { close(fd); return -1; }
    return fd;
}

static int fetch_identity(uint16_t http_port, char id[96]) {
    int fd = connect_loopback(http_port);
    if (fd < 0) return -1;
    const char request[] = "GET /api/me HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    char response[4096];
    size_t length = 0;
    int ok = send(fd, request, sizeof(request) - 1, 0) == (ssize_t)(sizeof(request) - 1);
    while (ok && length < sizeof(response) - 1) {
        ssize_t count = recv(fd, response + length, sizeof(response) - 1 - length, 0);
        if (count <= 0) break;
        length += (size_t)count;
    }
    close(fd);
    response[length] = '\0';
    const char *begin = strstr(response, "\"id\":\"");
    if (!ok || !begin) return -1;
    begin += strlen("\"id\":\"");
    const char *end = strchr(begin, '"');
    if (!end || end == begin || (size_t)(end - begin) >= 96) return -1;
    memcpy(id, begin, (size_t)(end - begin));
    id[end - begin] = '\0';
    return 0;
}

static int wait_exit(pid_t pid, int *status, unsigned timeout_ms) {
    uint64_t deadline = now_ms() + timeout_ms;
    do {
        pid_t result = waitpid(pid, status, WNOHANG);
        if (result == pid) return 0;
        if (result < 0 && errno != EINTR) return -1;
        delay_ms(10);
    } while (now_ms() < deadline);
    return -1;
}

static int database_is_valid(const char *directory) {
    char path[512];
    snprintf(path, sizeof(path), "%s/pcomm.sqlite", directory);
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int ok = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db, "PRAGMA quick_check;", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW &&
        strcmp((const char *)sqlite3_column_text(st, 0), "ok") == 0;
    sqlite3_finalize(st);
    if (db && sqlite3_close(db) != SQLITE_OK) ok = 0;
    return ok;
}

static void cleanup_directory(const char *directory) {
    static const char *files[] = {
        "identity.key", "pcomm.sqlite", "pcomm.sqlite-journal", "pcomm.sqlite-wal",
        "pcomm.sqlite-shm", "peers.txt", "process.log"
    };
    char path[512];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", directory, files[i]);
        if (unlink(path) != 0 && errno != ENOENT) perror("unlink test fixture");
    }
    if (rmdir(directory) != 0) perror("remove test fixture directory");
}

static int process_case(const char *binary, const char *ui, int signal_number,
                         const char *bootstrap_id, int bind_failure, char discovered_id[96]) {
    char directory[] = "process-shutdown-XXXXXX";
    char relay_address[64], http_address[64], peers_path[512], log_path[512] = {0};
    uint16_t relay_port = 0, http_port = 0, peer_port = 0;
    int relay_reservation = -1, relay_udp_reservation = -1, http_reservation = -1, peer_tcp = -1, peer_udp = -1;
    int slow_http = -1, slow_relay = -1, log_fd = -1, status = 0, ok = 0;
    pid_t child = -1;
    if (!mkdtemp(directory)) return 0;
    for (unsigned attempt = 0; attempt < 32; attempt++) {
        relay_reservation = bound_socket(SOCK_STREAM, 0, &relay_port);
        if (relay_reservation < 0) break;
        uint16_t udp_port = relay_port;
        relay_udp_reservation = bound_socket(SOCK_DGRAM, relay_port, &udp_port);
        if (relay_udp_reservation >= 0) break;
        close(relay_reservation);
        relay_reservation = -1;
    }
    http_reservation = bound_socket(SOCK_STREAM, 0, &http_port);
    if (relay_reservation < 0 || relay_udp_reservation < 0 || http_reservation < 0) goto done;
    snprintf(relay_address, sizeof(relay_address), "127.0.0.1:%u", relay_port);
    snprintf(http_address, sizeof(http_address), "127.0.0.1:%u", http_port);
    snprintf(peers_path, sizeof(peers_path), "%s/peers.txt", directory);
    snprintf(log_path, sizeof(log_path), "%s/process.log", directory);
    FILE *peers = fopen(peers_path, "w");
    if (!peers) goto done;
    if (bootstrap_id) {
        peer_tcp = bound_socket(SOCK_STREAM, 0, &peer_port);
        uint16_t udp_port = peer_port;
        peer_udp = bound_socket(SOCK_DGRAM, peer_port, &udp_port);
        if (peer_tcp < 0 || peer_udp < 0 || fprintf(peers, "%s 127.0.0.1 %u\n", bootstrap_id, peer_port) < 0) {
            fclose(peers);
            goto done;
        }
    }
    if (fclose(peers) != 0) goto done;
    log_fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (log_fd < 0) goto done;
    close(relay_reservation);
    relay_reservation = -1;
    close(relay_udp_reservation);
    relay_udp_reservation = -1;
    if (!bind_failure) { close(http_reservation); http_reservation = -1; }
    child = fork();
    if (child < 0) goto done;
    if (child == 0) {
        if (dup2(log_fd, STDOUT_FILENO) < 0 || dup2(log_fd, STDERR_FILENO) < 0) _exit(126);
        close(log_fd);
        execl(binary, binary, "--data-dir", directory, "--ui-dir", ui,
              "--relay", relay_address, "--http", http_address, "--peers", peers_path,
              "--allow-private-addrs", "--allow-private-exit", (char *)NULL);
        _exit(127);
    }
    close(log_fd);
    log_fd = -1;
    if (bind_failure) {
        if (wait_exit(child, &status, 5000) != 0) goto done;
        child = -1;
        if (!WIFEXITED(status) || WEXITSTATUS(status) == 0) goto done;
    } else {
        uint64_t deadline = now_ms() + 5000;
        while (fetch_identity(http_port, discovered_id) != 0) {
            if (now_ms() >= deadline) goto done;
            delay_ms(20);
        }
        slow_http = connect_loopback(http_port);
        slow_relay = connect_loopback(relay_port);
        if (slow_http < 0 || slow_relay < 0) goto done;
        const char partial[] = "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\nx";
        if (send(slow_http, partial, sizeof(partial) - 1, 0) != (ssize_t)(sizeof(partial) - 1) ||
            send(slow_relay, "P", 1, 0) != 1) goto done;
        if (peer_tcp >= 0) {
            struct pollfd ready = {peer_tcp, POLLIN, 0};
            if (poll(&ready, 1, 2000) <= 0 || !(ready.revents & POLLIN)) goto done;
        }
        delay_ms(100);
        uint64_t before = now_ms();
        if (kill(child, signal_number) != 0 || wait_exit(child, &status, 5000) != 0) goto done;
        child = -1;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || now_ms() - before > 5000) goto done;
    }
    if (!database_is_valid(directory)) goto done;
    relay_reservation = bound_socket(SOCK_STREAM, relay_port, &relay_port);
    uint16_t udp_port = relay_port;
    int udp_rebound = bound_socket(SOCK_DGRAM, relay_port, &udp_port);
    if (udp_rebound < 0) goto done;
    close(udp_rebound);
    if (relay_reservation < 0) goto done;
    ok = 1;
done:
    if (child > 0) {
        kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    }
    if (!ok) {
        fprintf(stderr, "Process shutdown fixture failed (signal=%d, bind_failure=%d).\n", signal_number, bind_failure);
        FILE *log = log_path[0] ? fopen(log_path, "r") : NULL;
        if (log) {
            char line[512];
            while (fgets(line, sizeof(line), log)) fputs(line, stderr);
            fclose(log);
        }
    }
    if (log_fd >= 0) close(log_fd);
    if (slow_http >= 0) close(slow_http);
    if (slow_relay >= 0) close(slow_relay);
    if (relay_reservation >= 0) close(relay_reservation);
    if (relay_udp_reservation >= 0) close(relay_udp_reservation);
    if (http_reservation >= 0) close(http_reservation);
    if (peer_tcp >= 0) close(peer_tcp);
    if (peer_udp >= 0) close(peer_udp);
    cleanup_directory(directory);
    return ok;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fputs("usage: test_process_shutdown PCOMM_BINARY UI_DIRECTORY\n", stderr);
        return EXIT_FAILURE;
    }
    signal(SIGPIPE, SIG_IGN);
    char first_id[96] = {0}, other_id[96] = {0};
    if (!process_case(argv[1], argv[2], SIGINT, NULL, 0, first_id) ||
        !process_case(argv[1], argv[2], SIGTERM, first_id, 0, other_id) ||
        !process_case(argv[1], argv[2], SIGINT, NULL, 1, other_id)) return EXIT_FAILURE;
    puts("SIGINT, SIGTERM with stalled peers, startup rollback, database integrity, and port reuse passed.");
    return EXIT_SUCCESS;
}
