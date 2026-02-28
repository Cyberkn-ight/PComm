#define _GNU_SOURCE
#include "http.h"
#include "net.h"
#include "sb.h"
#include "http_util.h"
#include "sendmsg.h"
#include "identity.h"
#include "hidden.h"
#include "db.h"
#include "crypto.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sqlite3.h>

typedef struct {
    pcomm_config_t cfg;
    pcomm_identity_t me;
    pcomm_db_t *db;
    int listen_fd;
} http_state_t;

static const char *mime_from_path(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    if (strcmp(ext, ".html") == 0) return "text/html; charset=utf-8";
    if (strcmp(ext, ".css") == 0) return "text/css; charset=utf-8";
    if (strcmp(ext, ".js") == 0) return "application/javascript; charset=utf-8";
    if (strcmp(ext, ".json") == 0) return "application/json; charset=utf-8";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".svg") == 0) return "image/svg+xml";
    return "application/octet-stream";
}

static int send_resp(int fd, int code, const char *ctype, const char *body, size_t body_len) {
    char hdr[512];
    const char *msg = (code == 200) ? "OK" : (code == 404) ? "Not Found" : (code == 400) ? "Bad Request" : "Error";
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "Cache-Control: no-store\r\n"
                     "\r\n",
                     code, msg, ctype ? ctype : "text/plain", body_len);
    if (n <= 0) return -1;
    if (net_sendall(fd, hdr, (size_t)n) != 0) return -1;
    if (body_len > 0 && body) {
        if (net_sendall(fd, body, body_len) != 0) return -1;
    }
    return 0;
}

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > 10*1024*1024) { fclose(f); return -1; }
    uint8_t *buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { free(buf); return -1; }
    *out = buf;
    *out_len = n;
    return 0;
}

static int serve_file(int fd, const char *ui_dir, const char *req_path) {
    char path[1024];
    if (strcmp(req_path, "/") == 0) req_path = "/index.html";

    if (strstr(req_path, "..")) return send_resp(fd, 400, "text/plain", "bad path", 8);

    snprintf(path, sizeof(path), "%s%s", ui_dir, req_path);

    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_file(path, &buf, &len) != 0) {
        return send_resp(fd, 404, "text/plain", "not found", 9);
    }

    int rc = send_resp(fd, 200, mime_from_path(path), (const char*)buf, len);
    free(buf);
    return rc;
}

static int api_me(http_state_t *st, int fd) {
    sb_t sb; sb_init(&sb);
    sb_append(&sb, "{");
    sb_append(&sb, "\"id\":\""); sb_append_json_escaped(&sb, st->me.user_id); sb_append(&sb, "\"");
    sb_appendf(&sb, ",\"relay\":{\"host\":\"%s\",\"port\":%u}", st->cfg.relay_host, (unsigned)st->cfg.relay_port);
    sb_appendf(&sb, ",\"http\":{\"host\":\"%s\",\"port\":%u}", st->cfg.http_host, (unsigned)st->cfg.http_port);
    sb_append(&sb, "}");
    int rc = send_resp(fd, 200, "application/json; charset=utf-8", sb.buf ? sb.buf : "{}", sb.len);
    sb_free(&sb);
    return rc;
}

static int api_contacts(http_state_t *st, int fd) {
    const char *sql = "SELECT user_id, host, port, is_relay FROM contacts ORDER BY added_at DESC LIMIT 200;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(st->db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return send_resp(fd, 500, "text/plain", "db error", 8);
    }

    sb_t sb; sb_init(&sb);
    sb_append(&sb, "[");
    int first = 1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *uid = (const char*)sqlite3_column_text(stmt, 0);
        const char *host = (const char*)sqlite3_column_text(stmt, 1);
        int port = sqlite3_column_int(stmt, 2);
        int is_relay = sqlite3_column_int(stmt, 3);
        if (!uid || !host) continue;
        if (!first) sb_append(&sb, ",");
        first = 0;
        sb_append(&sb, "{");
        sb_append(&sb, "\"id\":\""); sb_append_json_escaped(&sb, uid); sb_append(&sb, "\"");
        sb_append(&sb, ",\"host\":\""); sb_append_json_escaped(&sb, host); sb_append(&sb, "\"");
        sb_appendf(&sb, ",\"port\":%d,\"is_relay\":%d", port, is_relay);
        sb_append(&sb, "}");
    }
    sb_append(&sb, "]");

    sqlite3_finalize(stmt);
    int rc = send_resp(fd, 200, "application/json; charset=utf-8", sb.buf ? sb.buf : "[]", sb.len);
    sb_free(&sb);
    return rc;
}

static int api_conversations(http_state_t *st, int fd) {
    const char *sql =
        "SELECT c.id, IFNULL(c.uuid,''), c.type, IFNULL(c.title,''), "
        "CASE WHEN c.type='direct' THEN IFNULL((SELECT user_id FROM participants p WHERE p.conversation_id=c.id LIMIT 1), '') ELSE '' END AS peer, "
        "IFNULL((SELECT body FROM messages m WHERE m.conversation_id=c.id ORDER BY ts_unix DESC, id DESC LIMIT 1), '') AS last_body, "
        "IFNULL((SELECT ts_unix FROM messages m WHERE m.conversation_id=c.id ORDER BY ts_unix DESC, id DESC LIMIT 1), 0) AS last_ts "
        "FROM conversations c "
        "ORDER BY last_ts DESC LIMIT 200;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(st->db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return send_resp(fd, 500, "text/plain", "db error", 8);
    }

    sb_t sb; sb_init(&sb);
    sb_append(&sb, "[");
    int first = 1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(stmt, 0);
        const char *uuid = (const char*)sqlite3_column_text(stmt, 1);
        const char *type = (const char*)sqlite3_column_text(stmt, 2);
        const char *title = (const char*)sqlite3_column_text(stmt, 3);
        const char *peer = (const char*)sqlite3_column_text(stmt, 4);
        const char *last_body = (const char*)sqlite3_column_text(stmt, 5);
        int64_t last_ts = sqlite3_column_int64(stmt, 6);
        if (!type) type = "";
        if (!uuid) uuid = "";
        if (!title) title = "";
        if (!peer) peer = "";
        if (!last_body) last_body = "";

        if (!first) sb_append(&sb, ",");
        first = 0;

        sb_append(&sb, "{");
        sb_appendf(&sb, "\"id\":%lld,", (long long)id);
        sb_append(&sb, "\"uuid\":\""); sb_append_json_escaped(&sb, uuid); sb_append(&sb, "\",");
        sb_append(&sb, "\"type\":\""); sb_append_json_escaped(&sb, type); sb_append(&sb, "\",");
        sb_append(&sb, "\"title\":\""); sb_append_json_escaped(&sb, title); sb_append(&sb, "\",");
        sb_append(&sb, "\"peer\":\""); sb_append_json_escaped(&sb, peer); sb_append(&sb, "\",");
        sb_appendf(&sb, "\"last_ts\":%lld,", (long long)last_ts);
        sb_append(&sb, "\"last_body\":\""); sb_append_json_escaped(&sb, last_body); sb_append(&sb, "\"}");
    }
    sb_append(&sb, "]");

    sqlite3_finalize(stmt);
    int rc = send_resp(fd, 200, "application/json; charset=utf-8", sb.buf ? sb.buf : "[]", sb.len);
    sb_free(&sb);
    return rc;
}

static int api_messages(http_state_t *st, int fd, const char *query) {
    char conv_id_str[64] = {0};
    if (query) {
        const char *p = strstr(query, "conv=");
        if (p) {
            snprintf(conv_id_str, sizeof(conv_id_str), "%s", p + 5);
            char *amp = strchr(conv_id_str, '&');
            if (amp) *amp = '\0';
        }
    }
    if (conv_id_str[0] == '\0') return send_resp(fd, 400, "text/plain", "missing conv", 12);

    int64_t conv_id = atoll(conv_id_str);
    const char *sql =
        "SELECT direction, sender_user_id, body, ts_unix FROM messages WHERE conversation_id=? ORDER BY ts_unix ASC, id ASC LIMIT 1000;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(st->db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return send_resp(fd, 500, "text/plain", "db error", 8);
    }
    sqlite3_bind_int64(stmt, 1, conv_id);

    sb_t sb; sb_init(&sb);
    sb_append(&sb, "[");
    int first = 1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int direction = sqlite3_column_int(stmt, 0);
        const char *sender = (const char*)sqlite3_column_text(stmt, 1);
        const char *body = (const char*)sqlite3_column_text(stmt, 2);
        int64_t ts = sqlite3_column_int64(stmt, 3);
        if (!sender) sender = "";
        if (!body) body = "";
        if (!first) sb_append(&sb, ",");
        first = 0;
        sb_append(&sb, "{");
        sb_appendf(&sb, "\"dir\":%d,", direction);
        sb_append(&sb, "\"sender\":\""); sb_append_json_escaped(&sb, sender); sb_append(&sb, "\",");
        sb_appendf(&sb, "\"ts\":%lld,", (long long)ts);
        sb_append(&sb, "\"body\":\""); sb_append_json_escaped(&sb, body); sb_append(&sb, "\"}");
    }
    sb_append(&sb, "]");

    sqlite3_finalize(stmt);
    int rc = send_resp(fd, 200, "application/json; charset=utf-8", sb.buf ? sb.buf : "[]", sb.len);
    sb_free(&sb);
    return rc;
}

static int api_send(http_state_t *st, int fd, const char *body) {
    char to[128] = {0};
    char text[2048] = {0};
    if (form_get_field(body, "to", to, sizeof(to)) != 0) return send_resp(fd, 400, "text/plain", "missing to", 10);
    if (form_get_field(body, "text", text, sizeof(text)) != 0) return send_resp(fd, 400, "text/plain", "missing text", 12);

    int rc = pcomm_send_text(st->db, &st->cfg, &st->me, to, text);
    if (rc == 0) return send_resp(fd, 200, "application/json; charset=utf-8", "{\"ok\":true}", 11);
    return send_resp(fd, 500, "application/json; charset=utf-8", "{\"ok\":false}", 12);
}

static void trim(char *s) {
    if (!s) return;
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n-1])) { s[n-1] = '\0'; n--; }
}

static void hex16(uint8_t b[16], char out[33]) {
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[i*2+0] = hex[(b[i] >> 4) & 0xF];
        out[i*2+1] = hex[b[i] & 0xF];
    }
    out[32] = '\0';
}

static int api_create_group(http_state_t *st, int fd, const char *body) {
    char title[256] = {0};
    char members_raw[2048] = {0};
    form_get_field(body, "title", title, sizeof(title));
    if (form_get_field(body, "members", members_raw, sizeof(members_raw)) != 0) {
        return send_resp(fd, 400, "text/plain", "missing members", 15);
    }
    trim(title);
    trim(members_raw);

    char *tmp = strdup(members_raw);
    if (!tmp) return send_resp(fd, 500, "text/plain", "oom", 3);

    char *members[65];
    int mcount = 0;
    char *save = NULL;
    for (char *tok = strtok_r(tmp, ",", &save); tok && mcount < 64; tok = strtok_r(NULL, ",", &save)) {
        trim(tok);
        if (tok[0] == '\0') continue;
        uint8_t pk[32];
        if (pcomm_pubkey_from_user_id(tok, pk) != 0) continue;
        members[mcount++] = strdup(tok);
    }
    free(tmp);
    if (mcount == 0) return send_resp(fd, 400, "text/plain", "no valid members", 16);

    if (mcount < 65) members[mcount++] = strdup(st->me.user_id);

    uint8_t rnd[16];
    pcomm_random(rnd, sizeof(rnd));
    char uuid[33];
    hex16(rnd, uuid);

    int64_t conv_id = pcomm_db_get_or_create_group_conv(st->db, uuid, title[0] ? title : "");
    if (conv_id < 0) {
        for (int i = 0; i < mcount; i++) free(members[i]);
        return send_resp(fd, 500, "text/plain", "db error", 8);
    }
    for (int i = 0; i < mcount; i++) {
        pcomm_db_add_participant(st->db, conv_id, members[i]);
    }

    for (int i = 0; i < mcount; i++) {
        if (strcmp(members[i], st->me.user_id) == 0) continue;
        pcomm_hidden_send_group_invite(st->db, &st->cfg, &st->me, members[i], uuid, title, members, mcount);
    }

    for (int i = 0; i < mcount; i++) free(members[i]);

    sb_t sb; sb_init(&sb);
    sb_appendf(&sb, "{\"ok\":true,\"id\":%lld,\"uuid\":\"%s\"}", (long long)conv_id, uuid);
    int rc = send_resp(fd, 200, "application/json; charset=utf-8", sb.buf, sb.len);
    sb_free(&sb);
    return rc;
}

static int api_send_group(http_state_t *st, int fd, const char *body) {
    char conv_str[64] = {0};
    char text[2048] = {0};
    if (form_get_field(body, "conv", conv_str, sizeof(conv_str)) != 0) return send_resp(fd, 400, "text/plain", "missing conv", 12);
    if (form_get_field(body, "text", text, sizeof(text)) != 0) return send_resp(fd, 400, "text/plain", "missing text", 12);
    int64_t conv_id = atoll(conv_str);

    char uuid[256] = {0};
    char type[32] = {0};
    if (pcomm_db_get_conversation_uuid(st->db, conv_id, uuid, sizeof(uuid), type, sizeof(type)) != 0) {
        return send_resp(fd, 400, "text/plain", "bad conv", 8);
    }
    if (strcmp(type, "group") != 0 || uuid[0] == '\0') {
        return send_resp(fd, 400, "text/plain", "not group", 9);
    }

    char **members = NULL; int mcount = 0;
    if (pcomm_db_list_group_participants(st->db, conv_id, &members, &mcount) != 0 || mcount == 0) {
        return send_resp(fd, 500, "text/plain", "db error", 8);
    }

    for (int i = 0; i < mcount; i++) {
        if (!members[i]) continue;
        if (strcmp(members[i], st->me.user_id) == 0) continue;
        pcomm_hidden_send_group_text(st->db, &st->cfg, &st->me, members[i], uuid, text);
    }

    pcomm_db_insert_message(st->db, conv_id, 1, uuid, st->me.user_id, text, (const uint8_t*)"", 0, (int64_t)time(NULL));

    for (int i = 0; i < mcount; i++) free(members[i]);
    free(members);

    return send_resp(fd, 200, "application/json; charset=utf-8", "{\"ok\":true}", 11);
}

static int api_add_contact(http_state_t *st, int fd, const char *body) {
    char id[128] = {0};
    char host[128] = {0};
    char port_str[32] = {0};
    char relay_str[8] = {0};

    if (form_get_field(body, "id", id, sizeof(id)) != 0) return send_resp(fd, 400, "text/plain", "missing id", 10);
    form_get_field(body, "host", host, sizeof(host));
    form_get_field(body, "port", port_str, sizeof(port_str));
    form_get_field(body, "relay", relay_str, sizeof(relay_str));

    uint16_t port = (uint16_t)atoi(port_str);
    int is_relay = (relay_str[0] == '1') ? 1 : 0;

    uint8_t pubkey[32];
    if (pcomm_pubkey_from_user_id(id, pubkey) != 0) {
        return send_resp(fd, 400, "text/plain", "bad id", 6);
    }

    if (pcomm_db_upsert_contact(st->db, id, host[0] ? host : "", port, pubkey, is_relay) != 0) {
        return send_resp(fd, 500, "text/plain", "db error", 8);
    }

    return send_resp(fd, 200, "application/json; charset=utf-8", "{\"ok\":true}", 11);
}

static int route_request(http_state_t *st, int fd, const char *method, const char *path, const char *query, const char *body) {
    if (strncmp(path, "/api/", 5) == 0) {
        if (strcmp(path, "/api/me") == 0 && strcmp(method, "GET") == 0) return api_me(st, fd);
        if (strcmp(path, "/api/contacts") == 0 && strcmp(method, "GET") == 0) return api_contacts(st, fd);
        if (strcmp(path, "/api/conversations") == 0 && strcmp(method, "GET") == 0) return api_conversations(st, fd);
        if (strcmp(path, "/api/messages") == 0 && strcmp(method, "GET") == 0) return api_messages(st, fd, query);
        if (strcmp(path, "/api/send") == 0 && strcmp(method, "POST") == 0) return api_send(st, fd, body ? body : "");
        if (strcmp(path, "/api/create_group") == 0 && strcmp(method, "POST") == 0) return api_create_group(st, fd, body ? body : "");
        if (strcmp(path, "/api/send_group") == 0 && strcmp(method, "POST") == 0) return api_send_group(st, fd, body ? body : "");
        if (strcmp(path, "/api/add_contact") == 0 && strcmp(method, "POST") == 0) return api_add_contact(st, fd, body ? body : "");
        return send_resp(fd, 404, "text/plain", "not found", 9);
    }
    return serve_file(fd, st->cfg.ui_dir, path);
}

static void *http_thread(void *arg) {
    http_state_t *st = (http_state_t*)arg;

    for (;;) {
        int cfd = net_accept(st->listen_fd, NULL, 0, NULL);
        if (cfd < 0) continue;

        char req[8192];
        ssize_t n = recv(cfd, req, sizeof(req) - 1, 0);
        if (n <= 0) { close(cfd); continue; }
        req[n] = '\0';

        char *hdr_end = strstr(req, "\r\n\r\n");
        if (!hdr_end) { send_resp(cfd, 400, "text/plain", "bad request", 11); close(cfd); continue; }

        size_t header_len = (size_t)(hdr_end - req) + 4;
        char *body = req + header_len;
        size_t body_len = (size_t)n - header_len;

        char method[8] = {0};
        char target[1024] = {0};
        if (sscanf(req, "%7s %1023s", method, target) != 2) {
            send_resp(cfd, 400, "text/plain", "bad request", 11);
            close(cfd);
            continue;
        }

        size_t content_len = 0;
        const char *cl = strcasestr(req, "Content-Length:");
        if (cl) {
            cl += strlen("Content-Length:");
            while (*cl == ' ') cl++;
            content_len = (size_t)atoi(cl);
        }

        while (body_len < content_len && header_len + body_len < sizeof(req) - 1) {
            ssize_t m = recv(cfd, req + n, (sizeof(req) - 1) - (size_t)n, 0);
            if (m <= 0) break;
            n += m;
            req[n] = '\0';
            body = req + header_len;
            body_len = (size_t)n - header_len;
        }

        if (content_len > body_len) {
            send_resp(cfd, 400, "text/plain", "body too large", 14);
            close(cfd);
            continue;
        }

        char path[1024] = {0};
        char *q = strchr(target, '?');
        const char *query = NULL;
        if (q) {
            size_t plen = (size_t)(q - target);
            if (plen >= sizeof(path)) plen = sizeof(path)-1;
            memcpy(path, target, plen);
            path[plen] = '\0';
            query = q + 1;
        } else {
            snprintf(path, sizeof(path), "%s", target);
        }

        char *body_copy = NULL;
        if (content_len > 0) {
            body_copy = (char*)malloc(content_len + 1);
            if (!body_copy) { close(cfd); continue; }
            memcpy(body_copy, body, content_len);
            body_copy[content_len] = '\0';
        }

        route_request(st, cfd, method, path, query, body_copy);

        free(body_copy);
        close(cfd);
    }
    return NULL;
}

int pcomm_http_start(const pcomm_config_t *cfg, const pcomm_identity_t *me, pcomm_db_t *db) {
    if (!cfg || !me || !db) return -1;

    http_state_t *st = (http_state_t*)calloc(1, sizeof(http_state_t));
    if (!st) return -1;
    st->cfg = *cfg;
    st->me = *me;
    st->db = db;

    st->listen_fd = net_listen_tcp(cfg->http_host, cfg->http_port, 64);
    if (st->listen_fd < 0) {
        fprintf(stderr, "Failed to listen on http %s:%u\n", cfg->http_host, (unsigned)cfg->http_port);
        free(st);
        return -1;
    }

    pthread_t th;
    if (pthread_create(&th, NULL, http_thread, st) != 0) {
        close(st->listen_fd);
        free(st);
        return -1;
    }
    pthread_detach(th);

    fprintf(stderr, "HTTP UI listening on http://%s:%u\n", cfg->http_host, (unsigned)cfg->http_port);
    return 0;
}
