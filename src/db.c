#include "db.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

static int exec_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite error: %s\n", err ? err : "(unknown)");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int column_exists(sqlite3 *db, const char *table, const char *col) {
    char sql[256];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    int exists = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char*)sqlite3_column_text(st, 1);
        if (name && strcmp(name, col) == 0) { exists = 1; break; }
    }
    sqlite3_finalize(st);
    return exists;
}

int pcomm_db_open(pcomm_db_t *pdb, const char *data_dir) {
    if (!pdb || !data_dir) return -1;
    memset(pdb, 0, sizeof(*pdb));

    char path[1024];
    snprintf(path, sizeof(path), "%s/pcomm.sqlite", data_dir);

    if (sqlite3_open_v2(path, &pdb->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to open sqlite db: %s\n", sqlite3_errmsg(pdb->db));
        return -1;
    }
    sqlite3_busy_timeout(pdb->db, 2000);

    exec_sql(pdb->db, "PRAGMA foreign_keys=ON;");
    return 0;
}

void pcomm_db_close(pcomm_db_t *pdb) {
    if (!pdb) return;
    if (pdb->db) sqlite3_close(pdb->db);
    pdb->db = NULL;
}

int pcomm_db_init_schema(pcomm_db_t *pdb) {
    if (!pdb || !pdb->db) return -1;

    const char *sql =
        "CREATE TABLE IF NOT EXISTS contacts("
        " user_id TEXT PRIMARY KEY,"
        " host TEXT NOT NULL,"
        " port INTEGER NOT NULL,"
        " pubkey BLOB NOT NULL,"
        " is_relay INTEGER NOT NULL DEFAULT 0,"
        " added_at INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS conversations("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " uuid TEXT,"
        " type TEXT NOT NULL,"
        " title TEXT,"
        " created_at INTEGER NOT NULL"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_uuid ON conversations(uuid);"
        "CREATE TABLE IF NOT EXISTS participants("
        " conversation_id INTEGER NOT NULL,"
        " user_id TEXT NOT NULL,"
        " role TEXT NOT NULL DEFAULT 'member',"
        " PRIMARY KEY(conversation_id, user_id),"
        " FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE"
        ");"
        "CREATE TABLE IF NOT EXISTS messages("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " conversation_id INTEGER NOT NULL,"
        " direction INTEGER NOT NULL,"
        " peer_user_id TEXT NOT NULL,"
        " sender_user_id TEXT NOT NULL,"
        " body TEXT NOT NULL,"
        " ciphertext BLOB NOT NULL,"
        " ts_unix INTEGER NOT NULL,"
        " status INTEGER NOT NULL DEFAULT 0,"
        " FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_messages_conv_ts ON messages(conversation_id, ts_unix);";

    if (exec_sql(pdb->db, sql) != 0) return -1;
    if (!column_exists(pdb->db, "conversations", "uuid")) {
        if (exec_sql(pdb->db, "ALTER TABLE conversations ADD COLUMN uuid TEXT;") != 0) return -1;
        exec_sql(pdb->db, "CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_uuid ON conversations(uuid);");
    }
    const char *sql2 =
        "CREATE TABLE IF NOT EXISTS mailbox_items("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " mkey BLOB NOT NULL,"
        " ts_unix INTEGER NOT NULL,"
        " blob BLOB NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_mailbox_key_id ON mailbox_items(mkey, id);"
        "CREATE TABLE IF NOT EXISTS descriptors("
        " dkey BLOB PRIMARY KEY,"
        " ts_unix INTEGER NOT NULL,"
        " expires_unix INTEGER NOT NULL,"
        " blob BLOB NOT NULL"
        ");";

    if (exec_sql(pdb->db, sql2) != 0) return -1;

    return 0;
}

int pcomm_db_upsert_contact(pcomm_db_t *pdb, const char *user_id, const char *host, uint16_t port, const uint8_t pubkey[32], int is_relay) {
    if (!pdb || !pdb->db) return -1;
    const char *sql =
        "INSERT INTO contacts(user_id,host,port,pubkey,is_relay,added_at) VALUES(?,?,?,?,?,strftime('%s','now'))"
        " ON CONFLICT(user_id) DO UPDATE SET host=excluded.host, port=excluded.port, pubkey=excluded.pubkey, is_relay=excluded.is_relay;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(st, 1, user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, host, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, (int)port);
    sqlite3_bind_blob(st, 4, pubkey, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, is_relay ? 1 : 0);

    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int pcomm_db_get_contact(pcomm_db_t *pdb, const char *user_id, char *host_out, size_t host_cap, uint16_t *port_out, uint8_t pubkey_out[32], int *is_relay_out) {
    if (!pdb || !pdb->db) return -1;
    const char *sql = "SELECT host, port, pubkey, is_relay FROM contacts WHERE user_id=?;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, user_id, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }

    const char *host = (const char*)sqlite3_column_text(st, 0);
    int port = sqlite3_column_int(st, 1);
    const void *pk = sqlite3_column_blob(st, 2);
    int pklen = sqlite3_column_bytes(st, 2);
    int is_relay = sqlite3_column_int(st, 3);

    if (!host || pklen != 32) {
        sqlite3_finalize(st);
        return -1;
    }

    snprintf(host_out, host_cap, "%s", host);
    *port_out = (uint16_t)port;
    memcpy(pubkey_out, pk, 32);
    if (is_relay_out) *is_relay_out = is_relay;

    sqlite3_finalize(st);
    return 0;
}

static int64_t now_unix(sqlite3 *db) {
    sqlite3_stmt *st = NULL;
    int64_t t = 0;
    if (sqlite3_prepare_v2(db, "SELECT strftime('%s','now');", -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            t = sqlite3_column_int64(st, 0);
        }
    }
    sqlite3_finalize(st);
    return t;
}

static uint64_t to_be64(uint64_t x) {
    uint8_t b[8];
    b[0] = (uint8_t)((x >> 56) & 0xFF);
    b[1] = (uint8_t)((x >> 48) & 0xFF);
    b[2] = (uint8_t)((x >> 40) & 0xFF);
    b[3] = (uint8_t)((x >> 32) & 0xFF);
    b[4] = (uint8_t)((x >> 24) & 0xFF);
    b[5] = (uint8_t)((x >> 16) & 0xFF);
    b[6] = (uint8_t)((x >> 8) & 0xFF);
    b[7] = (uint8_t)(x & 0xFF);
    uint64_t y;
    memcpy(&y, b, 8);
    return y;
}

int64_t pcomm_db_get_or_create_direct_conv(pcomm_db_t *pdb, const char *peer_user_id) {
    if (!pdb || !pdb->db) return -1;
    const char *find_sql =
        "SELECT c.id FROM conversations c "
        "JOIN participants p ON p.conversation_id=c.id "
        "WHERE c.type='direct' AND p.user_id=? LIMIT 1;";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, find_sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, peer_user_id, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(st) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        return id;
    }
    sqlite3_finalize(st);
    exec_sql(pdb->db, "BEGIN;");

    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(pdb->db,
        "INSERT INTO conversations(uuid,type,title,created_at) VALUES(?, 'direct', NULL, ?);",
        -1, &ins, NULL) != SQLITE_OK) {
        exec_sql(pdb->db, "ROLLBACK;");
        return -1;
    }
    char uuid[256];
    snprintf(uuid, sizeof(uuid), "direct:%s", peer_user_id);
    sqlite3_bind_text(ins, 1, uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins, 2, now_unix(pdb->db));
    if (sqlite3_step(ins) != SQLITE_DONE) {
        sqlite3_finalize(ins);
        exec_sql(pdb->db, "ROLLBACK;");
        return -1;
    }
    sqlite3_finalize(ins);

    int64_t conv_id = sqlite3_last_insert_rowid(pdb->db);

    sqlite3_stmt *p1 = NULL;
    if (sqlite3_prepare_v2(pdb->db,
        "INSERT INTO participants(conversation_id,user_id,role) VALUES(?,?, 'member');",
        -1, &p1, NULL) != SQLITE_OK) {
        exec_sql(pdb->db, "ROLLBACK;");
        return -1;
    }
    sqlite3_bind_int64(p1, 1, conv_id);
    sqlite3_bind_text(p1, 2, peer_user_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(p1) != SQLITE_DONE) {
        sqlite3_finalize(p1);
        exec_sql(pdb->db, "ROLLBACK;");
        return -1;
    }
    sqlite3_finalize(p1);

    exec_sql(pdb->db, "COMMIT;");
    return conv_id;
}

int pcomm_db_insert_message(pcomm_db_t *pdb, int64_t conv_id, int direction, const char *peer_user_id,
                            const char *sender_user_id, const char *body_utf8,
                            const uint8_t *cipher, size_t cipher_len,
                            int64_t ts_unix) {
    if (!pdb || !pdb->db) return -1;

    const char *sql =
        "INSERT INTO messages(conversation_id,direction,peer_user_id,sender_user_id,body,ciphertext,ts_unix,status)"
        " VALUES(?,?,?,?,?,?,?,0);";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int64(st, 1, conv_id);
    sqlite3_bind_int(st, 2, direction);
    sqlite3_bind_text(st, 3, peer_user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, sender_user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, body_utf8, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 6, cipher, (int)cipher_len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, ts_unix);

    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int pcomm_db_add_participant(pcomm_db_t *pdb, int64_t conv_id, const char *user_id) {
    if (!pdb || !pdb->db || !user_id) return -1;
    const char *sql = "INSERT OR IGNORE INTO participants(conversation_id,user_id,role) VALUES(?,?,'member');";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, conv_id);
    sqlite3_bind_text(st, 2, user_id, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int64_t pcomm_db_get_or_create_group_conv(pcomm_db_t *pdb, const char *uuid, const char *title) {
    if (!pdb || !pdb->db || !uuid) return -1;

    const char *find_sql = "SELECT id FROM conversations WHERE type='group' AND uuid=? LIMIT 1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, find_sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, uuid, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        return id;
    }
    sqlite3_finalize(st);

    exec_sql(pdb->db, "BEGIN;");

    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(pdb->db,
        "INSERT INTO conversations(uuid,type,title,created_at) VALUES(?, 'group', ?, ?);",
        -1, &ins, NULL) != SQLITE_OK) {
        exec_sql(pdb->db, "ROLLBACK;");
        return -1;
    }
    sqlite3_bind_text(ins, 1, uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 2, title ? title : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins, 3, now_unix(pdb->db));
    if (sqlite3_step(ins) != SQLITE_DONE) {
        sqlite3_finalize(ins);
        exec_sql(pdb->db, "ROLLBACK;");
        return -1;
    }
    sqlite3_finalize(ins);
    int64_t conv_id = sqlite3_last_insert_rowid(pdb->db);
    exec_sql(pdb->db, "COMMIT;");
    return conv_id;
}

int pcomm_db_get_conversation_uuid(pcomm_db_t *pdb, int64_t conv_id, char *uuid_out, size_t uuid_cap, char *type_out, size_t type_cap) {
    if (!pdb || !pdb->db || !uuid_out || !type_out) return -1;
    const char *sql = "SELECT IFNULL(uuid,''), type FROM conversations WHERE id=?;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, conv_id);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    const char *uuid = (const char*)sqlite3_column_text(st, 0);
    const char *type = (const char*)sqlite3_column_text(st, 1);
    if (!uuid) uuid = "";
    if (!type) type = "";
    snprintf(uuid_out, uuid_cap, "%s", uuid);
    snprintf(type_out, type_cap, "%s", type);
    sqlite3_finalize(st);
    return 0;
}

int pcomm_db_list_group_participants(pcomm_db_t *pdb, int64_t conv_id, char ***ids_out, int *count_out) {
    if (!pdb || !pdb->db || !ids_out || !count_out) return -1;
    *ids_out = NULL;
    *count_out = 0;
    const char *sql = "SELECT user_id FROM participants WHERE conversation_id=? ORDER BY user_id ASC;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, conv_id);

    int cap = 8;
    char **arr = (char**)calloc((size_t)cap, sizeof(char*));
    if (!arr) { sqlite3_finalize(st); return -1; }
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *uid = (const char*)sqlite3_column_text(st, 0);
        if (!uid) continue;
        if (n >= cap) {
            cap *= 2;
            char **tmp = (char**)realloc(arr, (size_t)cap * sizeof(char*));
            if (!tmp) break;
            arr = tmp;
        }
        arr[n] = strdup(uid);
        if (!arr[n]) break;
        n++;
    }
    sqlite3_finalize(st);
    *ids_out = arr;
    *count_out = n;
    return 0;
}

int pcomm_db_mailbox_put(pcomm_db_t *pdb, const uint8_t key[32], const uint8_t *blob, uint32_t blob_len, int64_t ts_unix) {
    if (!pdb || !pdb->db || !key || !blob) return -1;
    const char *sql = "INSERT INTO mailbox_items(mkey,ts_unix,blob) VALUES(?,?,?);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, key, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, ts_unix);
    sqlite3_bind_blob(st, 3, blob, (int)blob_len, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int pcomm_db_mailbox_get_and_delete(pcomm_db_t *pdb, const uint8_t key[32], uint8_t **out, uint32_t *out_len) {
    if (!pdb || !pdb->db || !key || !out || !out_len) return -1;
    *out = NULL; *out_len = 0;

    exec_sql(pdb->db, "BEGIN;");

    const char *sel = "SELECT id, ts_unix, blob FROM mailbox_items WHERE mkey=? ORDER BY id ASC LIMIT 100;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, sel, -1, &st, NULL) != SQLITE_OK) {
        exec_sql(pdb->db, "ROLLBACK;");
        return -1;
    }
    sqlite3_bind_blob(st, 1, key, 32, SQLITE_TRANSIENT);
    int count = 0;
    uint64_t ids[100];
    int64_t tss[100];
    const void *blobs[100];
    int blens[100];
    while (sqlite3_step(st) == SQLITE_ROW && count < 100) {
        ids[count] = (uint64_t)sqlite3_column_int64(st, 0);
        tss[count] = sqlite3_column_int64(st, 1);
        blobs[count] = sqlite3_column_blob(st, 2);
        blens[count] = sqlite3_column_bytes(st, 2);
        if (!blobs[count] || blens[count] <= 0) continue;
        count++;
    }
    sqlite3_finalize(st);
    uint32_t total = 2;
    for (int i = 0; i < count; i++) {
        total += 8 + 4 + 4 + (uint32_t)blens[i];
    }

    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) {
        exec_sql(pdb->db, "ROLLBACK;");
        return -1;
    }
    uint16_t ncount = (uint16_t)count;
    uint16_t n = htons(ncount);
    memcpy(buf, &n, 2);
    uint32_t off = 2;
    for (int i = 0; i < count; i++) {
        uint64_t idn = to_be64(ids[i]);
        memcpy(buf + off, &idn, 8); off += 8;
        uint32_t tsn = htonl((uint32_t)tss[i]);
        memcpy(buf + off, &tsn, 4); off += 4;
        uint32_t ln = htonl((uint32_t)blens[i]);
        memcpy(buf + off, &ln, 4); off += 4;
        memcpy(buf + off, blobs[i], (size_t)blens[i]); off += (uint32_t)blens[i];
    }

    if (count > 0) {
        uint64_t max_id = ids[count-1];
        sqlite3_stmt *del = NULL;
        if (sqlite3_prepare_v2(pdb->db, "DELETE FROM mailbox_items WHERE mkey=? AND id<=?;", -1, &del, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(del, 1, key, 32, SQLITE_TRANSIENT);
            sqlite3_bind_int64(del, 2, (sqlite3_int64)max_id);
            sqlite3_step(del);
        }
        sqlite3_finalize(del);
    }

    exec_sql(pdb->db, "COMMIT;");

    *out = buf;
    *out_len = total;
    return 0;
}

int pcomm_db_desc_put(pcomm_db_t *pdb, const uint8_t key[32], const uint8_t *blob, uint32_t blob_len, int64_t expires_unix, int64_t ts_unix) {
    if (!pdb || !pdb->db || !key || !blob) return -1;
    const char *sql =
        "INSERT INTO descriptors(dkey,ts_unix,expires_unix,blob) VALUES(?,?,?,?) "
        "ON CONFLICT(dkey) DO UPDATE SET ts_unix=excluded.ts_unix, expires_unix=excluded.expires_unix, blob=excluded.blob;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, key, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, ts_unix);
    sqlite3_bind_int64(st, 3, expires_unix);
    sqlite3_bind_blob(st, 4, blob, (int)blob_len, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int pcomm_db_desc_get(pcomm_db_t *pdb, const uint8_t key[32], uint8_t **blob_out, uint32_t *blob_len_out) {
    if (!pdb || !pdb->db || !key || !blob_out || !blob_len_out) return -1;
    *blob_out = NULL; *blob_len_out = 0;

    const char *sql = "SELECT blob, expires_unix FROM descriptors WHERE dkey=?;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, key, 32, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    const void *b = sqlite3_column_blob(st, 0);
    int bl = sqlite3_column_bytes(st, 0);
    int64_t exp = sqlite3_column_int64(st, 1);
    int64_t now = now_unix(pdb->db);
    if (!b || bl <= 0 || exp < now) { sqlite3_finalize(st); return -1; }
    uint8_t *cpy = (uint8_t*)malloc((size_t)bl);
    if (!cpy) { sqlite3_finalize(st); return -1; }
    memcpy(cpy, b, (size_t)bl);
    sqlite3_finalize(st);
    *blob_out = cpy;
    *blob_len_out = (uint32_t)bl;
    return 0;
}
