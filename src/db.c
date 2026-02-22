#include "db.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
//I fucking hate SQL whyyyyyy
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
        " type TEXT NOT NULL," // 'direct' or 'group'
        " title TEXT,"
        " created_at INTEGER NOT NULL"
        ");"
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
        " direction INTEGER NOT NULL," // 0=in, 1=out
        " peer_user_id TEXT NOT NULL," // other party for direct chats
        " sender_user_id TEXT NOT NULL,"
        " body TEXT NOT NULL,"
        " ciphertext BLOB NOT NULL,"
        " ts_unix INTEGER NOT NULL,"
        " status INTEGER NOT NULL DEFAULT 0,"
        " FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_messages_conv_ts ON messages(conversation_id, ts_unix);";

    return exec_sql(pdb->db, sql);
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
        "INSERT INTO conversations(type,title,created_at) VALUES('direct',NULL,?);",
        -1, &ins, NULL) != SQLITE_OK) {
        exec_sql(pdb->db, "ROLLBACK;");
        return -1;
    }
    sqlite3_bind_int64(ins, 1, now_unix(pdb->db));
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
