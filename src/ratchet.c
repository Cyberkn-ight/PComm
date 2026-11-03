#include "ratchet.h"
#include "ratchet_crypto.h"
#include "crypto.h"
#include "identity.h"
#include "mailbox_limits.h"
#include "msg.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum { OFFER = 1, RESPONSE, CONFIRM, DATA, ACK };
enum { OFFERED = 1, PREPARED, ACTIVE };
enum { HEADER_LEN = 87, RETRY_SECONDS = 5, MAX_PLAIN = 2800 };
static const uint8_t magic[4] = {'P','C','R','3'};

typedef struct {
    char peer[96], context[64];
    uint8_t sid[16], local[32], remote[32], initial[32], private_key[32];
    uint8_t root[32], sending[32], receiving[32];
    int state, initiator;
    int64_t ns, nr;
    uint8_t *response;
    size_t response_len;
} session_t;

typedef struct {
    unsigned kind;
    const uint8_t *sender, *recipient, *sid, *body;
    char context[64];
    size_t header_len, body_len;
} frame_t;

static void put_u64(uint8_t out[8], uint64_t n) {
    for (unsigned i = 0; i < 8; i++) out[7-i] = (uint8_t)(n >> (8*i));
}
static uint64_t get_u64(const uint8_t in[8]) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++) n = (n << 8) | in[i];
    return n;
}
static int prepare(sqlite3 *db, const char *sql, sqlite3_stmt **st) {
    return sqlite3_prepare_v2(db, sql, -1, st, NULL) == SQLITE_OK ? 0 : -1;
}
static int finish(sqlite3_stmt *st) {
    int rc = sqlite3_step(st);
    int done = sqlite3_finalize(st);
    return rc == SQLITE_DONE && done == SQLITE_OK ? 0 : -1;
}
static int bind_conversation(sqlite3_stmt *st, const char *peer, const char *context) {
    int rc = sqlite3_bind_text(st, 1, peer, -1, SQLITE_TRANSIENT);
    return rc == SQLITE_OK ? sqlite3_bind_text(st, 2, context, -1, SQLITE_TRANSIENT) : rc;
}

#define BIND(call) do { if ((call) != SQLITE_OK) { sqlite3_finalize(st); return -1; } } while (0)
static int valid_context(const char *context) {
    return context && strlen(context) < 64;
}

static int canonical_public(const uint8_t key[32]) {
    static const uint8_t prime[32] = {
        0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f
    };
    for (int i = 31; i >= 0; i--) {
        if (key[i] < prime[i]) return 1;
        if (key[i] > prime[i]) return 0;
    }
    return 0;
}
static int peer_identity(const char *peer, char canonical[96], uint8_t public_key[32]) {
    return peer && pcomm_pubkey_from_user_id(peer, public_key) == 0 &&
        canonical_public(public_key) && pcomm_user_id_from_pubkey(public_key, canonical) == 0 ? 0 : -1;
}
static void clear_session(session_t *s) {
    free(s->response);
    OPENSSL_cleanse(s, sizeof(*s));
}
static int blob(sqlite3_stmt *st, int column, uint8_t *out, int len) {
    if (sqlite3_column_type(st, column) != SQLITE_BLOB || sqlite3_column_bytes(st, column) != len) return -1;
    const void *source = sqlite3_column_blob(st, column);
    if (!source) return -1;
    memcpy(out, source, (size_t)len);
    return 0;
}
static int load_session(sqlite3 *db, const char *peer, const char *context, session_t *s) {
    sqlite3_stmt *st = NULL;
    memset(s, 0, sizeof(*s));
    if (prepare(db, "SELECT sid,state,initiator,local_pub,peer_pub,init_eph,private_eph,"
                    "response,root_key,send_chain,recv_chain,send_n,recv_n FROM ratchet_sessions "
                    "WHERE peer=? AND context=?", &st) != 0) return -1;
    BIND(bind_conversation(st, peer, context));
    int step = sqlite3_step(st), rc = -1;
    if (step == SQLITE_DONE) { rc = 0; goto done; }
    if (step != SQLITE_ROW) goto done;
    s->state = sqlite3_column_int(st, 1);
    s->initiator = sqlite3_column_int(st, 2);
    s->ns = sqlite3_column_int64(st, 11);
    s->nr = sqlite3_column_int64(st, 12);
    if (blob(st, 0, s->sid, 16) || blob(st, 3, s->local, 32) ||
        blob(st, 4, s->remote, 32) || blob(st, 5, s->initial, 32) ||
        s->state < OFFERED || s->state > ACTIVE || s->ns < 0 || s->nr < 0 ||
        (s->initiator != 0 && s->initiator != 1)) goto done;
    if (s->state == OFFERED) {
        if (!s->initiator || blob(st, 6, s->private_key, 32)) goto done;
    } else if (blob(st, 8, s->root, 32) || blob(st, 9, s->sending, 32) ||
               blob(st, 10, s->receiving, 32) || sqlite3_column_type(st, 6) != SQLITE_NULL) goto done;
    if (sqlite3_column_type(st, 7) != SQLITE_NULL) {
        int n = sqlite3_column_bytes(st, 7);
        const void *source = sqlite3_column_blob(st, 7);
        if (n <= 0 || n > (int)PCOMM_MAILBOX_MAX_BLOB_LEN || !source) goto done;
        s->response = malloc((size_t)n);
        if (!s->response) goto done;
        memcpy(s->response, source, (size_t)n);
        s->response_len = (size_t)n;
    }
    memcpy(s->peer, peer, strlen(peer) + 1);
    memcpy(s->context, context, strlen(context) + 1);
    rc = 1;
done:
    if (sqlite3_finalize(st) != SQLITE_OK) rc = -1;
    if (rc < 0) clear_session(s);
    return rc;
}
static int save_session(sqlite3 *db, const session_t *s) {
    sqlite3_stmt *st = NULL;
    if (prepare(db, "INSERT INTO ratchet_sessions(peer,context,sid,state,initiator,local_pub,"
                    "peer_pub,init_eph,private_eph,response,root_key,send_chain,recv_chain,send_n,recv_n)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(peer,context) DO UPDATE SET "
                    "sid=excluded.sid,state=excluded.state,initiator=excluded.initiator,"
                    "local_pub=excluded.local_pub,peer_pub=excluded.peer_pub,init_eph=excluded.init_eph,"
                    "private_eph=excluded.private_eph,response=excluded.response,root_key=excluded.root_key,"
                    "send_chain=excluded.send_chain,recv_chain=excluded.recv_chain,"
                    "send_n=excluded.send_n,recv_n=excluded.recv_n", &st)) return -1;
    BIND(bind_conversation(st, s->peer, s->context));
    BIND(sqlite3_bind_blob(st, 3, s->sid, 16, SQLITE_TRANSIENT));
    BIND(sqlite3_bind_int(st, 4, s->state));
    BIND(sqlite3_bind_int(st, 5, s->initiator));
    BIND(sqlite3_bind_blob(st, 6, s->local, 32, SQLITE_TRANSIENT));
    BIND(sqlite3_bind_blob(st, 7, s->remote, 32, SQLITE_TRANSIENT));
    BIND(sqlite3_bind_blob(st, 8, s->initial, 32, SQLITE_TRANSIENT));
    if (s->state == OFFERED) BIND(sqlite3_bind_blob(st, 9, s->private_key, 32, SQLITE_TRANSIENT));
    if (s->response) BIND(sqlite3_bind_blob(st, 10, s->response, (int)s->response_len, SQLITE_TRANSIENT));
    if (s->state != OFFERED) {
        BIND(sqlite3_bind_blob(st, 11, s->root, 32, SQLITE_TRANSIENT));
        BIND(sqlite3_bind_blob(st, 12, s->sending, 32, SQLITE_TRANSIENT));
        BIND(sqlite3_bind_blob(st, 13, s->receiving, 32, SQLITE_TRANSIENT));
    }
    BIND(sqlite3_bind_int64(st, 14, s->ns));
    BIND(sqlite3_bind_int64(st, 15, s->nr));
    return finish(st);
}
static int count_rows(sqlite3 *db, const char *sql, const session_t *s, int64_t *count) {
    sqlite3_stmt *st = NULL;
    if (prepare(db, sql, &st)) return -1;
    if (s) BIND(bind_conversation(st, s->peer, s->context));
    int rc = sqlite3_step(st) == SQLITE_ROW ? 0 : -1;
    if (!rc) *count = sqlite3_column_int64(st, 0);
    if (sqlite3_finalize(st) != SQLITE_OK) rc = -1;
    return rc;
}
int pcomm_ratchet_is_packet(const uint8_t *plain, size_t len) {
    return plain && len >= sizeof(magic) && memcmp(plain, magic, sizeof(magic)) == 0;
}
static int parse_frame(const uint8_t *p, size_t len, frame_t *f) {
    if (!pcomm_ratchet_is_packet(p, len) || len < HEADER_LEN || p[4] != 1 ||
        p[5] < OFFER || p[5] > ACK || p[86] > 63 || len < HEADER_LEN + (size_t)p[86]) return -1;
    memset(f, 0, sizeof(*f));
    f->kind = p[5]; f->sender = p+6; f->recipient = p+38; f->sid = p+70;
    f->header_len = HEADER_LEN + p[86];
    memcpy(f->context, p+HEADER_LEN, p[86]);
    if (memchr(f->context, 0, p[86])) return -1;
    f->body = p + f->header_len; f->body_len = len - f->header_len;
    return canonical_public(f->sender) && canonical_public(f->recipient) ? 0 : -1;
}
static size_t header(uint8_t *p, unsigned kind, const session_t *s) {
    size_t n = strlen(s->context);
    memcpy(p, magic, 4); p[4] = 1; p[5] = (uint8_t)kind;
    memcpy(p+6, s->local, 32); memcpy(p+38, s->remote, 32); memcpy(p+70, s->sid, 16);
    p[86] = (uint8_t)n; memcpy(p+HEADER_LEN, s->context, n);
    return HEADER_LEN + n;
}
static int identity_mac(const pcomm_identity_t *me, const uint8_t peer[32],
                         const uint8_t *data, size_t len, uint8_t out[32]) {
    uint8_t shared[32] = {0}, key[32] = {0};
    const uint8_t info[] = "pcomm-ratchet-auth-v1";
    int rc = pcomm_x25519_derive(me->privkey, peer, shared);
    if (!rc) rc = pcomm_hkdf_sha256(shared, 32, NULL, 0, info, sizeof(info)-1, key, 32);
    if (!rc) rc = pcomm_ratchet_mac(key, data, len, out);
    OPENSSL_cleanse(shared, sizeof(shared)); OPENSSL_cleanse(key, sizeof(key));
    return rc;
}
static int queue_wire(sqlite3 *db, const session_t *s, unsigned kind, int64_t n,
                       const uint8_t *wire, size_t len, const uint8_t *digest) {
    int64_t count;
    if (!wire || !len || len > PCOMM_MAILBOX_MAX_BLOB_LEN ||
        count_rows(db, "SELECT count(*) FROM ratchet_outbox", NULL, &count)) return -1;
    sqlite3_stmt *st = NULL;
    if (count >= PCOMM_RATCHET_MAX_OUTBOX) {

        if (prepare(db, "UPDATE ratchet_outbox SET next_attempt=0 WHERE sid=? AND kind=? AND n=?", &st)) return -1;
        BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT));
        BIND(sqlite3_bind_int(st, 2, (int)kind)); BIND(sqlite3_bind_int64(st, 3, n));
        if (finish(st)) return -1;
        return sqlite3_changes(db) == 1 ? 0 : -1;
    }
    if (prepare(db, "INSERT INTO ratchet_outbox(peer,context,sid,kind,n,wire,digest,next_attempt)"
                    " VALUES(?,?,?,?,?,?,?,0) ON CONFLICT(sid,kind,n) DO UPDATE SET next_attempt=0", &st)) return -1;
    BIND(bind_conversation(st, s->peer, s->context));
    BIND(sqlite3_bind_blob(st, 3, s->sid, 16, SQLITE_TRANSIENT));
    BIND(sqlite3_bind_int(st, 4, (int)kind)); BIND(sqlite3_bind_int64(st, 5, n));
    BIND(sqlite3_bind_blob(st, 6, wire, (int)len, SQLITE_TRANSIENT));
    if (digest) BIND(sqlite3_bind_blob(st, 7, digest, 32, SQLITE_TRANSIENT));
    return finish(st);
}
static int seal_packet(const session_t *s, const uint8_t *packet, size_t len,
                        uint8_t **out, size_t *out_len) {
    if (len > PCOMM_MAILBOX_MAX_BLOB_LEN - 60) return -1;
    return pcomm_seal_for_recipient(s->remote, packet, len, out, out_len);
}
static int queue_packet(sqlite3 *db, const session_t *s, unsigned kind, int64_t n,
                         const uint8_t *packet, size_t len, const uint8_t *digest) {
    uint8_t *wire = NULL; size_t wire_len = 0;
    int rc = seal_packet(s, packet, len, &wire, &wire_len);
    if (!rc) rc = queue_wire(db, s, kind, n, wire, wire_len, digest);
    free(wire);
    return rc;
}
static int delete_outbox_kind(sqlite3 *db, const session_t *s, unsigned kind) {
    sqlite3_stmt *st = NULL;
    if (prepare(db, "DELETE FROM ratchet_outbox WHERE sid=? AND kind=?", &st)) return -1;
    BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT)); BIND(sqlite3_bind_int(st, 2, (int)kind));
    return finish(st);
}
static int queue_control(sqlite3 *db, const session_t *s, unsigned kind, int64_t n,
                          const uint8_t *digest) {
    uint8_t packet[HEADER_LEN+63+8+32+32];
    size_t len = header(packet, kind, s);
    if (kind == ACK) {
        put_u64(packet+len, (uint64_t)n); len += 8;
        memcpy(packet+len, digest, 32); len += 32;
    }
    if (pcomm_ratchet_mac(s->root, packet, len, packet+len)) return -1;
    return queue_packet(db, s, kind, n, packet, len+32, NULL);
}

static int queue_data(sqlite3 *db, session_t *s, const uint8_t *plain, size_t plain_len) {
    if (s->ns == INT64_MAX) return -1;
    sqlite3_stmt *st = NULL;
    if (prepare(db, "SELECT min(n) FROM ratchet_outbox WHERE sid=? AND kind=4", &st)) return -1;
    BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT));
    int rc = sqlite3_step(st) == SQLITE_ROW ? 0 : -1;
    if (!rc && sqlite3_column_type(st, 0) != SQLITE_NULL &&
        s->ns - sqlite3_column_int64(st, 0) >= PCOMM_RATCHET_MAX_SKIP) rc = 1;
    if (sqlite3_finalize(st) != SQLITE_OK) rc = -1;
    if (rc) return rc;

    uint8_t packet[PCOMM_MAILBOX_MAX_BLOB_LEN], next[32] = {0}, key[32] = {0}, digest[32];
    size_t h = header(packet, DATA, s);
    put_u64(packet+h, (uint64_t)s->ns); h += 8;
    if (plain_len > MAX_PLAIN || h+12+plain_len+16+60 > PCOMM_MAILBOX_MAX_BLOB_LEN) return -1;
    if (pcomm_random(packet+h, 12)) return -1;
    h += 12;
    size_t ct_len = sizeof(packet) - h;
    rc = pcomm_ratchet_chain_step(s->sending, next, key);
    if (!rc) rc = pcomm_aead_encrypt(key, packet+h-12, packet, h, plain, plain_len, packet+h, &ct_len);
    if (!rc && !SHA256(packet, h+ct_len, digest)) rc = -1;
    if (!rc) rc = queue_packet(db, s, DATA, s->ns, packet, h+ct_len, digest);
    if (!rc) { memcpy(s->sending, next, 32); s->ns++; }
    OPENSSL_cleanse(next, sizeof(next)); OPENSSL_cleanse(key, sizeof(key));
    return rc;
}
static int drain_pending(sqlite3 *db, session_t *s) {
    if (s->state != ACTIVE) return 0;
    for (;;) {
        sqlite3_stmt *st = NULL;
        if (prepare(db, "SELECT id,plain FROM ratchet_pending WHERE peer=? AND context=? ORDER BY id LIMIT 1", &st)) return -1;
        BIND(bind_conversation(st, s->peer, s->context));
        int step = sqlite3_step(st);
        if (step == SQLITE_DONE) return sqlite3_finalize(st) == SQLITE_OK ? 0 : -1;
        if (step != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
        int64_t id = sqlite3_column_int64(st, 0);
        int len = sqlite3_column_bytes(st, 1);
        const void *source = sqlite3_column_blob(st, 1);
        if (len <= 0 || len > MAX_PLAIN || !source) { sqlite3_finalize(st); return -1; }
        uint8_t *plain = malloc((size_t)len);
        if (!plain) { sqlite3_finalize(st); return -1; }
        memcpy(plain, source, (size_t)len);
        int rc = sqlite3_finalize(st) == SQLITE_OK ? queue_data(db, s, plain, (size_t)len) : -1;
        OPENSSL_cleanse(plain, (size_t)len); free(plain);
        if (rc) return rc == 1 ? 0 : -1;
        if (prepare(db, "DELETE FROM ratchet_pending WHERE id=?", &st)) return -1;
        BIND(sqlite3_bind_int64(st, 1, id));
        if (finish(st)) return -1;
    }
}
static int begin_offer(sqlite3 *db, const pcomm_identity_t *me, session_t *s) {
    uint8_t packet[HEADER_LEN+63+32+32];
    if (pcomm_random(s->sid, 16) || pcomm_ratchet_keygen(s->private_key, s->initial)) return -1;
    s->state = OFFERED; s->initiator = 1;
    size_t len = header(packet, OFFER, s);
    memcpy(packet+len, s->initial, 32); len += 32;
    if (identity_mac(me, s->remote, packet, len, packet+len)) return -1;
    return queue_packet(db, s, OFFER, -1, packet, len+32, NULL);
}
static int initialize_chains(session_t *s, const uint8_t shared[32], const uint8_t *transcript, size_t len) {
    uint8_t initiator[32] = {0}, responder[32] = {0};
    int rc = pcomm_ratchet_derive(shared, transcript, len, s->root, initiator, responder);
    if (!rc) {
        memcpy(s->sending, s->initiator ? initiator : responder, 32);
        memcpy(s->receiving, s->initiator ? responder : initiator, 32);
        OPENSSL_cleanse(s->private_key, 32);
        s->ns = s->nr = 0;
    }
    OPENSSL_cleanse(initiator, 32); OPENSSL_cleanse(responder, 32);
    return rc;
}
static int create_response(sqlite3 *db, const pcomm_identity_t *me, session_t *s) {
    uint8_t private_key[32] = {0}, public_key[32], shared[32] = {0};
    uint8_t packet[HEADER_LEN+63+64+32];
    size_t len = header(packet, RESPONSE, s);
    int rc = pcomm_ratchet_keygen(private_key, public_key);
    if (!rc) rc = pcomm_x25519_derive(private_key, s->initial, shared);
    if (!rc) {
        memcpy(packet+len, s->initial, 32); len += 32;
        memcpy(packet+len, public_key, 32); len += 32;
        rc = identity_mac(me, s->remote, packet, len, packet+len);
    }
    if (!rc) rc = initialize_chains(s, shared, packet, len);
    if (!rc) rc = seal_packet(s, packet, len+32, &s->response, &s->response_len);
    if (!rc) rc = queue_wire(db, s, RESPONSE, -1, s->response, s->response_len, NULL);
    OPENSSL_cleanse(private_key, 32); OPENSSL_cleanse(shared, 32);
    return rc;
}
static int validate_application(const pcomm_identity_t *me, const char *context,
                                  const uint8_t *plain, size_t len, char **direct_text,
                                  uint32_t *timestamp) {
    pcomm_plain_kind_t kind;
    char sender[96], group[64], *title = NULL, **members = NULL, *text = NULL;
    int member_count = 0, rc = -1;
    uint8_t sender_key[32];
    if (pcomm_msg_unpack_any(plain, len, &kind, timestamp, sender, sizeof(sender), group,
                             sizeof(group), &title, &members, &member_count, &text) == 0 &&
        pcomm_pubkey_from_user_id(sender, sender_key) == 0 &&
        CRYPTO_memcmp(sender_key, me->pubkey, 32) == 0 &&
        ((kind == PCOMM_PLAIN_DIRECT_TEXT && !*context) ||
         ((kind == PCOMM_PLAIN_GROUP_INVITE || kind == PCOMM_PLAIN_GROUP_TEXT) &&
          *context && strcmp(group, context) == 0))) {
        rc = 0;
        if (kind == PCOMM_PLAIN_DIRECT_TEXT) { *direct_text = text; text = NULL; }
    }
    free(title); free(text); pcomm_msg_free_members(members, member_count);
    return rc;
}
typedef struct {
    pcomm_db_t *db;
    const pcomm_identity_t *me;
    session_t session;
    const uint8_t *plain;
    size_t plain_len;
    const char *direct_text;
    uint32_t timestamp;
} send_operation_t;
static int send_operation(void *arg) {
    send_operation_t *op = arg;
    session_t loaded;
    session_t *s = &op->session;
    sqlite3 *db = op->db->db;
    int found = load_session(db, s->peer, s->context, &loaded), rc = -1;
    if (found < 0) return -1;
    if (found) {
        if (CRYPTO_memcmp(loaded.local, op->me->pubkey, 32)) { clear_session(&loaded); return -1; }
        *s = loaded;
        OPENSSL_cleanse(&loaded, sizeof(loaded));
    } else {
        int64_t count;
        if (count_rows(db, "SELECT count(*) FROM ratchet_sessions", NULL, &count) ||
            count >= PCOMM_RATCHET_MAX_SESSIONS || begin_offer(db, op->me, s)) goto done;
    }
    int64_t count;
    if (count_rows(db, "SELECT count(*) FROM ratchet_pending WHERE peer=? AND context=?", s, &count) ||
        count >= PCOMM_RATCHET_MAX_PENDING ||
        count_rows(db, "SELECT count(*) FROM ratchet_pending", NULL, &count) || count >= 1024) goto done;
    sqlite3_stmt *st = NULL;
    if (prepare(db, "INSERT INTO ratchet_pending(peer,context,plain) VALUES(?,?,?)", &st)) goto done;
    BIND(bind_conversation(st, s->peer, s->context));
    BIND(sqlite3_bind_blob(st, 3, op->plain, (int)op->plain_len, SQLITE_TRANSIENT));
    if (finish(st) || drain_pending(db, s) || save_session(db, s)) goto done;
    if (op->direct_text) {
        int64_t conversation = pcomm_db_get_or_create_direct_conv(op->db, s->peer);
        if (conversation < 0 || pcomm_db_insert_message(op->db, conversation, 1, s->peer,
                op->me->user_id, op->direct_text, (const uint8_t *)"", 0, op->timestamp)) goto done;
    }
    rc = 0;
done:
    return rc;
}
int pcomm_ratchet_send(pcomm_db_t *db, const pcomm_identity_t *me, const char *peer,
                       const char *context, const uint8_t *plain, size_t plain_len) {
    if (!db || !db->db || !me || !valid_context(context) || !plain || !plain_len ||
        plain_len > MAX_PLAIN || !canonical_public(me->pubkey)) return -1;
    send_operation_t op = {0};
    op.db = db; op.me = me; op.plain = plain; op.plain_len = plain_len;
    if (peer_identity(peer, op.session.peer, op.session.remote) ||
        CRYPTO_memcmp(op.session.remote, me->pubkey, 32) == 0) return -1;
    memcpy(op.session.local, me->pubkey, 32);
    memcpy(op.session.context, context, strlen(context)+1);

    if (HEADER_LEN+strlen(context)+8+12+plain_len+16+60 > PCOMM_MAILBOX_MAX_BLOB_LEN) return -1;
    char *text = NULL;
    if (validate_application(me, context, plain, plain_len, &text, &op.timestamp)) return -1;
    op.direct_text = text;
    int rc = pcomm_db_transaction(db, send_operation, &op);
    if (text) OPENSSL_cleanse(text, strlen(text));
    free(text); clear_session(&op.session);
    return rc;
}
int pcomm_ratchet_has_session(pcomm_db_t *db, const pcomm_identity_t *me,
                              const char *peer, const char *context) {
    if (!db || !db->db || !me || !valid_context(context)) return -1;
    char canonical[96]; uint8_t key[32];
    if (peer_identity(peer, canonical, key)) return -1;
    sqlite3_mutex *mutex = sqlite3_db_mutex(db->db);
    if (!mutex) return -1;
    sqlite3_mutex_enter(mutex);
    session_t s;
    int rc = load_session(db->db, canonical, context, &s);
    if (rc == 1 && CRYPTO_memcmp(s.local, me->pubkey, 32)) rc = -1;
    clear_session(&s);
    sqlite3_mutex_leave(mutex);
    return rc;
}

typedef struct {
    pcomm_db_t *db;
    const pcomm_identity_t *me;
    const uint8_t *packet;
    size_t packet_len;
    frame_t frame;
    pcomm_ratchet_store_fn store;
    void *arg;
    int result;
} receive_operation_t;

static int accept_offer(receive_operation_t *op, session_t *s, int found) {
    frame_t *f = &op->frame;
    sqlite3 *db = op->db->db;
    if (f->body_len != 64 || !canonical_public(f->body)) return -1;
    if (found && s->state != OFFERED) {
        if (CRYPTO_memcmp(s->sid, f->sid, 16) || s->initiator ||
            CRYPTO_memcmp(s->initial, f->body, 32) || !s->response) return -1;
        return queue_wire(db, s, RESPONSE, -1, s->response, s->response_len, NULL);
    }
    if (found && memcmp(s->local, s->remote, 32) < 0) {

        return 0;
    }
    if (!found) {
        int64_t count;
        if (count_rows(db, "SELECT count(*) FROM ratchet_sessions", NULL, &count) ||
            count >= PCOMM_RATCHET_MAX_SESSIONS) return -1;
    } else if (delete_outbox_kind(db, s, OFFER)) return -1;
    OPENSSL_cleanse(s->private_key, 32);
    memcpy(s->sid, f->sid, 16); memcpy(s->initial, f->body, 32);
    s->state = PREPARED; s->initiator = 0;
    return create_response(db, op->me, s);
}
static int accept_response(receive_operation_t *op, session_t *s) {
    frame_t *f = &op->frame;
    if (!s->initiator || f->body_len != 96 || CRYPTO_memcmp(s->initial, f->body, 32) ||
        !canonical_public(f->body+32)) return -1;
    if (s->state == OFFERED) {
        uint8_t shared[32] = {0};
        int rc = pcomm_x25519_derive(s->private_key, f->body+32, shared);
        if (!rc) rc = initialize_chains(s, shared, op->packet, op->packet_len-32);
        OPENSSL_cleanse(shared, 32);
        if (rc) return -1;
        s->state = ACTIVE;
        if (delete_outbox_kind(op->db->db, s, OFFER)) return -1;
    }
    return queue_control(op->db->db, s, CONFIRM, -1, NULL);
}
static int lookup_received(sqlite3 *db, const session_t *s, int64_t n, const uint8_t digest[32]) {
    sqlite3_stmt *st = NULL;
    if (prepare(db, "SELECT digest FROM ratchet_received WHERE sid=? AND n=?", &st)) return -1;
    BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT)); BIND(sqlite3_bind_int64(st, 2, n));
    int step = sqlite3_step(st), rc = -1;
    uint8_t stored[32];
    if (step == SQLITE_DONE) rc = 0;
    else if (step == SQLITE_ROW && !blob(st, 0, stored, 32) && !CRYPTO_memcmp(digest, stored, 32)) rc = 1;
    if (sqlite3_finalize(st) != SQLITE_OK) rc = -1;
    return rc;
}
static int insert_key(sqlite3 *db, const session_t *s, int64_t n, const uint8_t key[32]) {
    sqlite3_stmt *st = NULL;
    if (prepare(db, "INSERT INTO ratchet_skipped(sid,n,key) VALUES(?,?,?)", &st)) return -1;
    BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT)); BIND(sqlite3_bind_int64(st, 2, n));
    BIND(sqlite3_bind_blob(st, 3, key, 32, SQLITE_TRANSIENT));
    return finish(st);
}
static int receive_key(sqlite3 *db, session_t *s, int64_t n, uint8_t key[32], int *skipped) {
    sqlite3_stmt *st = NULL;
    *skipped = n < s->nr;
    if (*skipped) {
        if (prepare(db, "SELECT key FROM ratchet_skipped WHERE sid=? AND n=?", &st)) return -1;
        BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT)); BIND(sqlite3_bind_int64(st, 2, n));
        int rc = sqlite3_step(st) == SQLITE_ROW ? blob(st, 0, key, 32) : -1;
        if (sqlite3_finalize(st) != SQLITE_OK) rc = -1;
        return rc;
    }
    uint64_t gap = (uint64_t)(n - s->nr);
    if (gap > PCOMM_RATCHET_MAX_SKIP) return -1;
    if (prepare(db, "SELECT count(*) FROM ratchet_skipped WHERE sid=?", &st)) return -1;
    BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT));
    int rc = sqlite3_step(st) == SQLITE_ROW ? 0 : -1;
    if (!rc && (uint64_t)sqlite3_column_int64(st, 0)+gap > PCOMM_RATCHET_MAX_SKIP) rc = -1;
    if (sqlite3_finalize(st) != SQLITE_OK) rc = -1;
    if (rc) return -1;
    while (s->nr <= n) {
        uint8_t next[32] = {0};
        rc = pcomm_ratchet_chain_step(s->receiving, next, key);
        if (!rc && s->nr < n) rc = insert_key(db, s, s->nr, key);
        if (!rc) { memcpy(s->receiving, next, 32); s->nr++; }
        OPENSSL_cleanse(next, 32);
        if (rc) return -1;
    }
    return 0;
}
static int confirm_session(sqlite3 *db, session_t *s) {
    if (s->state == PREPARED) {
        s->state = ACTIVE;
    }

    if (!s->initiator && delete_outbox_kind(db, s, RESPONSE)) return -1;
    return 0;
}
static int accept_data(receive_operation_t *op, session_t *s) {
    frame_t *f = &op->frame;
    if (s->state == OFFERED || f->body_len < 8+12+16 || !op->store) return -1;
    uint64_t number = get_u64(f->body);
    if (number >= INT64_MAX) return -1;
    int64_t n = (int64_t)number;
    uint8_t digest[32], key[32] = {0};
    if (!SHA256(op->packet, op->packet_len, digest)) return -1;
    int found = lookup_received(op->db->db, s, n, digest);
    if (found < 0) return -1;
    if (found) {
        op->result = 1;
        return queue_control(op->db->db, s, ACK, n, digest) || confirm_session(op->db->db, s) ? -1 : 0;
    }
    if (n < s->nr && s->nr-n > PCOMM_RATCHET_MAX_SKIP) {

        op->result = 1;
        return 0;
    }
    int skipped = 0, rc = receive_key(op->db->db, s, n, key, &skipped);
    size_t plain_len = f->body_len-20;
    uint8_t *plain = malloc(plain_len);
    if (!plain) rc = -1;
    if (!rc) rc = pcomm_aead_decrypt(key, f->body+8, op->packet, f->header_len+20,
                                    f->body+20, f->body_len-20, plain, &plain_len);
    OPENSSL_cleanse(key, 32);
    if (!rc) rc = op->store(op->arg, s->peer, s->context, plain, plain_len);
    if (plain) OPENSSL_cleanse(plain, plain_len);
    free(plain);
    if (rc) return -1;

    sqlite3_stmt *st = NULL;
    if (skipped) {
        if (prepare(op->db->db, "DELETE FROM ratchet_skipped WHERE sid=? AND n=?", &st)) return -1;
        BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT)); BIND(sqlite3_bind_int64(st, 2, n));
        if (finish(st)) return -1;
    }
    if (prepare(op->db->db, "INSERT INTO ratchet_received(sid,n,digest) VALUES(?,?,?)", &st)) return -1;
    BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT)); BIND(sqlite3_bind_int64(st, 2, n));
    BIND(sqlite3_bind_blob(st, 3, digest, 32, SQLITE_TRANSIENT));
    if (finish(st) || queue_control(op->db->db, s, ACK, n, digest) || confirm_session(op->db->db, s)) return -1;
    if (prepare(op->db->db, "DELETE FROM ratchet_received WHERE sid=? AND n<?", &st)) return -1;
    BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT));
    BIND(sqlite3_bind_int64(st, 2, s->nr > PCOMM_RATCHET_MAX_SKIP ? s->nr-PCOMM_RATCHET_MAX_SKIP : 0));
    if (finish(st)) return -1;
    return 0;
}
static int accept_ack(receive_operation_t *op, session_t *s) {
    frame_t *f = &op->frame;
    if (f->body_len != 72) return -1;
    uint64_t number = get_u64(f->body);
    if (number >= (uint64_t)s->ns) return -1;
    sqlite3_stmt *st = NULL;
    if (prepare(op->db->db, "DELETE FROM ratchet_outbox WHERE sid=? AND kind=4 AND n=? AND digest=?", &st)) return -1;
    BIND(sqlite3_bind_blob(st, 1, s->sid, 16, SQLITE_TRANSIENT));
    BIND(sqlite3_bind_int64(st, 2, (int64_t)number));
    BIND(sqlite3_bind_blob(st, 3, f->body+8, 32, SQLITE_TRANSIENT));
    return finish(st);
}
static int receive_operation(void *arg) {
    receive_operation_t *op = arg;
    frame_t *f = &op->frame;
    session_t s = {0};
    char peer[96];
    if (pcomm_user_id_from_pubkey(f->sender, peer)) return -1;
    int found = load_session(op->db->db, peer, f->context, &s), rc = -1;
    if (found < 0) return -1;
    if (!found) {
        memcpy(s.peer, peer, strlen(peer)+1); memcpy(s.context, f->context, strlen(f->context)+1);
        memcpy(s.local, op->me->pubkey, 32); memcpy(s.remote, f->sender, 32);
    } else if (CRYPTO_memcmp(s.local, op->me->pubkey, 32) || CRYPTO_memcmp(s.remote, f->sender, 32)) goto done;

    uint8_t mac[32] = {0};
    if (f->kind == OFFER || f->kind == RESPONSE) {
        if (f->body_len < 32 || identity_mac(op->me, f->sender, op->packet, op->packet_len-32, mac) ||
            CRYPTO_memcmp(mac, op->packet+op->packet_len-32, 32)) goto done;
    }
    if (f->kind == OFFER) {
        rc = accept_offer(op, &s, found);
    } else {
        if (!found || CRYPTO_memcmp(s.sid, f->sid, 16)) goto done;
        if (f->kind == RESPONSE) rc = accept_response(op, &s);
        else if (f->kind == DATA) rc = accept_data(op, &s);
        else {
            if (s.state == OFFERED || f->body_len < 32 ||
                pcomm_ratchet_mac(s.root, op->packet, op->packet_len-32, mac) ||
                CRYPTO_memcmp(mac, op->packet+op->packet_len-32, 32)) goto done;
            if (f->kind == CONFIRM && f->body_len == 32) rc = confirm_session(op->db->db, &s);
            else if (f->kind == ACK) rc = accept_ack(op, &s);
        }
    }
    if (!rc && (drain_pending(op->db->db, &s) || save_session(op->db->db, &s))) rc = -1;
done:
    clear_session(&s);
    return rc;
}
int pcomm_ratchet_receive(pcomm_db_t *db, const pcomm_identity_t *me,
                          const uint8_t *packet, size_t packet_len,
                          pcomm_ratchet_store_fn store, void *arg) {
    if (!db || !db->db || !me || !packet || packet_len > PCOMM_MAILBOX_MAX_BLOB_LEN-60) return -1;
    receive_operation_t op = {0};
    op.db = db; op.me = me; op.packet = packet; op.packet_len = packet_len; op.store = store; op.arg = arg;
    if (parse_frame(packet, packet_len, &op.frame) ||
        CRYPTO_memcmp(op.frame.recipient, me->pubkey, 32) ||
        CRYPTO_memcmp(op.frame.sender, me->pubkey, 32) == 0) return -1;
    int rc = pcomm_db_transaction(db, receive_operation, &op);
    return rc ? -1 : op.result;
}

typedef struct {
    pcomm_db_t *db;
    int64_t now;
    pcomm_ratchet_outgoing_t *out;
    int found;
} outbox_operation_t;
static int outbox_operation(void *arg) {
    outbox_operation_t *op = arg;
    sqlite3_stmt *st = NULL;
    if (prepare(op->db->db, "SELECT id,peer,wire FROM ratchet_outbox WHERE next_attempt<=? OR next_attempt>? "
                            "ORDER BY next_attempt,id LIMIT 1", &st)) return -1;
    BIND(sqlite3_bind_int64(st, 1, op->now)); BIND(sqlite3_bind_int64(st, 2, op->now+60));
    int step = sqlite3_step(st);
    if (step == SQLITE_DONE) return sqlite3_finalize(st) == SQLITE_OK ? 0 : -1;
    if (step != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    int peer_len = sqlite3_column_bytes(st, 1), wire_len = sqlite3_column_bytes(st, 2);
    const void *peer = sqlite3_column_text(st, 1), *wire = sqlite3_column_blob(st, 2);
    if (peer_len <= 0 || peer_len >= 96 || wire_len <= 0 || wire_len > (int)PCOMM_MAILBOX_MAX_BLOB_LEN ||
        !peer || !wire || memchr(peer, 0, (size_t)peer_len)) {
        sqlite3_finalize(st); return -1;
    }
    op->out->id = sqlite3_column_int64(st, 0);
    memcpy(op->out->peer, peer, (size_t)peer_len);
    op->out->sealed = malloc((size_t)wire_len);
    if (!op->out->sealed) { sqlite3_finalize(st); return -1; }
    memcpy(op->out->sealed, wire, (size_t)wire_len);
    op->out->sealed_len = (size_t)wire_len;
    if (sqlite3_finalize(st) != SQLITE_OK) return -1;
    if (prepare(op->db->db, "UPDATE ratchet_outbox SET next_attempt=? WHERE id=?", &st)) return -1;
    BIND(sqlite3_bind_int64(st, 1, op->now+RETRY_SECONDS)); BIND(sqlite3_bind_int64(st, 2, op->out->id));
    if (finish(st)) return -1;
    op->found = 1;
    return 0;
}
int pcomm_ratchet_outbox_next(pcomm_db_t *db, int64_t now_unix, pcomm_ratchet_outgoing_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!db || !db->db || now_unix < 0 || now_unix > INT64_MAX-60) return -1;
    outbox_operation_t op = {db, now_unix, out, 0};
    if (pcomm_db_transaction(db, outbox_operation, &op)) { pcomm_ratchet_outgoing_free(out); return -1; }
    return op.found;
}
typedef struct { pcomm_db_t *db; int64_t id; } sent_operation_t;
static int sent_operation(void *arg) {
    sent_operation_t *op = arg;
    sqlite3_stmt *st = NULL;
    if (prepare(op->db->db, "DELETE FROM ratchet_outbox WHERE id=? AND kind IN (3,5)", &st)) return -1;
    BIND(sqlite3_bind_int64(st, 1, op->id));
    return finish(st);
}
int pcomm_ratchet_outbox_sent(pcomm_db_t *db, int64_t id, int transport_ok) {
    if (!db || !db->db || id <= 0) return -1;
    if (!transport_ok) return 0;
    sent_operation_t op = {db, id};
    return pcomm_db_transaction(db, sent_operation, &op);
}
void pcomm_ratchet_outgoing_free(pcomm_ratchet_outgoing_t *out) {
    if (!out) return;
    free(out->sealed);
    memset(out, 0, sizeof(*out));
}
