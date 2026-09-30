/**
 * Nodus Connect thin core — R0 fault matrix against a node over real
 * tier-2 (package NC-2; design rev 5 §1.4 R0 / R1, §2.1, §6.4 F1; thin-core
 * decision S3 + Q1 + the EXCLUSIVE profile-write decision).
 *
 * The REAL nodus client (compiled from the same sources as the wasm build)
 * talks to a fake node built the way nodus/tests/test_client_spend_status.c
 * builds its fake (nodus_tcp_t + nodus_t2_* encoders, plain auth_ok,
 * unencrypted session). The fake answers GET / GET_ALL with a reply chosen
 * per case and counts every PUT it receives.
 *
 * What it proves:
 *   F1  timeout (the node never answers)      -> UNREADABLE(timeout)
 *   F2  empty result                          -> EMPTY
 *   F3  a value with a broken DHT signature   -> UNREADABLE(bad_signature)
 *   F4  a value owned by another identity     -> UNREADABLE(wrong_owner)
 *   F5  a "val" that does not decode (F1)     -> UNREADABLE(undecodable)
 *   F6  a good own profile                    -> FOUND, record verified
 *   W1  profile update after F1/F3/F4/F5-type answers: status "wait" and
 *       the node received ZERO PUTs (UNREADABLE never leads to a write)
 *   W2  EMPTY for a restored identity (fresh = false): "wait", zero PUTs (Q1)
 *   W3  EMPTY for a fresh identity (fresh = true): one PUT, type EXCLUSIVE,
 *       ttl 0, value_id = nodus_identity_value_id; the record verifies and
 *       carries the edited field (created = true)
 *   W4  FOUND: one EXCLUSIVE PUT; the record keeps the fields it did not
 *       edit (bio from the node), version = node version + 1
 *   W5  the PUT answered NODUS_ERR_KEY_OWNED -> status "taken" (terminal)
 *   Q1  get_all of the request inbox whose only item does not decode ->
 *       UNREADABLE, never EMPTY
 *   L1  contact-list add after timeout / bad signature / undecodable: wait,
 *       zero PUTs (even for a fresh identity)
 *   L2  contact-list add, EMPTY, restored identity: wait, zero PUTs (Q1)
 *   L3  EMPTY, fresh: one PUT, EXCLUSIVE, ttl 0, own value_id; the bytes,
 *       served back, read as the own list (CLST blob, self-Seal, authorship)
 *   L4  FOUND: merge only — the stored entry keeps its position and salt
 *       (a different salt for it is counted, not written), the new entry
 *       is appended
 *   L5  FOUND already holding every entry: unchanged, zero PUTs
 *   L6  a list sealed by another identity under the own DHT owner:
 *       UNREADABLE(bad_record), zero PUTs
 *   L7  first list answered NODUS_ERR_KEY_OWNED -> taken
 *   S1  salt sync after a timeout: wait, zero PUTs
 *   S2  salt sync, EMPTY + a local salt, restored identity: wait, zero PUTs
 *   S3  salt sync, EMPTY and no local salt: nothing to write
 *   S4  salt sync, EMPTY + a local salt, fresh identity: one EPHEMERAL PUT,
 *       ttl SALT_AGREEMENT_TTL, own value_id, a v1 packet (PACKET_TOTAL_SIZE)
 *       whose signature verifies under the own key and whose peer entry the
 *       peer's round-3 key unwraps to the local salt
 *
 * What it requires: the native build of web-wallet/connect/tests; no
 * environment. Ports: the fake listens on 127.0.0.1:0 (kernel-chosen).
 * The client's request timeout is set to 1500 ms so F1 completes; that is
 * the case's input, not a tuned wait (every other case is answered).
 * What it leaves behind: nothing (fake thread joined, client closed).
 *
 * How it can lie:
 *   - A real node cannot be made to serve a bad signature or an
 *     undecodable value; the fake does, so F3/F5 prove the client-side
 *     classification only.
 *   - "Zero PUTs" is counted at the fake: a PUT the client failed to send
 *     would also count zero — W3/W4, L3/L4 and S4 show the same code paths
 *     do send.
 *   - L3/L4 read the PUT back with the same C that wrote it: they prove the
 *     core agrees with the codecs it compiles, not that the frozen app reads
 *     the list (NC-3's job against real app records).
 */

#include "nc_core.h"
#include "codec/salt_agreement_codec.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_value.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"

#include <json-c/json.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed, failed;
#define CHECK(cond, name) do {                                        \
    if (cond) { passed++; printf("  PASS %s\n", name); }              \
    else { failed++; printf("  FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

static const char *WORDS =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art";

typedef enum {
    M_TIMEOUT = 0, M_EMPTY, M_GOOD, M_BAD_SIG, M_WRONG_OWNER, M_UNDECODABLE,
    M_VALS_JUNK,
    M_PAYLOAD      /* g_fake.serve as an own EXCLUSIVE value ("val") */
} mode_t_;

typedef struct {
    nodus_tcp_t     *tcp;
    _Atomic int      mode;
    _Atomic int      put_reply;     /* 0 = ok, else an error code */
    _Atomic int      puts;
    _Atomic bool     stop;
    pthread_t        tid;
    uint8_t         *buf;
    /* last PUT */
    pthread_mutex_t  mu;
    int              put_type;
    uint32_t         put_ttl;
    uint64_t         put_vid;
    char            *put_data;
    size_t           put_len;
    /* M_PAYLOAD: the bytes served (set while the fake is idle) */
    uint8_t         *serve;
    size_t           serve_len;
} fake_t;

#define FAKE_BUF (1024 * 1024)
static fake_t g_fake;
static nc_keys_t *g_keys;
static nodus_identity_t *g_stranger;

static void resp_header(cbor_encoder_t *enc, uint32_t txn) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "t"); cbor_encode_uint(enc, txn);
    cbor_encode_cstr(enc, "y"); cbor_encode_cstr(enc, "r");
    cbor_encode_cstr(enc, "q"); cbor_encode_cstr(enc, "result");
}

/* A valid own profile record, bio "from-dht", version 5. */
static char *profile_json(void) {
    dna_unified_identity_t *id = dna_identity_create();
    if (!id) return NULL;
    memcpy(id->fingerprint, g_keys->fp, NC_FP_HEX_LEN);
    memcpy(id->dilithium_pubkey, g_keys->id.pk.bytes, sizeof(id->dilithium_pubkey));
    memcpy(id->kyber_pubkey, g_keys->kyber_pk, sizeof(id->kyber_pubkey));
    snprintf(id->bio, sizeof(id->bio), "from-dht");
    id->version = 5;
    id->timestamp = 1700000000ULL;
    char *u = dna_identity_to_json_unsigned(id);
    size_t sl = sizeof(id->signature);
    char *json = NULL;
    if (u && qgp_dsa87_sign(id->signature, &sl, (const uint8_t *)u, strlen(u),
                            g_keys->id.sk.bytes) == 0)
        json = dna_identity_to_json(id);
    free(u);
    dna_identity_free(id);
    return json;
}

static int value_bytes(const nodus_key_t *key, const nodus_identity_t *owner,
                       int corrupt, uint8_t **out, size_t *out_len) {
    char *json = NULL;
    const uint8_t *data;
    size_t data_len;
    if (atomic_load(&g_fake.mode) == M_PAYLOAD) {
        data = g_fake.serve;
        data_len = g_fake.serve_len;
    } else {
        json = profile_json();
        if (!json) return -1;
        data = (const uint8_t *)json;
        data_len = strlen(json);
    }
    nodus_value_t *v = NULL;
    int rc = nodus_value_create(key, data, data_len,
                                NODUS_VALUE_EXCLUSIVE, 0,
                                nodus_identity_value_id(owner), 1,
                                &owner->pk, &v);
    free(json);
    if (rc != 0 || nodus_value_sign(v, &owner->sk) != 0) {
        nodus_value_free(v);
        return -1;
    }
    if (corrupt) v->signature.bytes[5] ^= 0x01;
    rc = nodus_value_serialize(v, out, out_len);
    nodus_value_free(v);
    return rc;
}

static void send_get_reply(nodus_tcp_conn_t *conn, uint32_t txn,
                           const nodus_key_t *key) {
    int mode = atomic_load(&g_fake.mode);
    if (mode == M_TIMEOUT) return;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_fake.buf, FAKE_BUF);
    resp_header(&enc, txn);
    cbor_encode_cstr(&enc, "r");
    uint8_t *vb = NULL;
    size_t vl = 0;
    static const uint8_t junk[3] = { 1, 2, 3 };
    switch (mode) {
    case M_EMPTY:
        cbor_encode_map(&enc, 0);
        break;
    case M_GOOD:
    case M_PAYLOAD:
    case M_BAD_SIG:
    case M_WRONG_OWNER:
        if (value_bytes(key, mode == M_WRONG_OWNER ? g_stranger : &g_keys->id,
                        mode == M_BAD_SIG, &vb, &vl) != 0) return;
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "val");
        cbor_encode_bstr(&enc, vb, vl);
        free(vb);
        break;
    case M_UNDECODABLE:
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "val");
        cbor_encode_bstr(&enc, junk, sizeof(junk));
        break;
    case M_VALS_JUNK:
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "vals");
        cbor_encode_array(&enc, 1);
        cbor_encode_bstr(&enc, junk, sizeof(junk));
        break;
    default:
        return;
    }
    size_t len = cbor_encoder_len(&enc);
    if (len > 0 && !enc.error) nodus_tcp_send(conn, g_fake.buf, len);
}

static void on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                     size_t len, void *ctx) {
    (void)ctx;
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(payload, len, &msg) != 0) { nodus_t2_msg_free(&msg); return; }
    size_t out = 0;
    if (strcmp(msg.method, "hello") == 0) {
        uint8_t nonce[NODUS_NONCE_LEN];
        nodus_random(nonce, NODUS_NONCE_LEN);
        if (nodus_t2_challenge(msg.txn_id, nonce, g_fake.buf, FAKE_BUF, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    } else if (strcmp(msg.method, "auth") == 0) {
        uint8_t token[NODUS_SESSION_TOKEN_LEN];
        memset(token, 0x5a, sizeof(token));
        if (nodus_t2_auth_ok(msg.txn_id, token, g_fake.buf, FAKE_BUF, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    } else if (strcmp(msg.method, "get") == 0 || strcmp(msg.method, "get_all") == 0) {
        send_get_reply(conn, msg.txn_id, &msg.key);
    } else if (strcmp(msg.method, "put") == 0) {
        atomic_fetch_add(&g_fake.puts, 1);
        pthread_mutex_lock(&g_fake.mu);
        g_fake.put_type = (int)msg.val_type;
        g_fake.put_ttl = msg.ttl;
        g_fake.put_vid = msg.vid;
        free(g_fake.put_data);
        g_fake.put_data = malloc(msg.data_len + 1);
        g_fake.put_len = 0;
        if (g_fake.put_data) {
            memcpy(g_fake.put_data, msg.data, msg.data_len);
            g_fake.put_data[msg.data_len] = '\0';
            g_fake.put_len = msg.data_len;
        }
        pthread_mutex_unlock(&g_fake.mu);
        int err = atomic_load(&g_fake.put_reply);
        if (err ? nodus_t2_error(msg.txn_id, err, "owned", g_fake.buf, FAKE_BUF, &out) == 0
                : nodus_t2_put_ok(msg.txn_id, g_fake.buf, FAKE_BUF, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    }
    nodus_t2_msg_free(&msg);
}

static void *fake_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_fake.stop)) nodus_tcp_poll(g_fake.tcp, 20);
    return NULL;
}

static int fake_start(void) {
    memset(&g_fake, 0, sizeof(g_fake));
    pthread_mutex_init(&g_fake.mu, NULL);
    g_fake.tcp = calloc(1, sizeof(nodus_tcp_t));
    g_fake.buf = malloc(FAKE_BUF);
    if (!g_fake.tcp || !g_fake.buf) return -1;
    if (nodus_tcp_init(g_fake.tcp, -1) != 0) return -1;
    g_fake.tcp->on_frame = on_frame;
    if (nodus_tcp_listen(g_fake.tcp, "127.0.0.1", 0) != 0) return -1;
    return pthread_create(&g_fake.tid, NULL, fake_thread, NULL) == 0 ? 0 : -1;
}

static void fake_stop(void) {
    atomic_store(&g_fake.stop, true);
    pthread_join(g_fake.tid, NULL);
    nodus_tcp_close(g_fake.tcp);
    free(g_fake.tcp);
    free(g_fake.buf);
    free(g_fake.put_data);
    free(g_fake.serve);
    pthread_mutex_destroy(&g_fake.mu);
}

static void read_case(const nc_ctx_t *ctx, int mode, nc_outcome_t want,
                      nc_why_t why, const char *name) {
    atomic_store(&g_fake.mode, mode);
    nc_read_t raw;
    dna_unified_identity_t *id = NULL;
    nc_profile_read(ctx, g_keys->fp, &raw, &id, NULL);
    CHECK(raw.outcome == want && (want != NC_UNREADABLE || raw.why == why) &&
          (want == NC_FOUND) == (id != NULL), name);
    dna_identity_free(id);
    nc_read_clear(&raw);
}

static void write_gate_case(nc_ctx_t *ctx, int mode, bool fresh,
                            const char *name) {
    atomic_store(&g_fake.mode, mode);
    atomic_store(&g_fake.puts, 0);
    ctx->fresh = fresh;
    nc_profile_result_t r;
    int rc = nc_profile_publish(ctx, "{\"bio\":\"edited\"}", &r);
    CHECK(rc == NC_OK && r.status == NC_PROFILE_WAIT &&
          atomic_load(&g_fake.puts) == 0, name);
}

/* The PUT the fake received: an EXCLUSIVE own-value_id record that
 * verifies, with `bio` and `version`. */
static int put_record_ok(const char *bio, uint32_t version) {
    pthread_mutex_lock(&g_fake.mu);
    int ok = g_fake.put_type == NODUS_VALUE_EXCLUSIVE && g_fake.put_ttl == 0 &&
             g_fake.put_vid == nodus_identity_value_id(&g_keys->id) &&
             g_fake.put_data != NULL;
    dna_unified_identity_t *id = NULL;
    if (ok) ok = dna_identity_from_json(g_fake.put_data, &id) == 0 && id;
    pthread_mutex_unlock(&g_fake.mu);
    if (ok) {
        char *u = dna_identity_to_json_unsigned(id);
        ok = u && qgp_dsa87_verify(id->signature, sizeof(id->signature),
                                   (const uint8_t *)u, strlen(u),
                                   id->dilithium_pubkey) == 0 &&
             strcmp(id->bio, bio) == 0 && id->version == version &&
             id->has_mlkem_pubkey &&
             memcmp(id->mlkem_pubkey, g_keys->mlkem_pk, sizeof(id->mlkem_pubkey)) == 0;
        free(u);
    }
    dna_identity_free(id);
    return ok;
}

/* ── R4 / R3 gated writes ─────────────────────────────────────────────── */

static const char *WORDS_PEER =
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
static nc_keys_t *g_peer_keys;

static void serve_payload(const uint8_t *b, size_t n) {
    free(g_fake.serve);
    g_fake.serve = malloc(n ? n : 1);
    if (g_fake.serve) memcpy(g_fake.serve, b, n);
    g_fake.serve_len = g_fake.serve ? n : 0;
    atomic_store(&g_fake.mode, M_PAYLOAD);
}

static void contact(nc_contact_t *c, const char *fp, uint8_t salt_byte) {
    memset(c, 0, sizeof(*c));
    memcpy(c->fp, fp, NC_FP_HEX_LEN);
    if (salt_byte) { c->has_salt = true; memset(c->salt, salt_byte, NC_SALT_LEN); }
}

static void list_gate_case(nc_ctx_t *ctx, int mode, bool fresh, const char *name) {
    atomic_store(&g_fake.mode, mode);
    atomic_store(&g_fake.puts, 0);
    ctx->fresh = fresh;
    nc_contact_t add;
    contact(&add, g_peer_keys->fp, 0x11);
    nc_list_result_t r;
    int rc = nc_contactlist_add(ctx, &add, 1, &r);
    CHECK(rc == NC_OK && r.status == NC_LIST_WAIT && atomic_load(&g_fake.puts) == 0, name);
}

/* The last PUT as an EXCLUSIVE own contact list: serve it back and read it. */
static size_t put_list_readback(nc_ctx_t *ctx, nc_contactlist_t *out) {
    pthread_mutex_lock(&g_fake.mu);
    int ok = g_fake.put_type == NODUS_VALUE_EXCLUSIVE && g_fake.put_ttl == 0 &&
             g_fake.put_vid == nodus_identity_value_id(&g_keys->id) && g_fake.put_data;
    uint8_t *copy = ok ? malloc(g_fake.put_len) : NULL;
    size_t len = g_fake.put_len;
    if (copy) memcpy(copy, g_fake.put_data, len);
    pthread_mutex_unlock(&g_fake.mu);
    memset(out, 0, sizeof(*out));
    if (!copy) return (size_t)-1;
    serve_payload(copy, len);
    free(copy);
    nc_contactlist_read(ctx, out);
    return out->read.outcome == NC_FOUND ? out->count : (size_t)-1;
}

static void test_contactlist_gate(nc_ctx_t *ctx) {
    list_gate_case(ctx, M_TIMEOUT, true, "L1a list add, timeout: wait, zero PUTs (even fresh)");
    list_gate_case(ctx, M_BAD_SIG, true, "L1b list add, bad signature: wait, zero PUTs");
    list_gate_case(ctx, M_UNDECODABLE, true, "L1c list add, undecodable: wait, zero PUTs");
    list_gate_case(ctx, M_EMPTY, false, "L2 list add, EMPTY for a restored identity: wait, zero PUTs (Q1)");

    /* L3: EMPTY + fresh -> the first list, one EXCLUSIVE PUT that reads back. */
    atomic_store(&g_fake.mode, M_EMPTY);
    atomic_store(&g_fake.puts, 0);
    atomic_store(&g_fake.put_reply, 0);
    ctx->fresh = true;
    nc_contact_t first;
    contact(&first, g_peer_keys->fp, 0x11);
    nc_list_result_t r;
    int rc = nc_contactlist_add(ctx, &first, 1, &r);
    nc_contactlist_t back;
    size_t n = (rc == NC_OK && r.status == NC_LIST_PUBLISHED && r.created &&
                atomic_load(&g_fake.puts) == 1) ? put_list_readback(ctx, &back) : (size_t)-1;
    CHECK(n == 1 && strcmp(back.items[0].fp, g_peer_keys->fp) == 0 && back.items[0].has_salt &&
          back.items[0].salt[0] == 0x11,
          "L3 EMPTY, fresh: one EXCLUSIVE own-value_id PUT; the list reads back (CLST, self-Seal, authorship)");
    nc_contactlist_clear(&back);

    /* L4: FOUND (the list above is served) + a new contact -> merge: the
     * stored entry first and unchanged, the new one appended. */
    ctx->fresh = false;
    atomic_store(&g_fake.puts, 0);
    nc_contact_t more[2];
    contact(&more[0], g_peer_keys->fp, 0x22);          /* same fp, other salt */
    contact(&more[1], g_stranger->fingerprint, 0);     /* new, no salt */
    rc = nc_contactlist_add(ctx, more, 2, &r);
    n = (rc == NC_OK && r.status == NC_LIST_PUBLISHED && !r.created && r.count_before == 1 &&
         r.count_after == 2 && r.salt_kept == 1 && atomic_load(&g_fake.puts) == 1)
            ? put_list_readback(ctx, &back) : (size_t)-1;
    CHECK(n == 2 && strcmp(back.items[0].fp, g_peer_keys->fp) == 0 &&
          back.items[0].salt[0] == 0x11 &&
          strcmp(back.items[1].fp, g_stranger->fingerprint) == 0 && !back.items[1].has_salt,
          "L4 FOUND: merge only — stored entry and its salt kept, new entry appended");
    nc_contactlist_clear(&back);

    /* L5: nothing new -> no PUT. */
    atomic_store(&g_fake.puts, 0);
    rc = nc_contactlist_add(ctx, more, 2, &r);
    CHECK(rc == NC_OK && r.status == NC_LIST_UNCHANGED && atomic_load(&g_fake.puts) == 0,
          "L5 FOUND with every entry already stored: unchanged, zero PUTs");

    /* L6: a list sealed by another identity, served under the own DHT
     * owner -> the Seal/authorship check fails -> wait, zero PUTs. */
    uint8_t *alien = NULL;
    size_t alien_len = 0;
    nc_contact_t one;
    contact(&one, g_keys->fp, 0);
    rc = nc_contactlist_build(g_peer_keys, &one, 1, 1700000000ULL, &alien, &alien_len);
    if (rc == NC_OK) serve_payload(alien, alien_len);
    free(alien);
    atomic_store(&g_fake.puts, 0);
    nc_contact_t add;
    contact(&add, g_peer_keys->fp, 0);
    rc = nc_contactlist_add(ctx, &add, 1, &r);
    CHECK(rc == NC_OK && r.status == NC_LIST_WAIT && r.read_outcome == NC_UNREADABLE &&
          r.read_why == NC_WHY_BAD_RECORD && atomic_load(&g_fake.puts) == 0,
          "L6 list not sealed by the own key: UNREADABLE(bad_record), zero PUTs");

    /* L7: KEY_OWNED on the first list -> taken. */
    atomic_store(&g_fake.mode, M_EMPTY);
    atomic_store(&g_fake.puts, 0);
    atomic_store(&g_fake.put_reply, NODUS_ERR_KEY_OWNED);
    ctx->fresh = true;
    rc = nc_contactlist_add(ctx, &first, 1, &r);
    CHECK(rc == NC_OK && r.status == NC_LIST_TAKEN && atomic_load(&g_fake.puts) == 1,
          "L7 KEY_OWNED -> taken (one attempt)");
    atomic_store(&g_fake.put_reply, 0);
    ctx->fresh = false;
}

static void test_salt_gate(nc_ctx_t *ctx) {
    nc_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    memcpy(peer.fp, g_peer_keys->fp, NC_FP_HEX_LEN);
    memcpy(peer.dsa_pk, g_peer_keys->id.pk.bytes, sizeof(peer.dsa_pk));
    memcpy(peer.kyber_pk, g_peer_keys->kyber_pk, sizeof(peer.kyber_pk));
    uint8_t local[NC_SALT_LEN];
    memset(local, 0x5c, sizeof(local));
    nc_salt_sync_t s;

    atomic_store(&g_fake.mode, M_TIMEOUT);
    atomic_store(&g_fake.puts, 0);
    ctx->fresh = true;
    int rc = nc_salt_sync(ctx, &peer, local, &s);
    CHECK(rc == NC_OK && s.status == NC_SALT_SYNC_WAIT && atomic_load(&g_fake.puts) == 0,
          "S1 salt sync, timeout: wait, zero PUTs (even fresh)");
    nc_salt_sync_clear(&s);

    atomic_store(&g_fake.mode, M_EMPTY);
    atomic_store(&g_fake.puts, 0);
    ctx->fresh = false;
    rc = nc_salt_sync(ctx, &peer, local, &s);
    CHECK(rc == NC_OK && s.status == NC_SALT_SYNC_WAIT && atomic_load(&g_fake.puts) == 0,
          "S2 salt sync, EMPTY + local salt, restored identity: wait, zero PUTs (Q1)");
    nc_salt_sync_clear(&s);

    atomic_store(&g_fake.puts, 0);
    rc = nc_salt_sync(ctx, &peer, NULL, &s);
    CHECK(rc == NC_OK && s.status == NC_SALT_SYNC_NOTHING_TO_WRITE && s.choice == NC_SALT_NONE &&
          atomic_load(&g_fake.puts) == 0,
          "S3 salt sync, EMPTY and no local salt: nothing to write");
    nc_salt_sync_clear(&s);

    atomic_store(&g_fake.puts, 0);
    ctx->fresh = true;
    rc = nc_salt_sync(ctx, &peer, local, &s);
    int ok = rc == NC_OK && s.status == NC_SALT_SYNC_PUBLISHED && atomic_load(&g_fake.puts) == 1 &&
             memcmp(s.chosen, local, NC_SALT_LEN) == 0;
    pthread_mutex_lock(&g_fake.mu);
    ok = ok && g_fake.put_type == NODUS_VALUE_EPHEMERAL && g_fake.put_ttl == SALT_AGREEMENT_TTL &&
         g_fake.put_vid == nodus_identity_value_id(&g_keys->id) &&
         g_fake.put_len == PACKET_TOTAL_SIZE;
    uint8_t peer_bin[FP_BIN_SIZE], got[NC_SALT_LEN];
    ok = ok && salt_agreement_fp_hex_to_bin(g_peer_keys->fp, peer_bin) == 0 &&
         salt_agreement_packet_verify_signature((const uint8_t *)g_fake.put_data, g_fake.put_len,
                                                PACKET_DATA_SIZE, g_keys->id.pk.bytes, NULL) == 0 &&
         salt_agreement_packet_decrypt_salt((const uint8_t *)g_fake.put_data, g_fake.put_len,
                                            peer_bin, g_peer_keys->kyber_sk, NULL, got) == 0 &&
         memcmp(got, local, NC_SALT_LEN) == 0;
    pthread_mutex_unlock(&g_fake.mu);
    CHECK(ok, "S4 salt sync, EMPTY + local salt, fresh: one EPHEMERAL v1 PUT the peer decrypts");
    nc_salt_sync_clear(&s);
    ctx->fresh = false;
}

int main(void) {
    printf("=== Nodus Connect: R0 fault matrix (fake node, real client) ===\n");
    g_keys = calloc(1, sizeof(*g_keys));
    g_peer_keys = calloc(1, sizeof(*g_peer_keys));
    g_stranger = calloc(1, sizeof(*g_stranger));
    if (!g_keys || !g_peer_keys || !g_stranger || nc_keys_from_words(WORDS, g_keys) != 0 ||
        nc_keys_from_words(WORDS_PEER, g_peer_keys) != 0 ||
        nodus_identity_generate(g_stranger) != 0) {
        printf("FATAL: identities\n");
        return 1;
    }
    if (fake_start() != 0) { printf("FATAL: fake node\n"); return 1; }

    nodus_client_t *c = calloc(1, sizeof(*c));
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = g_fake.tcp->port;
    cfg.server_count = 1;
    cfg.connect_timeout_ms = 3000;
    cfg.request_timeout_ms = 1500;
    if (!c || nodus_client_init(c, &cfg, &g_keys->id) != 0 ||
        nodus_client_connect(c) != 0 || !nodus_client_is_ready(c)) {
        printf("FATAL: client did not connect to the fake node\n");
        return 1;
    }
    static int cancel_flag;
    nc_ctx_t ctx = { .client = c, .keys = g_keys, .fresh = false, .cancel = &cancel_flag };

    read_case(&ctx, M_TIMEOUT, NC_UNREADABLE, NC_WHY_TIMEOUT, "F1 timeout -> UNREADABLE(timeout)");
    read_case(&ctx, M_EMPTY, NC_EMPTY, NC_WHY_NONE, "F2 empty -> EMPTY");
    read_case(&ctx, M_BAD_SIG, NC_UNREADABLE, NC_WHY_BAD_SIGNATURE, "F3 bad DHT signature -> UNREADABLE");
    read_case(&ctx, M_WRONG_OWNER, NC_UNREADABLE, NC_WHY_WRONG_OWNER, "F4 wrong owner -> UNREADABLE");
    read_case(&ctx, M_UNDECODABLE, NC_UNREADABLE, NC_WHY_UNDECODABLE, "F5 undecodable val -> UNREADABLE (F1)");
    read_case(&ctx, M_GOOD, NC_FOUND, NC_WHY_NONE, "F6 good own profile -> FOUND");

    write_gate_case(&ctx, M_TIMEOUT, true, "W1a timeout: wait, zero PUTs (even fresh)");
    write_gate_case(&ctx, M_BAD_SIG, true, "W1b bad signature: wait, zero PUTs");
    write_gate_case(&ctx, M_WRONG_OWNER, true, "W1c wrong owner: wait, zero PUTs");
    write_gate_case(&ctx, M_UNDECODABLE, true, "W1d undecodable: wait, zero PUTs");
    write_gate_case(&ctx, M_EMPTY, false, "W2 EMPTY, restored identity: wait, zero PUTs (Q1)");

    {
        atomic_store(&g_fake.mode, M_EMPTY);
        atomic_store(&g_fake.puts, 0);
        atomic_store(&g_fake.put_reply, 0);
        ctx.fresh = true;
        nc_profile_result_t r;
        int rc = nc_profile_publish(&ctx, "{\"bio\":\"hello\",\"wallets\":{\"eth\":\"0xabc\"}}", &r);
        CHECK(rc == NC_OK && r.status == NC_PROFILE_PUBLISHED && r.created &&
              atomic_load(&g_fake.puts) == 1 && put_record_ok("hello", 1),
              "W3 EMPTY, fresh identity: one EXCLUSIVE PUT, record verifies");
    }
    {
        atomic_store(&g_fake.mode, M_GOOD);
        atomic_store(&g_fake.puts, 0);
        ctx.fresh = false;
        nc_profile_result_t r;
        int rc = nc_profile_publish(&ctx, "{\"location\":\"Istanbul\"}", &r);
        CHECK(rc == NC_OK && r.status == NC_PROFILE_PUBLISHED && !r.created &&
              r.version == 6 && atomic_load(&g_fake.puts) == 1 &&
              put_record_ok("from-dht", 6),
              "W4 FOUND: one EXCLUSIVE PUT keeping unedited fields, version + 1");
    }
    {
        atomic_store(&g_fake.mode, M_GOOD);
        atomic_store(&g_fake.puts, 0);
        atomic_store(&g_fake.put_reply, NODUS_ERR_KEY_OWNED);
        nc_profile_result_t r;
        int rc = nc_profile_publish(&ctx, "{\"bio\":\"x\"}", &r);
        CHECK(rc == NC_OK && r.status == NC_PROFILE_TAKEN &&
              r.put_rc == NODUS_ERR_KEY_OWNED && atomic_load(&g_fake.puts) == 1,
              "W5 KEY_OWNED -> taken (one attempt, no retry)");
        atomic_store(&g_fake.put_reply, 0);
    }
    {
        atomic_store(&g_fake.mode, M_VALS_JUNK);
        nc_requests_t rq;
        int rc = nc_requests_fetch(&ctx, &rq);
        CHECK(rc == NC_OK && rq.read.outcome == NC_UNREADABLE &&
              rq.read.why == NC_WHY_UNDECODABLE && rq.count == 0,
              "Q1 request inbox with only an undecodable item -> UNREADABLE");
        nc_requests_clear(&rq);
    }
    test_contactlist_gate(&ctx);
    test_salt_gate(&ctx);

    nodus_client_close(c);
    free(c);
    fake_stop();
    nc_keys_wipe(g_keys);
    nc_keys_wipe(g_peer_keys);
    free(g_peer_keys);
    nodus_identity_clear(g_stranger);
    free(g_keys);
    free(g_stranger);
    printf("=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed ? 1 : 0;
}
