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
 *   (F1..F6 and W1..W5 read the profile with get_all since the shadowing
 *   fix: the fake answers get_all with "vals", a single GET with "val".)
 *   P1  profile shadowing: a stranger's PERMANENT row with seq 2^40 next
 *       to the owner's PERMANENT seq-1 row (the node's single GET would
 *       return the stranger's) -> FOUND with the OWNER's record, foreign 1
 *   P2  the stranger's row alone -> UNREADABLE(wrong_owner), foreign 1 —
 *       never FOUND. Chosen over EMPTY because design rev 5 §1.4 R0 maps
 *       "a value whose owner_fp is not the expected writer" to UNREADABLE
 *   P3  ... and the write gate waits with zero PUTs even for a fresh identity
 *   P4  shadow + update: the base is the owner's record (version 5 -> 6,
 *       unedited bio kept), one EXCLUSIVE PUT, foreign 1 reported
 *   P5  owner row + an item that does not decode -> UNREADABLE(undecodable)
 *   P6  ... and zero PUTs (the item may be the owner's newer row)
 *   C1  a profile row kept from a FOUND read passes nc_profile_check again
 *       (same keys) — the page's profile cache (profile_cache.h:40)
 *   C2  the same row under another fingerprint is refused
 *   C3  the row with one byte changed inside the signed part is refused
 *   B1  a day bucket read with no skip hash is decoded and its SHA3-256
 *       blob hash is set
 *   B2  the same bucket with that hash as skip_blob: FOUND, unchanged,
 *       nothing decoded (the app's blob cache, dht_dm_outbox.c:30-80)
 *   B3  a skip hash of another bucket: decoded as usual
 *   (B1-B3 read the fake's profile row as a bucket: it does not decode as
 *   messages, which is enough to tell "decoded" from "skipped"; they do
 *   not prove anything about real message decoding.)
 *   (Since the paged reads — DHT Package A, nc_read_all — every get_all the
 *   core sends carries "pg" (+ "own" for an owner-filtered read); the fake
 *   answers it as a paging node, "more": false unless a mode below asks
 *   for more pages, and still serves every mode above. Expectations of the
 *   cases above are unchanged.)
 *   N1  the owner's row on page 2 behind more = true + "next" -> FOUND; two
 *       page requests, both with "own" = the owner's fp
 *   N2  an owner-filtered read with pages left after NC_READ_MAX_PAGES ->
 *       UNREADABLE(too_large) after exactly NC_READ_MAX_PAGES requests;
 *       profile and contact-list writes wait with zero PUTs (fresh too)
 *   N3  a pre-paging reply ("vals": [], no "more") -> UNREADABLE(node_error),
 *       never EMPTY; zero PUTs even for a fresh identity
 *   N4  error 21 (unavailable) -> UNREADABLE(node_error), zero PUTs
 *   N5  the owner-less request inbox past NC_READ_MAX_PAGES: truncated; with
 *       nothing read UNREADABLE(too_large), not EMPTY
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
 *   - P1-P6: the fake decides what get_all returns and in which order (it
 *     sends seq DESC as nodus_storage.c GET_ALL_SQL does); they prove the
 *     client-side choice, not that a real node keeps both rows. A real
 *     node's get_all is also never complete (design §6.4 F5): the owner's
 *     row can be missing from a real answer, which reads as P2.
 *   - The fake never applies "own": it sends the rows of its mode whatever
 *     the filter (as a node that ignores it would). F4, W1c and P1-P4 thus
 *     pin the client's counting of a foreign row; a real Package A node
 *     filters by owner, sends no foreign row, and answers F4 / P2 / P3 as
 *     an empty page (EMPTY — for a fresh identity P3 would then write).
 *   - N1-N5 prove the client's paging loop against the fake's cursors, not
 *     a real node's page budget (nodus_storage_get_all_page).
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
    M_PAYLOAD,         /* g_fake.serve as an own EXCLUSIVE value            */
    M_SHADOW,          /* get_all: stranger PERMANENT high seq + owner row  */
    M_FOREIGN_ONLY,    /* get_all: the stranger's row alone                 */
    M_OWNER_PLUS_JUNK, /* get_all: owner row + an item that does not decode */
    M_PAGED_OWNER,     /* paged get_all: page 1 empty + more/next, page 2
                        * (asked with that cursor) = the owner's row        */
    M_ENDLESS,         /* paged get_all: every page empty + more = true     */
    M_LEGACY_EMPTY,    /* any read: a pre-paging reply ("vals": [], no
                        * "more")                                           */
    M_UNAVAILABLE      /* any read: error NODUS_ERR_UNAVAILABLE (21)        */
} mode_t_;

typedef struct {
    nodus_tcp_t     *tcp;
    _Atomic int      mode;
    _Atomic int      put_reply;     /* 0 = ok, else an error code */
    _Atomic int      puts;
    _Atomic int      page_reqs;     /* get_all requests with "pg" / "after" */
    _Atomic int      own_reqs;      /* ... of which "own" = the own fp      */
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
static nc_keys_t *g_peer_keys;
static nodus_key_t g_own_fp;            /* g_keys->fp as a key */
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

/* One signed, serialised DHT value of `owner` at `key`. */
static int sign_value(const nodus_key_t *key, const nodus_identity_t *owner,
                      const uint8_t *data, size_t data_len,
                      nodus_value_type_t type, uint64_t seq, int corrupt,
                      uint8_t **out, size_t *out_len) {
    nodus_value_t *v = NULL;
    int rc = nodus_value_create(key, data, data_len, type, 0,
                                nodus_identity_value_id(owner), seq,
                                &owner->pk, &v);
    if (rc != 0 || nodus_value_sign(v, &owner->sk) != 0) {
        nodus_value_free(v);
        return -1;
    }
    if (corrupt) v->signature.bytes[5] ^= 0x01;
    rc = nodus_value_serialize(v, out, out_len);
    nodus_value_free(v);
    return rc;
}

/* The mode's value: the served payload (M_PAYLOAD) or the good own
 * profile, EXCLUSIVE, seq 1. */
static int value_bytes(const nodus_key_t *key, const nodus_identity_t *owner,
                       int corrupt, uint8_t **out, size_t *out_len) {
    if (atomic_load(&g_fake.mode) == M_PAYLOAD)
        return sign_value(key, owner, g_fake.serve, g_fake.serve_len,
                          NODUS_VALUE_EXCLUSIVE, 1, corrupt, out, out_len);
    char *json = profile_json();
    if (!json) return -1;
    int rc = sign_value(key, owner, (const uint8_t *)json, strlen(json),
                        NODUS_VALUE_EXCLUSIVE, 1, corrupt, out, out_len);
    free(json);
    return rc;
}

/* F1 shape: a stranger's PERMANENT row at the profile key with a seq far
 * above the owner's. In M_SHADOW the owner's row is PERMANENT too (what
 * the frozen app's update leaves), so no row is EXCLUSIVE and the node's
 * single GET (nodus_storage.c GET_SQL :43-46, seq DESC) would return the
 * stranger's row. Its data is not a profile: if the core ever chose it,
 * the record checks would fail and the read would not be FOUND. */
#define SHADOW_SEQ (1ULL << 40)
static const char SHADOW_DATA[] = "{\"shadow\":1}";

static int stranger_row(const nodus_key_t *key, uint8_t **out, size_t *out_len) {
    return sign_value(key, g_stranger, (const uint8_t *)SHADOW_DATA,
                      sizeof(SHADOW_DATA) - 1, NODUS_VALUE_PERMANENT,
                      SHADOW_SEQ, 0, out, out_len);
}

/* The owner's good profile as the frozen app leaves it after an update:
 * PERMANENT (keyserver_profiles.c:199-201), seq 1. */
static int owner_row_permanent(const nodus_key_t *key, uint8_t **out,
                               size_t *out_len) {
    char *json = profile_json();
    if (!json) return -1;
    int rc = sign_value(key, &g_keys->id, (const uint8_t *)json, strlen(json),
                        NODUS_VALUE_PERMANENT, 1, 0, out, out_len);
    free(json);
    return rc;
}

/* The cursor M_PAGED_OWNER hands out after page 1 (and expects back). */
static const uint64_t PAGE1_NEXT_VID = 0;

static void enc_cursor(cbor_encoder_t *enc, const nodus_key_t *owner,
                       uint64_t vid) {
    cbor_encode_map(enc, 2);
    cbor_encode_cstr(enc, "o"); cbor_encode_bstr(enc, owner->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(enc, "v"); cbor_encode_uint(enc, vid);
}

/* "r" of a paged get_all reply (nodus_t2_result_page's shape): "vals" with
 * the given items, "more", and "next" when more. */
static void enc_page(cbor_encoder_t *enc, const uint8_t *const *items,
                     const size_t *lens, size_t n, bool more,
                     const nodus_key_t *next_owner, uint64_t next_vid) {
    cbor_encode_map(enc, more ? 3 : 2);
    cbor_encode_cstr(enc, "vals");
    cbor_encode_array(enc, n);
    for (size_t i = 0; i < n; i++) cbor_encode_bstr(enc, items[i], lens[i]);
    cbor_encode_cstr(enc, "more"); cbor_encode_bool(enc, more);
    if (more) {
        cbor_encode_cstr(enc, "next");
        enc_cursor(enc, next_owner, next_vid);
    }
}

/* `paged`: a get_all that carried "pg" / "after". Every mode below except
 * M_LEGACY_EMPTY answers it as a paging node (plus "more"); the fake never
 * applies "own" — it sends the rows of its mode whatever the filter, as a
 * node that ignores the filter would, so the client-side classification of
 * a foreign row stays under test. */
static void send_get_reply(nodus_tcp_conn_t *conn, const nodus_tier2_msg_t *msg,
                           bool all) {
    int mode = atomic_load(&g_fake.mode);
    if (mode == M_TIMEOUT) return;
    uint32_t txn = msg->txn_id;
    const nodus_key_t *key = &msg->key;
    bool paged = all && (msg->page || msg->has_after);
    size_t out = 0;
    if (mode == M_UNAVAILABLE) {
        if (nodus_t2_error(txn, NODUS_ERR_UNAVAILABLE, "unavailable",
                           g_fake.buf, FAKE_BUF, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
        return;
    }
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_fake.buf, FAKE_BUF);
    resp_header(&enc, txn);
    cbor_encode_cstr(&enc, "r");
    uint8_t *vb = NULL, *vb2 = NULL;
    size_t vl = 0, vl2 = 0;
    static const uint8_t junk[3] = { 1, 2, 3 };
    static const nodus_key_t zero_fp;
    switch (mode) {
    case M_EMPTY:
        if (paged) enc_page(&enc, NULL, NULL, 0, false, NULL, 0);
        else cbor_encode_map(&enc, 0);
        break;
    case M_LEGACY_EMPTY:     /* a pre-paging node: no "more", ever */
        cbor_encode_map(&enc, all ? 1 : 0);
        if (all) { cbor_encode_cstr(&enc, "vals"); cbor_encode_array(&enc, 0); }
        break;
    case M_GOOD:
    case M_PAYLOAD:
    case M_BAD_SIG:
    case M_WRONG_OWNER:
        if (value_bytes(key, mode == M_WRONG_OWNER ? g_stranger : &g_keys->id,
                        mode == M_BAD_SIG, &vb, &vl) != 0) return;
        cbor_encode_map(&enc, paged ? 2 : 1);
        /* get_all answers "vals" (client_get_all_impl reads only that) */
        cbor_encode_cstr(&enc, all ? "vals" : "val");
        if (all) cbor_encode_array(&enc, 1);
        cbor_encode_bstr(&enc, vb, vl);
        if (paged) { cbor_encode_cstr(&enc, "more"); cbor_encode_bool(&enc, false); }
        free(vb);
        break;
    case M_UNDECODABLE:
        cbor_encode_map(&enc, paged ? 2 : 1);
        cbor_encode_cstr(&enc, all ? "vals" : "val");
        if (all) cbor_encode_array(&enc, 1);
        cbor_encode_bstr(&enc, junk, sizeof(junk));
        if (paged) { cbor_encode_cstr(&enc, "more"); cbor_encode_bool(&enc, false); }
        break;
    case M_VALS_JUNK:
        cbor_encode_map(&enc, paged ? 2 : 1);
        cbor_encode_cstr(&enc, "vals");
        cbor_encode_array(&enc, 1);
        cbor_encode_bstr(&enc, junk, sizeof(junk));
        if (paged) { cbor_encode_cstr(&enc, "more"); cbor_encode_bool(&enc, false); }
        break;
    case M_SHADOW:          /* get_all only: [stranger, owner] (seq DESC) */
    case M_FOREIGN_ONLY:    /* get_all only: [stranger]                   */
    case M_OWNER_PLUS_JUNK: /* get_all only: [owner, junk]                */
        if (!all) return;
        if (mode != M_OWNER_PLUS_JUNK && stranger_row(key, &vb, &vl) != 0) return;
        if (mode != M_FOREIGN_ONLY && owner_row_permanent(key, &vb2, &vl2) != 0) {
            free(vb);
            return;
        }
        cbor_encode_map(&enc, paged ? 2 : 1);
        cbor_encode_cstr(&enc, "vals");
        cbor_encode_array(&enc, mode == M_FOREIGN_ONLY ? 1 : 2);
        if (vb) cbor_encode_bstr(&enc, vb, vl);
        if (vb2) cbor_encode_bstr(&enc, vb2, vl2);
        if (mode == M_OWNER_PLUS_JUNK) cbor_encode_bstr(&enc, junk, sizeof(junk));
        if (paged) { cbor_encode_cstr(&enc, "more"); cbor_encode_bool(&enc, false); }
        free(vb);
        free(vb2);
        break;
    case M_PAGED_OWNER:
        if (!paged) return;
        if (msg->has_after &&
            memcmp(msg->after.owner.bytes, zero_fp.bytes, NODUS_KEY_BYTES) == 0 &&
            msg->after.vid == PAGE1_NEXT_VID) {
            /* page 2: the owner's good profile row, last page */
            if (value_bytes(key, &g_keys->id, 0, &vb, &vl) != 0) return;
            const uint8_t *items[1] = { vb };
            enc_page(&enc, items, &vl, 1, false, NULL, 0);
            free(vb);
        } else {
            /* page 1 — also the answer to a page-2 request that lost the
             * cursor, so such a client pages until NC_READ_MAX_PAGES */
            enc_page(&enc, NULL, NULL, 0, true, &zero_fp, PAGE1_NEXT_VID);
        }
        break;
    case M_ENDLESS:
        if (!paged) return;
        /* an advancing cursor that never ends */
        enc_page(&enc, NULL, NULL, 0, true, &zero_fp,
                 msg->has_after ? msg->after.vid + 1 : 1);
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
        bool all = strcmp(msg.method, "get_all") == 0;
        if (all && (msg.page || msg.has_after)) {
            atomic_fetch_add(&g_fake.page_reqs, 1);
            if (msg.has_own &&
                memcmp(msg.own_fp.bytes, g_own_fp.bytes, NODUS_KEY_BYTES) == 0)
                atomic_fetch_add(&g_fake.own_reqs, 1);
        }
        send_get_reply(conn, &msg, all);
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

/* ── R1 shadowing (get-all filtered to the owner) ─────────────────────── */

static void test_profile_shadow(nc_ctx_t *ctx) {
    /* P1: stranger's high-seq PERMANENT row + the owner's row -> the
     * owner's record, foreign counted. */
    atomic_store(&g_fake.mode, M_SHADOW);
    nodus_key_t own;
    nc_fp_parse(g_keys->fp, &own);
    nc_read_t raw;
    dna_unified_identity_t *id = NULL;
    nc_profile_read(ctx, g_keys->fp, &raw, &id, NULL);
    CHECK(raw.outcome == NC_FOUND && raw.foreign == 1 && id &&
          strcmp(id->bio, "from-dht") == 0 && id->version == 5 && raw.value &&
          memcmp(raw.value->owner_fp.bytes, own.bytes, NODUS_KEY_BYTES) == 0 &&
          raw.value->seq == 1,
          "P1 shadow: stranger row seq 2^40 + owner row -> FOUND, owner's record, foreign 1");
    dna_identity_free(id);
    nc_read_clear(&raw);

    /* P2: the stranger's row alone -> not FOUND. R0 (design rev 5 §1.4 R0,
     * nc_classify_all) maps a value of another writer to UNREADABLE; the
     * write gate then waits, even for a fresh identity. */
    atomic_store(&g_fake.mode, M_FOREIGN_ONLY);
    id = NULL;
    nc_profile_read(ctx, g_keys->fp, &raw, &id, NULL);
    CHECK(raw.outcome == NC_UNREADABLE && raw.why == NC_WHY_WRONG_OWNER &&
          raw.foreign == 1 && !id && !raw.value,
          "P2 foreign row alone -> UNREADABLE(wrong_owner), foreign 1, never FOUND");
    dna_identity_free(id);
    nc_read_clear(&raw);
    write_gate_case(ctx, M_FOREIGN_ONLY, true,
                    "P3 foreign row alone, fresh identity: wait, zero PUTs");

    /* P4: shadow + an update: the base is the owner's record (bio kept,
     * version 5 + 1), one EXCLUSIVE PUT; foreign reported. */
    atomic_store(&g_fake.mode, M_SHADOW);
    atomic_store(&g_fake.puts, 0);
    atomic_store(&g_fake.put_reply, 0);
    ctx->fresh = false;
    nc_profile_result_t r;
    int rc = nc_profile_publish(ctx, "{\"location\":\"Ankara\"}", &r);
    CHECK(rc == NC_OK && r.status == NC_PROFILE_PUBLISHED && !r.created &&
          r.read.foreign == 1 && r.version == 6 && atomic_load(&g_fake.puts) == 1 &&
          put_record_ok("from-dht", 6),
          "P4 shadow + update: base = owner's record, one EXCLUSIVE PUT, foreign 1");

    /* P5: the owner's row + an item that does not decode -> UNREADABLE
     * (the item may be the owner's newer row), zero PUTs. */
    read_case(ctx, M_OWNER_PLUS_JUNK, NC_UNREADABLE, NC_WHY_UNDECODABLE,
              "P5 owner row + undecodable item -> UNREADABLE(undecodable)");
    write_gate_case(ctx, M_OWNER_PLUS_JUNK, true,
                    "P6 owner row + undecodable item: wait, zero PUTs");
    ctx->fresh = false;
}

/* ── Profile cache: a kept row is checked again (nc_profile_check) ───── */

static void test_profile_cache(nc_ctx_t *ctx) {
    atomic_store(&g_fake.mode, M_GOOD);
    nc_read_t raw;
    nc_profile_read(ctx, g_keys->fp, &raw, NULL, NULL);
    CHECK(raw.outcome == NC_FOUND && raw.value, "C0 good own profile read for the cache cases");
    if (raw.outcome != NC_FOUND || !raw.value) { nc_read_clear(&raw); return; }
    size_t len = raw.value->data_len;
    uint8_t *kept = malloc(len);
    if (!kept) { nc_read_clear(&raw); CHECK(0, "C0 allocation"); return; }
    memcpy(kept, raw.value->data, len);
    nc_read_clear(&raw);

    dna_unified_identity_t *id = NULL;
    nc_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    CHECK(nc_profile_check(g_keys->fp, kept, len, &id, &peer) == 0 && id &&
          strcmp(id->bio, "from-dht") == 0 && strcmp(peer.fp, g_keys->fp) == 0 &&
          memcmp(peer.dsa_pk, g_keys->id.pk.bytes, sizeof(peer.dsa_pk)) == 0,
          "C1 kept profile row: passes the record checks again, same keys");
    dna_identity_free(id);

    id = NULL;
    CHECK(nc_profile_check(g_peer_keys->fp, kept, len, &id, NULL) != 0 && !id,
          "C2 kept row under another fingerprint: refused");

    /* a changed byte inside the signed part: "from-dht" -> "from-dhT" */
    uint8_t *edited = malloc(len);
    const char *at = NULL;
    if (edited) {
        memcpy(edited, kept, len);
        for (size_t i = 0; i + 8 <= len; i++)
            if (memcmp(edited + i, "from-dht", 8) == 0) { edited[i + 7] = 'T'; at = "x"; break; }
    }
    id = NULL;
    CHECK(edited && at && nc_profile_check(g_keys->fp, edited, len, &id, NULL) != 0 && !id,
          "C3 kept row with one changed byte: refused (signature)");
    free(edited);
    free(kept);
}

/* ── Day bucket blob skip (the app's blob cache, dht_dm_outbox.c:30-80) ─ */

static void serve_payload(const uint8_t *b, size_t n);

static void test_blob_skip(nc_ctx_t *ctx) {
    /* The fake serves one fixed payload (M_PAYLOAD; the DHT value around it
     * is signed afresh per answer, its data is not) owned by this identity;
     * read as a day bucket of the "peer" = this identity it is FOUND, does
     * not decode as messages (BAD_RECORD), and its blob hash is set. (M_GOOD
     * cannot be used: the profile inside is re-signed per answer, and an
     * ML-DSA signature differs each time.) */
    static const char bucket[] = "a fixed day bucket that is not a message list";
    serve_payload((const uint8_t *)bucket, sizeof(bucket) - 1);
    nc_peer_t self;
    memset(&self, 0, sizeof(self));
    memcpy(self.fp, g_keys->fp, NC_FP_HEX_LEN);
    memcpy(self.dsa_pk, g_keys->id.pk.bytes, sizeof(self.dsa_pk));
    uint8_t salt[NC_SALT_LEN];
    memset(salt, 0x5a, sizeof(salt));
    nc_inbox_t first;
    int rc = nc_outbox_fetch_day(ctx, &self, salt, 20000, NULL, &first);
    uint8_t zero[32] = {0};
    CHECK(rc == NC_OK && first.read.outcome == NC_UNREADABLE &&
          first.read.why == NC_WHY_BAD_RECORD && !first.unchanged &&
          memcmp(first.blob, zero, sizeof(zero)) != 0,
          "B1 no skip hash: the bucket is decoded (here: refused), its blob hash is set");
    uint8_t blob[32];
    memcpy(blob, first.blob, sizeof(blob));
    nc_inbox_clear(&first);

    nc_inbox_t again;
    rc = nc_outbox_fetch_day(ctx, &self, salt, 20000, blob, &again);
    CHECK(rc == NC_OK && again.read.outcome == NC_FOUND && again.unchanged &&
          again.count == 0 && memcmp(again.blob, blob, sizeof(blob)) == 0,
          "B2 skip hash equal to the bucket: FOUND, unchanged, nothing decoded");
    nc_inbox_clear(&again);

    blob[0] ^= 1;
    nc_inbox_t other;
    rc = nc_outbox_fetch_day(ctx, &self, salt, 20000, blob, &other);
    CHECK(rc == NC_OK && !other.unchanged && other.read.outcome == NC_UNREADABLE,
          "B3 skip hash of another bucket: decoded as usual");
    nc_inbox_clear(&other);
}

/* ── Paged, owner-filtered reads (DHT Package A) ─────────────────────── */

static void list_gate_case(nc_ctx_t *ctx, int mode, bool fresh, const char *name);

static void reset_page_counters(void) {
    atomic_store(&g_fake.page_reqs, 0);
    atomic_store(&g_fake.own_reqs, 0);
}

static void test_paging(nc_ctx_t *ctx) {
    /* N1: the owner's row is on page 2, behind more = true + a cursor. The
     * read follows the cursor, sends "own" = the owner's fp on both pages,
     * and finds the row. */
    reset_page_counters();
    read_case(ctx, M_PAGED_OWNER, NC_FOUND, NC_WHY_NONE,
              "N1 owner row on page 2 (more + next) -> FOUND");
    CHECK(atomic_load(&g_fake.page_reqs) == 2 && atomic_load(&g_fake.own_reqs) == 2,
          "N1 two page requests, both owner-filtered to the owner's fp");

    /* N2: more than NC_READ_MAX_PAGES pages for an owner-filtered read ->
     * UNREADABLE(too_large) after exactly NC_READ_MAX_PAGES requests; the
     * write gate then waits with zero PUTs, even for a fresh identity. */
    reset_page_counters();
    read_case(ctx, M_ENDLESS, NC_UNREADABLE, NC_WHY_TOO_LARGE,
              "N2 owner-filtered read past NC_READ_MAX_PAGES -> UNREADABLE(too_large)");
    CHECK(atomic_load(&g_fake.page_reqs) == NC_READ_MAX_PAGES,
          "N2 stops after NC_READ_MAX_PAGES page requests");
    write_gate_case(ctx, M_ENDLESS, true,
                    "N2b too large, fresh identity: wait, zero PUTs");
    list_gate_case(ctx, M_ENDLESS, true,
                   "N2c contact list too large, fresh identity: wait, zero PUTs");

    /* N3: a pre-paging node's empty reply ("vals": [], no "more") is not
     * EMPTY: UNREADABLE(node_error), zero PUTs even for a fresh identity. */
    read_case(ctx, M_LEGACY_EMPTY, NC_UNREADABLE, NC_WHY_NODE_ERROR,
              "N3 legacy empty reply -> UNREADABLE(node_error), never EMPTY");
    write_gate_case(ctx, M_LEGACY_EMPTY, true,
                    "N3b legacy empty, fresh identity: wait, zero PUTs");
    list_gate_case(ctx, M_LEGACY_EMPTY, true,
                   "N3c contact list, legacy empty, fresh identity: wait, zero PUTs");

    /* N4: the node could not look (error 21) -> UNREADABLE(node_error). */
    read_case(ctx, M_UNAVAILABLE, NC_UNREADABLE, NC_WHY_NODE_ERROR,
              "N4 error 21 (unavailable) -> UNREADABLE(node_error)");
    write_gate_case(ctx, M_UNAVAILABLE, true,
                    "N4b unavailable, fresh identity: wait, zero PUTs");

    /* N5: the owner-less request inbox past NC_READ_MAX_PAGES: truncated,
     * and with not one item read it is UNREADABLE(too_large), not EMPTY. */
    {
        atomic_store(&g_fake.mode, M_ENDLESS);
        reset_page_counters();
        nc_requests_t rq;
        int rc = nc_requests_fetch(ctx, &rq);
        CHECK(rc == NC_OK && rq.read.outcome == NC_UNREADABLE &&
              rq.read.why == NC_WHY_TOO_LARGE && rq.read.truncated &&
              rq.count == 0 && atomic_load(&g_fake.page_reqs) == NC_READ_MAX_PAGES &&
              atomic_load(&g_fake.own_reqs) == 0,
              "N5 request inbox past NC_READ_MAX_PAGES: truncated, nothing read -> UNREADABLE(too_large)");
        nc_requests_clear(&rq);
    }
    ctx->fresh = false;
}

/* ── R4 / R3 gated writes ─────────────────────────────────────────────── */

static const char *WORDS_PEER =
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";

static void serve_payload(const uint8_t *b, size_t n) {
    free(g_fake.serve);
    g_fake.serve = malloc(n ? n : 1);
    if (g_fake.serve) memcpy(g_fake.serve, b, n);
    g_fake.serve_len = g_fake.serve ? n : 0;
    atomic_store(&g_fake.mode, M_PAYLOAD);
}

/* G9 name check (nc_name_verify): a registered name is shown only when the
 * "<name>:lookup" record written BY that identity holds its fingerprint.
 * Live check of punk / chip / nocdem: tools/nc_live_read "name check". */
static void test_name_verify(nc_ctx_t *ctx) {
    const char *fp = g_keys->fp;
    serve_payload((const uint8_t *)fp, NC_FP_HEX_LEN);
    CHECK(nc_name_verify(ctx, fp, "alice") == 1,
          "N6 own lookup record holding the own fp -> name VERIFIED");
    serve_payload((const uint8_t *)g_peer_keys->fp, NC_FP_HEX_LEN);
    CHECK(nc_name_verify(ctx, fp, "alice") == 0,
          "N7 own lookup record holding ANOTHER fp -> not verified");
    atomic_store(&g_fake.mode, M_WRONG_OWNER);
    CHECK(nc_name_verify(ctx, fp, "alice") != 1,
          "N8 lookup record written by a stranger -> never verified");
    atomic_store(&g_fake.mode, M_EMPTY);
    CHECK(nc_name_verify(ctx, fp, "Alice") == 0,
          "N9 no lookup record (both spellings) -> not verified");
    atomic_store(&g_fake.mode, M_TIMEOUT);
    CHECK(nc_name_verify(ctx, fp, "alice") == -1,
          "N10 node did not answer -> could not read (-1), never verified");
    serve_payload((const uint8_t *)fp, NC_FP_HEX_LEN);
    CHECK(nc_name_verify(ctx, fp, "0123456789abcdef01") == 0 &&
          nc_name_verify(ctx, fp, "punk...") == 0 &&
          nc_name_verify(ctx, fp, "") == 0,
          "N11 names the app's validator refuses are never verified");
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
    if (nc_fp_parse(g_keys->fp, &g_own_fp) != 0) {
        printf("FATAL: own fingerprint\n");
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
    test_profile_shadow(&ctx);
    test_profile_cache(&ctx);
    test_blob_skip(&ctx);
    test_paging(&ctx);
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
    test_name_verify(&ctx);

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
