/*
 * DNA Engine — Calls Module (PQ VoIP Faz A: signaling + key agreement)
 *
 * Live-engine glue over the tested headless core. Owns the orchestrator + a
 * per-call secret keystore (ephemeral Kyber keypair, K_call). See
 * dna_engine_calls.h and docs/functions/calls.md.
 *
 * @file dna_engine_calls.c
 */

#define DNA_ENGINE_CALLS_IMPL
#include "engine_includes.h"

#include "dna_engine_calls.h"
#include "dna_call_orch.h"
#include "dna_call_crypto.h"
#include "dna_call_fsm.h"

#include "database/keyserver_cache.h"
#include "database/contacts_db.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/utils/qgp_types.h"   /* qgp_key_t, qgp_key_load, qgp_key_load_encrypted */

#include <time.h>

#undef LOG_TAG
#define LOG_TAG "CALLS"

#define DNA_CALLS_MAX_KEYS      DNA_CALL_ORCH_MAX_CALLS
#define DNA_CALL_WINDOW_MS      60000u   /* ring/answer timeout */
#define DNA_CALL_GATE_MS        30000u   /* consent-gate window after accept */

extern void qgp_secure_memzero(void *ptr, size_t len);

/* Per-call secret material (kept out of the pure orchestrator). */
typedef struct {
    int      in_use;
    uint8_t  call_id[16];
    uint8_t  peer_fp[64];
    uint32_t tx_seq;                              /* our outbound sequence */
    int      have_eph;
    uint8_t  eph_pk[QGP_KEM1024_PUBLICKEYBYTES];  /* 1568 */
    uint8_t  eph_sk[QGP_KEM1024_SECRETKEYBYTES];  /* 3168 (caller only) */
    int      have_kcall;
    uint8_t  k_call[32];
} call_keys_t;

typedef struct {
    dna_call_orch_t *orch;
    pthread_mutex_t  mu;
    call_keys_t      keys[DNA_CALLS_MAX_KEYS];
} dna_calls_ctx_t;

/* ---- lifecycle ---- */

void *dna_calls_ctx_create(void)
{
    dna_calls_ctx_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->orch = dna_call_orch_create();
    if (!c->orch) { free(c); return NULL; }
    pthread_mutex_init(&c->mu, NULL);
    return c;
}

void dna_calls_ctx_destroy(void *calls_ctx)
{
    dna_calls_ctx_t *c = (dna_calls_ctx_t *)calls_ctx;
    if (!c) return;
    for (int i = 0; i < DNA_CALLS_MAX_KEYS; i++)
        qgp_secure_memzero(&c->keys[i], sizeof(c->keys[i]));
    dna_call_orch_destroy(c->orch);
    pthread_mutex_destroy(&c->mu);
    free(c);
}

/* ---- helpers ---- */

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int hexnib(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t nbytes)
{
    if (!hex || strlen(hex) < nbytes * 2) return -1;
    for (size_t i = 0; i < nbytes; i++) {
        int hi = hexnib(hex[i * 2]), lo = hexnib(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void bytes_to_hex(const uint8_t *b, size_t n, char *out)
{
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[i*2] = h[b[i] >> 4]; out[i*2+1] = h[b[i] & 0xf]; }
    out[n * 2] = '\0';
}

/* keystore (caller holds ctx->mu) */
static call_keys_t *ks_find(dna_calls_ctx_t *c, const uint8_t id[16])
{
    for (int i = 0; i < DNA_CALLS_MAX_KEYS; i++)
        if (c->keys[i].in_use && memcmp(c->keys[i].call_id, id, 16) == 0)
            return &c->keys[i];
    return NULL;
}

static call_keys_t *ks_alloc(dna_calls_ctx_t *c, const uint8_t id[16], const uint8_t peer_fp[64])
{
    call_keys_t *k = ks_find(c, id);
    if (k) return k;
    for (int i = 0; i < DNA_CALLS_MAX_KEYS; i++) {
        if (!c->keys[i].in_use) {
            k = &c->keys[i];
            memset(k, 0, sizeof(*k));
            k->in_use = 1;
            k->tx_seq = 1;
            memcpy(k->call_id, id, 16);
            memcpy(k->peer_fp, peer_fp, 64);
            return k;
        }
    }
    return NULL;
}

static void ks_free(dna_calls_ctx_t *c, const uint8_t id[16])
{
    call_keys_t *k = ks_find(c, id);
    if (k) qgp_secure_memzero(k, sizeof(*k));
}

/* Load a local private key file (identity.dsa / identity.kem). Caller frees. */
static int load_local_privkey(dna_engine_t *engine, const char *fname,
                              size_t expect, uint8_t **out)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/keys/%s", engine->data_dir, fname);
    qgp_key_t *k = NULL;
    int rc = engine->session_password
             ? qgp_key_load_encrypted(path, engine->session_password, &k)
             : qgp_key_load(path, &k);
    if (rc != 0 || !k || !k->private_key || k->private_key_size != expect) {
        if (k) qgp_key_free(k);
        return -1;
    }
    *out = malloc(expect);
    if (!*out) { qgp_key_free(k); return -1; }
    memcpy(*out, k->private_key, expect);
    qgp_key_free(k);
    return 0;
}

/* Build + inner-sign + send a call signal to peer_fp (128 hex). */
static int build_sign_send(dna_engine_t *engine, const char *peer_fp,
                           const dna_call_signal_t *sig)
{
    int rc = -1;
    char *body = malloc(DNA_CALL_SIG_MAX_BODY);
    char *signed_body = malloc(DNA_CALL_SIG_MAX_BODY);
    uint8_t *dsa_sk = NULL;
    if (!body || !signed_body) goto done;

    size_t body_len = 0;
    if (dna_call_build_body(sig, body, DNA_CALL_SIG_MAX_BODY, &body_len) != DNA_CALL_OK)
        goto done;
    if (load_local_privkey(engine, "identity.dsa", QGP_DSA87_SECRETKEYBYTES, &dsa_sk) != 0)
        goto done;

    size_t signed_len = 0;
    if (dna_call_sign_body(body, body_len, dsa_sk,
                           signed_body, DNA_CALL_SIG_MAX_BODY, &signed_len) != DNA_CALL_OK)
        goto done;

    dna_engine_send_message(engine, peer_fp, signed_body, NULL, NULL);
    rc = 0;

done:
    if (dsa_sk) { qgp_secure_memzero(dsa_sk, QGP_DSA87_SECRETKEYBYTES); free(dsa_sk); }
    free(body);
    free(signed_body);
    return rc;
}

/* Emit a call event to the UI (call OUTSIDE the orchestrator mutex). */
static void emit_call_event(dna_engine_t *engine, dna_event_type_t type,
                            const char *call_id_hex, const char *peer_fp,
                            int state, int reason, int is_incoming)
{
    dna_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = type;
    snprintf(ev.data.call.call_id, sizeof(ev.data.call.call_id), "%s", call_id_hex ? call_id_hex : "");
    snprintf(ev.data.call.peer_fp, sizeof(ev.data.call.peer_fp), "%s", peer_fp ? peer_fp : "");
    ev.data.call.state = state;
    ev.data.call.reason = reason;
    ev.data.call.is_incoming = is_incoming ? true : false;
    dna_dispatch_event(engine, &ev);
}

/* ---- incoming ---- */

void dna_calls_handle_incoming(dna_engine_t *engine, const char *sender_fp, const char *body)
{
    if (!engine || !engine->calls_ctx || !sender_fp || !body) return;
    dna_calls_ctx_t *c = (dna_calls_ctx_t *)engine->calls_ctx;

    dna_call_parsed_t p;
    if (dna_call_parse_body(body, strlen(body), &p) != DNA_CALL_OK) return;

    /* Verify the inner Dilithium signature against the sender's cached pubkey. */
    keyserver_cache_entry_t *ks = NULL;
    if (keyserver_cache_get(sender_fp, &ks) != 0 || !ks ||
        !ks->dilithium_pubkey || ks->dilithium_pubkey_len != QGP_DSA87_PUBLICKEYBYTES) {
        if (ks) keyserver_cache_free_entry(ks);
        QGP_LOG_WARN(LOG_TAG, "call signal from %.20s...: no cached pubkey, dropping", sender_fp);
        return;
    }
    int vr = dna_call_verify_body(body, strlen(body), ks->dilithium_pubkey);
    keyserver_cache_free_entry(ks);
    if (vr != DNA_CALL_OK) {
        QGP_LOG_WARN(LOG_TAG, "call signal from %.20s...: signature INVALID, dropping", sender_fp);
        return;
    }

    /* Contacts-only ringing (Q3=no): drop INVITEs from non-contacts / blocked. */
    if (strcmp(p.kind, DNA_CALL_KIND_INVITE) == 0) {
        if (!contacts_db_exists(sender_fp) || contacts_db_is_blocked(sender_fp)) {
            QGP_LOG_INFO(LOG_TAG, "INVITE from non-contact/blocked %.20s..., dropping", sender_fp);
            return;
        }
    }

    uint8_t sraw[64], idraw[16];
    if (hex_to_bytes(sender_fp, sraw, 64) != 0) return;
    if (hex_to_bytes(p.call_id_hex, idraw, 16) != 0) return;

    pthread_mutex_lock(&c->mu);
    dna_call_action_t action = dna_call_orch_on_signal(c->orch, &p, sraw, now_ms(), DNA_CALL_WINDOW_MS);

    dna_call_signal_t out = {0};
    int do_send = 0;
    int emit_type = 0, emit_state = 0, emit_incoming = 0;   /* UI event to fire after unlock */
    char peer_hex[129];
    strncpy(peer_hex, sender_fp, sizeof(peer_hex) - 1);
    peer_hex[sizeof(peer_hex) - 1] = '\0';

    switch (action) {
    case CALL_ACT_SEND_RINGING: {
        /* New inbound INVITE: stash the caller's ephemeral pk + peer fp. */
        call_keys_t *k = ks_alloc(c, idraw, sraw);
        if (k && p.has_eph_pk) { memcpy(k->eph_pk, p.eph_pk, sizeof(k->eph_pk)); k->have_eph = 1; }
        if (k) {
            out.kind = DNA_CALL_KIND_RINGING;
            out.call_id_hex = p.call_id_hex;
            out.seq = k->tx_seq++;
            do_send = 1;
            emit_type = DNA_EVENT_CALL_INCOMING;   /* ring UI */
            emit_incoming = 1;
        }
        break;
    }
    case CALL_ACT_OPEN_MEDIA: {
        /* Caller received ACCEPT: derive K_call for Faz B media. */
        call_keys_t *k = ks_find(c, idraw);
        if (k && k->have_eph && p.has_eph_ct && p.has_static_ct) {
            uint8_t ss_eph[32], ss_static[32], *kem_sk = NULL;
            int ok = (qgp_kem1024_decapsulate(ss_eph, p.eph_ct, k->eph_sk) == 0);
            if (ok && load_local_privkey(engine, "identity.kem",
                                         QGP_KEM1024_SECRETKEYBYTES, &kem_sk) == 0) {
                ok = (qgp_kem1024_decapsulate(ss_static, p.static_ct, kem_sk) == 0);
                if (ok) {
                    uint8_t my_fp[64];
                    hex_to_bytes(engine->fingerprint, my_fp, 64);
                    if (dna_call_derive_key(ss_eph, ss_static, my_fp, k->peer_fp,
                                            k->call_id, k->eph_pk, k->k_call) == DNA_CALL_OK)
                        k->have_kcall = 1;
                }
                qgp_secure_memzero(kem_sk, QGP_KEM1024_SECRETKEYBYTES); free(kem_sk);
            }
            qgp_secure_memzero(ss_eph, 32); qgp_secure_memzero(ss_static, 32);
            QGP_LOG_INFO(LOG_TAG, "call %.16s... connected (K_call agreed, media=Faz B)", p.call_id_hex);
        }
        emit_type = DNA_EVENT_CALL_STATE;
        emit_state = DNA_CALL_UI_ACTIVE;   /* our outgoing call connected */
        break;
    }
    case CALL_ACT_TEARDOWN:
        ks_free(c, idraw);
        QGP_LOG_INFO(LOG_TAG, "call %.16s... ended by peer", p.call_id_hex);
        emit_type = DNA_EVENT_CALL_STATE;
        emit_state = DNA_CALL_UI_ENDED;
        break;
    default:
        break;
    }
    pthread_mutex_unlock(&c->mu);

    if (do_send) build_sign_send(engine, peer_hex, &out);
    if (emit_type)
        emit_call_event(engine, (dna_event_type_t)emit_type, p.call_id_hex,
                        peer_hex, emit_state, 0, emit_incoming);
}

/* ---- user actions ---- */

int dna_engine_call_invite(dna_engine_t *engine, const char *peer_fp)
{
    if (!engine || !engine->calls_ctx || !peer_fp || strlen(peer_fp) < 128) return -1;
    dna_calls_ctx_t *c = (dna_calls_ctx_t *)engine->calls_ctx;

    uint8_t id[16], praw[64];
    if (qgp_randombytes(id, 16) != 0) return -1;
    if (hex_to_bytes(peer_fp, praw, 64) != 0) return -1;
    char id_hex[33]; bytes_to_hex(id, 16, id_hex);

    pthread_mutex_lock(&c->mu);
    dna_call_action_t action = dna_call_orch_start(c->orch, id, praw, now_ms(), DNA_CALL_WINDOW_MS);
    dna_call_signal_t out = {0};
    int do_send = 0;
    if (action == CALL_ACT_SEND_INVITE) {
        call_keys_t *k = ks_alloc(c, id, praw);
        if (k && qgp_kem1024_keypair(k->eph_pk, k->eph_sk) == 0) {
            k->have_eph = 1;
            out.kind = DNA_CALL_KIND_INVITE;
            out.call_id_hex = id_hex;
            out.seq = k->tx_seq++;
            out.caller_fp_hex = engine->fingerprint;
            out.eph_pk = k->eph_pk;
            do_send = 1;
        }
    }
    pthread_mutex_unlock(&c->mu);

    if (!do_send) return -1;
    int rc = build_sign_send(engine, peer_fp, &out);
    if (rc == 0)
        emit_call_event(engine, DNA_EVENT_CALL_STATE, id_hex, peer_fp,
                        DNA_CALL_UI_RINGING, 0, 0);   /* outgoing "Calling…" */
    return rc;
}

int dna_engine_call_accept(dna_engine_t *engine, const char *call_id_hex)
{
    if (!engine || !engine->calls_ctx || !call_id_hex) return -1;
    dna_calls_ctx_t *c = (dna_calls_ctx_t *)engine->calls_ctx;
    uint8_t id[16];
    if (hex_to_bytes(call_id_hex, id, 16) != 0) return -1;

    pthread_mutex_lock(&c->mu);
    int rc = -1, do_send = 0;
    dna_call_signal_t out = {0};
    char peer_hex[129] = {0};
    static uint8_t eph_ct[QGP_KEM1024_CIPHERTEXTBYTES], static_ct[QGP_KEM1024_CIPHERTEXTBYTES];

    dna_call_action_t action = dna_call_orch_user(c->orch, id, CALL_EV_USER_ACCEPT,
                                                  now_ms(), DNA_CALL_GATE_MS);
    if (action == CALL_ACT_ACCEPT) {
        call_keys_t *k = ks_find(c, id);
        if (k && k->have_eph) {
            bytes_to_hex(k->peer_fp, 64, peer_hex);
            keyserver_cache_entry_t *ks = NULL;
            if (keyserver_cache_get(peer_hex, &ks) == 0 && ks &&
                ks->kyber_pubkey && ks->kyber_pubkey_len == QGP_KEM1024_PUBLICKEYBYTES) {
                uint8_t ss_eph[32], ss_static[32];
                if (qgp_kem1024_encapsulate(eph_ct, ss_eph, k->eph_pk) == 0 &&
                    qgp_kem1024_encapsulate(static_ct, ss_static, ks->kyber_pubkey) == 0) {
                    uint8_t my_fp[64];
                    hex_to_bytes(engine->fingerprint, my_fp, 64);
                    if (dna_call_derive_key(ss_eph, ss_static, k->peer_fp, my_fp,
                                            k->call_id, k->eph_pk, k->k_call) == DNA_CALL_OK) {
                        k->have_kcall = 1;
                        out.kind = DNA_CALL_KIND_ACCEPT;
                        out.call_id_hex = call_id_hex;
                        out.seq = k->tx_seq++;
                        out.eph_ct = eph_ct;
                        out.static_ct = static_ct;
                        do_send = 1;
                        rc = 0;
                    }
                }
                qgp_secure_memzero(ss_eph, 32); qgp_secure_memzero(ss_static, 32);
            }
            if (ks) keyserver_cache_free_entry(ks);
        }
    }
    pthread_mutex_unlock(&c->mu);

    if (do_send) build_sign_send(engine, peer_hex, &out);
    if (rc == 0)
        emit_call_event(engine, DNA_EVENT_CALL_STATE, call_id_hex, peer_hex,
                        DNA_CALL_UI_ACTIVE, 0, 1);   /* we answered → connected */
    return rc;
}

static int user_end(dna_engine_t *engine, const char *call_id_hex,
                    dna_call_event_t ev, const char *kind)
{
    if (!engine || !engine->calls_ctx || !call_id_hex) return -1;
    dna_calls_ctx_t *c = (dna_calls_ctx_t *)engine->calls_ctx;
    uint8_t id[16];
    if (hex_to_bytes(call_id_hex, id, 16) != 0) return -1;

    pthread_mutex_lock(&c->mu);
    dna_call_signal_t out = {0};
    int do_send = 0;
    char peer_hex[129] = {0};
    call_keys_t *k = ks_find(c, id);
    if (k) bytes_to_hex(k->peer_fp, 64, peer_hex);

    dna_call_action_t action = dna_call_orch_user(c->orch, id, ev, now_ms(), DNA_CALL_GATE_MS);
    if ((action == CALL_ACT_SEND_REJECT || action == CALL_ACT_END) && k) {
        out.kind = kind;
        out.call_id_hex = call_id_hex;
        out.seq = k->tx_seq++;
        out.has_reason = 1;
        out.reason = 0;
        do_send = 1;
    }
    ks_free(c, id);
    pthread_mutex_unlock(&c->mu);

    if (do_send && peer_hex[0]) build_sign_send(engine, peer_hex, &out);
    emit_call_event(engine, DNA_EVENT_CALL_STATE, call_id_hex, peer_hex,
                    DNA_CALL_UI_ENDED, 0, 0);
    return 0;
}

int dna_engine_call_reject(dna_engine_t *engine, const char *call_id_hex)
{
    return user_end(engine, call_id_hex, CALL_EV_USER_REJECT, DNA_CALL_KIND_REJECT);
}

int dna_engine_call_hangup(dna_engine_t *engine, const char *call_id_hex)
{
    return user_end(engine, call_id_hex, CALL_EV_USER_HANGUP, DNA_CALL_KIND_END);
}
