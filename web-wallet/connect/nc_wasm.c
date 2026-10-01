/* Nodus Connect thin core — the browser entry (packages NC-2 / NC-4b of
 * docs/plans/2026-09-24-web-connect-design.md rev 5, §1.1, §1.8, §1.9).
 *
 * LINKED INTO THE WALLET'S ONE MODULE (NC-4b). This file owns no session:
 * scripts/build-nodus-send-wasm.sh links it (and the library nc_*.c) into
 * src/nodus/send.wasm, whose crypto/nodus-send-wasm.c owns the identity's
 * ONE tier-2 session, the op bracket and the cancel flag, and hands them
 * over through the "Host" functions of nc_core.h. Two sessions of one
 * identity to one node knock each other off (nodus_auth.c:95-116, design
 * §1.1); the module that built them no longer exists.
 *
 * Keys: the session identity is the send module's (nodus_identity_from_seed
 * of the signing seed). The Messages KEM keys (round-3 Kyber from the
 * encryption seed, ML-KEM-1024 from the master seed, nc_keys_from_words)
 * cannot be derived from that seed, so nc_unlock takes the words once,
 * derives nc_keys_t, and refuses unless its ML-DSA-87 public key IS the
 * session's. nc_keys_t carries its own copy of the ML-DSA key (the
 * library's nc_ctx_t signs with keys->id); both copies are wiped by the
 * wallet's lock (nsw_lock -> nc_session_wipe) and by nc_lock.
 *
 * Call model (the send module's, nodus-send-wasm.c "op bracket"):
 *   - every async export (may reach emscripten_sleep) runs inside
 *     nc_begin/nc_end, which enter the SEND MODULE'S bracket: one export
 *     of the whole module at a time, none after its cancel/lock;
 *   - nc_lock, nc_salt_pick and nc_day_today are synchronous and never
 *     reach emscripten_sleep, so JS may call them while another export is
 *     suspended; the module's cancel / lock are nsw_cancel / nsw_lock;
 *   - each async export does ONE bounded network step (one GET, one GET_ALL
 *     or one PUT, each bounded by the client's request timeout) so the JS
 *     queue can put a wallet operation between two sync steps (design §6.4
 *     F7). The exceptions are the three gated writes — nc_profile_update,
 *     nc_salt_reconcile, nc_contacts_add: a read then at most one write
 *     (at most two request timeouts) — the PUT must not be split from the
 *     read it is based on (§6.4 F4). No export loops over contacts or days.
 *   - results are one JSON object (json-c), read with nc_result(); u64
 *     values cross as decimal strings, bytes as lowercase hex.
 *
 * RANDOMNESS: the module's one qgp_platform_random (nodus-send-wasm.c:
 * getentropy() -> crypto.getRandomValues in the shipped build) is the only
 * source; this file defines none, nor qgp_secure_memzero.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef __EMSCRIPTEN__
#error "nc_wasm.c is the browser entry; native tests link the library files only"
#endif
#if !defined(NODUS_SEND_RELEASE) && !defined(NODUS_SEND_TEST_FIXED_RANDOM)
#error "nc_wasm.c is linked into the send module only (scripts/build-nodus-send-wasm.sh)"
#endif

#include "nc_core.h"
#include "nc_history.h"

#include "dht/shared/dht_dm_outbox.h"
#include "crypto/nodus_identity.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"      /* qgp_platform_random (the
                                             * module's, nodus-send-wasm.c) */

#include <emscripten.h>
#include <json-c/json.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "NC_WASM"

/* A history record's plaintext cap. The hex of a record crosses ccall as a
 * string, which Emscripten copies onto the 1 MiB C stack
 * (stringToUTF8OnStack); 64 KiB of plaintext is 128 KiB of hex. */
#define NC_HIST_PT_MAX 65536u

static void nc_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* dna_context_new (messenger/dna_api.c:132-150) refuses to build a context
 * without a home directory; it only records "<home>/.qgp" and the Seal code
 * this module calls never reads it. qgp_platform_linux.c is not linked (its
 * qgp_platform_random would replace the module's), so the linux body is
 * given here minus the getpwuid fallback, which Emscripten has no passwd
 * database for: Emscripten's environment sets HOME (/home/web_user). */
const char *qgp_platform_home_dir(void) {
    return getenv("HOME");
}

/* ── error / result ─────────────────────────────────────────────────── */

static char  g_error[256];
static char *g_result;
static size_t g_result_len;

const char *nc_error(void)  { return g_error; }
const char *nc_result(void) { return g_result ? g_result : "{}"; }

static void result_drop(void) {
    if (g_result) { nc_wipe(g_result, g_result_len); free(g_result); }
    g_result = NULL;
    g_result_len = 0;
}

static int fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_error, sizeof(g_error), fmt, ap);
    va_end(ap);
    QGP_LOG_WARN(LOG_TAG, "%s", g_error);
    return -1;
}

/* Takes ownership of `o`. */
static int set_result(json_object *o) {
    result_drop();
    if (!o) return fail("Out of memory.");
    const char *s = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    g_result_len = s ? strlen(s) + 1 : 0;
    g_result = s ? malloc(g_result_len) : NULL;
    if (g_result) memcpy(g_result, s, g_result_len);
    json_object_put(o);
    return g_result ? 0 : fail("Out of memory.");
}

static json_object *jstr_u64(uint64_t v) {
    char b[21];
    snprintf(b, sizeof(b), "%llu", (unsigned long long)v);
    return json_object_new_string(b);
}

static json_object *jhex(const uint8_t *p, size_t n) {
    static const char d[] = "0123456789abcdef";
    char *s = malloc(2 * n + 1);
    if (!s) return NULL;
    for (size_t i = 0; i < n; i++) { s[2*i] = d[p[i] >> 4]; s[2*i+1] = d[p[i] & 15]; }
    s[2 * n] = '\0';
    json_object *o = json_object_new_string(s);
    nc_wipe(s, 2 * n);
    free(s);
    return o;
}

static void add_read(json_object *o, nc_outcome_t outcome, nc_why_t why) {
    json_object_object_add(o, "outcome",
                           json_object_new_string(nc_outcome_str(outcome)));
    json_object_object_add(o, "why", json_object_new_string(nc_why_str(why)));
}

static int parse_salt(const char *hex, uint8_t out[NC_SALT_LEN]) {
    if (!hex || strnlen(hex, 2 * NC_SALT_LEN + 1) != 2 * NC_SALT_LEN) return -1;
    for (size_t i = 0; i < NC_SALT_LEN; i++) {
        int v[2];
        for (int j = 0; j < 2; j++) {
            char c = hex[2 * i + (size_t)j];
            v[j] = (c >= '0' && c <= '9') ? c - '0'
                 : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
            if (v[j] < 0) return -1;
        }
        out[i] = (uint8_t)(v[0] << 4 | v[1]);
    }
    return 0;
}

static int parse_u64(const char *s, uint64_t *out) {
    if (!s) return -1;
    size_t n = strnlen(s, 21);
    if (n == 0 || n > 20 || (n > 1 && s[0] == '0')) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        uint64_t d = (uint64_t)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10u) return -1;
        v = v * 10u + d;
    }
    *out = v;
    return 0;
}

/* Lowercase hex of 1..max bytes -> a malloc'd buffer (caller wipes and
 * frees). */
static int parse_hex_var(const char *hex, size_t max, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;
    if (!hex) return -1;
    size_t h = strnlen(hex, 2 * max + 1);
    if (h == 0 || h > 2 * max || (h & 1u)) return -1;
    uint8_t *b = malloc(h / 2);
    if (!b) return -1;
    for (size_t i = 0; i < h / 2; i++) {
        int v[2];
        for (int j = 0; j < 2; j++) {
            char c = hex[2 * i + (size_t)j];
            v[j] = (c >= '0' && c <= '9') ? c - '0'
                 : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
            if (v[j] < 0) { nc_wipe(b, h / 2); free(b); return -1; }
        }
        b[i] = (uint8_t)(v[0] << 4 | v[1]);
    }
    *out = b;
    *out_len = h / 2;
    return 0;
}

static int parse_hex_fixed(const char *hex, uint8_t *out, size_t n) {
    uint8_t *b;
    size_t len;
    if (parse_hex_var(hex, n, &b, &len) != 0) return -1;
    int rc = len == n ? 0 : -1;
    if (rc == 0) memcpy(out, b, n);
    nc_wipe(b, len);
    free(b);
    return rc;
}

/* ── Messages state (the session itself is the host's) ──────────────── */

static nc_keys_t      g_keys;
static nc_ctx_t       g_ctx;
static char          *g_words;          /* the caller's words, until unlock */
static size_t         g_words_len;
static uint8_t        g_hist_key[NC_HISTORY_KEY_LEN];
static int g_used;                      /* nc_unlock ran (success or not)   */
static int g_unlocked;                  /* keys derived and checked         */
static int g_closed;                    /* nc_lock ran: terminal            */
static int g_inside;                    /* an nc export is in the bracket   */
static int g_hist_ok;                   /* g_hist_key holds K               */

static int nc_begin(void) {
    if (g_closed) return fail("Messages is locked.");
    if (nc_host_begin() != 0) return fail("%s", nc_host_error());
    g_inside = 1;
    g_error[0] = '\0';
    result_drop();
    return 0;
}

static int nc_end(int rc) {
    g_inside = 0;
    int stopped = nc_host_end();
    if (g_closed) nc_session_wipe();        /* nc_lock ran meanwhile       */
    if (stopped || g_closed) { result_drop(); return fail("Wallet is locked."); }
    return rc;
}

static int session_ok(void) {
    if (!g_unlocked) return fail("Messages is not connected.");
    if (!g_ctx.client || g_ctx.client != nc_host_client() ||
        !nodus_client_is_ready(g_ctx.client))
        return fail("Nodus connection is not ready. Try again shortly.");
    return 0;
}

/* ── peer cache: verified profile keys, in memory until lock ────────── */

#define NC_PEERS_MAX 64
static nc_peer_t g_peers[NC_PEERS_MAX];
static int g_n_peers, g_next_peer;

static const nc_peer_t *peer_find(const char *fp) {
    if (!fp) return NULL;
    for (int i = 0; i < g_n_peers; i++)
        if (strcmp(g_peers[i].fp, fp) == 0) return &g_peers[i];
    return NULL;
}

static void peer_store(const nc_peer_t *p) {
    for (int i = 0; i < g_n_peers; i++)
        if (strcmp(g_peers[i].fp, p->fp) == 0) { g_peers[i] = *p; return; }
    if (g_n_peers < NC_PEERS_MAX) { g_peers[g_n_peers++] = *p; return; }
    g_peers[g_next_peer] = *p;               /* oldest slot, round robin   */
    g_next_peer = (g_next_peer + 1) % NC_PEERS_MAX;
}

static const nc_peer_t *peer_need(const char *fp) {
    const nc_peer_t *p = peer_find(fp);
    if (!p) fail("Load this contact's profile first.");
    return p;
}

/* ── unlock ─────────────────────────────────────────────────────────── */

/* The words: a buffer of `len` bytes the page fills (UTF-8, NFKD as the
 * wallet normalises them); a NUL follows. nc_unlock wipes and frees it on
 * every path. */
char *nc_words_alloc(int len) {
    if (g_words) { nc_wipe(g_words, g_words_len); free(g_words); g_words = NULL; }
    if (len <= 0 || len > 4096 || g_used || g_closed) return NULL;
    g_words = calloc(1, (size_t)len + 1);
    g_words_len = g_words ? (size_t)len + 1 : 0;
    return g_words;
}

static void words_drop(void) {
    if (g_words) { nc_wipe(g_words, g_words_len); free(g_words); }
    g_words = NULL;
    g_words_len = 0;
}

/* Runs after the wallet's nsw_unlock, on ITS session: no client is created
 * and nothing is sent. Derives the Messages keys from the words and refuses
 * unless they belong to the session identity. Synchronous in practice
 * (PBKDF2 + key generation, no network wait), bracketed like the others. */
int nc_unlock(int fresh) {
    if (nc_begin() != 0) { words_drop(); return -1; }
    if (g_used) { words_drop(); return nc_end(fail("This Messages connection was already used.")); }
    g_used = 1;
    nodus_client_t *client = nc_host_client();
    const nodus_identity_t *session_id = nc_host_identity();
    if (!client || !session_id) {
        words_drop();
        return nc_end(fail("Connect the wallet to Nodus first."));
    }
    if (!g_words) return nc_end(fail("Recovery phrase is missing."));
    int rc = nc_keys_from_words(g_words, &g_keys);
    words_drop();
    if (rc != NC_OK) return nc_end(fail("Recovery phrase was refused."));
    if (memcmp(g_keys.id.pk.bytes, session_id->pk.bytes, sizeof(session_id->pk.bytes)) != 0) {
        nc_keys_wipe(&g_keys);
        return nc_end(fail("These words belong to another Nodus address. Nothing was connected."));
    }

    g_ctx.client = client;
    g_ctx.keys = &g_keys;
    g_ctx.fresh = fresh ? true : false;
    g_ctx.cancel = nc_host_cancel();
    g_unlocked = 1;

    json_object *o = json_object_new_object();
    json_object_object_add(o, "fingerprint", json_object_new_string(g_keys.fp));
    json_object_object_add(o, "fresh", json_object_new_boolean(g_ctx.fresh));
    return nc_end(set_result(o));
}

/* ── R1 ─────────────────────────────────────────────────────────────── */

static json_object *profile_json(const dna_unified_identity_t *id) {
    json_object *p = json_object_new_object();
    json_object_object_add(p, "fingerprint", json_object_new_string(id->fingerprint));
    /* registered_name is shown as a name only after the name->fingerprint
     * check (design §1.9 G9) — NC-4's job; here it is a claim. */
    json_object_object_add(p, "claimed_name",
                           json_object_new_string(id->has_registered_name ? id->registered_name : ""));
    json_object_object_add(p, "bio", json_object_new_string(id->bio));
    json_object_object_add(p, "location", json_object_new_string(id->location));
    json_object_object_add(p, "website", json_object_new_string(id->website));
    json_object_object_add(p, "avatar_base64", json_object_new_string(id->avatar_base64));
    json_object *w = json_object_new_object();
    json_object_object_add(w, "backbone", json_object_new_string(id->wallets.backbone));
    json_object_object_add(w, "eth", json_object_new_string(id->wallets.eth));
    json_object_object_add(w, "sol", json_object_new_string(id->wallets.sol));
    json_object_object_add(w, "trx", json_object_new_string(id->wallets.trx));
    json_object_object_add(w, "bsc", json_object_new_string(id->wallets.bsc));
    json_object_object_add(p, "wallets", w);
    json_object *s = json_object_new_object();
    json_object_object_add(s, "telegram", json_object_new_string(id->socials.telegram));
    json_object_object_add(s, "x", json_object_new_string(id->socials.x));
    json_object_object_add(s, "github", json_object_new_string(id->socials.github));
    json_object_object_add(s, "facebook", json_object_new_string(id->socials.facebook));
    json_object_object_add(s, "instagram", json_object_new_string(id->socials.instagram));
    json_object_object_add(s, "linkedin", json_object_new_string(id->socials.linkedin));
    json_object_object_add(s, "google", json_object_new_string(id->socials.google));
    json_object_object_add(p, "socials", s);
    json_object_object_add(p, "has_mlkem", json_object_new_boolean(id->has_mlkem_pubkey));
    json_object_object_add(p, "version", jstr_u64(id->version));
    json_object_object_add(p, "timestamp", jstr_u64(id->timestamp));
    return p;
}

int nc_profile_get(const char *fp) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    nodus_key_t chk;
    if (nc_fp_parse(fp, &chk) != 0) return nc_end(fail("Invalid Nodus address."));
    nc_read_t raw;
    dna_unified_identity_t *id = NULL;
    nc_peer_t peer;
    nc_profile_read(&g_ctx, fp, &raw, &id, &peer);
    json_object *o = json_object_new_object();
    add_read(o, raw.outcome, raw.why);
    if (raw.outcome == NC_FOUND && id) {
        json_object_object_add(o, "profile", profile_json(id));
        if (strcmp(fp, g_keys.fp) != 0) peer_store(&peer);
    }
    dna_identity_free(id);
    nc_read_clear(&raw);
    return nc_end(set_result(o));
}

int nc_profile_update(const char *patch_json) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    nc_profile_result_t r;
    int rc = nc_profile_publish(&g_ctx, patch_json, &r);
    if (rc != NC_OK) return nc_end(fail("Profile update did not run (%d).", rc));
    static const char *const ST[] = { "published", "wait", "taken", "failed", "bad_patch" };
    json_object *o = json_object_new_object();
    json_object_object_add(o, "status", json_object_new_string(ST[r.status]));
    json_object *rd = json_object_new_object();
    add_read(rd, r.read.outcome, r.read.why);
    json_object_object_add(o, "read", rd);
    json_object_object_add(o, "created", json_object_new_boolean(r.created));
    json_object_object_add(o, "put_rc", json_object_new_int(r.put_rc));
    json_object_object_add(o, "version", jstr_u64(r.version));
    return nc_end(set_result(o));
}

/* ── R2 ─────────────────────────────────────────────────────────────── */

int nc_requests_get(void) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    nc_requests_t r;
    int rc = nc_requests_fetch(&g_ctx, &r);
    if (rc != NC_OK) return nc_end(fail("Contact requests could not be read (%d).", rc));
    json_object *o = json_object_new_object();
    add_read(o, r.read.outcome, r.read.why);
    json_object_object_add(o, "partial", json_object_new_boolean(true));
    json_object *c = json_object_new_object();
    json_object_object_add(c, "undecodable", jstr_u64(r.read.undecodable));
    json_object_object_add(c, "bad_signature", jstr_u64(r.read.bad_sig));
    json_object_object_add(c, "wrong_key", jstr_u64(r.read.wrong_key));
    json_object_object_add(c, "bad_request", jstr_u64(r.bad_request));
    json_object_object_add(c, "cancelled", jstr_u64(r.cancelled));
    json_object_object_add(o, "dropped", c);
    json_object *a = json_object_new_array();
    for (size_t i = 0; i < r.count; i++) {
        const nc_request_t *q = &r.items[i];
        json_object *e = json_object_new_object();
        json_object_object_add(e, "sender", json_object_new_string(q->sender_fp));
        json_object_object_add(e, "claimed_name", json_object_new_string(q->sender_name));
        json_object_object_add(e, "message", json_object_new_string(q->message));
        json_object_object_add(e, "timestamp", jstr_u64(q->timestamp));
        json_object_object_add(e, "expiry", jstr_u64(q->expiry));
        json_object_object_add(e, "salt", q->has_salt ? jhex(q->salt, NC_SALT_LEN) : NULL);
        json_object_object_add(e, "acceptance", json_object_new_boolean(q->is_acceptance));
        json_object_array_add(a, e);
    }
    json_object_object_add(o, "requests", a);
    nc_requests_clear(&r);
    return nc_end(set_result(o));
}

int nc_request_new(const char *fp, const char *message) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    /* A fresh per-contact salt, as the app does at send
     * (dna_engine_contacts.c:349-356). */
    uint8_t salt[NC_SALT_LEN];
    if (qgp_platform_random(salt, sizeof(salt)) != 0)
        return nc_end(fail("No randomness available."));
    int rc = nc_request_send(&g_ctx, fp, message && message[0] ? message : NULL, salt);
    if (rc != 0) {
        nc_wipe(salt, sizeof(salt));
        return nc_end(fail("Contact request was not sent (%d).", rc));
    }
    json_object *o = json_object_new_object();
    json_object_object_add(o, "salt", jhex(salt, sizeof(salt)));
    nc_wipe(salt, sizeof(salt));
    return nc_end(set_result(o));
}

int nc_request_approve(const char *fp, const char *salt_hex) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    uint8_t salt[NC_SALT_LEN];
    const uint8_t *sp = NULL;
    if (salt_hex && salt_hex[0]) {
        if (parse_salt(salt_hex, salt) != 0) return nc_end(fail("Invalid salt."));
        sp = salt;
    }
    int rc = nc_request_accept(&g_ctx, fp, sp);
    nc_wipe(salt, sizeof(salt));
    if (rc != 0) return nc_end(fail("Acceptance was not sent (%d).", rc));
    return nc_end(set_result(json_object_new_object()));
}

int nc_request_withdraw(const char *fp) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    int rc = nc_request_cancel(&g_ctx, fp);
    if (rc != 0) return nc_end(fail("Request was not withdrawn (%d).", rc));
    return nc_end(set_result(json_object_new_object()));
}

/* ── R3 ─────────────────────────────────────────────────────────────── */

int nc_salt_get(const char *fp) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    const nc_peer_t *peer = peer_need(fp);
    if (!peer) return nc_end(-1);
    nc_salt_read_t r;
    int rc = nc_salt_read(&g_ctx, peer, &r);
    if (rc != NC_OK) return nc_end(fail("Salt could not be read (%d).", rc));
    json_object *o = json_object_new_object();
    add_read(o, r.read.outcome, r.read.why);
    json_object_object_add(o, "partial", json_object_new_boolean(true));
    json_object_object_add(o, "found", json_object_new_boolean(r.found));
    json_object_object_add(o, "salt", r.found ? jhex(r.salt, NC_SALT_LEN) : NULL);
    json_object_object_add(o, "authenticated", jstr_u64(r.authenticated));
    nc_salt_read_clear(&r);
    return nc_end(set_result(o));
}

/* Synchronous and pure: the native reconcile rule. */
int nc_salt_pick(const char *local_hex, const char *dht_hex) {
    uint8_t l[NC_SALT_LEN], d[NC_SALT_LEN], c[NC_SALT_LEN];
    const uint8_t *lp = NULL, *dp = NULL;
    if (local_hex && local_hex[0]) { if (parse_salt(local_hex, l) != 0) return fail("Invalid salt."); lp = l; }
    if (dht_hex && dht_hex[0]) { if (parse_salt(dht_hex, d) != 0) return fail("Invalid salt."); dp = d; }
    bool republish = false;
    nc_salt_choice_t ch = nc_salt_choose(lp, dp, c, &republish);
    static const char *const CH[] = { "keep_local", "take_dht", "none" };
    json_object *o = json_object_new_object();
    json_object_object_add(o, "choice", json_object_new_string(CH[ch]));
    json_object_object_add(o, "salt", ch == NC_SALT_NONE ? NULL : jhex(c, NC_SALT_LEN));
    json_object_object_add(o, "republish_wanted", json_object_new_boolean(republish));
    nc_wipe(l, sizeof(l)); nc_wipe(d, sizeof(d)); nc_wipe(c, sizeof(c));
    return set_result(o);
}

/* Read + reconcile + (gated) publish; local_hex "" = no local salt. The
 * page stores "salt" unless status is "wait". */
int nc_salt_reconcile(const char *fp, const char *local_hex) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    const nc_peer_t *peer = peer_need(fp);
    if (!peer) return nc_end(-1);
    uint8_t l[NC_SALT_LEN];
    const uint8_t *lp = NULL;
    if (local_hex && local_hex[0]) {
        if (parse_salt(local_hex, l) != 0) return nc_end(fail("Invalid salt."));
        lp = l;
    }
    nc_salt_sync_t s;
    int rc = nc_salt_sync(&g_ctx, peer, lp, &s);
    nc_wipe(l, sizeof(l));
    if (rc != NC_OK) { nc_salt_sync_clear(&s); return nc_end(fail("Salt could not be reconciled (%d).", rc)); }
    static const char *const ST[] = { "nothing_to_write", "published", "wait", "failed" };
    static const char *const CH[] = { "keep_local", "take_dht", "none" };
    json_object *o = json_object_new_object();
    json_object_object_add(o, "status", json_object_new_string(ST[s.status]));
    add_read(o, s.read.read.outcome, s.read.read.why);
    json_object_object_add(o, "choice", json_object_new_string(CH[s.choice]));
    json_object_object_add(o, "salt", (s.status == NC_SALT_SYNC_WAIT || s.choice == NC_SALT_NONE)
                                          ? NULL : jhex(s.chosen, NC_SALT_LEN));
    json_object_object_add(o, "put_rc", json_object_new_int(s.put_rc));
    nc_salt_sync_clear(&s);
    return nc_end(set_result(o));
}

/* ── R4 ─────────────────────────────────────────────────────────────── */

int nc_contacts_get(void) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    nc_contactlist_t l;
    nc_contactlist_read(&g_ctx, &l);
    json_object *o = json_object_new_object();
    add_read(o, l.read.outcome, l.read.why);
    json_object_object_add(o, "invalid", jstr_u64(l.invalid));
    json_object_object_add(o, "timestamp", jstr_u64(l.timestamp));
    json_object *a = json_object_new_array();
    for (size_t i = 0; i < l.count; i++) {
        json_object *e = json_object_new_object();
        json_object_object_add(e, "fp", json_object_new_string(l.items[i].fp));
        json_object_object_add(e, "salt", l.items[i].has_salt ? jhex(l.items[i].salt, NC_SALT_LEN) : NULL);
        json_object_array_add(a, e);
    }
    json_object_object_add(o, "contacts", a);
    nc_contactlist_clear(&l);
    return nc_end(set_result(o));
}

/* add_json: [{"fp":"<128 hex>","salt":"<64 hex>"|null}, ...] — merged into
 * the list read in the same call (merge only). */
int nc_contacts_add(const char *add_json) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    json_object *arr = add_json ? json_tokener_parse(add_json) : NULL;
    size_t n = arr && json_object_is_type(arr, json_type_array) ? json_object_array_length(arr) : 0;
    if (n == 0 || n > 4096) {
        if (arr) json_object_put(arr);
        return nc_end(fail("Invalid contact list."));
    }
    nc_contact_t *c = calloc(n, sizeof(*c));
    if (!c) { json_object_put(arr); return nc_end(fail("Out of memory.")); }
    for (size_t i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(arr, i), *jf, *js;
        const char *fp = (e && json_object_object_get_ex(e, "fp", &jf) &&
                          json_object_is_type(jf, json_type_string))
                             ? json_object_get_string(jf) : NULL;
        nodus_key_t chk;
        if (!fp || nc_fp_parse(fp, &chk) != 0) {
            nc_wipe(c, n * sizeof(*c)); free(c); json_object_put(arr);
            return nc_end(fail("Invalid contact list."));
        }
        memcpy(c[i].fp, fp, NC_FP_HEX_LEN);
        if (json_object_object_get_ex(e, "salt", &js) && js &&
            !json_object_is_type(js, json_type_null)) {
            if (!json_object_is_type(js, json_type_string) ||
                parse_salt(json_object_get_string(js), c[i].salt) != 0) {
                nc_wipe(c, n * sizeof(*c)); free(c); json_object_put(arr);
                return nc_end(fail("Invalid salt."));
            }
            c[i].has_salt = true;
        }
    }
    json_object_put(arr);
    nc_list_result_t r;
    int rc = nc_contactlist_add(&g_ctx, c, n, &r);
    nc_wipe(c, n * sizeof(*c));
    free(c);
    if (rc != NC_OK) return nc_end(fail("Contact list update did not run (%d).", rc));
    static const char *const ST[] = { "published", "unchanged", "wait", "taken", "failed", "refused" };
    json_object *o = json_object_new_object();
    json_object_object_add(o, "status", json_object_new_string(ST[r.status]));
    add_read(o, r.read_outcome, r.read_why);
    json_object_object_add(o, "created", json_object_new_boolean(r.created));
    json_object_object_add(o, "count_before", jstr_u64(r.count_before));
    json_object_object_add(o, "count_after", jstr_u64(r.count_after));
    json_object_object_add(o, "salt_kept", jstr_u64(r.salt_kept));
    json_object_object_add(o, "put_rc", json_object_new_int(r.put_rc));
    return nc_end(set_result(o));
}

/* ── R5 ─────────────────────────────────────────────────────────────── */

static char g_day[21];
const char *nc_day_today(void) {
    snprintf(g_day, sizeof(g_day), "%llu",
             (unsigned long long)dht_dm_outbox_get_day_bucket());
    return g_day;
}

static int day_arg(const char *day_dec, uint64_t *day) {
    if (!day_dec || !day_dec[0]) { *day = dht_dm_outbox_get_day_bucket(); return 0; }
    return parse_u64(day_dec, day);
}

/* msgs_json: [{"seq":"<u64>","ts":"<u64>","text":"<utf-8>"}, ...] — the
 * whole pending set for this recipient (design §1.4 R5). */
int nc_outbox_send(const char *fp, const char *salt_hex, const char *msgs_json) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    const nc_peer_t *peer = peer_need(fp);
    if (!peer) return nc_end(-1);
    uint8_t salt[NC_SALT_LEN];
    if (parse_salt(salt_hex, salt) != 0) return nc_end(fail("No salt for this contact: nothing is sent."));
    json_object *arr = msgs_json ? json_tokener_parse(msgs_json) : NULL;
    size_t n = arr && json_object_is_type(arr, json_type_array) ? json_object_array_length(arr) : 0;
    if (n == 0 || n > NC_OUTBOX_MAX_MESSAGES) {
        if (arr) json_object_put(arr);
        return nc_end(fail("Invalid message list."));
    }
    nc_outmsg_t *m = calloc(n, sizeof(*m));
    if (!m) { json_object_put(arr); return nc_end(fail("Out of memory.")); }
    for (size_t i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(arr, i), *js, *jt, *jx;
        if (!e || !json_object_object_get_ex(e, "seq", &js) ||
            !json_object_object_get_ex(e, "ts", &jt) ||
            !json_object_object_get_ex(e, "text", &jx) ||
            !json_object_is_type(jx, json_type_string) ||
            parse_u64(json_object_get_string(js), &m[i].seq) != 0 ||
            parse_u64(json_object_get_string(jt), &m[i].timestamp) != 0) {
            free(m); json_object_put(arr);
            return nc_end(fail("Invalid message list."));
        }
        m[i].text = json_object_get_string(jx);
    }
    uint64_t day = dht_dm_outbox_get_day_bucket();
    uint8_t alg = 0;
    int rc = nc_outbox_publish(&g_ctx, peer, salt, day, m, n, &alg);
    free(m);
    json_object_put(arr);
    nc_wipe(salt, sizeof(salt));
    if (rc != 0) return nc_end(fail("Messages were not sent (%d).", rc));
    json_object *o = json_object_new_object();
    json_object_object_add(o, "day", jstr_u64(day));
    json_object_object_add(o, "alg", json_object_new_int(alg));
    json_object_object_add(o, "count", jstr_u64(n));
    return nc_end(set_result(o));
}

int nc_outbox_get(const char *fp, const char *salt_hex, const char *day_dec) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    const nc_peer_t *peer = peer_need(fp);
    if (!peer) return nc_end(-1);
    uint8_t salt[NC_SALT_LEN];
    uint64_t day;
    if (parse_salt(salt_hex, salt) != 0 || day_arg(day_dec, &day) != 0)
        return nc_end(fail("Invalid salt or day."));
    nc_inbox_t in;
    int rc = nc_outbox_fetch_day(&g_ctx, peer, salt, day, &in);
    nc_wipe(salt, sizeof(salt));
    if (rc != NC_OK) return nc_end(fail("Messages could not be read (%d).", rc));
    json_object *o = json_object_new_object();
    add_read(o, in.read.outcome, in.read.why);
    json_object_object_add(o, "day", jstr_u64(day));
    json_object_object_add(o, "dropped", jstr_u64(in.dropped));
    /* authentic non-chat payloads: counted, never returned as text */
    json_object_object_add(o, "other", jstr_u64(in.other));
    json_object *a = json_object_new_array();
    for (size_t i = 0; i < in.count; i++) {
        json_object *e = json_object_new_object();
        json_object_object_add(e, "seq", jstr_u64(in.items[i].seq));
        json_object_object_add(e, "sender_ts", jstr_u64(in.items[i].sender_timestamp));
        json_object_object_add(e, "text_hex", jhex(in.items[i].plaintext, in.items[i].plaintext_len));
        json_object_array_add(a, e);
    }
    json_object_object_add(o, "messages", a);
    for (size_t i = 0; i < in.count; i++)
        nc_wipe(in.items[i].plaintext, in.items[i].plaintext_len);
    nc_inbox_clear(&in);
    return nc_end(set_result(o));
}

/* ack_ts_dec: the newest sender timestamp (decimal unix seconds, > 0) of
 * this contact's messages the page has durably stored — never a clock
 * (nc_core.h nc_ack_publish, design §5 G11). */
int nc_ack_send(const char *fp, const char *salt_hex, const char *ack_ts_dec) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    uint8_t salt[NC_SALT_LEN];
    uint64_t ack_ts;
    if (parse_u64(ack_ts_dec, &ack_ts) != 0 || ack_ts == 0)
        return nc_end(fail("Invalid delivery confirmation."));
    if (parse_salt(salt_hex, salt) != 0) return nc_end(fail("Invalid salt."));
    int rc = nc_ack_publish(&g_ctx, fp, salt, ack_ts);
    nc_wipe(salt, sizeof(salt));
    if (rc != 0) return nc_end(fail("Delivery confirmation was not sent (%d).", rc));
    return nc_end(set_result(json_object_new_object()));
}

int nc_ack_get(const char *fp, const char *salt_hex) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    uint8_t salt[NC_SALT_LEN];
    if (parse_salt(salt_hex, salt) != 0) return nc_end(fail("Invalid salt."));
    nc_read_t raw;
    uint64_t ts = 0;
    nc_ack_read(&g_ctx, fp, salt, &raw, &ts);
    nc_wipe(salt, sizeof(salt));
    json_object *o = json_object_new_object();
    add_read(o, raw.outcome, raw.why);
    json_object_object_add(o, "ack_ts", raw.outcome == NC_FOUND ? jstr_u64(ts) : NULL);
    nc_read_clear(&raw);
    return nc_end(set_result(o));
}

/* ── history at rest (NC-4a crypto, decision 2026-09-30-connect-history-
 *    at-rest.md rev 2): K stays in this module; no network ────────────── */

/* K = nc_history_derive_key(session ML-DSA-87 sk, vault id). vault_id_hex:
 * the wallet vault's 16-byte id (src/vault.js), 32 lowercase hex. A second
 * call replaces K. */
int nc_hist_key(const char *vault_id_hex) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    const nodus_identity_t *session_id = nc_host_identity();
    if (!session_id) return nc_end(fail("Messages is not connected."));
    uint8_t vid[NC_HISTORY_VAULT_ID_LEN];
    if (parse_hex_fixed(vault_id_hex, vid, sizeof(vid)) != 0)
        return nc_end(fail("Invalid vault id."));
    g_hist_ok = 0;
    int rc = nc_history_derive_key(session_id->sk.bytes, sizeof(session_id->sk.bytes),
                                   vid, g_hist_key);
    nc_wipe(vid, sizeof(vid));
    if (rc != NC_HISTORY_OK) return nc_end(fail("History key could not be derived (%d).", rc));
    g_hist_ok = 1;
    return nc_end(set_result(json_object_new_object()));
}

/* One record. store / id: UTF-8 strings (the AAD, nc_history.h); pt_hex:
 * 1..NC_HIST_PT_MAX bytes; counter_dec: the vault's invocation counter.
 * Result { nonce, ct, tag (hex), counter (decimal, +1) }. */
int nc_hist_encrypt(const char *store, const char *id, const char *pt_hex,
                    const char *counter_dec) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked || !g_hist_ok) return nc_end(fail("History key is not ready."));
    uint64_t counter;
    if (!store || !id || parse_u64(counter_dec, &counter) != 0)
        return nc_end(fail("Invalid history record."));
    uint8_t *pt;
    size_t pt_len;
    if (parse_hex_var(pt_hex, NC_HIST_PT_MAX, &pt, &pt_len) != 0)
        return nc_end(fail("Invalid history record."));
    uint8_t *ct = malloc(pt_len);
    if (!ct) { nc_wipe(pt, pt_len); free(pt); return nc_end(fail("Out of memory.")); }
    uint8_t nonce[NC_HISTORY_NONCE_LEN], tag[NC_HISTORY_TAG_LEN];
    int rc = nc_history_encrypt(g_hist_key, &counter,
                                (const uint8_t *)store, strlen(store),
                                (const uint8_t *)id, strlen(id),
                                pt, pt_len, ct, nonce, tag);
    nc_wipe(pt, pt_len);
    free(pt);
    if (rc != NC_HISTORY_OK) {
        free(ct);
        return nc_end(rc == NC_HISTORY_REFUSED
                      ? fail("History record refused (budget used up or invalid input).")
                      : fail("History record could not be sealed."));
    }
    json_object *o = json_object_new_object();
    json_object_object_add(o, "nonce", jhex(nonce, sizeof(nonce)));
    json_object_object_add(o, "ct", jhex(ct, pt_len));
    json_object_object_add(o, "tag", jhex(tag, sizeof(tag)));
    json_object_object_add(o, "counter", jstr_u64(counter));
    free(ct);
    return nc_end(set_result(o));
}

/* Result { pt (hex) }; a record that does not authenticate is an error. */
int nc_hist_decrypt(const char *store, const char *id, const char *nonce_hex,
                    const char *ct_hex, const char *tag_hex) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked || !g_hist_ok) return nc_end(fail("History key is not ready."));
    uint8_t nonce[NC_HISTORY_NONCE_LEN], tag[NC_HISTORY_TAG_LEN];
    uint8_t *ct;
    size_t ct_len;
    if (!store || !id || parse_hex_fixed(nonce_hex, nonce, sizeof(nonce)) != 0 ||
        parse_hex_fixed(tag_hex, tag, sizeof(tag)) != 0 ||
        parse_hex_var(ct_hex, NC_HIST_PT_MAX, &ct, &ct_len) != 0)
        return nc_end(fail("Invalid history record."));
    uint8_t *pt = malloc(ct_len);
    if (!pt) { free(ct); return nc_end(fail("Out of memory.")); }
    int rc = nc_history_decrypt(g_hist_key,
                                (const uint8_t *)store, strlen(store),
                                (const uint8_t *)id, strlen(id),
                                ct, ct_len, nonce, tag, pt);
    free(ct);
    if (rc != NC_HISTORY_OK) {
        free(pt);                           /* wiped by nc_history_decrypt */
        return nc_end(fail("History record did not open."));
    }
    json_object *o = json_object_new_object();
    json_object_object_add(o, "pt", jhex(pt, ct_len));
    nc_wipe(pt, ct_len);
    free(pt);
    return nc_end(set_result(o));
}

/* ── lock: synchronous, never reaches emscripten_sleep ───────────────── */

/* Every Messages secret and cache. Called by the host's lock (nsw_lock,
 * which then closes the session; JS zeroes the linear memory and aborts
 * the instance) and by nc_lock / nc_end below. */
void nc_session_wipe(void) {
    nc_keys_wipe(&g_keys);
    words_drop();
    result_drop();
    nc_wipe(g_hist_key, sizeof(g_hist_key));
    g_hist_ok = 0;
    nc_wipe(g_peers, sizeof(g_peers));
    g_n_peers = 0;
    g_next_peer = 0;
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_unlocked = 0;
}

/* Always set: the context's cancel flag once Messages is closed. */
static volatile const int g_stopped = 1;

/* Closes Messages only; the wallet's session stays (its lock is nsw_lock).
 * Terminal for this module instance. With an nc export suspended in the
 * bracket, the wipe runs when it returns (nc_end), so the resumed export
 * never touches wiped keys — and the context's cancel now reads the set
 * flag above instead of the wallet's (which nc_lock does not set), so a
 * suspended gated export (read, then PUT) refuses its PUT, and any further
 * read, with NC_ERR_CANCELLED (nc_read.c checks ctx->cancel before every
 * network call). Before nc_lock the pointer is the wallet's cancel flag
 * (nc_unlock), so the wallet's cancel/lock stops Messages too. */
void nc_lock(void) {
    g_closed = 1;
    g_ctx.cancel = &g_stopped;
    if (!g_inside) nc_session_wipe();
}
