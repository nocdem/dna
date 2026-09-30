/* Nodus Connect thin core — the standalone WebAssembly entry (package
 * NC-2 of docs/plans/2026-09-24-web-connect-design.md rev 5, §1.9).
 *
 * TEST ARTIFACT, NOT FOR SHIPPING BESIDE THE WALLET. This entry owns its
 * own tier-2 session. The wallet's NODUS send module (crypto/nodus-send-
 * wasm.c) owns another; the same identity on two sessions to one node knock
 * each other off (nodus_auth.c:95-116, design §1.1). Package NC-4 links the
 * library (nc_*.c except this file) into the ONE shared module and passes
 * that module's session in nc_ctx_t.
 *
 * Call model (the send module's, nodus-send-wasm.c "op bracket"):
 *   - every async export (may reach emscripten_sleep) runs inside
 *     nc_begin/nc_end: one at a time, none after cancel/lock;
 *   - nc_cancel / nc_lock are synchronous and never reach emscripten_sleep,
 *     so JS may call them while another export is suspended;
 *   - each async export does ONE bounded network step (one GET, one GET_ALL
 *     or one PUT, each bounded by the client's request timeout) so the JS
 *     queue can put a wallet operation between two sync steps (design §6.4
 *     F7). No export loops over contacts or days.
 *   - results are one JSON object (json-c), read with nc_result(); u64
 *     values cross as decimal strings, bytes as lowercase hex.
 *
 * RANDOMNESS: qgp_platform_random below is the only source (nodus_random,
 * qgp_randombytes and the hedged ML-DSA rnd all call it), getentropy() ->
 * crypto.getRandomValues, exactly as nodus-send-wasm.c.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef __EMSCRIPTEN__
#error "nc_wasm.c is the browser entry; native tests link the library files only"
#endif

#include "nc_core.h"

#include "dht/shared/dht_dm_outbox.h"
#include "crypto/nodus_identity.h"
#include "crypto/utils/qgp_log.h"

#include <emscripten.h>
#include <json-c/json.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>                         /* getentropy */

#define LOG_TAG "NC_WASM"

/* ── memory hygiene / randomness (nodus-send-wasm.c) ─────────────────── */

static void nc_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

void qgp_secure_memzero(void *ptr, size_t len) {
    if (ptr) nc_wipe(ptr, len);
}

int qgp_platform_random(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return -1;
    while (len > 0) {                       /* getentropy: <= 256 per call */
        size_t n = len > 256 ? 256 : len;
        if (getentropy(buf, n) != 0) return -1;
        buf += n;
        len -= n;
    }
    return 0;
}

/* dna_context_new (messenger/dna_api.c:132-149) refuses to build a context
 * without a home directory; it only records "<home>/.qgp" and the Seal code
 * this module calls never reads it. qgp_platform_linux.c is not linked (its
 * qgp_platform_random would replace the one above), so the linux body is
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

/* ── network settings (the embedded list, nc_servers_parse) ─────────── */

static nc_servers_t g_net;
static int g_net_ok;

/* ── session state ──────────────────────────────────────────────────── */

static nodus_client_t g_client;         /* static: large; pending slots must
                                         * outlive any wait                 */
static nc_keys_t      g_keys;
static nc_ctx_t       g_ctx;
static char          *g_words;          /* the caller's words, until unlock */
static size_t         g_words_len;
static int g_client_inited, g_used, g_unlocked, g_locked, g_busy;
static volatile int g_cancel;

int nc_net_load(const char *json) {
    if (g_used) return fail("The network is fixed once Messages connects.");
    char why[128];
    g_net_ok = 0;
    if (nc_servers_parse(json, &g_net, why, sizeof(why)) != 0)
        return fail("Nodus server list refused: %s.", why);
    g_net_ok = 1;
    return 0;
}

static int nc_begin(void) {
    if (g_locked || g_cancel) return fail("Wallet is locked.");
    if (g_busy) return fail("Another Messages operation is still running.");
    g_busy = 1;
    g_error[0] = '\0';
    result_drop();
    return 0;
}

static int nc_end(int rc) {
    g_busy = 0;
    if (g_locked || g_cancel) { result_drop(); return fail("Wallet is locked."); }
    return rc;
}

static int session_ok(void) {
    if (!g_unlocked) return fail("Messages is not connected.");
    if (!nodus_client_is_ready(&g_client))
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
    if (len <= 0 || len > 4096 || g_used) return NULL;
    g_words = calloc(1, (size_t)len + 1);
    g_words_len = g_words ? (size_t)len + 1 : 0;
    return g_words;
}

static void words_drop(void) {
    if (g_words) { nc_wipe(g_words, g_words_len); free(g_words); }
    g_words = NULL;
    g_words_len = 0;
}

int nc_unlock(int fresh) {
    if (nc_begin() != 0) { words_drop(); return -1; }
    if (g_used) { words_drop(); return nc_end(fail("This Messages connection was already used.")); }
    g_used = 1;
    if (!g_net_ok) { words_drop(); return nc_end(fail("Nodus server list is missing.")); }
    if (!g_words) return nc_end(fail("Recovery phrase is missing."));
    int rc = nc_keys_from_words(g_words, &g_keys);
    words_drop();
    if (rc != NC_OK) return nc_end(fail("Recovery phrase was refused."));

    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    memcpy(cfg.servers, g_net.endpoints, sizeof(cfg.servers));
    cfg.server_count = g_net.n_endpoints;
    cfg.auto_reconnect = true;
    cfg.pinned_server_fps = g_net.pins;
    cfg.pinned_server_fp_count = g_net.n_pins;
    if (nodus_client_init(&g_client, &cfg, &g_keys.id) != 0)
        return nc_end(fail("Nodus client setup failed."));
    g_client_inited = 1;
    if (g_cancel) return nc_end(-1);
    if (nodus_client_connect(&g_client) != 0)
        return nc_end(fail("Could not open a verified connection to any Nodus node."));
    if (g_cancel) return nc_end(-1);

    g_ctx.client = &g_client;
    g_ctx.keys = &g_keys;
    g_ctx.fresh = fresh ? true : false;
    g_ctx.cancel = &g_cancel;
    g_unlocked = 1;

    json_object *o = json_object_new_object();
    json_object_object_add(o, "fingerprint", json_object_new_string(g_keys.fp));
    json_object_object_add(o, "fresh", json_object_new_boolean(g_ctx.fresh));
    return nc_end(set_result(o));
}

int nc_tick(void) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    nodus_client_tick(&g_client);
    nodus_client_state_t st = nodus_client_state(&g_client);
    if (st != NODUS_CLIENT_READY && st != NODUS_CLIENT_RECONNECTING)
        return nc_end(fail("Nodus connection lost."));
    return nc_end(0);
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
     * (dna_engine_contacts.c:345-350). */
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

int nc_ack_send(const char *fp, const char *salt_hex) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    uint8_t salt[NC_SALT_LEN];
    if (parse_salt(salt_hex, salt) != 0) return nc_end(fail("Invalid salt."));
    int rc = nc_ack_publish(&g_ctx, fp, salt);
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

/* ── cancel / lock: synchronous, never reach emscripten_sleep ─────────── */

void nc_cancel(void) {
    g_cancel = 1;
}

/* Same order as nsw_lock: with an export suspended (g_busy) the socket is
 * only closed (its wait ends at the next wake-up); the JS side then zeroes
 * the whole linear memory and aborts the instance. */
void nc_lock(void) {
    g_cancel = 1;
    g_locked = 1;
    if (g_client_inited) {
        if (g_busy) {
            nodus_client_force_disconnect(&g_client);
        } else {
            nodus_client_close(&g_client);
            g_client_inited = 0;
        }
        nc_wipe(&g_client.identity, sizeof(g_client.identity));
    }
    nc_keys_wipe(&g_keys);
    words_drop();
    result_drop();
    nc_wipe(g_peers, sizeof(g_peers));
    g_n_peers = 0;
    g_next_peer = 0;
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_unlocked = 0;
}
