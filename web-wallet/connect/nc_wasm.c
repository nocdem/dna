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
 *   - the groups codec exports (nc_group_*, package G2) are synchronous and
 *     pure (no network). Those that hold no session material
 *     (nc_group_addr_str, nc_group_salt, nc_group_record_read,
 *     nc_group_accept, nc_group_json_read) run outside the bracket, like
 *     nc_salt_pick; every one that uses the session's keys or the verified
 *     peer cache runs inside it, like nc_hist_*;
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
#include "nc_group.h"
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

/* Every export that SENDS. Messages unlocks on the identity alone (the
 * wallet may not be connected yet), so the client is bound here, on each
 * call: the host's one client exists only once its connect succeeded and
 * its chain was checked (nc_host_client), and the same check the wallet's
 * own exports run (nc_host_session_ok) gates every send. */
static int session_ok(void) {
    if (!g_unlocked) return fail("Messages is not connected.");
    if (nc_host_session_ok() != 0) return fail("%s", nc_host_error());
    nodus_client_t *client = nc_host_client();
    if (!client || !nodus_client_is_ready(client))
        return fail("Nodus connection is not ready. Try again shortly.");
    g_ctx.client = client;
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

/* Runs after the wallet's nsw_identify (or nsw_unlock), on ITS identity:
 * no client is created and nothing is sent — the wallet need not be
 * connected yet; the exports that send bind its client later (session_ok).
 * Derives the Messages keys from the words and refuses unless they belong
 * to the session identity. Synchronous in practice (PBKDF2 + key
 * generation, no network wait), bracketed like the others. */
int nc_unlock(int fresh) {
    if (nc_begin() != 0) { words_drop(); return -1; }
    if (g_used) { words_drop(); return nc_end(fail("This Messages connection was already used.")); }
    g_used = 1;
    const nodus_identity_t *session_id = nc_host_identity();
    if (!session_id) {
        words_drop();
        return nc_end(fail("Open the wallet first."));
    }
    if (!g_words) return nc_end(fail("Recovery phrase is missing."));
    int rc = nc_keys_from_words(g_words, &g_keys);
    words_drop();
    if (rc != NC_OK) return nc_end(fail("Recovery phrase was refused."));
    if (memcmp(g_keys.id.pk.bytes, session_id->pk.bytes, sizeof(session_id->pk.bytes)) != 0) {
        nc_keys_wipe(&g_keys);
        return nc_end(fail("These words belong to another Nodus address. Nothing was connected."));
    }

    g_ctx.client = NULL;                    /* bound by session_ok          */
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
    /* rows of another owner at the profile key: someone is interfering */
    json_object_object_add(o, "foreign", jstr_u64(raw.foreign));
    if (raw.outcome == NC_FOUND && id) {
        json_object *p = profile_json(id);
        /* "name": the registered name ONLY when nc_name_verify proved it
         * (design §1.9 G9); otherwise "" and the UI shows the ID with the
         * claim beside it. */
        bool verified = id->has_registered_name &&
                        nc_name_verify(&g_ctx, fp, id->registered_name) == 1;
        json_object_object_add(p, "name",
                               json_object_new_string(verified ? id->registered_name : ""));
        json_object_object_add(o, "profile", p);
        /* the signed row as read, for the page's profile cache
         * (nc_profile_load); it is checked again when loaded */
        json_object_object_add(o, "record",
                               json_object_new_string_len((const char *)raw.value->data,
                                                          (int)raw.value->data_len));
        if (strcmp(fp, g_keys.fp) != 0) peer_store(&peer);
    }
    dna_identity_free(id);
    nc_read_clear(&raw);
    return nc_end(set_result(o));
}

/* A profile row the page kept from an earlier nc_profile_get ("record") —
 * the app keeps profiles 7 days (profile_cache.h:40). No network: the same
 * record checks as a read (nc_profile_check), then the peer's keys are
 * held as after a read. `name`: the name nc_name_verify proved when the row
 * was read; kept only if it is still the row's registered name. */
#define NC_PROFILE_RECORD_MAX 65536
int nc_profile_load(const char *fp, const char *record, const char *name) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    nodus_key_t chk;
    if (nc_fp_parse(fp, &chk) != 0) return nc_end(fail("Invalid Nodus address."));
    size_t len = record ? strnlen(record, NC_PROFILE_RECORD_MAX + 1) : 0;
    if (len == 0 || len > NC_PROFILE_RECORD_MAX || !name)
        return nc_end(fail("Invalid stored profile."));
    dna_unified_identity_t *id = NULL;
    nc_peer_t peer;
    if (nc_profile_check(fp, (const uint8_t *)record, len, &id, &peer) != 0)
        return nc_end(fail("The stored profile failed its checks."));
    json_object *p = profile_json(id);
    bool keep = name[0] && id->has_registered_name &&
                strcmp(name, id->registered_name) == 0;
    json_object_object_add(p, "name", json_object_new_string(keep ? name : ""));
    json_object *o = json_object_new_object();
    json_object_object_add(o, "profile", p);
    if (strcmp(fp, g_keys.fp) != 0) peer_store(&peer);
    dna_identity_free(id);
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
    json_object_object_add(rd, "foreign", jstr_u64(r.read.foreign));
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
    /* The node had pages left after NC_READ_MAX_PAGES (nc_read_all). */
    json_object_object_add(o, "truncated",
                           json_object_new_boolean(r.read.truncated));
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
    json_object_object_add(o, "wrong_pair", jstr_u64(r.wrong_pair));
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
    json_object_object_add(o, "wrong_pair", jstr_u64(s.read.wrong_pair));
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

/* skip_hex: "" or the 64-hex "blob" of an earlier answer for this day whose
 * messages the page has stored (nc_core.h nc_outbox_fetch_day). */
int nc_outbox_get(const char *fp, const char *salt_hex, const char *day_dec,
                  const char *skip_hex) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    const nc_peer_t *peer = peer_need(fp);
    if (!peer) return nc_end(-1);
    uint8_t salt[NC_SALT_LEN], skip[32];
    uint64_t day;
    bool has_skip = skip_hex && skip_hex[0];
    if (parse_salt(salt_hex, salt) != 0 || day_arg(day_dec, &day) != 0 ||
        (has_skip && parse_hex_fixed(skip_hex, skip, sizeof(skip)) != 0))
        return nc_end(fail("Invalid salt, day or blob."));
    nc_inbox_t in;
    int rc = nc_outbox_fetch_day(&g_ctx, peer, salt, day,
                                 has_skip ? skip : NULL, &in);
    nc_wipe(salt, sizeof(salt));
    if (rc != NC_OK) return nc_end(fail("Messages could not be read (%d).", rc));
    json_object *o = json_object_new_object();
    add_read(o, in.read.outcome, in.read.why);
    json_object_object_add(o, "day", jstr_u64(day));
    if (in.read.outcome == NC_FOUND) json_object_object_add(o, "blob", jhex(in.blob, sizeof(in.blob)));
    json_object_object_add(o, "unchanged", json_object_new_boolean(in.unchanged));
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

/* ── groups codec (package G2): synchronous, pure, no network ───────────
 *
 * The codec and every rule: nc_group.h. Governing records:
 * docs/plans/2026-10-05-connect-groups-bytes.md items 1-7 + REV 2
 * (approved, decisions/2026-10-05-groups-apt-bytes-approved.md);
 * decisions/2026-10-04-connect-groups.md items 1-11 (item 11: message text
 * >= 1 byte).
 *
 * Crossing: bytes as lowercase hex; v, day, count, key_version and the
 * millisecond timestamps as decimal strings; fingerprints in the 128-hex
 * form. A group key, addr_secret or salt_v crosses as hex like the 1:1
 * salts — the page holds them; every copy this file makes is wiped.
 *
 * KEY BINDING (nc_group.h): no signer's or member's key is ever taken from
 * the page. The own fingerprint uses the session's Messages keys (g_keys:
 * ML-DSA-87 signs and verifies, ML-KEM-1024 decapsulates); every other
 * fingerprint resolves through the peer cache above, which only
 * nc_profile_get / nc_profile_load fill (nc_profile_read / nc_profile_check:
 * SHA3-512(pk) == fp on the owner-filtered profile). A fingerprint not in it
 * is refused ("Load this contact's profile first.").
 *
 * Readers (kp_read, record_read, head_read, bucket_read, json_read) answer 0
 * with a "status" — the codec's verdict on the bytes; a bad argument, a
 * value over its size cap or a fault is an error (-1, nc_error()), and the
 * page treats such a value as refused. Writers (the *_new exports, invite,
 * accept, welcome) answer the bytes or an error.
 *
 * Hex inputs are copied onto the 1 MiB C stack by ccall (NC_HIST_PT_MAX
 * above). Caps: a key packet of 64 members is 107,795 B (215,590 hex); a
 * record <= 4,255 B; a HEAD 4,817 B; a bucket is read up to
 * NC_GROUP_BKT_IN_MAX — see there. */

_Static_assert(sizeof(((nc_keys_t *)0)->id.pk.bytes) == NC_GROUP_DSA_PK_LEN, "ML-DSA-87 pk");
_Static_assert(sizeof(((nc_keys_t *)0)->id.sk.bytes) == NC_GROUP_DSA_SK_LEN, "ML-DSA-87 sk");
_Static_assert(sizeof(((nc_keys_t *)0)->id.node_id.bytes) == NC_GROUP_FP_LEN, "fingerprint");
_Static_assert(sizeof(((nc_keys_t *)0)->mlkem_pk) == NC_GROUP_KEM_PK_LEN, "ML-KEM-1024 ek");
_Static_assert(sizeof(((nc_keys_t *)0)->mlkem_sk) == NC_GROUP_KEM_SK_LEN, "ML-KEM-1024 dk");
_Static_assert(sizeof(((nc_peer_t *)0)->dsa_pk) == NC_GROUP_DSA_PK_LEN, "peer ML-DSA-87 pk");
_Static_assert(sizeof(((nc_peer_t *)0)->mlkem_pk) == NC_GROUP_KEM_PK_LEN, "peer ML-KEM-1024 ek");
_Static_assert(NC_FP_HEX_LEN == 2 * NC_GROUP_FP_LEN, "fingerprint hex");

#define NC_GROUP_KP_MAX  (NC_GROUP_KP_HEADER_LEN + NC_GROUP_MAX_MEMBERS * NC_GROUP_ENTRY_LEN + \
                          2 + NC_GROUP_SIG_LEN)
#define NC_GROUP_REC_MAX (NC_GROUP_REC_HEADER_LEN + NC_GROUP_RECORD_PT_MAX + NC_GROUP_GCM_TAG_LEN)
/* A bucket may hold up to 1 MiB (NC_GROUP_BUCKET_MAX) = 2 MiB of hex, more
 * than the whole C stack ccall copies it onto. Read here: up to 256 KiB
 * (512 KiB of hex, leaving half the stack for the frames below — the deepest
 * is the ML-DSA-87 verify; its peak is not measured, the signing peak is
 * ~121 KB per scripts/build-mldsa87-sign-wasm.sh). A larger bucket is an
 * error, never a partial read. Full-size buckets need a heap input buffer
 * export (the nsw_req_env_alloc form) — not part of this package. */
#define NC_GROUP_BKT_IN_MAX (256u * 1024u)

static int parse_u32_dec(const char *s, uint32_t *out) {
    uint64_t v;
    if (parse_u64(s, &v) != 0 || v > UINT32_MAX) return -1;
    *out = (uint32_t)v;
    return 0;
}

static int own_fp_is(const char *fp) {
    return fp && strcmp(fp, g_keys.fp) == 0;
}

/* The ML-DSA-87 key (and ML-KEM-1024 key, NULL when the profile carries
 * none) of `fp`: the session's own, or the verified peer cache's. The
 * pointers stay valid for the export (no group export stores a peer). */
static int group_keys_of(const char *fp, uint8_t fp_out[NC_GROUP_FP_LEN],
                         const uint8_t **dsa_pk, const uint8_t **kem_pk) {
    nodus_key_t k;
    if (nc_fp_parse(fp, &k) != 0) return fail("Invalid Nodus address.");
    memcpy(fp_out, k.bytes, NC_GROUP_FP_LEN);
    if (own_fp_is(fp)) {
        if (dsa_pk) *dsa_pk = g_keys.id.pk.bytes;
        if (kem_pk) *kem_pk = g_keys.mlkem_pk;
        return 0;
    }
    const nc_peer_t *p = peer_need(fp);
    if (!p) return -1;
    if (dsa_pk) *dsa_pk = p->dsa_pk;
    if (kem_pk) *kem_pk = p->has_mlkem ? p->mlkem_pk : NULL;
    return 0;
}

typedef struct {
    uint8_t fp[NC_GROUP_FP_LEN];
    char    hex[NC_FP_HEX_LEN + 1];
} group_member_t;

static int member_cmp(const void *a, const void *b) {
    return memcmp(((const group_member_t *)a)->fp, ((const group_member_t *)b)->fp,
                  NC_GROUP_FP_LEN);
}

/* members_json: ["<128 hex>", ...], 1..64 entries. Sorted here into the
 * codec's order (fingerprints ascending, memcmp — nc_group.h); a duplicate
 * or a list without the owner is then refused by the codec. */
static int parse_members(const char *members_json, group_member_t m[NC_GROUP_MAX_MEMBERS],
                         size_t *n) {
    *n = 0;
    json_object *arr = members_json ? json_tokener_parse(members_json) : NULL;
    size_t c = arr && json_object_is_type(arr, json_type_array) ? json_object_array_length(arr) : 0;
    if (c == 0 || c > NC_GROUP_MAX_MEMBERS) {
        if (arr) json_object_put(arr);
        return fail("Invalid member list (1 to 64 Nodus addresses).");
    }
    for (size_t i = 0; i < c; i++) {
        json_object *e = json_object_array_get_idx(arr, i);
        const char *fp = e && json_object_is_type(e, json_type_string)
                             ? json_object_get_string(e) : NULL;
        nodus_key_t k;
        if (!fp || nc_fp_parse(fp, &k) != 0) {     /* exactly 128 lowercase hex */
            json_object_put(arr);
            return fail("Invalid member list (1 to 64 Nodus addresses).");
        }
        memcpy(m[i].fp, k.bytes, NC_GROUP_FP_LEN);
        memcpy(m[i].hex, fp, NC_FP_HEX_LEN);
        m[i].hex[NC_FP_HEX_LEN] = '\0';
    }
    json_object_put(arr);
    qsort(m, c, sizeof(*m), member_cmp);
    *n = c;
    return 0;
}

/* K for (purpose 1 HEAD | 2 KEY PACKET | 3 RECORD | 4 OUTBOX, group_id,
 * secret = addr_secret (1, 2) or salt_v (3, 4), x = 0 | v | v | day).
 * Result { key: "ncg:" + 128 hex } — the DHT layer hashes that string once
 * more (nc_key_str), not done here. */
int nc_group_addr_str(int purpose, const char *group_id_hex, const char *secret_hex,
                      const char *x_dec) {
    uint8_t gid[NC_GROUP_ID_LEN], sec[NC_GROUP_SECRET_LEN], k[NC_GROUP_DIGEST_LEN];
    char s[NC_GROUP_ADDR_STR_LEN + 1];
    uint64_t x;
    if (purpose < NC_GROUP_PURPOSE_HEAD || purpose > NC_GROUP_PURPOSE_OUTBOX ||
        parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 ||
        parse_hex_fixed(secret_hex, sec, sizeof(sec)) != 0 || parse_u64(x_dec, &x) != 0) {
        nc_wipe(sec, sizeof(sec));
        return fail("Invalid group address input.");
    }
    int rc = nc_group_addr((nc_group_purpose_t)purpose, gid, sec, x, k, s);
    nc_wipe(sec, sizeof(sec));
    if (rc != NC_GROUP_OK)
        return fail(rc == NC_GROUP_REFUSED
                    ? "Group address input refused (version or day out of range)."
                    : "Group address could not be derived.");
    json_object *o = json_object_new_object();
    json_object_object_add(o, "key", json_object_new_string(s));
    return set_result(o);
}

/* Result { salt: 64 hex } = salt_v of (group_id, group_key_v, v). */
int nc_group_salt(const char *group_id_hex, const char *group_key_hex, const char *v_dec) {
    uint8_t gid[NC_GROUP_ID_LEN], gk[NC_GROUP_KEY_LEN], salt[NC_GROUP_SECRET_LEN];
    uint32_t v;
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 ||
        parse_hex_fixed(group_key_hex, gk, sizeof(gk)) != 0 || parse_u32_dec(v_dec, &v) != 0) {
        nc_wipe(gk, sizeof(gk));
        return fail("Invalid group key input.");
    }
    int rc = nc_group_salt_v(gid, gk, v, salt);
    nc_wipe(gk, sizeof(gk));
    if (rc != NC_GROUP_OK) {
        nc_wipe(salt, sizeof(salt));
        return fail(rc == NC_GROUP_REFUSED ? "Group key version must be at least 1."
                                           : "Group salt could not be derived.");
    }
    json_object *o = json_object_new_object();
    json_object_object_add(o, "salt", jhex(salt, sizeof(salt)));
    nc_wipe(salt, sizeof(salt));
    return set_result(o);
}

/* The owner's key packet for version v: owner = the session; members_json
 * as parse_members (must include the own fingerprint); each member's
 * ML-KEM-1024 key from the verified peer cache (the own from g_keys) — a
 * member without one fails the whole build, as a key failing ek_check does
 * (design §3: never skipped). prev_digest_hex: "" for v = 1, required for
 * v > 1 (digest of packet v-1). Result { packet, digest (hex), count }. */
int nc_group_kp_new(const char *group_id_hex, const char *v_dec, const char *prev_digest_hex,
                    const char *record_digest_hex, const char *issued_at_dec,
                    const char *group_key_hex, const char *members_json) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    nc_group_kp_hdr_t h;
    memset(&h, 0, sizeof(h));
    bool has_prev = prev_digest_hex && prev_digest_hex[0];
    if (parse_hex_fixed(group_id_hex, h.group_id, sizeof(h.group_id)) != 0 ||
        parse_u32_dec(v_dec, &h.v) != 0 || h.v == 0 ||
        (h.v == 1 && has_prev) || (h.v > 1 && !has_prev) ||
        (has_prev && parse_hex_fixed(prev_digest_hex, h.prev_digest, sizeof(h.prev_digest)) != 0) ||
        parse_hex_fixed(record_digest_hex, h.record_digest, sizeof(h.record_digest)) != 0 ||
        parse_u64(issued_at_dec, &h.issued_at_ms) != 0)
        return nc_end(fail("Invalid key packet input (version 1 has no previous digest, "
                           "a later version needs one)."));
    memcpy(h.owner_fp, g_keys.id.node_id.bytes, NC_GROUP_FP_LEN);
    uint8_t gk[NC_GROUP_KEY_LEN];
    if (parse_hex_fixed(group_key_hex, gk, sizeof(gk)) != 0)
        return nc_end(fail("Invalid group key."));
    group_member_t m[NC_GROUP_MAX_MEMBERS];
    uint8_t fps[NC_GROUP_MAX_MEMBERS][NC_GROUP_FP_LEN];
    size_t n = 0;
    if (parse_members(members_json, m, &n) != 0) {
        nc_wipe(gk, sizeof(gk));
        return nc_end(-1);
    }
    uint8_t (*eks)[NC_GROUP_KEM_PK_LEN] = malloc(n * NC_GROUP_KEM_PK_LEN);
    if (!eks) {
        nc_wipe(gk, sizeof(gk));
        return nc_end(fail("Out of memory."));
    }
    for (size_t i = 0; i < n; i++) {
        const uint8_t *kem = NULL;
        int krc = group_keys_of(m[i].hex, fps[i], NULL, &kem);
        if (krc == 0 && !kem)
            krc = fail("A member's profile has no ML-KEM-1024 key: nothing was built.");
        if (krc != 0) {
            free(eks);
            nc_wipe(gk, sizeof(gk));
            return nc_end(-1);
        }
        memcpy(eks[i], kem, NC_GROUP_KEM_PK_LEN);
    }
    uint8_t *pkt = NULL, dig[NC_GROUP_DIGEST_LEN];
    size_t pl = 0;
    int rc = nc_group_kp_build(&h, gk, (const uint8_t (*)[NC_GROUP_FP_LEN])fps,
                               (const uint8_t (*)[NC_GROUP_KEM_PK_LEN])eks, n,
                               g_keys.id.pk.bytes, g_keys.id.sk.bytes, &pkt, &pl, dig);
    nc_wipe(gk, sizeof(gk));
    free(eks);
    if (rc != NC_GROUP_OK)
        return nc_end(rc == NC_GROUP_REFUSED
                      ? fail("Key packet refused: the members must be distinct and include "
                             "you, and every member's ML-KEM-1024 key must pass its check.")
                      : fail("Key packet could not be built."));
    json_object *o = json_object_new_object();
    json_object_object_add(o, "packet", jhex(pkt, pl));
    json_object_object_add(o, "digest", jhex(dig, sizeof(dig)));
    json_object_object_add(o, "count", jstr_u64(n));
    free(pkt);                                 /* ciphertexts and wraps only */
    return nc_end(set_result(o));
}

/* A member reads the key packet of version v (nc_group_kp_open order:
 * structure, owner signature FIRST, group / version / owner, prev_digest,
 * trial unwrap with the session's ML-KEM-1024 key). owner_fp: the pinned
 * owner (own or verified peer cache). prev_digest_hex: the stored digest of
 * packet v-1, "" when not held (v > 1 then answers "prev_unavailable").
 * Result { status: ok | bad_structure | bad_sig | mismatch | prev_conflict
 * | prev_unavailable | no_entry } and, once the signature verified, v,
 * count, digest, prev_digest, record_digest, issued_at_ms; group_key only
 * on ok. */
int nc_group_kp_read(const char *packet_hex, const char *owner_fp, const char *group_id_hex,
                     const char *v_dec, const char *prev_digest_hex) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    uint8_t gid[NC_GROUP_ID_LEN], ofp[NC_GROUP_FP_LEN], prev[NC_GROUP_DIGEST_LEN];
    uint32_t v;
    bool has_prev = prev_digest_hex && prev_digest_hex[0];
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 || parse_u32_dec(v_dec, &v) != 0 ||
        (has_prev && parse_hex_fixed(prev_digest_hex, prev, sizeof(prev)) != 0))
        return nc_end(fail("Invalid key packet input."));
    const uint8_t *opk = NULL;
    if (group_keys_of(owner_fp, ofp, &opk, NULL) != 0) return nc_end(-1);
    uint8_t *pkt;
    size_t pl;
    if (parse_hex_var(packet_hex, NC_GROUP_KP_MAX, &pkt, &pl) != 0)
        return nc_end(fail("Invalid key packet (not hex, or over %u bytes).",
                           (unsigned)NC_GROUP_KP_MAX));
    nc_group_kp_open_t r;
    nc_group_kp_status_t st = nc_group_kp_open(pkt, pl, opk, gid, ofp, v,
                                               has_prev ? prev : NULL,
                                               g_keys.id.node_id.bytes,
                                               nc_group_decap_mlkem, g_keys.mlkem_sk, &r);
    free(pkt);                                 /* public bytes */
    static const char *const ST[] = { "ok", "bad_structure", "bad_sig", "mismatch",
                                      "prev_conflict", "prev_unavailable", "no_entry" };
    if ((unsigned)st >= sizeof(ST) / sizeof(ST[0])) {
        nc_wipe(&r, sizeof(r));
        return nc_end(fail("Key packet could not be read (fault)."));
    }
    json_object *o = json_object_new_object();
    json_object_object_add(o, "status", json_object_new_string(ST[st]));
    if (st != NC_GROUP_KP_BAD_STRUCTURE && st != NC_GROUP_KP_BAD_SIG) {
        json_object_object_add(o, "v", jstr_u64(r.hdr.v));
        json_object_object_add(o, "count", jstr_u64(r.count));
        json_object_object_add(o, "digest", jhex(r.digest, sizeof(r.digest)));
        json_object_object_add(o, "prev_digest", jhex(r.hdr.prev_digest, sizeof(r.hdr.prev_digest)));
        json_object_object_add(o, "record_digest",
                               jhex(r.hdr.record_digest, sizeof(r.hdr.record_digest)));
        json_object_object_add(o, "issued_at_ms", jstr_u64(r.hdr.issued_at_ms));
    }
    if (st == NC_GROUP_KP_OK)
        json_object_object_add(o, "group_key", jhex(r.group_key, sizeof(r.group_key)));
    nc_wipe(&r, sizeof(r));
    return nc_end(set_result(o));
}

/* The owner's member record for version v: owner = the session; name: the
 * group name, UTF-8, <= 64 bytes ("" allowed); members_json as
 * parse_members (must include the own fingerprint). Result { record,
 * digest (hex) } — digest = the record_digest the key packet carries. */
int nc_group_record_new(const char *group_id_hex, const char *v_dec, const char *group_key_hex,
                        const char *name, const char *members_json, const char *created_at_dec) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    uint8_t gid[NC_GROUP_ID_LEN], gk[NC_GROUP_KEY_LEN];
    uint32_t v;
    uint64_t created;
    size_t name_len = name ? strnlen(name, NC_GROUP_NAME_MAX + 1) : 0;
    if (!name || name_len > NC_GROUP_NAME_MAX)
        return nc_end(fail("Group name must be at most 64 bytes."));
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 || parse_u32_dec(v_dec, &v) != 0 ||
        parse_u64(created_at_dec, &created) != 0)
        return nc_end(fail("Invalid group record input."));
    if (parse_hex_fixed(group_key_hex, gk, sizeof(gk)) != 0)
        return nc_end(fail("Invalid group key."));
    group_member_t m[NC_GROUP_MAX_MEMBERS];
    uint8_t fps[NC_GROUP_MAX_MEMBERS][NC_GROUP_FP_LEN];
    size_t n = 0;
    if (parse_members(members_json, m, &n) != 0) {
        nc_wipe(gk, sizeof(gk));
        return nc_end(-1);
    }
    for (size_t i = 0; i < n; i++) memcpy(fps[i], m[i].fp, NC_GROUP_FP_LEN);
    uint8_t *rec = NULL, dig[NC_GROUP_DIGEST_LEN];
    size_t rl = 0;
    int rc = nc_group_record_seal(gid, v, gk, g_keys.id.node_id.bytes,
                                  (const uint8_t *)name, name_len,
                                  (const uint8_t (*)[NC_GROUP_FP_LEN])fps, n, created,
                                  &rec, &rl, dig);
    nc_wipe(gk, sizeof(gk));
    if (rc != NC_GROUP_OK)
        return nc_end(rc == NC_GROUP_REFUSED
                      ? fail("Group record refused: version 1 or later, members distinct "
                             "and including you.")
                      : fail("Group record could not be sealed."));
    json_object *o = json_object_new_object();
    json_object_object_add(o, "record", jhex(rec, rl));
    json_object_object_add(o, "digest", jhex(dig, sizeof(dig)));
    free(rec);                                 /* ciphertext only */
    return nc_end(set_result(o));
}

/* Open the record read at RECORD(v) (nc_group_record_open order).
 * digest_hex / count_dec: the record_digest and count of the key packet of
 * v that passed nc_group_kp_read; owner_fp: the group's owner. No session
 * key is used. Result { status: ok | bad_structure | mismatch | bad_digest
 * | bad_auth | bad_plaintext | count | no_owner } and, on ok, name_hex (the
 * raw name bytes — not validated as UTF-8, nc_group.h), members (128 hex
 * each, ascending) and created_at_ms. */
int nc_group_record_read(const char *record_hex, const char *group_key_hex,
                         const char *group_id_hex, const char *v_dec, const char *digest_hex,
                         const char *count_dec, const char *owner_fp) {
    uint8_t gk[NC_GROUP_KEY_LEN], gid[NC_GROUP_ID_LEN], dig[NC_GROUP_DIGEST_LEN];
    uint32_t v;
    uint64_t count;
    nodus_key_t ofp;
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 || parse_u32_dec(v_dec, &v) != 0 ||
        parse_hex_fixed(digest_hex, dig, sizeof(dig)) != 0 || parse_u64(count_dec, &count) != 0 ||
        count < 1 || count > NC_GROUP_MAX_MEMBERS || nc_fp_parse(owner_fp, &ofp) != 0)
        return fail("Invalid group record input.");
    if (parse_hex_fixed(group_key_hex, gk, sizeof(gk)) != 0) return fail("Invalid group key.");
    uint8_t *rec;
    size_t rl;
    if (parse_hex_var(record_hex, NC_GROUP_REC_MAX, &rec, &rl) != 0) {
        nc_wipe(gk, sizeof(gk));
        return fail("Invalid group record (not hex, or over %u bytes).",
                    (unsigned)NC_GROUP_REC_MAX);
    }
    nc_group_record_t r;
    nc_group_rec_status_t st = nc_group_record_open(rec, rl, gk, gid, v, dig, (size_t)count,
                                                    ofp.bytes, &r);
    nc_wipe(gk, sizeof(gk));
    free(rec);                                 /* ciphertext */
    static const char *const ST[] = { "ok", "bad_structure", "mismatch", "bad_digest",
                                      "bad_auth", "bad_plaintext", "count", "no_owner" };
    if ((unsigned)st >= sizeof(ST) / sizeof(ST[0])) {
        nc_wipe(&r, sizeof(r));
        return fail("Group record could not be read (fault).");
    }
    json_object *o = json_object_new_object();
    json_object_object_add(o, "status", json_object_new_string(ST[st]));
    if (st == NC_GROUP_REC_OK) {
        json_object_object_add(o, "name_hex", jhex(r.name, r.name_len));
        json_object *a = json_object_new_array();
        for (size_t i = 0; i < r.count; i++) json_object_array_add(a, jhex(r.members[i], NC_GROUP_FP_LEN));
        json_object_object_add(o, "members", a);
        json_object_object_add(o, "created_at_ms", jstr_u64(r.created_at_ms));
    }
    nc_wipe(&r, sizeof(r));
    return set_result(o);
}

/* The owner's HEAD: owner = the session. Result { head (hex, 4,817 B) }. */
int nc_group_head_new(const char *group_id_hex, const char *v_dec, const char *kp_digest_hex,
                      const char *issued_at_dec) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    nc_group_head_t h;
    memset(&h, 0, sizeof(h));
    if (parse_hex_fixed(group_id_hex, h.group_id, sizeof(h.group_id)) != 0 ||
        parse_u32_dec(v_dec, &h.v) != 0 ||
        parse_hex_fixed(kp_digest_hex, h.kp_digest, sizeof(h.kp_digest)) != 0 ||
        parse_u64(issued_at_dec, &h.issued_at_ms) != 0)
        return nc_end(fail("Invalid group head input."));
    memcpy(h.owner_fp, g_keys.id.node_id.bytes, NC_GROUP_FP_LEN);
    uint8_t *out = malloc(NC_GROUP_HEAD_LEN);
    if (!out) return nc_end(fail("Out of memory."));
    int rc = nc_group_head_build(&h, g_keys.id.pk.bytes, g_keys.id.sk.bytes, out);
    if (rc != NC_GROUP_OK) {
        free(out);
        return nc_end(rc == NC_GROUP_REFUSED ? fail("Group head refused: version must be at least 1.")
                                             : fail("Group head could not be signed."));
    }
    json_object *o = json_object_new_object();
    json_object_object_add(o, "head", jhex(out, NC_GROUP_HEAD_LEN));
    free(out);
    return nc_end(set_result(o));
}

/* Verify a HEAD under the pinned owner (own or verified peer cache).
 * Result { status: ok | bad_structure | bad_sig | mismatch } and, on ok,
 * v, kp_digest, issued_at_ms. The forward-only rule (v above the stored
 * high-water mark, kp_digest == the digest of packet v) is the page's: it
 * holds that state (nc_group.h nc_group_head_verify). */
int nc_group_head_read(const char *head_hex, const char *owner_fp, const char *group_id_hex) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    uint8_t gid[NC_GROUP_ID_LEN], ofp[NC_GROUP_FP_LEN];
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0)
        return nc_end(fail("Invalid group head input."));
    const uint8_t *opk = NULL;
    if (group_keys_of(owner_fp, ofp, &opk, NULL) != 0) return nc_end(-1);
    uint8_t *hb;
    size_t hl;
    if (parse_hex_var(head_hex, NC_GROUP_HEAD_LEN + 1, &hb, &hl) != 0)
        return nc_end(fail("Invalid group head (not hex, or too long)."));
    nc_group_head_t h;
    nc_group_head_status_t st = nc_group_head_verify(hb, hl, opk, gid, ofp, &h);
    free(hb);
    static const char *const ST[] = { "ok", "bad_structure", "bad_sig", "mismatch" };
    if ((unsigned)st >= sizeof(ST) / sizeof(ST[0]))
        return nc_end(fail("Group head could not be read (fault)."));
    json_object *o = json_object_new_object();
    json_object_object_add(o, "status", json_object_new_string(ST[st]));
    if (st == NC_GROUP_HEAD_OK) {
        json_object_object_add(o, "v", jstr_u64(h.v));
        json_object_object_add(o, "kp_digest", jhex(h.kp_digest, sizeof(h.kp_digest)));
        json_object_object_add(o, "issued_at_ms", jstr_u64(h.issued_at_ms));
    }
    return nc_end(set_result(o));
}

/* Seal and sign one group message: sender = the session; text: UTF-8,
 * 1..4,000 bytes (decision 11: >= 1). The day bucket is not built here.
 * Result { item (hex), message_id (32 hex), day }. */
int nc_group_msg_new(const char *group_key_hex, const char *group_id_hex, const char *v_dec,
                     const char *timestamp_dec, const char *text) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    size_t tl = text ? strnlen(text, NC_GROUP_TEXT_MAX + 1) : 0;
    if (tl == 0) return nc_end(fail("Message text must be at least 1 byte."));
    if (tl > NC_GROUP_TEXT_MAX) return nc_end(fail("Message text is over 4,000 bytes."));
    uint8_t gid[NC_GROUP_ID_LEN], gk[NC_GROUP_KEY_LEN], mid[NC_GROUP_MSG_ID_LEN];
    uint32_t v, day;
    uint64_t ts;
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 || parse_u32_dec(v_dec, &v) != 0 ||
        parse_u64(timestamp_dec, &ts) != 0 || nc_group_day(ts, &day) != NC_GROUP_OK)
        return nc_end(fail("Invalid group message input."));
    if (parse_hex_fixed(group_key_hex, gk, sizeof(gk)) != 0)
        return nc_end(fail("Invalid group key."));
    uint8_t *item = NULL;
    size_t il = 0;
    int rc = nc_group_msg_seal(gk, gid, v, g_keys.id.node_id.bytes, ts,
                               (const uint8_t *)text, tl,
                               g_keys.id.pk.bytes, g_keys.id.sk.bytes, mid, &item, &il);
    nc_wipe(gk, sizeof(gk));
    if (rc != NC_GROUP_OK)
        return nc_end(rc == NC_GROUP_REFUSED ? fail("Group message refused (version must be "
                                                    "at least 1).")
                                             : fail("Group message could not be sealed."));
    json_object *o = json_object_new_object();
    json_object_object_add(o, "item", jhex(item, il));
    json_object_object_add(o, "message_id", jhex(mid, sizeof(mid)));
    json_object_object_add(o, "day", jstr_u64(day));
    free(item);                                /* ciphertext only */
    return nc_end(set_result(o));
}

/* Decode a day bucket read at OUTBOX(salt_v, day) and open every item with
 * the sender's key (own or verified peer cache) and group_key_v.
 * Result { status: ok | bad_structure | sender_unknown, sender (128 hex,
 * when items exist), messages: [{ message_id, timestamp_ms, status: ok |
 * bad_sig | bad_auth | refused, text_hex (ok only) }] }. "sender_unknown":
 * load that profile (nc_profile_get), then read again. NOT checked here, the
 * page's (nc_group.h nc_group_bucket_decode): the DHT value's owner ==
 * sender, and the membership rule (nc_group_msg_accept, decision 6). */
int nc_group_bucket_read(const char *bucket_hex, const char *group_id_hex, const char *v_dec,
                         const char *day_dec, const char *group_key_hex) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    uint8_t gid[NC_GROUP_ID_LEN], gk[NC_GROUP_KEY_LEN];
    uint32_t v, day;
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 || parse_u32_dec(v_dec, &v) != 0 ||
        parse_u32_dec(day_dec, &day) != 0)
        return nc_end(fail("Invalid group bucket input."));
    uint8_t *b;
    size_t bl;
    if (parse_hex_var(bucket_hex, NC_GROUP_BKT_IN_MAX, &b, &bl) != 0)
        return nc_end(fail("Invalid group bucket (not hex, or over %u bytes).",
                           (unsigned)NC_GROUP_BKT_IN_MAX));
    if (parse_hex_fixed(group_key_hex, gk, sizeof(gk)) != 0) {
        free(b);
        return nc_end(fail("Invalid group key."));
    }
    nc_group_msg_t *items = NULL;
    size_t n = 0;
    int rc = nc_group_bucket_decode(b, bl, gid, v, day, &items, &n);
    if (rc == NC_GROUP_FAULT) {
        nc_wipe(gk, sizeof(gk));
        free(b);
        return nc_end(fail("Group bucket could not be read (fault)."));
    }
    json_object *o = json_object_new_object();
    json_object *a = json_object_new_array();
    const char *status = rc == NC_GROUP_OK ? "ok" : "bad_structure";
    if (rc == NC_GROUP_OK && n > 0) {
        char sender[NC_FP_HEX_LEN + 1];
        static const char d[] = "0123456789abcdef";
        for (size_t i = 0; i < NC_GROUP_FP_LEN; i++) {
            sender[2 * i] = d[items[0].sender_fp[i] >> 4];
            sender[2 * i + 1] = d[items[0].sender_fp[i] & 15];
        }
        sender[NC_FP_HEX_LEN] = '\0';
        json_object_object_add(o, "sender", json_object_new_string(sender));
        const uint8_t *spk = NULL;
        if (own_fp_is(sender)) {
            spk = g_keys.id.pk.bytes;
        } else {
            const nc_peer_t *p = peer_find(sender);
            if (p) spk = p->dsa_pk;
        }
        if (!spk) {
            status = "sender_unknown";
        } else {
            static const char *const ST[] = { "ok", "bad_sig", "bad_auth", "refused", "fault" };
            uint8_t text[NC_GROUP_TEXT_MAX];
            for (size_t i = 0; i < n; i++) {
                size_t tl = 0;
                nc_group_msg_status_t st = nc_group_msg_open(&items[i], gk, spk, text, &tl);
                json_object *e = json_object_new_object();
                json_object_object_add(e, "message_id",
                                       jhex(items[i].message_id, NC_GROUP_MSG_ID_LEN));
                json_object_object_add(e, "timestamp_ms", jstr_u64(items[i].timestamp_ms));
                json_object_object_add(e, "status", json_object_new_string(
                    (unsigned)st < sizeof(ST) / sizeof(ST[0]) ? ST[st] : "fault"));
                if (st == NC_GROUP_MSG_OK)
                    json_object_object_add(e, "text_hex", jhex(text, tl));
                json_object_array_add(a, e);
                nc_wipe(text, sizeof(text));
            }
        }
    }
    json_object_object_add(o, "status", json_object_new_string(status));
    json_object_object_add(o, "messages", a);
    free(items);                               /* pointers into b */
    free(b);
    nc_wipe(gk, sizeof(gk));
    return nc_end(set_result(o));
}

/* The owner's invite (1:1 plaintext, contacts only — decision 8): owner =
 * the session; invite_id = 16 fresh bytes (the module's one random source).
 * name: UTF-8, <= 64 bytes. Result { json, invite_id (32 hex) } — the page
 * keeps invite_id as pending for that contact. */
int nc_group_invite(const char *group_id_hex, const char *name) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    uint8_t gid[NC_GROUP_ID_LEN], iid[NC_GROUP_INVITE_ID_LEN];
    size_t name_len = name ? strnlen(name, NC_GROUP_NAME_MAX + 1) : 0;
    if (!name || name_len > NC_GROUP_NAME_MAX)
        return nc_end(fail("Group name must be at most 64 bytes."));
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0)
        return nc_end(fail("Invalid group id."));
    if (qgp_platform_random(iid, sizeof(iid)) != 0)
        return nc_end(fail("No randomness available."));
    char *js = NULL;
    size_t jl = 0;
    int rc = nc_group_invite_encode(gid, g_keys.id.node_id.bytes, name, name_len, iid, &js, &jl);
    if (rc != NC_GROUP_OK)
        return nc_end(rc == NC_GROUP_REFUSED ? fail("Group invite refused (the name must be "
                                                    "valid UTF-8).")
                                             : fail("Group invite could not be written."));
    json_object *o = json_object_new_object();
    json_object_object_add(o, "json", json_object_new_string_len(js, (int)jl));
    json_object_object_add(o, "invite_id", jhex(iid, sizeof(iid)));
    free(js);
    return nc_end(set_result(o));
}

/* A member's answer to an invite. No session key. Result { json }. */
int nc_group_accept(const char *group_id_hex, const char *invite_id_hex) {
    uint8_t gid[NC_GROUP_ID_LEN], iid[NC_GROUP_INVITE_ID_LEN];
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 ||
        parse_hex_fixed(invite_id_hex, iid, sizeof(iid)) != 0)
        return fail("Invalid group accept input.");
    char *js = NULL;
    size_t jl = 0;
    if (nc_group_accept_encode(gid, iid, &js, &jl) != NC_GROUP_OK)
        return fail("Group accept could not be written.");
    json_object *o = json_object_new_object();
    json_object_object_add(o, "json", json_object_new_string_len(js, (int)jl));
    free(js);
    return set_result(o);
}

/* The owner's welcome (carries addr_secret: SECRET): owner = the session.
 * key_version: the current v (>= 1); kp_digest: digest of packet v.
 * Result { json }. */
int nc_group_welcome(const char *group_id_hex, const char *addr_secret_hex,
                     const char *key_version_dec, const char *kp_digest_hex,
                     const char *invite_id_hex) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    uint8_t gid[NC_GROUP_ID_LEN], sec[NC_GROUP_SECRET_LEN], dig[NC_GROUP_DIGEST_LEN];
    uint8_t iid[NC_GROUP_INVITE_ID_LEN];
    uint32_t kv;
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 ||
        parse_u32_dec(key_version_dec, &kv) != 0 || kv == 0 ||
        parse_hex_fixed(kp_digest_hex, dig, sizeof(dig)) != 0 ||
        parse_hex_fixed(invite_id_hex, iid, sizeof(iid)) != 0)
        return nc_end(fail("Invalid group welcome input."));
    if (parse_hex_fixed(addr_secret_hex, sec, sizeof(sec)) != 0)
        return nc_end(fail("Invalid group address secret."));
    char *js = NULL;
    size_t jl = 0;
    int rc = nc_group_welcome_encode(gid, g_keys.id.node_id.bytes, sec, kv, dig, iid, &js, &jl);
    nc_wipe(sec, sizeof(sec));
    if (rc != NC_GROUP_OK) return nc_end(fail("Group welcome could not be written."));
    json_object *o = json_object_new_object();
    json_object_object_add(o, "json", json_object_new_string_len(js, (int)jl));
    nc_wipe(js, jl);
    free(js);
    return nc_end(set_result(o));
}

/* Strict parse of one decrypted 1:1 plaintext (nc_group_json_parse). No
 * session key. Result { status: ok | refused } and, on ok, type (invite |
 * accept | welcome), group_id, invite_id; invite / welcome: owner; invite:
 * name (UTF-8 checked by the parser); welcome: addr_secret, key_version,
 * kp_digest. Who may send which (invite / welcome only from the pinned
 * owner == the authenticated 1:1 sender; accept only for a pending
 * invite_id of that contact, consumed once) is the page's. */
int nc_group_json_read(const char *json) {
    if (!json) return fail("Invalid group message.");
    size_t len = strnlen(json, NC_GROUP_JSON_MAX + 1);   /* over the cap: refused */
    nc_group_json_t j;
    int rc = nc_group_json_parse(json, len, &j);
    if (rc == NC_GROUP_FAULT) {
        nc_wipe(&j, sizeof(j));
        return fail("Group message could not be read (fault).");
    }
    json_object *o = json_object_new_object();
    json_object_object_add(o, "status", json_object_new_string(rc == NC_GROUP_OK ? "ok" : "refused"));
    if (rc == NC_GROUP_OK) {
        static const char *const TY[] = { "", "invite", "accept", "welcome" };
        json_object_object_add(o, "type", json_object_new_string(TY[j.type]));
        json_object_object_add(o, "group_id", jhex(j.group_id, sizeof(j.group_id)));
        json_object_object_add(o, "invite_id", jhex(j.invite_id, sizeof(j.invite_id)));
        if (j.type != NC_GROUP_JSON_ACCEPT)
            json_object_object_add(o, "owner", jhex(j.owner_fp, sizeof(j.owner_fp)));
        if (j.type == NC_GROUP_JSON_INVITE)
            json_object_object_add(o, "name", json_object_new_string_len(j.name, (int)j.name_len));
        if (j.type == NC_GROUP_JSON_WELCOME) {
            json_object_object_add(o, "addr_secret", jhex(j.addr_secret, sizeof(j.addr_secret)));
            json_object_object_add(o, "key_version", jstr_u64(j.key_version));
            json_object_object_add(o, "kp_digest", jhex(j.kp_digest, sizeof(j.kp_digest)));
        }
    }
    nc_wipe(&j, sizeof(j));
    return set_result(o);
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
