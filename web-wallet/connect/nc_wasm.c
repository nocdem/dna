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
 *     nc_group_accept, nc_group_json_read, and G3's nc_group_random,
 *     nc_group_leave, nc_group_in_alloc) run outside the bracket, like
 *     nc_salt_pick; every one that uses the session's keys or the verified
 *     peer cache runs inside it, like nc_hist_*. G3's nc_group_get,
 *     nc_group_put, nc_group_bucket_send and nc_group_bucket_fetch reach
 *     the network (inside the bracket, session_ok);
 *   - each async export does ONE bounded network step (one GET, one GET_ALL
 *     or one PUT, each bounded by the client's request timeout) so the JS
 *     queue can put a wallet operation between two sync steps (design §6.4
 *     F7). The exceptions are the gated writes — nc_profile_update,
 *     nc_salt_reconcile, nc_contacts_add, nc_group_put,
 *     nc_group_bucket_send: a read then at most one write (at most two
 *     request timeouts) — the PUT must not be split from the read it is
 *     based on (§6.4 F4). No export loops over groups; two loop over keys:
 *     - nc_outbox_get_days (web 0.1.73) over days: up to NC_READ_MANY_MAX
 *       (8) day buckets of ONE contact, read with the same strict request
 *       per day, first pages pipelined NC_READ_PIPELINE (4) at a time —
 *       about one request timeout per wave of 4 (two waves at most), plus
 *       the sequential later pages of a day that has more (as
 *       nc_outbox_get), the cancel flag checked before every wave and every
 *       later page. One request per day would cost a round trip per day.
 *     - nc_contact_reads (web 0.1.74) over contacts: the READS of up to
 *       NC_CONTACT_READS_MAX (4) contacts' message checks — per contact the
 *       ACK (nc_ack_get's read) and up to 8 day buckets (nc_outbox_get_days'
 *       reads), the same strict request and checks per key. Up to
 *       NC_CONTACT_READS_KEYS (36) keys, first pages pipelined
 *       NC_READ_PIPELINE (4) at a time and never more in flight (the node's
 *       16 forwarded-lookup slots, NODUS_BF_MAX_BATCHES, are shared by
 *       every user of that node): worst case 9 waves, about 9 request
 *       timeouts (10 s default, nodus.h nodus_client_config_t
 *       request_timeout_ms), plus the sequential later pages of a key that
 *       has more; the usual check (3 days per contact) is 16 keys, 4 waves.
 *       The cancel flag is checked before every wave and every later page.
 *       No write: the salt step (nc_salt_reconcile, a gated read + write)
 *       and every publish stay one contact per call.
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

/* Wipes the plaintexts of one day's answer, then frees it. */
static void inbox_wipe_clear(nc_inbox_t *in) {
    for (size_t i = 0; i < in->count; i++)
        nc_wipe(in->items[i].plaintext, in->items[i].plaintext_len);
    nc_inbox_clear(in);
}

/* One day's answer as nc_outbox_get returns it; consumes `in` (wiped and
 * cleared). Shared by nc_outbox_get and nc_outbox_get_days. */
static json_object *inbox_json(uint64_t day, nc_inbox_t *in) {
    json_object *o = json_object_new_object();
    add_read(o, in->read.outcome, in->read.why);
    json_object_object_add(o, "day", jstr_u64(day));
    if (in->read.outcome == NC_FOUND) json_object_object_add(o, "blob", jhex(in->blob, sizeof(in->blob)));
    json_object_object_add(o, "unchanged", json_object_new_boolean(in->unchanged));
    json_object_object_add(o, "dropped", jstr_u64(in->dropped));
    /* authentic non-chat payloads: counted, never returned as text */
    json_object_object_add(o, "other", jstr_u64(in->other));
    json_object *a = json_object_new_array();
    for (size_t i = 0; i < in->count; i++) {
        json_object *e = json_object_new_object();
        json_object_object_add(e, "seq", jstr_u64(in->items[i].seq));
        json_object_object_add(e, "sender_ts", jstr_u64(in->items[i].sender_timestamp));
        json_object_object_add(e, "text_hex", jhex(in->items[i].plaintext, in->items[i].plaintext_len));
        json_object_array_add(a, e);
    }
    json_object_object_add(o, "messages", a);
    inbox_wipe_clear(in);
    return o;
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
    return nc_end(set_result(inbox_json(day, &in)));
}

/* Up to NC_READ_MANY_MAX day buckets of ONE contact's outbox in one call
 * (nc_core.h nc_outbox_fetch_days: the first pages pipelined,
 * NC_READ_PIPELINE at once; each day read and processed exactly as
 * nc_outbox_get does). days_json: [{"day":"<u64>","skip":"" | "<64 hex>"},
 * ...], 1..NC_READ_MANY_MAX entries, "skip" as nc_outbox_get's skip_hex.
 * Result: {"days":[<nc_outbox_get's object>, ...]} in the order asked.
 * A day that could not be processed (nc_outbox_get would fail) fails the
 * whole call, nothing returned. */
int nc_outbox_get_days(const char *fp, const char *salt_hex, const char *days_json) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    const nc_peer_t *peer = peer_need(fp);
    if (!peer) return nc_end(-1);
    uint8_t salt[NC_SALT_LEN];
    if (parse_salt(salt_hex, salt) != 0) return nc_end(fail("Invalid salt, day or blob."));
    json_object *arr = days_json ? json_tokener_parse(days_json) : NULL;
    size_t n = arr && json_object_is_type(arr, json_type_array) ? json_object_array_length(arr) : 0;
    if (n == 0 || n > NC_READ_MANY_MAX) {
        if (arr) json_object_put(arr);
        nc_wipe(salt, sizeof(salt));
        return nc_end(fail("Invalid salt, day or blob."));
    }
    nc_outbox_day_req_t req[NC_READ_MANY_MAX];
    uint8_t skip[NC_READ_MANY_MAX][32];
    for (size_t i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(arr, i), *jd, *js;
        const char *skip_hex = NULL;
        if (!e || !json_object_object_get_ex(e, "day", &jd) ||
            !json_object_is_type(jd, json_type_string) ||
            parse_u64(json_object_get_string(jd), &req[i].day) != 0 ||
            (json_object_object_get_ex(e, "skip", &js) &&
             !json_object_is_type(js, json_type_string))) {
            json_object_put(arr);
            nc_wipe(salt, sizeof(salt));
            return nc_end(fail("Invalid salt, day or blob."));
        }
        if (json_object_object_get_ex(e, "skip", &js)) skip_hex = json_object_get_string(js);
        req[i].skip_blob = NULL;
        if (skip_hex && skip_hex[0]) {
            if (parse_hex_fixed(skip_hex, skip[i], sizeof(skip[i])) != 0) {
                json_object_put(arr);
                nc_wipe(salt, sizeof(salt));
                return nc_end(fail("Invalid salt, day or blob."));
            }
            req[i].skip_blob = skip[i];
        }
    }
    json_object_put(arr);
    nc_inbox_t *in = calloc(n, sizeof(*in));
    int *rcs = calloc(n, sizeof(*rcs));
    if (!in || !rcs) {
        free(in); free(rcs);
        nc_wipe(salt, sizeof(salt));
        return nc_end(fail("Out of memory."));
    }
    int rc = nc_outbox_fetch_days(&g_ctx, peer, salt, req, n, in, rcs);
    nc_wipe(salt, sizeof(salt));
    for (size_t i = 0; rc == NC_OK && i < n; i++)
        if (rcs[i] != NC_OK) rc = rcs[i];
    json_object *o = NULL, *a = NULL;
    if (rc == NC_OK) {
        o = json_object_new_object();
        a = json_object_new_array();
    }
    for (size_t i = 0; i < n; i++) {
        if (a) json_object_array_add(a, inbox_json(req[i].day, &in[i]));
        else inbox_wipe_clear(&in[i]);
    }
    free(in);
    free(rcs);
    if (!o) return nc_end(fail("Messages could not be read (%d).", rc));
    json_object_object_add(o, "days", a);
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

/* One day list of nc_contact_reads (nc_outbox_get_days' days_json shape)
 * into req[] / skip[]. 0 / -1. */
static int parse_days(json_object *arr, nc_outbox_day_req_t req[NC_READ_MANY_MAX],
                      uint8_t skip[NC_READ_MANY_MAX][32], size_t *n_out) {
    size_t n = arr && json_object_is_type(arr, json_type_array) ? json_object_array_length(arr) : 0;
    if (n == 0 || n > NC_READ_MANY_MAX) return -1;
    for (size_t i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(arr, i), *jd, *js;
        if (!e || !json_object_object_get_ex(e, "day", &jd) ||
            !json_object_is_type(jd, json_type_string) ||
            parse_u64(json_object_get_string(jd), &req[i].day) != 0)
            return -1;
        req[i].skip_blob = NULL;
        if (json_object_object_get_ex(e, "skip", &js)) {
            if (!json_object_is_type(js, json_type_string)) return -1;
            const char *skip_hex = json_object_get_string(js);
            if (skip_hex && skip_hex[0]) {
                if (parse_hex_fixed(skip_hex, skip[i], sizeof(skip[i])) != 0) return -1;
                req[i].skip_blob = skip[i];
            }
        }
    }
    *n_out = n;
    return 0;
}

/* The read phase of up to NC_CONTACT_READS_MAX contacts' message checks in
 * ONE call (web 0.1.74; nc_core.h nc_contact_reads_many): per contact its
 * ACK (nc_ack_get) and its day buckets (nc_outbox_get_days), every key read
 * with the same strict request and checks as those two exports, the first
 * pages pipelined NC_READ_PIPELINE at once across all the contacts. No
 * write. reads_json: [{"fp":"<128 hex>","salt":"<64 hex>","days":[<as
 * nc_outbox_get_days' days_json>]}, ...], 1..NC_CONTACT_READS_MAX contacts.
 * Result: {"contacts":[{"ack":<nc_ack_get's object>,"days":[<nc_outbox_get's
 * object>, ...]} | {"error":"<text>"}, ...]} in the order asked. "error":
 * that contact only — what its nc_outbox_get_days call would have failed
 * with (no verified profile loaded, or a day that could not be processed);
 * the other contacts' answers stand. Malformed input fails the whole call,
 * nothing read. */
int nc_contact_reads(const char *reads_json) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    json_object *arr = reads_json ? json_tokener_parse(reads_json) : NULL;
    size_t n = arr && json_object_is_type(arr, json_type_array) ? json_object_array_length(arr) : 0;
    if (n == 0 || n > NC_CONTACT_READS_MAX) {
        if (arr) json_object_put(arr);
        return nc_end(fail("Invalid contact, salt, day or blob."));
    }
    nc_contact_reads_t c[NC_CONTACT_READS_MAX];
    nc_outbox_day_req_t req[NC_CONTACT_READS_MAX][NC_READ_MANY_MAX];
    uint8_t skip[NC_CONTACT_READS_MAX][NC_READ_MANY_MAX][32];
    uint8_t salt[NC_CONTACT_READS_MAX][NC_SALT_LEN];
    const char *missing[NC_CONTACT_READS_MAX];   /* no verified profile    */
    memset(c, 0, sizeof(c));
    memset(missing, 0, sizeof(missing));
    int bad = 0;
    for (size_t i = 0; i < n && !bad; i++) {
        json_object *e = json_object_array_get_idx(arr, i), *jf, *js, *jd;
        const char *fp = (e && json_object_object_get_ex(e, "fp", &jf) &&
                          json_object_is_type(jf, json_type_string))
                             ? json_object_get_string(jf) : NULL;
        nodus_key_t chk;
        if (!fp || nc_fp_parse(fp, &chk) != 0 ||
            !json_object_object_get_ex(e, "salt", &js) ||
            !json_object_is_type(js, json_type_string) ||
            parse_salt(json_object_get_string(js), salt[i]) != 0 ||
            !json_object_object_get_ex(e, "days", &jd) ||
            parse_days(jd, req[i], skip[i], &c[i].n_days) != 0) {
            bad = 1;
            break;
        }
        c[i].peer = peer_find(fp);
        if (!c[i].peer) missing[i] = "Load this contact's profile first.";
        c[i].salt = salt[i];
        c[i].days = req[i];
    }
    json_object_put(arr);
    if (bad) {
        nc_wipe(salt, sizeof(salt));
        return nc_end(fail("Invalid contact, salt, day or blob."));
    }
    /* Only the contacts whose profile is loaded are read (compacted). */
    nc_contact_reads_t r[NC_CONTACT_READS_MAX];
    size_t m = 0;
    int rc = NC_OK;
    for (size_t i = 0; i < n; i++) {
        if (missing[i]) continue;
        r[m] = c[i];
        r[m].outs = calloc(c[i].n_days, sizeof(nc_inbox_t));
        r[m].rcs = calloc(c[i].n_days, sizeof(int));
        if (!r[m].outs || !r[m].rcs) rc = NC_ERR_INTERNAL;
        m++;
    }
    if (rc == NC_OK && m > 0) rc = nc_contact_reads_many(&g_ctx, r, m);
    nc_wipe(salt, sizeof(salt));
    json_object *o = NULL, *a = NULL;
    if (rc == NC_OK) {
        o = json_object_new_object();
        a = json_object_new_array();
    }
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        json_object *e = a ? json_object_new_object() : NULL;
        if (missing[i]) {
            if (e) json_object_object_add(e, "error", json_object_new_string(missing[i]));
            if (a) json_object_array_add(a, e);
            continue;
        }
        nc_contact_reads_t *x = &r[j++];
        int day_rc = x->rc;
        for (size_t d = 0; day_rc == NC_OK && x->rcs && d < x->n_days; d++)
            if (x->rcs[d] != NC_OK) day_rc = x->rcs[d];
        if (e && day_rc == NC_OK) {
            /* nc_ack_get's object, then nc_outbox_get_days' days (each
             * inbox consumed — wiped and cleared — by inbox_json) */
            json_object *ack = json_object_new_object();
            add_read(ack, x->ack.outcome, x->ack.why);
            json_object_object_add(ack, "ack_ts", x->ack.outcome == NC_FOUND ? jstr_u64(x->ack_ts) : NULL);
            json_object *days = json_object_new_array();
            for (size_t d = 0; d < x->n_days; d++)
                json_object_array_add(days, inbox_json(x->days[d].day, &x->outs[d]));
            json_object_object_add(e, "ack", ack);
            json_object_object_add(e, "days", days);
        } else {
            if (e) {
                char msg[64];
                snprintf(msg, sizeof(msg), "Messages could not be read (%d).", day_rc);
                json_object_object_add(e, "error", json_object_new_string(msg));
            }
            for (size_t d = 0; x->outs && d < x->n_days; d++) inbox_wipe_clear(&x->outs[d]);
        }
        nc_read_clear(&x->ack);
        free(x->outs);
        free(x->rcs);
        if (a) json_object_array_add(a, e);
    }
    if (!o) return nc_end(fail("Messages could not be read (%d).", rc));
    json_object_object_add(o, "contacts", a);
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
 * than the whole C stack ccall copies it onto. As a hex ARGUMENT a bucket is
 * read up to 256 KiB (512 KiB of hex, leaving half the stack for the frames
 * below — the deepest is the ML-DSA-87 verify; its peak is not measured, the
 * signing peak is ~121 KB per scripts/build-mldsa87-sign-wasm.sh). A larger
 * one is passed through the heap input buffer (nc_group_in_alloc, G3) and
 * read up to the full 1 MiB; never a partial read. */
#define NC_GROUP_BKT_IN_MAX (256u * 1024u)

/* ── large inputs (G3): one heap buffer, the nsw_req_env_alloc form ──────
 * The page asks for `len` bytes (nc_group_in_alloc), fills them through
 * HEAPU8 and calls the export that consumes them IN THE SAME queue slot
 * (src/connect/core.js): that export takes the buffer (in_take) before
 * anything else, so it is wiped and freed on every path, and a buffer is
 * never read twice. Up to NC_GROUP_BUCKET_MAX (1 MiB): a whole day bucket,
 * a key packet (107,795 B at 64 members) or the own items of one bucket. */
static uint8_t *g_in;
static size_t   g_in_len;

static void in_drop(void) {
    if (g_in) { nc_wipe(g_in, g_in_len); free(g_in); }
    g_in = NULL;
    g_in_len = 0;
}

uint8_t *nc_group_in_alloc(int len) {
    in_drop();
    if (len <= 0 || (size_t)len > NC_GROUP_BUCKET_MAX || g_closed) return NULL;
    g_in = malloc((size_t)len);
    if (g_in) g_in_len = (size_t)len;
    return g_in;
}

/* The buffer, now owned by the caller (wipe + free), or NULL. */
static uint8_t *in_take(size_t *len) {
    uint8_t *b = g_in;
    *len = b ? g_in_len : 0;
    g_in = NULL;
    g_in_len = 0;
    return b;
}

static void in_free(uint8_t *b, size_t len) {
    if (b) { nc_wipe(b, len); free(b); }
}

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
 * pinned_digest_hex (G3): "" or the welcome's kp_digest of v — the packet a
 * new member is welcomed into, opened with nc_group_kp_open_pinned (its
 * digest must equal it, prev_digest is not checked; prev_digest_hex must
 * then be ""). Result { status: ok | bad_structure | bad_sig | mismatch |
 * prev_conflict | prev_unavailable | no_entry } and, once the signature
 * verified, v, count, digest, prev_digest, record_digest, issued_at_ms;
 * group_key only on ok. */
int nc_group_kp_read(const char *packet_hex, const char *owner_fp, const char *group_id_hex,
                     const char *v_dec, const char *prev_digest_hex,
                     const char *pinned_digest_hex) {
    if (nc_begin() != 0) return -1;
    if (!g_unlocked) return nc_end(fail("Messages is not connected."));
    uint8_t gid[NC_GROUP_ID_LEN], ofp[NC_GROUP_FP_LEN], prev[NC_GROUP_DIGEST_LEN];
    uint8_t pin[NC_GROUP_DIGEST_LEN];
    uint32_t v;
    bool has_prev = prev_digest_hex && prev_digest_hex[0];
    bool has_pin = pinned_digest_hex && pinned_digest_hex[0];
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 || parse_u32_dec(v_dec, &v) != 0 ||
        (has_prev && has_pin) ||
        (has_prev && parse_hex_fixed(prev_digest_hex, prev, sizeof(prev)) != 0) ||
        (has_pin && parse_hex_fixed(pinned_digest_hex, pin, sizeof(pin)) != 0))
        return nc_end(fail("Invalid key packet input."));
    const uint8_t *opk = NULL;
    if (group_keys_of(owner_fp, ofp, &opk, NULL) != 0) return nc_end(-1);
    uint8_t *pkt;
    size_t pl;
    if (parse_hex_var(packet_hex, NC_GROUP_KP_MAX, &pkt, &pl) != 0)
        return nc_end(fail("Invalid key packet (not hex, or over %u bytes).",
                           (unsigned)NC_GROUP_KP_MAX));
    nc_group_kp_open_t r;
    nc_group_kp_status_t st = has_pin
        ? nc_group_kp_open_pinned(pkt, pl, opk, gid, ofp, v, pin, g_keys.id.node_id.bytes,
                                  nc_group_decap_mlkem, g_keys.mlkem_sk, &r)
        : nc_group_kp_open(pkt, pl, opk, gid, ofp, v, has_prev ? prev : NULL,
                           g_keys.id.node_id.bytes, nc_group_decap_mlkem, g_keys.mlkem_sk, &r);
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

static void fp_hex(const uint8_t fp[NC_GROUP_FP_LEN], char out[NC_FP_HEX_LEN + 1]) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < NC_GROUP_FP_LEN; i++) {
        out[2 * i] = d[fp[i] >> 4];
        out[2 * i + 1] = d[fp[i] & 15];
    }
    out[NC_FP_HEX_LEN] = '\0';
}

/* One day bucket into `o`: decode (nc_group_bucket_decode: group / v / day
 * equal the address inputs, one sender, unique message_ids, caps) and open
 * every item with the sender's key (own or verified peer cache) and
 * group_key_v. Adds "status": ok | bad_structure | wrong_owner |
 * sender_unknown, "sender" (when items exist) and "messages". `owner`: the
 * DHT value's owner — when given, the items' sender must be it (design §6:
 * the value's owner == sender_fp), else "wrong_owner" and nothing is
 * opened; NULL leaves that check to the caller. 0, or -1 on a fault. */
static int bucket_entry(json_object *o, const uint8_t *b, size_t bl,
                        const uint8_t gid[NC_GROUP_ID_LEN], uint32_t v, uint32_t day,
                        const uint8_t gk[NC_GROUP_KEY_LEN], const uint8_t *owner) {
    nc_group_msg_t *items = NULL;
    size_t n = 0;
    int rc = nc_group_bucket_decode(b, bl, gid, v, day, &items, &n);
    if (rc == NC_GROUP_FAULT) return -1;
    json_object *a = json_object_new_array();
    const char *status = rc == NC_GROUP_OK ? "ok" : "bad_structure";
    if (rc == NC_GROUP_OK && n > 0) {
        char sender[NC_FP_HEX_LEN + 1];
        fp_hex(items[0].sender_fp, sender);
        json_object_object_add(o, "sender", json_object_new_string(sender));
        const uint8_t *spk = NULL;
        if (owner && memcmp(owner, items[0].sender_fp, NC_GROUP_FP_LEN) != 0) {
            status = "wrong_owner";
        } else if (own_fp_is(sender)) {
            spk = g_keys.id.pk.bytes;
        } else {
            const nc_peer_t *p = peer_find(sender);
            if (p) spk = p->dsa_pk;
            else status = "sender_unknown";
        }
        if (spk) {
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
    return 0;
}

/* Decode a day bucket read at OUTBOX(salt_v, day) and open every item with
 * the sender's key (own or verified peer cache) and group_key_v.
 * bucket_hex: the bucket as hex (up to NC_GROUP_BKT_IN_MAX), or "" = the
 * bytes the page put in the heap input buffer (nc_group_in_alloc, up to
 * 1 MiB — G3). Result { status: ok | bad_structure | sender_unknown, sender
 * (128 hex, when items exist), messages: [{ message_id, timestamp_ms,
 * status: ok | bad_sig | bad_auth | refused, text_hex (ok only) }] }.
 * "sender_unknown": load that profile (nc_profile_get), then read again.
 * NOT checked here, the page's (nc_group.h nc_group_bucket_decode): the DHT
 * value's owner == sender (nc_group_bucket_fetch does check it), and the
 * membership rule (nc_group_msg_accept, decision 6). */
int nc_group_bucket_read(const char *bucket_hex, const char *group_id_hex, const char *v_dec,
                         const char *day_dec, const char *group_key_hex) {
    size_t inl;
    uint8_t *in = in_take(&inl);
    if (nc_begin() != 0) { in_free(in, inl); return -1; }
    if (!g_unlocked) { in_free(in, inl); return nc_end(fail("Messages is not connected.")); }
    uint8_t gid[NC_GROUP_ID_LEN], gk[NC_GROUP_KEY_LEN];
    uint32_t v, day;
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0 || parse_u32_dec(v_dec, &v) != 0 ||
        parse_u32_dec(day_dec, &day) != 0) {
        in_free(in, inl);
        return nc_end(fail("Invalid group bucket input."));
    }
    uint8_t *b;
    size_t bl;
    if (bucket_hex && bucket_hex[0]) {
        in_free(in, inl);
        if (parse_hex_var(bucket_hex, NC_GROUP_BKT_IN_MAX, &b, &bl) != 0)
            return nc_end(fail("Invalid group bucket (not hex, or over %u bytes).",
                               (unsigned)NC_GROUP_BKT_IN_MAX));
    } else {
        if (!in) return nc_end(fail("No group bucket was given."));
        b = in;
        bl = inl;
    }
    if (parse_hex_fixed(group_key_hex, gk, sizeof(gk)) != 0) {
        in_free(b, bl);
        return nc_end(fail("Invalid group key."));
    }
    json_object *o = json_object_new_object();
    int rc = bucket_entry(o, b, bl, gid, v, day, gk, NULL);
    in_free(b, bl);
    nc_wipe(gk, sizeof(gk));
    if (rc != 0) {
        json_object_put(o);
        return nc_end(fail("Group bucket could not be read (fault)."));
    }
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
 * accept | welcome | leave), group_id; invite_id (not for leave); invite /
 * welcome: owner; invite: name (UTF-8 checked by the parser); welcome:
 * addr_secret, key_version, kp_digest. Who may send which (invite / welcome
 * only from the pinned owner == the authenticated 1:1 sender; accept only
 * for a pending invite_id of that contact, consumed once; leave only from a
 * current member, decision 13) is the page's. */
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
        static const char *const TY[] = { "", "invite", "accept", "welcome", "leave" };
        json_object_object_add(o, "type", json_object_new_string(TY[j.type]));
        json_object_object_add(o, "group_id", jhex(j.group_id, sizeof(j.group_id)));
        if (j.type != NC_GROUP_JSON_LEAVE)
            json_object_object_add(o, "invite_id", jhex(j.invite_id, sizeof(j.invite_id)));
        if (j.type == NC_GROUP_JSON_INVITE || j.type == NC_GROUP_JSON_WELCOME)
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

/* ── groups (package G3): secrets, the leave, and the network ───────────
 *
 * Governing records: design docs/plans/2026-10-04-connect-groups-design.md
 * rev 1 §3, §6; bytes items 1-7 + REV 2 (R2-4: HEAD / packet / record read
 * with the pinned owner, HEAD written EXCLUSIVE; R2-5: buckets read
 * owner-less, owner == sender checked here); decisions/2026-10-04-connect-
 * groups.md item 10 (packets, records, HEAD PERMANENT — HEAD EXCLUSIVE,
 * which is permanent too, nodus_types.h:438 — day buckets EPHEMERAL 7 days)
 * and item 13 (leave); decisions/2026-09-30-nodus-connect-thin-core.md S3
 * (every read three outcomes, "could not read" never leads to a write) and
 * design rev 5 §6.4 F4 (a PUT is never split from the read it is based on).
 *
 * The three writes (nc_group_put, nc_group_bucket_send) read this
 * identity's own row at the address IN THE SAME CALL, then write at most
 * once. A read that returned only rows of OTHER owners (nc_read_one:
 * UNREADABLE(WRONG_OWNER)) is a complete answer about this identity's row
 * as much as EMPTY is (both are "the node returned no row of mine", F5),
 * and is treated as EMPTY for the own write: a removed member still knows
 * addr_secret (bytes §1) and could otherwise park a row at the next packet
 * address and stop the owner from ever publishing it; the readers never
 * see such rows (they read with the owner, R2-4). Every other UNREADABLE
 * is "wait": nothing written. */

#define NC_GROUP_BUCKET_TTL (7u * 24u * 3600u)   /* decision item 10: 7 days */

/* The DHT key of (purpose, group_id, secret, x): SHA3-512 of the "ncg:"
 * string (nc_group_addr; the DHT layer hashes the string once more, as
 * nodus_ops_*_str do — nc_key_str). */
static int group_dht_key(int purpose, const char *group_id_hex, const char *secret_hex,
                         uint64_t x, uint8_t gid[NC_GROUP_ID_LEN], nodus_key_t *key) {
    uint8_t sec[NC_GROUP_SECRET_LEN], k[NC_GROUP_DIGEST_LEN];
    char s[NC_GROUP_ADDR_STR_LEN + 1];
    if (purpose < NC_GROUP_PURPOSE_HEAD || purpose > NC_GROUP_PURPOSE_OUTBOX ||
        parse_hex_fixed(group_id_hex, gid, NC_GROUP_ID_LEN) != 0 ||
        parse_hex_fixed(secret_hex, sec, sizeof(sec)) != 0) {
        nc_wipe(sec, sizeof(sec));
        return fail("Invalid group address input.");
    }
    int rc = nc_group_addr((nc_group_purpose_t)purpose, gid, sec, x, k, s);
    nc_wipe(sec, sizeof(sec));
    if (rc != NC_GROUP_OK) return fail("Group address input refused (version or day out of range).");
    nc_key_str(s, key);
    return 0;
}

/* Fresh group secrets from the module's one random source (nodus-send-
 * wasm.c qgp_platform_random). Synchronous, no session. Result { group_id,
 * group_key, addr_secret } (32 bytes each, hex): a new group takes all
 * three (bytes "Secrets per group"); a rotation takes group_key only. */
int nc_group_random(void) {
    uint8_t b[NC_GROUP_ID_LEN + NC_GROUP_KEY_LEN + NC_GROUP_SECRET_LEN];
    if (qgp_platform_random(b, sizeof(b)) != 0) return fail("No randomness available.");
    json_object *o = json_object_new_object();
    json_object_object_add(o, "group_id", jhex(b, NC_GROUP_ID_LEN));
    json_object_object_add(o, "group_key", jhex(b + NC_GROUP_ID_LEN, NC_GROUP_KEY_LEN));
    json_object_object_add(o, "addr_secret",
                           jhex(b + NC_GROUP_ID_LEN + NC_GROUP_KEY_LEN, NC_GROUP_SECRET_LEN));
    nc_wipe(b, sizeof(b));
    return set_result(o);
}

/* A member's leave (decision 13), sent to the owner over 1:1. No session
 * key. Result { json }. */
int nc_group_leave(const char *group_id_hex) {
    uint8_t gid[NC_GROUP_ID_LEN];
    if (parse_hex_fixed(group_id_hex, gid, sizeof(gid)) != 0) return fail("Invalid group id.");
    char *js = NULL;
    size_t jl = 0;
    if (nc_group_leave_encode(gid, &js, &jl) != NC_GROUP_OK)
        return fail("Group leave could not be written.");
    json_object *o = json_object_new_object();
    json_object_object_add(o, "json", json_object_new_string_len(js, (int)jl));
    free(js);
    return set_result(o);
}

/* ONE value at a HEAD (1), KEY PACKET (2) or RECORD (3) address, read with
 * the pinned owner (R2-4: nc_read_one with expect_owner, the owner-filtered
 * paged read — a stranger's row never shadows the owner's). secret_hex:
 * addr_secret (1, 2) or salt_v (3); x_dec: 0 | v | v. owner_fp: the pinned
 * owner. One bounded network step. Result { outcome: found | empty |
 * unreadable, why, foreign (rows of other owners the node sent), data (hex,
 * found only) }. A found value over its structure's size (HEAD 4,817 B, a
 * packet of 64 members, a record of 64) is "unreadable" / "bad_record". */
int nc_group_get(int purpose, const char *group_id_hex, const char *secret_hex,
                 const char *x_dec, const char *owner_fp) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    if (purpose == NC_GROUP_PURPOSE_OUTBOX)
        return nc_end(fail("Day buckets are read with nc_group_bucket_fetch."));
    uint8_t gid[NC_GROUP_ID_LEN];
    uint64_t x;
    nodus_key_t key, owner;
    if (parse_u64(x_dec, &x) != 0) return nc_end(fail("Invalid group address input."));
    if (group_dht_key(purpose, group_id_hex, secret_hex, x, gid, &key) != 0) return nc_end(-1);
    if (nc_fp_parse(owner_fp, &owner) != 0) return nc_end(fail("Invalid Nodus address."));
    nc_read_t raw;
    nc_read_one(&g_ctx, &key, &owner, &raw);
    size_t cap = purpose == NC_GROUP_PURPOSE_HEAD ? NC_GROUP_HEAD_LEN
               : purpose == NC_GROUP_PURPOSE_KEY_PACKET ? NC_GROUP_KP_MAX : NC_GROUP_REC_MAX;
    json_object *o = json_object_new_object();
    if (raw.outcome == NC_FOUND && raw.value &&
        (raw.value->data_len == 0 || raw.value->data_len > cap)) {
        add_read(o, NC_UNREADABLE, NC_WHY_BAD_RECORD);
    } else {
        add_read(o, raw.outcome, raw.why);
        if (raw.outcome == NC_FOUND && raw.value)
            json_object_object_add(o, "data", jhex(raw.value->data, raw.value->data_len));
    }
    json_object_object_add(o, "foreign", jstr_u64(raw.foreign));
    nc_read_clear(&raw);
    return nc_end(set_result(o));
}

/* The owner publishes its HEAD (1), key packet (2) or record (3) of a
 * version: the value is in the heap input buffer (nc_group_in_alloc —
 * a packet of 64 members is 107,795 B). Owner = the session. The bytes are
 * checked to be this owner's for that address (HEAD: verifies under the
 * session key for this group, x = 0; packet: parses, version x, this
 * group, this owner; record: tag, this group, version x, size), then the
 * own row is read IN THIS CALL (nc_read_one, owner = self):
 *   unreadable (other than "only other owners' rows")      -> wait
 *   found, same bytes                                      -> unchanged
 *   found HEAD of a higher version                         -> stale (never
 *     rolled back: another device of this owner moved on)
 *   found HEAD of the same version: same packet digest -> unchanged,
 *     another digest -> conflict
 *   found packet / record with other bytes                 -> conflict (a
 *     version is never replaced, design §3; R2-2: the owner republishes the
 *     exact staged bytes)
 *   empty (or only other owners' rows), or an older HEAD   -> PUT:
 *     HEAD EXCLUSIVE, packet / record PERMANENT, ttl 0, value_id =
 *     nodus_identity_value_id (decision item 10, R2-4).
 * Result { status: published | unchanged | wait | stale | conflict | taken
 * | failed, outcome, why, foreign, put_rc }. "taken" = NODUS_ERR_KEY_OWNED:
 * the EXCLUSIVE HEAD address is held by someone else — terminal. */
int nc_group_put(int purpose, const char *group_id_hex, const char *secret_hex,
                 const char *x_dec) {
    size_t vl;
    uint8_t *val = in_take(&vl);
    if (nc_begin() != 0) { in_free(val, vl); return -1; }
    if (session_ok() != 0) { in_free(val, vl); return nc_end(-1); }
    uint8_t gid[NC_GROUP_ID_LEN];
    uint64_t x;
    nodus_key_t key;
    if (!val) return nc_end(fail("Nothing to publish."));
    if (purpose == NC_GROUP_PURPOSE_OUTBOX) {
        in_free(val, vl);
        return nc_end(fail("Day buckets are sent with nc_group_bucket_send."));
    }
    if (parse_u64(x_dec, &x) != 0 ||
        group_dht_key(purpose, group_id_hex, secret_hex, x, gid, &key) != 0) {
        in_free(val, vl);
        return nc_end(g_error[0] ? -1 : fail("Invalid group address input."));
    }
    const uint8_t *own = g_keys.id.node_id.bytes;
    bool ok = false;
    nc_group_head_t mine;
    memset(&mine, 0, sizeof(mine));
    if (purpose == NC_GROUP_PURPOSE_HEAD) {
        ok = x == 0 && nc_group_head_verify(val, vl, g_keys.id.pk.bytes, gid, own, &mine) ==
                       NC_GROUP_HEAD_OK;
    } else if (purpose == NC_GROUP_PURPOSE_KEY_PACKET) {
        nc_group_kp_hdr_t h;
        ok = nc_group_kp_parse(val, vl, &h, NULL) == NC_GROUP_OK && h.v == x &&
             memcmp(h.group_id, gid, NC_GROUP_ID_LEN) == 0 &&
             memcmp(h.owner_fp, own, NC_GROUP_FP_LEN) == 0;
    } else {
        ok = vl >= NC_GROUP_REC_HEADER_LEN + NC_GROUP_GCM_TAG_LEN && vl <= NC_GROUP_REC_MAX &&
             memcmp(val, nc_group_tag(NC_GROUP_TAG_GREC), NC_GROUP_TAG_LEN) == 0 &&
             memcmp(val + NC_GROUP_TAG_LEN, gid, NC_GROUP_ID_LEN) == 0 &&
             ((uint64_t)val[48] << 24 | (uint64_t)val[49] << 16 |
              (uint64_t)val[50] << 8 | (uint64_t)val[51]) == x;
    }
    if (!ok) {
        in_free(val, vl);
        return nc_end(fail("These group bytes do not belong at this address: nothing was published."));
    }

    nc_read_t raw;
    nc_read_one(&g_ctx, &key, &g_keys.id.node_id, &raw);
    const char *status = NULL;
    bool put = false;
    if (raw.outcome == NC_UNREADABLE && raw.why != NC_WHY_WRONG_OWNER) {
        status = "wait";
    } else if (raw.outcome == NC_FOUND && raw.value) {
        const nodus_value_t *f = raw.value;
        if (f->data_len == vl && memcmp(f->data, val, vl) == 0) {
            status = "unchanged";
        } else if (purpose == NC_GROUP_PURPOSE_HEAD) {
            nc_group_head_t found;
            if (nc_group_head_verify(f->data, f->data_len, g_keys.id.pk.bytes, gid, own, &found) ==
                NC_GROUP_HEAD_OK) {
                if (found.v > mine.v) status = "stale";
                else if (found.v == mine.v)
                    status = memcmp(found.kp_digest, mine.kp_digest, NC_GROUP_DIGEST_LEN) == 0
                             ? "unchanged" : "conflict";
                else put = true;
            } else {
                put = true;                      /* own row, not a HEAD of this group */
            }
        } else {
            status = "conflict";
        }
    } else {
        put = true;                              /* empty, or only other owners' rows */
    }
    int put_rc = 0;
    if (put) {
        put_rc = nc_put(&g_ctx, &key, val, vl,
                        purpose == NC_GROUP_PURPOSE_HEAD ? NODUS_VALUE_EXCLUSIVE
                                                         : NODUS_VALUE_PERMANENT,
                        0, nodus_identity_value_id(&g_keys.id));
        status = put_rc == 0 ? "published" : put_rc == NODUS_ERR_KEY_OWNED ? "taken" : "failed";
    }
    in_free(val, vl);
    json_object *o = json_object_new_object();
    json_object_object_add(o, "status", json_object_new_string(status));
    add_read(o, raw.outcome, raw.why);
    json_object_object_add(o, "foreign", jstr_u64(raw.foreign));
    json_object_object_add(o, "put_rc", json_object_new_int(put_rc));
    nc_read_clear(&raw);
    return nc_end(set_result(o));
}

static int u32_args(const char *v_dec, const char *day_dec, uint32_t *v, uint32_t *day) {
    return parse_u32_dec(v_dec, v) != 0 || *v == 0 || parse_u32_dec(day_dec, day) != 0 ? -1 : 0;
}

/* The sender's own day bucket of (group, v, day), read before it is
 * written, IN THIS CALL (design §6: "own bucket write: base = a read made in
 * the same call; UNREADABLE -> wait, never write"). The heap input buffer
 * (nc_group_in_alloc) holds the page's OWN items for this bucket — every one
 * this device keeps for (group, v, day), each as nc_group_msg_new made it,
 * concatenated; each must parse (nc_group_msg_parse), carry this group /
 * v / day and the session as sender. salt_hex: salt_v of v. Then:
 *   own row unreadable (other than "only other owners' rows") -> wait;
 *   own row found -> decoded (nc_group_bucket_decode, this group / v / day,
 *     this identity as its one sender); a row that does not decode is NOT
 *     overwritten -> refused;
 *   the bucket = the row's items in their order, then the page's items
 *     whose message_id it lacks (so a node that answered "empty" for an
 *     existing row loses nothing this device sent); nothing new ->
 *     unchanged (no PUT); over 100 items or 1 MiB -> full (nothing written);
 *   PUT EPHEMERAL, ttl 7 days, value_id = nodus_identity_value_id (one row
 *     per sender, decision item 10).
 * Result { status: published | unchanged | wait | refused | full | failed,
 * outcome, why, count, put_rc, ids: [message_id hex of the bucket on the
 * network after this call — published / unchanged only] }. */
int nc_group_bucket_send(const char *group_id_hex, const char *salt_hex, const char *v_dec,
                         const char *day_dec) {
    size_t il;
    uint8_t *in = in_take(&il);
    if (nc_begin() != 0) { in_free(in, il); return -1; }
    if (session_ok() != 0) { in_free(in, il); return nc_end(-1); }
    uint8_t gid[NC_GROUP_ID_LEN];
    uint32_t v, day;
    nodus_key_t key;
    if (!in) return nc_end(fail("No group message to send."));
    if (u32_args(v_dec, day_dec, &v, &day) != 0 ||
        group_dht_key(NC_GROUP_PURPOSE_OUTBOX, group_id_hex, salt_hex, day, gid, &key) != 0) {
        in_free(in, il);
        return nc_end(g_error[0] ? -1 : fail("Invalid group bucket input."));
    }
    const uint8_t *own = g_keys.id.node_id.bytes;
    /* the page's items */
    const uint8_t *pi[NC_GROUP_BUCKET_ITEMS_MAX];
    size_t pl[NC_GROUP_BUCKET_ITEMS_MAX], pn = 0;
    uint8_t pid[NC_GROUP_BUCKET_ITEMS_MAX][NC_GROUP_MSG_ID_LEN];
    for (size_t off = 0; off < il;) {
        nc_group_msg_t m;
        if (pn == NC_GROUP_BUCKET_ITEMS_MAX ||
            nc_group_msg_parse(in + off, il - off, false, &m) != NC_GROUP_OK ||
            memcmp(m.group_id, gid, NC_GROUP_ID_LEN) != 0 || m.v != v || m.day != day ||
            memcmp(m.sender_fp, own, NC_GROUP_FP_LEN) != 0) {
            in_free(in, il);
            return nc_end(fail("A group message to send is not this bucket's: nothing was sent."));
        }
        pi[pn] = in + off;
        pl[pn] = m.item_len;
        memcpy(pid[pn], m.message_id, NC_GROUP_MSG_ID_LEN);
        pn++;
        off += m.item_len;
    }

    nc_read_t raw;
    nc_read_one(&g_ctx, &key, &g_keys.id.node_id, &raw);
    const char *status = NULL;
    nc_group_msg_t *base = NULL;
    size_t bn = 0;
    if (raw.outcome == NC_UNREADABLE && raw.why != NC_WHY_WRONG_OWNER) {
        status = "wait";
    } else if (raw.outcome == NC_FOUND && raw.value) {
        int rc = nc_group_bucket_decode(raw.value->data, raw.value->data_len, gid, v, day,
                                        &base, &bn);
        if (rc == NC_GROUP_FAULT) {
            nc_read_clear(&raw);
            in_free(in, il);
            return nc_end(fail("Group bucket could not be read (fault)."));
        }
        if (rc != NC_GROUP_OK || (bn > 0 && memcmp(base[0].sender_fp, own, NC_GROUP_FP_LEN) != 0))
            status = "refused";
    }

    /* union: the row's items, then the page's new ones */
    const uint8_t *all[NC_GROUP_BUCKET_ITEMS_MAX];
    size_t all_len[NC_GROUP_BUCKET_ITEMS_MAX], an = 0, added = 0;
    if (!status) {
        for (size_t i = 0; i < bn && an < NC_GROUP_BUCKET_ITEMS_MAX; i++) {
            all[an] = base[i].h;
            all_len[an++] = base[i].item_len;
        }
        for (size_t j = 0; j < pn && !status; j++) {
            bool have = false;
            for (size_t i = 0; i < bn && !have; i++)
                have = memcmp(base[i].message_id, pid[j], NC_GROUP_MSG_ID_LEN) == 0;
            for (size_t k = 0; k < j && !have; k++)   /* a repeat inside the page's set */
                have = memcmp(pid[k], pid[j], NC_GROUP_MSG_ID_LEN) == 0;
            if (have) continue;
            if (an == NC_GROUP_BUCKET_ITEMS_MAX) { status = "full"; break; }
            all[an] = pi[j];
            all_len[an++] = pl[j];
            added++;
        }
        if (!status && added == 0) status = "unchanged";
    }
    int put_rc = 0;
    if (!status) {
        uint8_t *bucket = NULL;
        size_t bl = 0;
        int rc = nc_group_bucket_encode(all, all_len, an, &bucket, &bl);
        if (rc == NC_GROUP_FAULT) {
            free(base);
            nc_read_clear(&raw);
            in_free(in, il);
            return nc_end(fail("Group bucket could not be written (fault)."));
        }
        if (rc != NC_GROUP_OK) {
            status = "full";                       /* over 1 MiB */
        } else {
            put_rc = nc_put(&g_ctx, &key, bucket, bl, NODUS_VALUE_EPHEMERAL,
                            NC_GROUP_BUCKET_TTL, nodus_identity_value_id(&g_keys.id));
            status = put_rc == 0 ? "published" : "failed";
        }
        free(bucket);                              /* ciphertexts and signatures */
    }
    json_object *o = json_object_new_object();
    json_object_object_add(o, "status", json_object_new_string(status));
    add_read(o, raw.outcome, raw.why);
    json_object_object_add(o, "put_rc", json_object_new_int(put_rc));
    bool listed = strcmp(status, "published") == 0 || strcmp(status, "unchanged") == 0;
    json_object_object_add(o, "count", jstr_u64(listed ? an : 0));
    json_object *ids = json_object_new_array();
    if (listed) {
        for (size_t i = 0; i < an; i++) {
            nc_group_msg_t m;
            if (nc_group_msg_parse(all[i], all_len[i], true, &m) == NC_GROUP_OK)
                json_object_array_add(ids, jhex(m.message_id, NC_GROUP_MSG_ID_LEN));
        }
    }
    json_object_object_add(o, "ids", ids);
    free(base);                                    /* pointers into raw.value */
    nc_read_clear(&raw);
    in_free(in, il);
    return nc_end(set_result(o));
}

/* Every sender's day bucket of (group, v, day): one owner-less paged read
 * (nc_read_all, R2-5), then per row: the row's owner, its bucket decoded
 * against this group / v / day, its one sender == the row's owner (design
 * §6; else "wrong_owner", nothing opened), each item verified with the
 * sender's key (own or verified peer cache) and opened with group_key_v.
 * NOT applied here, the page's: the membership rule (sender in record(v)
 * and, when record(v+1) is held, in it too — decision 6), deduplication.
 * Result { outcome, why, truncated, dropped: { undecodable, bad_signature,
 * wrong_key }, buckets: [{ owner, status: ok | bad_structure | wrong_owner
 * | sender_unknown, sender?, messages: [{ message_id, timestamp_ms, status,
 * text_hex? }] }] }. "sender_unknown": load that profile, then read again. */
int nc_group_bucket_fetch(const char *group_id_hex, const char *salt_hex, const char *v_dec,
                          const char *day_dec, const char *group_key_hex) {
    if (nc_begin() != 0) return -1;
    if (session_ok() != 0) return nc_end(-1);
    uint8_t gid[NC_GROUP_ID_LEN], gk[NC_GROUP_KEY_LEN];
    uint32_t v, day;
    nodus_key_t key;
    if (u32_args(v_dec, day_dec, &v, &day) != 0)
        return nc_end(fail("Invalid group bucket input."));
    if (group_dht_key(NC_GROUP_PURPOSE_OUTBOX, group_id_hex, salt_hex, day, gid, &key) != 0)
        return nc_end(-1);
    if (parse_hex_fixed(group_key_hex, gk, sizeof(gk)) != 0)
        return nc_end(fail("Invalid group key."));
    nc_read_all_t all;
    nc_read_all(&g_ctx, &key, NULL, 0, &all);
    json_object *o = json_object_new_object();
    add_read(o, all.outcome, all.why);
    json_object_object_add(o, "truncated", json_object_new_boolean(all.truncated));
    json_object *c = json_object_new_object();
    json_object_object_add(c, "undecodable", jstr_u64(all.undecodable));
    json_object_object_add(c, "bad_signature", jstr_u64(all.bad_sig));
    json_object_object_add(c, "wrong_key", jstr_u64(all.wrong_key));
    json_object_object_add(o, "dropped", c);
    json_object *a = json_object_new_array();
    int fault = 0;
    for (size_t i = 0; i < all.count && !fault; i++) {
        const nodus_value_t *val = all.values[i];
        json_object *e = json_object_new_object();
        char owner[NC_FP_HEX_LEN + 1];
        fp_hex(val->owner_fp.bytes, owner);
        json_object_object_add(e, "owner", json_object_new_string(owner));
        if (bucket_entry(e, val->data, val->data_len, gid, v, day, gk, val->owner_fp.bytes) != 0)
            fault = 1;
        json_object_array_add(a, e);
    }
    json_object_object_add(o, "buckets", a);
    nc_read_all_clear(&all);
    nc_wipe(gk, sizeof(gk));
    if (fault) {
        json_object_put(o);
        return nc_end(fail("Group bucket could not be read (fault)."));
    }
    return nc_end(set_result(o));
}

/* ── lock: synchronous, never reaches emscripten_sleep ───────────────── */

/* Every Messages secret and cache. Called by the host's lock (nsw_lock,
 * which then closes the session; JS zeroes the linear memory and aborts
 * the instance) and by nc_lock / nc_end below. */
void nc_session_wipe(void) {
    nc_keys_wipe(&g_keys);
    words_drop();
    in_drop();
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
