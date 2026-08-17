/**
 * Nodus — Ledger V2: the witness-side ENVELOPE PREFLIGHT SEAM
 * (nodus_witness_v2_env.{h,c}), the one place candidate envelope bytes
 * become DERIVED transaction identities.
 *
 * The properties pinned here, in increasing order of importance:
 *
 *   1. SEAM CHAIN-ID AUTHORITY — the seam binds to the DERIVED chain id
 *      (committed genesis block_id, full 32 bytes), never to the LEGACY
 *      witness->chain_id whose bytes 16..31 are always zero
 *      (nodus_witness.c:265-280). The fixture's genesis id is non-zero in
 *      every one of those bytes, so a regression that reached for the
 *      legacy value would produce a DIFFERENT tx_id — and this suite
 *      computes that different value and asserts the seam does not match
 *      it.
 *   2. FORGED-DUPLICATE IMPOSSIBILITY — the API has no transaction-id
 *      input at all (pinned by a _Static_assert on the envelope struct's
 *      size), so two envelopes whose first 64 wire bytes are byte-
 *      identical still receive distinct identities.
 *   3. BATCH-FAILURE NON-PUBLICATION — any rejection zeroes the ENTIRE
 *      out array, including entries that had already succeeded. Proven by
 *      pre-filling the array with a 0xAA sentinel and asserting not one
 *      byte survives.
 *   4. FAIL-CLOSED CHAIN IDENTITY — a database with the V2 schema but no
 *      committed genesis derives nothing and rejects.
 *
 * @file test_v2_env_preflight.c
 */

/* mkdtemp() and lstat() are POSIX, not ISO C: under a strict -std=c11 the
 * glibc headers hide them and both calls become implicit declarations.
 * Declaring the feature set makes this file compile clean under
 * -std=c11 -Wall -Wextra -Werror -pedantic as well as in the project
 * build, where the default is already permissive. */
#define _DEFAULT_SOURCE 1

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_env.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/env_wire.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "v2_genesis_fixture.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* The no-ID-field pin: nodus_v2_envelope_t is EXACTLY a pointer and a
 * length. If anyone ever adds a caller-supplied tx_id to it, this fails to
 * compile — which is the point. A derived identity that a caller can
 * override is not a derived identity. */
_Static_assert(sizeof(nodus_v2_envelope_t) ==
                   sizeof(const uint8_t *) + sizeof(size_t),
               "nodus_v2_envelope_t gained a field — a caller-supplied "
               "transaction id must never be possible");

/* ── fs + fixture (test_v2_apply.c:78-133 pattern) ──────────────────── */
static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

typedef struct {
    nodus_witness_t *w;              /* HEAP: nodus_witness_t is multi-MB,
                                      * a stack instance segfaults        */
    char             dir[256];
    uint8_t          chain_id16[16];
} fixture_t;

static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_env_pf_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x33, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    nodus_chain_config_db_migrate(fx->w);
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

/**
 * Genesis block id, NON-ZERO THROUGHOUT: bytes 0x40..0x7F. The derived
 * chain id is its first 32 bytes (0x40..0x5F), so bytes 16..31 of the
 * chain id are 0x50..0x5F — every one non-zero, and distinct from bytes
 * 0..15. That is what makes the legacy-value regression observable.
 */
static void mk_gen_id(uint8_t out[64], uint8_t base) {
    for (int i = 0; i < 64; i++) out[i] = (uint8_t)(base + i);
}

/* ── envelope construction ──────────────────────────────────────────── */

/** A 1-leg envelope. Caller owns the returned buffer. */
static uint8_t *mk_env(uint32_t domain, uint32_t ruleset_version,
                       uint64_t expiry, const uint8_t *call,
                       uint32_t call_len, size_t *len_out) {
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = domain;
    leg.hdr.runtime_op           = 1;
    leg.hdr.ruleset_version      = ruleset_version;
    leg.hdr.access_mode          = (uint8_t)DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = 1;
    leg.hdr.call_len             = call_len;
    leg.hdr.auth_len             = 0;
    leg.hdr.res_max_effects      = 2;
    leg.hdr.res_max_effect_bytes = 64;
    leg.call_data                = call;
    leg.auth_data                = NULL;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height       = expiry;
    in.fee_amount          = 10;
    in.res_max_total_units = 100;
    in.leg_count           = 1;
    in.legs                = &leg;

    size_t need = 0;
    if (dna_env_encoded_size(&leg, 1, &need) != 0) return NULL;
    uint8_t *buf = malloc(need);
    if (!buf) return NULL;
    if (dna_env_encode(&in, buf, need, len_out) != 0) { free(buf); return NULL; }
    return buf;
}

/** Like mk_env, but with a NON-EMPTY auth blob — the one region tx_id
 *  covers that auth_context_commit does not (env_wire.h:105-118). */
static uint8_t *mk_env_auth(uint32_t domain, const uint8_t *call,
                            uint32_t call_len, const uint8_t *auth,
                            uint32_t auth_len, size_t *len_out) {
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = domain;
    leg.hdr.runtime_op           = 1;
    leg.hdr.ruleset_version      = 1;
    leg.hdr.access_mode          = (uint8_t)DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = 1;
    leg.hdr.call_len             = call_len;
    leg.hdr.auth_len             = auth_len;
    leg.hdr.res_max_effects      = 2;
    leg.hdr.res_max_effect_bytes = 64;
    leg.call_data                = call;
    leg.auth_data                = auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height       = 0;
    in.fee_amount          = 10;
    in.res_max_total_units = 100;
    in.leg_count           = 1;
    in.legs                = &leg;

    size_t need = 0;
    if (dna_env_encoded_size(&leg, 1, &need) != 0) return NULL;
    uint8_t *buf = malloc(need);
    if (!buf) return NULL;
    if (dna_env_encode(&in, buf, need, len_out) != 0) { free(buf); return NULL; }
    return buf;
}

/** The engine-owned contextual ruleset table: domain 1, version 1. */
static void mk_rulesets(dna_env_leg_ctx_t *tab, uint8_t hash_fill) {
    memset(tab, 0, sizeof(*tab));
    tab->domain_id       = 1;
    tab->ruleset_version = 1;
    memset(tab->ruleset_hash, hash_fill, DNA_ENV_RULESET_HASH_LEN);
}

static int all_zero(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

/** A rejected batch must leave EVERY entry fully zeroed. */
static int batch_zeroed(const dna_env_preflight_t *out, size_t n) {
    const uint8_t *raw = (const uint8_t *)out;
    return all_zero(raw, n * sizeof(*out));
}

int main(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture"); OK();
    CHECK(nodus_witness_db_migrate_v2s9(fx.w) == 0, "migrate"); OK();

    uint8_t gen_id[64], vset[64];
    (void)mk_gen_id;
    memset(vset, 0x77, sizeof(vset));
    /* O14: the genesis BlockID is DERIVED by the engine. */
    CHECK(v2x_genesis_min(fx.w, vset, gen_id, NULL) == 0, "genesis");
    OK();

    dna_env_leg_ctx_t tab;
    mk_rulesets(&tab, 0xB7);

    /* ── 2. SEAM CHAIN-ID AUTHORITY ─────────────────────────────────── */
    uint8_t derived[DNA_CHAIN_ID_LEN];
    CHECK(nodus_witness_v2_chain_id(fx.w, derived) == 0, "derive chain id");
    OK();
    /* full 32-byte prefix of the genesis block id */
    CHECK(memcmp(derived, gen_id, DNA_CHAIN_ID_LEN) == 0,
          "derived chain id != genesis block_id[0..31]"); OK();
    /* bytes 16..31 are NON-zero — the legacy value's are always zero */
    CHECK(!all_zero(derived + 16, 16),
          "fixture cannot detect a legacy-chain-id regression"); OK();

    /* the LEGACY shape, reconstructed exactly as nodus_witness.c:265-280
     * would produce it: first 16 bytes kept, 16..31 zeroed */
    uint8_t legacy[DNA_CHAIN_ID_LEN];
    memcpy(legacy, derived, 16);
    memset(legacy + 16, 0, 16);
    CHECK(memcmp(legacy, derived, DNA_CHAIN_ID_LEN) != 0,
          "legacy and derived chain ids coincide"); OK();

    /* ── 1. HAPPY BATCH ─────────────────────────────────────────────── */
    static const uint8_t c0[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    static const uint8_t c1[8] = { 0, 1, 2, 3, 4, 5, 6, 8 };
    static const uint8_t c2[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
    size_t l0 = 0, l1 = 0, l2 = 0;
    uint8_t *e0 = mk_env(1, 1, 0, c0, 8, &l0);
    uint8_t *e1 = mk_env(1, 1, 0, c1, 8, &l1);
    uint8_t *e2 = mk_env(1, 1, 0, c2, 8, &l2);
    CHECK(e0 && e1 && e2, "envelope encode"); OK();

    nodus_v2_envelope_t envs[NODUS_V2_ENV_BATCH_MAX];
    memset(envs, 0, sizeof(envs));
    envs[0].env_bytes = e0; envs[0].env_len = l0;
    envs[1].env_bytes = e1; envs[1].env_len = l1;
    envs[2].env_bytes = e2; envs[2].env_len = l2;

    /* HEAP: each entry is ~11 KB, so a 16-entry array is ~175 KB */
    dna_env_preflight_t *out =
        calloc(NODUS_V2_ENV_BATCH_MAX, sizeof(*out));
    CHECK(out != NULL, "out alloc"); OK();

    size_t fail_idx = 999;
    dna_env_preflight_status_t pf_st = DNA_ENV_PF_ERR_HASH;
    CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, envs, 3,
                                               out, &fail_idx, &pf_st)
          == NODUS_V2_ENV_OK, "happy batch"); OK();
    CHECK(fail_idx == 0 && pf_st == DNA_ENV_PF_OK,
          "optional outs not cleared"); OK();

    /* three DISTINCT derived identities */
    CHECK(memcmp(out[0].wire_id, out[1].wire_id, 64) != 0, "tx0 == tx1"); OK();
    CHECK(memcmp(out[1].wire_id, out[2].wire_id, 64) != 0, "tx1 == tx2"); OK();
    CHECK(memcmp(out[0].wire_id, out[2].wire_id, 64) != 0, "tx0 == tx2"); OK();

    /* SEAM <-> SHARED agreement: each equals a direct recomputation with
     * the chain id nodus_witness_v2_chain_id produced. */
    {
        dna_env_preflight_t *ref = calloc(1, sizeof(*ref));
        CHECK(ref != NULL, "ref alloc");
        const uint8_t *bufs[3] = { e0, e1, e2 };
        const size_t lens[3] = { l0, l1, l2 };
        for (int i = 0; i < 3; i++) {
            CHECK(dna_env_preflight(bufs[i], lens[i], derived, 1, &tab, 1,
                                    ref) == DNA_ENV_PF_OK, "ref preflight");
            CHECK(memcmp(ref->wire_id, out[i].wire_id, 64) == 0,
                  "seam tx_id != shared recomputation"); OK();
            CHECK(memcmp(ref->auth_context_commit,
                         out[i].auth_context_commit, 64) == 0,
                  "seam authctx != shared recomputation"); OK();
        }

        /* and the LEGACY chain id would have produced a DIFFERENT id —
         * this is the truncation-regression detector */
        CHECK(dna_env_preflight(e0, l0, legacy, 1, &tab, 1, ref)
              == DNA_ENV_PF_OK, "legacy preflight");
        CHECK(memcmp(ref->wire_id, out[0].wire_id, 64) != 0,
              "seam used the LEGACY chain id"); OK();
        free(ref);
    }

    /* ── 3. CROSS-CHAIN: a different genesis, same bytes, same table ── */
    {
        fixture_t fb;
        CHECK(fx_open(&fb) == 0, "fixture b");
        CHECK(nodus_witness_db_migrate_v2s9(fb.w) == 0, "migrate b");
        uint8_t gen_b[64], vset_b[64];
        /* O14: a different chain comes from a different committed
         * VALIDATOR SET — genesis binds the committed authority, so a
         * different set yields a different vset hash, genesis BlockID
         * and chain id. Seed it before genesis. */
        memset(vset_b, 0x80, sizeof(vset_b));
        CHECK(v2x_seed_authority_fill(fb.w, 0x80) == 0, "seed set b");
        CHECK(v2x_genesis_min(fb.w, vset_b, gen_b, NULL) == 0,
              "genesis b");

        dna_env_preflight_t *ob = calloc(1, sizeof(*ob));
        CHECK(ob != NULL, "ob alloc");
        nodus_v2_envelope_t one = { e0, l0 };
        CHECK(nodus_witness_v2_env_preflight_batch(fb.w, 1, &tab, 1, &one, 1,
                                                   ob, NULL, NULL)
              == NODUS_V2_ENV_OK, "batch b"); OK();
        CHECK(memcmp(ob->wire_id, out[0].wire_id, 64) != 0,
              "same identity on two different chains"); OK();
        free(ob);
        fx_close(&fb);
    }

    /* ── 4. CROSS-RULESET: same chain, a different contextual hash ──── */
    {
        dna_env_leg_ctx_t other;
        mk_rulesets(&other, 0xC9);       /* same (domain, version), other hash */
        CHECK(other.domain_id == tab.domain_id &&
              other.ruleset_version == tab.ruleset_version,
              "cross-ruleset case changed more than the hash"); OK();
        dna_env_preflight_t *o2 = calloc(1, sizeof(*o2));
        CHECK(o2 != NULL, "o2 alloc");
        nodus_v2_envelope_t one = { e0, l0 };
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &other, 1, &one,
                                                   1, o2, NULL, NULL)
              == NODUS_V2_ENV_OK, "cross-ruleset batch"); OK();
        CHECK(memcmp(o2->wire_id, out[0].wire_id, 64) != 0,
              "ruleset hash does not bind the identity"); OK();
        free(o2);
    }

    /* ── 6. FORGED-DUPLICATE IMPOSSIBILITY ──────────────────────────── */
    {
        /* e0 and e1 differ ONLY in call_data, at the last byte. Their
         * headers are identical, so their first 64 wire bytes are
         * byte-identical — a seam that identified a transaction by a
         * prefix, or by any caller-supplied value, would collide here. */
        CHECK(l0 == l1, "forged-duplicate case: lengths differ"); OK();
        CHECK(memcmp(e0, e1, 64) == 0,
              "forged-duplicate precondition: first 64 bytes differ"); OK();
        CHECK(memcmp(e0, e1, l0) != 0, "envelopes are identical"); OK();

        dna_env_preflight_t *o2 = calloc(2, sizeof(*o2));
        CHECK(o2 != NULL, "o2 alloc");
        nodus_v2_envelope_t two[2] = { { e0, l0 }, { e1, l1 } };
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, two, 2,
                                                   o2, NULL, NULL)
              == NODUS_V2_ENV_OK, "prefix-identical pair rejected"); OK();
        CHECK(memcmp(o2[0].wire_id, o2[1].wire_id, 64) != 0,
              "prefix-identical envelopes share an identity"); OK();
        free(o2);
    }

    /* ── 6b. AUTH-DATA MALLEABILITY — CLOSED (intent season) ──────────
     * Two envelopes differing ONLY in auth_data derive DISTINCT wire_ids
     * (the full-wire identity covers the complete bytes) but ONE
     * intent_id (authorization evidence is outside the intent preimage —
     * env_wire.h). The seam's dedup now runs at BOTH levels, so the pair
     * that the capacity season honestly pinned as "BOTH accepted" is now
     * REJECTED as ERR_DUP_INTENT with the SECOND member accused: one
     * semantic transaction cannot enter a batch twice, no matter how it
     * is authorized. Derived individually (batch of one each), the two
     * realizations prove the identity split: same intent_id, different
     * wire_id, same auth_context_commit. */
    {
        static const uint8_t authA[16] = { 0x11, 0x11, 0x11, 0x11,
                                           0x11, 0x11, 0x11, 0x11,
                                           0x11, 0x11, 0x11, 0x11,
                                           0x11, 0x11, 0x11, 0x11 };
        static const uint8_t authB[16] = { 0x11, 0x11, 0x11, 0x11,
                                           0x11, 0x11, 0x11, 0x11,
                                           0x11, 0x11, 0x11, 0x11,
                                           0x11, 0x11, 0x11, 0x22 };
        size_t la = 0, lb = 0;
        uint8_t *ea = mk_env_auth(1, c0, 8, authA, 16, &la);
        uint8_t *eb = mk_env_auth(1, c0, 8, authB, 16, &lb);
        CHECK(ea && eb, "auth-pair encode"); OK();
        CHECK(la == lb && memcmp(ea, eb, la) != 0,
              "auth pair not distinct"); OK();

        dna_env_preflight_t *o2 = malloc(2 * sizeof(*o2));
        CHECK(o2 != NULL, "auth o2 alloc");
        memset(o2, 0xAA, 2 * sizeof(*o2));   /* DIRTY: zeroing is proven */
        nodus_v2_envelope_t two[2] = { { ea, la }, { eb, lb } };
        size_t fidx = 99;
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, two, 2,
                                                   o2, &fidx, NULL)
              == NODUS_V2_ENV_ERR_DUP_INTENT,
              "auth-differing same-intent pair accepted"); OK();
        CHECK(fidx == 1, "second member not accused"); OK();
        /* rejection published nothing — FULL raw scan of both entries
         * over a pre-dirtied buffer (the file's own discipline; a
         * partial-memset mutant cannot pass a single-field sample) */
        CHECK(batch_zeroed(o2, 2),
              "rejected batch leaked a result"); OK();

        /* Individually the two realizations are both valid — and their
         * identities split exactly as the dual-identity model demands. */
        dna_env_preflight_t *oa = calloc(1, sizeof(*oa));
        dna_env_preflight_t *ob = calloc(1, sizeof(*ob));
        CHECK(oa && ob, "single alloc");
        nodus_v2_envelope_t onea[1] = { { ea, la } };
        nodus_v2_envelope_t oneb[1] = { { eb, lb } };
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, onea,
                                                   1, oa, NULL, NULL)
              == NODUS_V2_ENV_OK, "realization A rejected"); OK();
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, oneb,
                                                   1, ob, NULL, NULL)
              == NODUS_V2_ENV_OK, "realization B rejected"); OK();
        CHECK(memcmp(oa->wire_id, ob->wire_id, 64) != 0,
              "auth mutation did not move wire_id"); OK();
        CHECK(memcmp(oa->intent_id, ob->intent_id, 64) == 0,
              "auth mutation moved intent_id"); OK();
        CHECK(memcmp(oa->auth_context_commit, ob->auth_context_commit,
                     64) == 0,
              "auth mutation moved the signing commitment"); OK();
        free(ob); free(oa);
        free(o2);
        free(eb); free(ea);
    }

    /* ── 6c. MULTI-LEG THROUGH THE SEAM — per-leg context resolution ──
     * A 2-leg envelope (domains 1 and 5): with a table covering only
     * domain 1 the SECOND leg's lookup fails (ERR_CTX_MISSING — the
     * legs[l>0] path); with both domains present the batch accepts. */
    {
        dna_env_leg_in_t legs2[2];
        memset(legs2, 0, sizeof(legs2));
        for (int i = 0; i < 2; i++) {
            legs2[i].hdr.domain_id       = i == 0 ? 1 : 5;
            legs2[i].hdr.runtime_op      = 1;
            legs2[i].hdr.ruleset_version = 1;
            legs2[i].hdr.access_mode     = (uint8_t)DNA_ENV_ACCESS_INVOKE;
            legs2[i].hdr.auth_kind       = 1;
            legs2[i].hdr.call_len        = 8;
            legs2[i].call_data           = c0;
        }
        dna_env_in_t in2;
        memset(&in2, 0, sizeof(in2));
        in2.fee_amount = 10; in2.res_max_total_units = 100;
        in2.leg_count = 2; in2.legs = legs2;
        size_t need2 = 0, lml = 0;
        CHECK(dna_env_encoded_size(legs2, 2, &need2) == 0, "2-leg size");
        uint8_t *eml = malloc(need2);
        CHECK(eml != NULL, "2-leg alloc");
        CHECK(dna_env_encode(&in2, eml, need2, &lml) == 0, "2-leg encode");
        OK();

        dna_env_leg_ctx_t tab2[2];
        mk_rulesets(&tab2[0], 0xB7);                  /* domain 1 */
        mk_rulesets(&tab2[1], 0xB9); tab2[1].domain_id = 5;

        dna_env_preflight_t *om = calloc(1, sizeof(*om));
        CHECK(om != NULL, "ml out alloc");
        nodus_v2_envelope_t one_ml = { eml, lml };

        size_t fi = 999;
        memset(om, 0xAA, sizeof(*om));
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, tab2, 1, &one_ml,
                                                   1, om, &fi, NULL)
              == NODUS_V2_ENV_ERR_CTX_MISSING,
              "second leg's missing entry accepted"); OK();
        CHECK(fi == 0 && batch_zeroed(om, 1), "ml missing not fail-closed");
        OK();

        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, tab2, 2, &one_ml,
                                                   1, om, NULL, NULL)
              == NODUS_V2_ENV_OK, "2-leg envelope rejected"); OK();
        CHECK(om->view.leg_count == 2, "2-leg view wrong"); OK();
        free(om);
        free(eml);
    }

    /* ── 5. DUPLICATES (identical bytes => identical derived id) ────── */
    {
        /* FIRST pair (0,1 of 4), MIDDLE (1,2 of 5), FINAL pair, and the
         * MAX batch with the duplicate at 14/15. */
        static const struct { size_t n, a, b; } cases[] = {
            { 4,  0,  1 },
            { 5,  1,  2 },
            { 4,  2,  3 },
            /* NON-ADJACENT pair: an implementation that compared only
             * neighbouring entries survived every adjacent case above
             * (independent test-review catch, 2026-08-07) — this is the
             * case that kills it. */
            { 5,  0,  3 },
            { NODUS_V2_ENV_BATCH_MAX, 14, 15 },
        };
        for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
            size_t n = cases[k].n;
            /* n distinct envelopes, then position b overwritten with a
             * byte-identical copy of position a */
            uint8_t *bufs[NODUS_V2_ENV_BATCH_MAX];
            size_t   lens[NODUS_V2_ENV_BATCH_MAX];
            nodus_v2_envelope_t ev[NODUS_V2_ENV_BATCH_MAX];
            memset(ev, 0, sizeof(ev));
            for (size_t i = 0; i < n; i++) {
                uint8_t body[8];
                memset(body, (uint8_t)(0x20 + i), sizeof(body));
                bufs[i] = mk_env(1, 1, 0, body, 8, &lens[i]);
                CHECK(bufs[i] != NULL, "dup-case encode");
            }
            free(bufs[cases[k].b]);
            {
                uint8_t body[8];
                memset(body, (uint8_t)(0x20 + cases[k].a), sizeof(body));
                bufs[cases[k].b] = mk_env(1, 1, 0, body, 8,
                                          &lens[cases[k].b]);
                CHECK(bufs[cases[k].b] != NULL, "dup-case re-encode");
            }
            CHECK(lens[cases[k].a] == lens[cases[k].b] &&
                  memcmp(bufs[cases[k].a], bufs[cases[k].b],
                         lens[cases[k].a]) == 0,
                  "duplicate pair is not byte-identical"); OK();
            for (size_t i = 0; i < n; i++) {
                ev[i].env_bytes = bufs[i];
                ev[i].env_len   = lens[i];
            }

            dna_env_preflight_t *ob = calloc(n, sizeof(*ob));
            CHECK(ob != NULL, "dup out alloc");
            /* sentinel: prove the reject clears a DIRTY buffer */
            memset(ob, 0xAA, n * sizeof(*ob));

            size_t fi = 999;
            dna_env_preflight_status_t ps = DNA_ENV_PF_OK;
            CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, ev,
                                                       n, ob, &fi, &ps)
                  == NODUS_V2_ENV_ERR_DUP, "duplicate not rejected"); OK();
            /* the SECOND member of the pair */
            CHECK(fi == cases[k].b, "wrong duplicate index reported"); OK();
            CHECK(batch_zeroed(ob, n),
                  "duplicate reject left a readable entry"); OK();

            free(ob);
            for (size_t i = 0; i < n; i++) free(bufs[i]);
        }
    }

    /* ── 7. EXPIRY THROUGH THE SEAM ─────────────────────────────────── */
    {
        size_t le = 0;
        uint8_t *exp0 = mk_env(1, 1, 0, c0, 8, &le);
        CHECK(exp0 != NULL, "expiry env 0");
        size_t le1 = 0;
        uint8_t *exp1 = mk_env(1, 1, 1, c0, 8, &le1);
        CHECK(exp1 != NULL, "expiry env 1");

        dna_env_preflight_t *ob = calloc(1, sizeof(*ob));
        CHECK(ob != NULL, "expiry out alloc");

        /* candidate height 1: no-expiry accepts, expiry 1 accepts */
        nodus_v2_envelope_t one = { exp0, le };
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, &one, 1,
                                                   ob, NULL, NULL)
              == NODUS_V2_ENV_OK, "expiry 0 at H=1"); OK();
        one.env_bytes = exp1; one.env_len = le1;
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, &one, 1,
                                                   ob, NULL, NULL)
              == NODUS_V2_ENV_OK, "expiry 1 at H=1"); OK();

        /* candidate height 2: expiry 1 is now in the past */
        size_t fi = 999;
        dna_env_preflight_status_t ps = DNA_ENV_PF_OK;
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 2, &tab, 1, &one, 1,
                                                   ob, &fi, &ps)
              == NODUS_V2_ENV_ERR_PREFLIGHT, "expiry 1 at H=2"); OK();
        CHECK(ps == DNA_ENV_PF_ERR_EXPIRED, "wrong pf status"); OK();
        CHECK(fi == 0, "wrong fail index"); OK();
        CHECK(batch_zeroed(ob, 1), "expired batch left a readable entry");
        OK();

        /* DOMAIN-HEIGHT IRRELEVANCE: after genesis every domain height is
         * 0, and 0 < 1 — yet the envelope with expiry 1 is rejected at
         * candidate global height 2. The gate is the GLOBAL candidate
         * height, never a per-domain height. Read the domain heights here
         * so the claim is grounded in this fixture, not assumed. */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "SELECT MAX(domain_height) FROM v2_domain_heads", -1,
                  &st, NULL) == SQLITE_OK, "prep heads");
            CHECK(sqlite3_step(st) == SQLITE_ROW, "heads row");
            uint64_t maxdh = (uint64_t)sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
            CHECK(maxdh == 0, "fixture domain heights are not 0"); OK();
        }

        free(ob);
        free(exp1);
        free(exp0);
    }

    /* ── 11. BATCH-FAILURE NON-PUBLICATION ──────────────────────────── */
    {
        /* three envelopes, the MIDDLE one expired: envelope 0 would have
         * passed, and must still come back zeroed. */
        size_t la = 0, lb = 0, lc = 0;
        uint8_t *ea = mk_env(1, 1, 0, c0, 8, &la);
        uint8_t *eb = mk_env(1, 1, 1, c1, 8, &lb);   /* expires at 1 */
        uint8_t *ec = mk_env(1, 1, 0, c2, 8, &lc);
        CHECK(ea && eb && ec, "non-publication encode"); OK();

        nodus_v2_envelope_t ev[3] = { { ea, la }, { eb, lb }, { ec, lc } };
        dna_env_preflight_t *ob = calloc(3, sizeof(*ob));
        CHECK(ob != NULL, "np out alloc");
        memset(ob, 0xAA, 3 * sizeof(*ob));

        size_t fi = 999;
        dna_env_preflight_status_t ps = DNA_ENV_PF_OK;
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 5, &tab, 1, ev, 3,
                                                   ob, &fi, &ps)
              == NODUS_V2_ENV_ERR_PREFLIGHT, "mid-batch expiry"); OK();
        CHECK(fi == 1, "wrong fail index"); OK();
        CHECK(ps == DNA_ENV_PF_ERR_EXPIRED, "wrong pf status"); OK();
        CHECK(batch_zeroed(ob, 3),
              "failed batch published a would-have-passed entry"); OK();

        free(ob);
        free(ec); free(eb); free(ea);
    }

    /* ── 9. CTX_MISSING ─────────────────────────────────────────────── */
    {
        size_t l5 = 0;
        uint8_t *e5 = mk_env(5, 1, 0, c0, 8, &l5);   /* domain 5 */
        CHECK(e5 != NULL, "domain-5 encode");
        nodus_v2_envelope_t one = { e5, l5 };
        dna_env_preflight_t *ob = calloc(1, sizeof(*ob));
        CHECK(ob != NULL, "ctx out alloc");
        memset(ob, 0xAA, sizeof(*ob));

        size_t fi = 999;
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, &one, 1,
                                                   ob, &fi, NULL)
              == NODUS_V2_ENV_ERR_CTX_MISSING, "unknown domain accepted");
        OK();
        CHECK(fi == 0, "wrong ctx-missing index"); OK();
        CHECK(batch_zeroed(ob, 1), "ctx-missing left a readable entry");
        OK();
        free(ob);
        free(e5);
    }

    /* ── 10. BAD RULESET TABLE ──────────────────────────────────────── */
    {
        dna_env_preflight_t *ob = calloc(1, sizeof(*ob));
        CHECK(ob != NULL, "bad-table out alloc");
        nodus_v2_envelope_t one = { e0, l0 };

        dna_env_leg_ctx_t desc[2];
        mk_rulesets(&desc[0], 0x11); desc[0].domain_id = 7;
        mk_rulesets(&desc[1], 0x22); desc[1].domain_id = 1;   /* descending */
        memset(ob, 0xAA, sizeof(*ob));    /* DIRTY: zeroing must be proven */
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, desc, 2, &one, 1,
                                                   ob, NULL, NULL)
              == NODUS_V2_ENV_ERR_RULESETS, "descending table accepted");
        OK();
        CHECK(batch_zeroed(ob, 1), "bad table left a readable entry"); OK();

        dna_env_leg_ctx_t dup[2];
        mk_rulesets(&dup[0], 0x11); dup[0].domain_id = 1;
        mk_rulesets(&dup[1], 0x22); dup[1].domain_id = 1;     /* duplicate  */
        memset(ob, 0xAA, sizeof(*ob));
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, dup, 2, &one, 1,
                                                   ob, NULL, NULL)
              == NODUS_V2_ENV_ERR_RULESETS, "duplicate table accepted");
        OK();
        CHECK(batch_zeroed(ob, 1), "duplicate table left a readable entry");
        OK();
        free(ob);
    }

    /* ── 12. ARG MATRIX ─────────────────────────────────────────────── */
    {
        nodus_v2_envelope_t one = { e0, l0 };
        /* n_envs = 17 gets a 17-entry array, so the case is safe under
         * either clear-then-check or check-then-clear ordering. */
        dna_env_preflight_t *big =
            calloc(NODUS_V2_ENV_BATCH_MAX + 1, sizeof(*big));
        CHECK(big != NULL, "big alloc");

        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, &one, 0,
                                                   big, NULL, NULL)
              == NODUS_V2_ENV_ERR_ARG, "n_envs 0 accepted"); OK();
        CHECK(nodus_witness_v2_env_preflight_batch(
                  fx.w, 1, &tab, 1, &one, NODUS_V2_ENV_BATCH_MAX + 1, big,
                  NULL, NULL) == NODUS_V2_ENV_ERR_ARG,
              "n_envs 17 accepted"); OK();
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, &one, 1,
                                                   NULL, NULL, NULL)
              == NODUS_V2_ENV_ERR_ARG, "NULL out accepted"); OK();
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1, NULL, 1,
                                                   big, NULL, NULL)
              == NODUS_V2_ENV_ERR_ARG, "NULL envs accepted"); OK();
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, NULL, 1, &one, 1,
                                                   big, NULL, NULL)
              == NODUS_V2_ENV_ERR_ARG, "NULL rulesets accepted"); OK();
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 0, &one, 1,
                                                   big, NULL, NULL)
              == NODUS_V2_ENV_ERR_ARG, "n_rulesets 0 accepted"); OK();
        CHECK(nodus_witness_v2_env_preflight_batch(NULL, 1, &tab, 1, &one, 1,
                                                   big, NULL, NULL)
              == NODUS_V2_ENV_ERR_ARG, "NULL witness accepted"); OK();

        /* an envelope with NULL bytes is an ARGUMENT fault, not a decode
         * fault — the two answers differ, so the seam checks it up front */
        {
            nodus_v2_envelope_t nullbytes[2] = { { e0, l0 }, { NULL, 0 } };
            size_t fi = 999;
            memset(big, 0xAA, 2 * sizeof(*big));   /* DIRTY */
            CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1,
                                                       nullbytes, 2, big,
                                                       &fi, NULL)
                  == NODUS_V2_ENV_ERR_ARG, "NULL env_bytes accepted"); OK();
            CHECK(fi == 1, "wrong NULL-bytes index"); OK();
            CHECK(batch_zeroed(big, 2), "NULL bytes left a readable entry");
            OK();
        }

        /* malformed bytes ARE a preflight/decode fault */
        {
            uint8_t *trunc = malloc(l0);
            CHECK(trunc != NULL, "trunc alloc");
            memcpy(trunc, e0, l0);
            nodus_v2_envelope_t bad = { trunc, l0 - 1 };
            size_t fi = 999;
            dna_env_preflight_status_t ps = DNA_ENV_PF_OK;
            memset(big, 0xAA, sizeof(*big));       /* DIRTY */
            CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 1, &tab, 1,
                                                       &bad, 1, big, &fi,
                                                       &ps)
                  == NODUS_V2_ENV_ERR_PREFLIGHT, "truncated accepted"); OK();
            CHECK(ps == DNA_ENV_PF_ERR_DECODE, "wrong decode status"); OK();
            CHECK(batch_zeroed(big, 1), "decode reject left an entry"); OK();
            free(trunc);
        }
        free(big);
    }

    /* ── 8. PRE-GENESIS FAIL-CLOSED ─────────────────────────────────── */
    {
        fixture_t fc;
        CHECK(fx_open(&fc) == 0, "fixture c");
        CHECK(nodus_witness_db_migrate_v2s9(fc.w) == 0, "migrate c"); OK();
        /* schema present, NO genesis committed => no chain identity */
        uint8_t probe[DNA_CHAIN_ID_LEN];
        CHECK(nodus_witness_v2_chain_id(fc.w, probe) != 0,
              "chain id derivable without genesis"); OK();

        dna_env_preflight_t *ob = calloc(1, sizeof(*ob));
        CHECK(ob != NULL, "pre-genesis out alloc");
        memset(ob, 0xAA, sizeof(*ob));
        nodus_v2_envelope_t one = { e0, l0 };
        CHECK(nodus_witness_v2_env_preflight_batch(fc.w, 1, &tab, 1, &one, 1,
                                                   ob, NULL, NULL)
              == NODUS_V2_ENV_ERR_CHAIN, "pre-genesis batch accepted"); OK();
        CHECK(batch_zeroed(ob, 1), "pre-genesis left a readable entry");
        OK();
        free(ob);
        fx_close(&fc);
    }

    free(out);
    free(e2); free(e1); free(e0);
    fx_close(&fx);

    printf("test_v2_env_preflight: all %d checks passed\n", g_checks);
    return 0;
}
