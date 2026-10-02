/**
 * @file nodus/tests/test_hf4_names.c
 * @brief HF-4 part A2 — CORE rule 8 NAME_REGISTER at the HOOK level, the
 *        name byte rule and price fold, the name_root KATs, the describer,
 *        the CheckTx owner key, the pins generation tuples and the client
 *        decoders of the new queries / v3-block keys.
 *
 * Design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.6, §1.7,
 * §2; decision docs/plans/decisions/2026-10-02-onchain-names.md items
 * 2-6, 10, 11, 16, 18.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. dnac_name_bytes_ok: a-z0-9 only, 3..36 bytes, an all-[0-9a-f] name
 *     of 8+ bytes refused (7 accepted, digits count as hex);
 *     dnac_name_price_for_len: the MONOTONIC fold over the four tiers
 *     (3 = max of all, 4 = max of 4..6, 5 = max of 5..6, 6+ = P6), 0
 *     outside 3..36.
 *  2. name_root (shared/dnac/ledger_roots_v2.c): the leaf / node / root
 *     vectors (a)-(e) given in the A2 dispatch (owners = 64 × the byte),
 *     the empty root == DNA_V2_EMPTY_NAMES, BINARY order ("abc" < "abcd"
 *     < "abd"), descending / duplicate rows and a zero-length leaf
 *     refused.
 *  3. read plan (nodus_rt_core_read_plan, generation-2 CORE runtime):
 *     inputs (op 1) ascending, the pool (op 3 key 3), NAME (op 5, the name
 *     bytes), OWNER (op 6, the verdict's signer_fp[0]) — exactly that
 *     order; generation 1 / NULL runtime, a bad name (uppercase, 2 / 37
 *     bytes, hex-like, a '-'), a trailing byte, an input count of 0 or 14,
 *     a non-native or zero-amount output, no verdict, two signers, auth
 *     kind 2 / 3 are all -1.
 *  4. exec (nodus_rt_core_exec): an accepted registration yields EXACTLY
 *     [CREATE utxo, CREATE name PRE_ABSENT (owner ‖ height BE), SET pool
 *     EXISTS_VERSION old → old + fee + price, DELETE input]; a 36-byte
 *     name pays the 6+ tier; a zero-change registration (two inputs, no
 *     output) is accepted; unlock = height − 1 is spendable. Refusals are
 *     -1, NEVER -2: name taken, owner already holds a name, input missing,
 *     locked (unlock = height), non-native, not owned, wrong declared
 *     price, fee below the floor (gas price 0 — the floor alone), Σin off
 *     by one, two legs, no pool row, generation 1 / NULL runtime, no
 *     verdict, two signers, kind 2. -2 only for an engine-side breakage:
 *     a ctx price tier out of [MIN, MAX], a read count that is not the
 *     plan's.
 *  5. describer: name / price filled, price NOT in `burned`; consumed and
 *     created coins as the call carries them.
 *  6. nodus_rt_core_name_owner_key: (op 6, signer_fp[0]) for an op-8 leg;
 *     1 for a SPEND leg; -1 for two signers.
 *  7. pins: nodus_v2_pins_generation_count == NODUS_RT_GEN_MAX and every
 *     pinned generation's (SYSTEM, CORE) tuple equals the compiled
 *     runtime table's; generation 0 / count + 1 are refused.
 *  8. client decoders (no network): dnac_ruleset_info (all nine keys
 *     required, gen 0 / a duplicate / a missing key / truncation refused),
 *     dnac_name_lookup / _name_of (found ⇔ the row keys; rh 0, an
 *     uppercase name refused), the dnac_fee_info HF-4 keys (np exactly 4
 *     non-zero, ns ≤ NODUS_DNAC_NAME_SCHED_MAX maps of p/v/e; an older
 *     node's reply without "np" refused), and dnac_v3_block "nm"/"pr" (a
 *     pair, applied items only, a-z0-9).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build. Environment: none. No
 * database, no network.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Sections 3-6 FABRICATE the verdict and the mediated reads; that the
 *    ENGINE builds them as fabricated here (read results in plan order,
 *    the price tiers from params 10-13) is test_hf4_names_engine.c's
 *    block-level case, not this file's.
 *  - The adapter op ids (1 UTXO, 2 UTXDEL, 3 SUPPLY, 5 NAME, 6 NAMEOWN)
 *    and the pool selector 3 are restated here from
 *    nodus_witness_rt_native.c (file-static there).
 *  - The name_root vectors were computed by the ORCHESTRATOR's oracle;
 *    this file carries them verbatim. They prove the C equals that
 *    oracle, not that the oracle read the design right.
 *  - Section 8 drives the decoders only; the node-side handlers in
 *    nodus_witness_handlers.c are static (they only send) and are not
 *    driven — the existing test_v3_block_query.c convention.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_rt_native.h"
#include "nodus/nodus.h"
#include "nodus/nodus_v2_spend.h"
#include "protocol/nodus_cbor.h"

#include "dnac/dnac.h"
#include "dnac/env_wire.h"
#include "dnac/effect_wire.h"
#include "dnac/domain_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

/* nodus_witness_rt_native.c RTN_CORE_OP_* / RTN_SUPPLY_SEL_POOL (static
 * there) — restated, see HOW IT CAN LIE */
#define OP_UTXO     1u
#define OP_UTXDEL   2u
#define OP_SUPPLY   3u
#define OP_NAME     5u
#define OP_NAMEOWN  6u
#define SEL_POOL    3u

#define UTXO_REC    284u          /* NODUS_RT_CORE_UTXO_REC_LEN          */
#define OUT_LEN     232u          /* NODUS_V2_SPEND_OUT_LEN              */
#define AUTH_LEN    (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define CALL_MAX    (1u + 64u + 8u + 1u + 16u * 64u + 1u + 17u * OUT_LEN)

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}
static int is_name(const char *s) {
    return dnac_name_bytes_ok((const uint8_t *)s, strlen(s));
}

/* ══ 1. the byte rule and the price fold ═════════════════════════════ */

static int t_bytes_and_price(void) {
    /* 'z' is not a hex digit: these exercise the LENGTH bounds alone */
    char z36[37], z37[38], a36[37];
    memset(z36, 'z', 36); z36[36] = '\0';
    memset(z37, 'z', 37); z37[37] = '\0';
    memset(a36, 'a', 36); a36[36] = '\0';
    CHECK(is_name("abc") && is_name("punk") && is_name("n0dus") &&
          is_name(z36), "a-z0-9 of 3..36 accepted");
    CHECK(!is_name("ab") && !is_name(z37) && !is_name(""),
          "length bounds refused");
    CHECK(!is_name(a36), "36 x 'a' is all-hex of 8+ bytes: refused "
          "(decision item 11), whatever its length");
    CHECK(!is_name("Punk") && !is_name("pu-k") && !is_name("pu k") &&
          !is_name("pünk"), "uppercase / punctuation / non-ASCII refused");
    CHECK(is_name("cafe") && is_name("deadbee") && is_name("1234567"),
          "hex-like below 8 bytes accepted");
    CHECK(!is_name("deadbeef") && !is_name("12345678") &&
          !is_name("0123456789abcdef"), "hex-like of 8+ bytes refused");
    CHECK(is_name("deadbeeg") && is_name("1234567z"),
          "one non-hex letter makes it a name");

    const uint64_t def[4] = { DNAC_NAME_PRICE_3P_DEFAULT,
                              DNAC_NAME_PRICE_4P_DEFAULT,
                              DNAC_NAME_PRICE_5P_DEFAULT,
                              DNAC_NAME_PRICE_6P_DEFAULT };
    CHECK(dnac_name_price_for_len(def, 3) == DNAC_NAME_PRICE_3P_DEFAULT &&
          dnac_name_price_for_len(def, 4) == DNAC_NAME_PRICE_4P_DEFAULT &&
          dnac_name_price_for_len(def, 5) == DNAC_NAME_PRICE_5P_DEFAULT &&
          dnac_name_price_for_len(def, 6) == DNAC_NAME_PRICE_6P_DEFAULT &&
          dnac_name_price_for_len(def, 36) == DNAC_NAME_PRICE_6P_DEFAULT,
          "the compiled defaults are already monotonic");
    /* votes that are NOT monotonic: the fold keeps a shorter name never
     * cheaper than a longer one */
    const uint64_t p[4] = { 100000000ULL, 5000000000ULL, 200000000ULL,
                            300000000ULL };
    CHECK(dnac_name_price_for_len(p, 3) == 5000000000ULL, "3 = max(all)");
    CHECK(dnac_name_price_for_len(p, 4) == 5000000000ULL, "4 = max(4..6)");
    CHECK(dnac_name_price_for_len(p, 5) == 300000000ULL, "5 = max(5, 6)");
    CHECK(dnac_name_price_for_len(p, 6) == 300000000ULL &&
          dnac_name_price_for_len(p, 36) == 300000000ULL, "6+ = P6");
    CHECK(dnac_name_price_for_len(p, 2) == 0 &&
          dnac_name_price_for_len(p, 37) == 0 &&
          dnac_name_price_for_len(p, 0) == 0, "no price outside 3..36");
    return 0;
}

/* ══ 2. name_root — the A2 dispatch vectors (ORCHESTRATOR's oracle) ══ */

static const char *KAT_LEAF_BIOS =
    "f9c7fca420b37d54a3b8a051d7578c3930b6f14d1a03c82bf3e346e173e19567"
    "31a978d3b8ae32f7768c5e88d95fbbed2bec16b8a2ba7ead0e207af28488fb24";
static const char *KAT_LEAF_PUNK =
    "1b734a189219c3e95bbde9666051ea08e37986710b4df849d6a47e84aad56fc3"
    "ef07dd8fae39d4cf4df0bf5e637c939c4564be9160fea9b841de9d5ceac9e0cd";
static const char *KAT_NODE_BIOS_PUNK =
    "e7851e39f65607fa60670a36d7b86ce38670c0fb3e8314d5f37afbbe69613d95"
    "4ebfcf22ec3d7b9d8afe47afbff52f8e2f256b893327eb8479c2e2d32eb98d8c";
static const char *KAT_LEAF_NODUS =
    "577d8cf840646f9b740e4f90217b5a4df95adac650c725fca4e5bf43f52fa83d"
    "e66f172ead7b4f8d7b38720caaf8dfd292f676f1166e88cb45de514c8b20bb63";
static const char *KAT_ROOT_3 =
    "d6bb49e00dca04d81a24f4ea8dea468a3fc9913d8dbf9e2948bbf132906399e5"
    "50e6cf03fb031405035658fb0241086f018eaad6a54ba24317ccd67def0ea908";
static const char *KAT_ROOT_ABC =
    "c65cb86cacce66cedab9c7b5328a8998abfebdfe1467581d5bcf854ee190ab3d"
    "fb2a823db85dd9565940f5de29829f531285d127528b5d81ec0eba59cd20d543";
static const char *KAT_LEAF_CHIP =
    "a29416fd9a1b57bf066edc358a90d4b02dfcfd81e62976c67e00c64862e45b35"
    "2c38acff5ef290f43dcbc51ffae8f152eaf01ba5bee36fdfd33bef6221340830";

static int unhex64(const char *h, uint8_t out[64]) {
    if (strlen(h) != 128) return -1;
    for (int i = 0; i < 64; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char c = h[2 * i + k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else return -1;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

static void row_set(dna_v2_name_row_t *r, const char *name, uint8_t owner,
                    uint64_t h) {
    memset(r, 0, sizeof(*r));
    r->name_len = (uint8_t)strlen(name);
    memcpy(r->name, name, r->name_len);
    memset(r->owner, owner, 64);
    r->registered_height = h;
}

static int kat_eq(const uint8_t got[64], const char *want_hex) {
    uint8_t w[64];
    return unhex64(want_hex, w) == 0 && memcmp(got, w, 64) == 0;
}

static int t_name_root(void) {
    dna_v2_name_row_t r[3];
    uint8_t lb[64], lp[64], ln[64], out[64];

    row_set(&r[0], "bios", 0x11, 1);
    row_set(&r[1], "punk", 0x22, 2);
    CHECK(dna_v2_name_leaf_hash(&r[0], lb) == 0 &&
          kat_eq(lb, KAT_LEAF_BIOS), "(a) leaf bios/0x11/1");
    CHECK(dna_v2_name_leaf_hash(&r[1], lp) == 0 &&
          kat_eq(lp, KAT_LEAF_PUNK), "(b) leaf punk/0x22/2");
    CHECK(dna_v2_names_root(r, 2, out) == 0 &&
          kat_eq(out, KAT_NODE_BIOS_PUNK), "(b) node(bios, punk)");
    CHECK(dna_v2_names_root(r, 1, out) == 0 && memcmp(out, lb, 64) == 0,
          "one row: the root is its leaf");

    /* (c) three rows, BINARY order: bios < nodus < punk */
    row_set(&r[0], "bios", 0x11, 1);
    row_set(&r[1], "nodus", 0x33, 3);
    row_set(&r[2], "punk", 0x22, 2);
    CHECK(dna_v2_name_leaf_hash(&r[1], ln) == 0 &&
          kat_eq(ln, KAT_LEAF_NODUS), "(c) leaf nodus/0x33/3");
    CHECK(dna_v2_names_root(r, 3, out) == 0 && kat_eq(out, KAT_ROOT_3),
          "(c) 3-row root (odd node promoted)");

    /* (d) the prefix order abc < abcd < abd */
    row_set(&r[0], "abc", 0x11, 10);
    row_set(&r[1], "abcd", 0x22, 20);
    row_set(&r[2], "abd", 0x33, 30);
    CHECK(dna_v2_name_cmp(r[0].name, 3, r[1].name, 4) < 0 &&
          dna_v2_name_cmp(r[1].name, 4, r[2].name, 3) < 0 &&
          dna_v2_name_cmp(r[0].name, 3, r[0].name, 3) == 0,
          "BINARY order: a prefix sorts first");
    CHECK(dna_v2_names_root(r, 3, out) == 0 && kat_eq(out, KAT_ROOT_ABC),
          "(d) abc/abcd/abd root");

    /* (e) a height above 2^32 — the u64 BE encoding */
    row_set(&r[0], "chip", 0x44, 4294967301ULL);
    CHECK(dna_v2_name_leaf_hash(&r[0], out) == 0 &&
          kat_eq(out, KAT_LEAF_CHIP), "(e) leaf chip/0x44/4294967301");

    /* empty, order and shape refusals */
    {
        uint8_t e[64];
        CHECK(dna_v2_empty_root(DNA_V2_EMPTY_NAMES, e) == 0 &&
              dna_v2_names_root(NULL, 0, out) == 0 &&
              memcmp(out, e, 64) == 0, "no rows = NDS.E.NAMES.v1");
    }
    row_set(&r[0], "punk", 0x22, 2);
    row_set(&r[1], "bios", 0x11, 1);
    CHECK(dna_v2_names_root(r, 2, out) == -1, "descending rows refused");
    row_set(&r[1], "punk", 0x33, 3);
    CHECK(dna_v2_names_root(r, 2, out) == -1, "a duplicate name refused");
    r[0].name_len = 0;
    CHECK(dna_v2_name_leaf_hash(&r[0], out) == -1, "a zero-length leaf");
    r[0].name_len = DNA_V2_NAME_MAX_LEN + 1u;
    CHECK(dna_v2_name_leaf_hash(&r[0], out) == -1, "a 37-byte leaf");
    return 0;
}

/* ══ 3-6. the hooks over a fabricated verdict and fabricated reads ═══ */

static uint8_t g_owner[64];        /* the registering signer's fp        */
static char    g_owner_hex[129];
static uint8_t g_other[64];
static char    g_other_hex[129];

typedef struct {
    uint8_t  call[CALL_MAX];
    size_t   call_len;
    uint8_t  auth[AUTH_LEN];
    uint8_t *bytes;
    size_t   len;
    dna_env_view_t view;
} nm_env_t;

/* One output record of the transfer section. */
typedef struct {
    const char *owner_hex;
    uint64_t    amount;
    const uint8_t *token;          /* NULL = native                      */
    uint8_t     seed_byte;
} nm_out_t;

/* call v1: name_len ‖ name ‖ price u64 BE ‖ in_count ‖ nullifiers ‖
 * out_count ‖ outputs. `name_len` overrides strlen when non-zero (to
 * write a length the bytes disagree with). */
static size_t nm_call(uint8_t *dst, const char *name, uint64_t price,
                      uint8_t n_in, uint8_t (*ins)[64],
                      uint8_t n_out, const nm_out_t *outs) {
    size_t off = 0, nl = strlen(name);
    dst[off++] = (uint8_t)nl;
    memcpy(dst + off, name, nl);  off += nl;
    put64(dst + off, price);      off += 8;
    dst[off++] = n_in;
    for (uint8_t i = 0; i < n_in; i++) {
        memcpy(dst + off, ins[i], 64);
        off += 64;
    }
    dst[off++] = n_out;
    for (uint8_t o = 0; o < n_out; o++) {
        uint8_t seed[32];
        memset(seed, outs[o].seed_byte, sizeof(seed));
        nodus_v2_xfer_out_put(dst + off, outs[o].owner_hex, outs[o].amount,
                              outs[o].token, seed);
        off += OUT_LEN;
    }
    return off;
}

/* Encode + decode an envelope whose LAST leg is the CORE op-`op` leg.
 * n_legs 2 puts a SYSTEM CHAIN_CONFIG leg (the same call bytes — the
 * codec does not parse calls) in front of it: legs must be strictly
 * ascending by domain (SYSTEM 0 < CORE 1), so two CORE legs cannot
 * exist (dna_env_decode refuses a repeated domain). */
static int nm_env(nm_env_t *e, uint32_t op, uint8_t auth_kind,
                  uint16_t n_legs, uint64_t fee) {
    dna_env_leg_in_t legs[2];
    if (n_legs < 1 || n_legs > 2) return -1;
    memset(legs, 0, sizeof(legs));
    for (uint16_t l = 0; l < n_legs; l++) {
        legs[l].hdr.domain_id            = DNA_DOMAIN_CORE;
        legs[l].hdr.runtime_op           = op;
        legs[l].hdr.ruleset_version      = 5;
        legs[l].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
        legs[l].hdr.auth_kind            = auth_kind;
        legs[l].hdr.call_len             = (uint32_t)e->call_len;
        legs[l].hdr.auth_len             = AUTH_LEN;
        legs[l].hdr.res_max_effects      = 40;
        legs[l].hdr.res_max_effect_bytes = 16384;
        legs[l].call_data = e->call;
        legs[l].auth_data = e->auth;
    }
    if (n_legs == 2) {
        legs[0].hdr.domain_id       = DNA_DOMAIN_SYSTEM;
        legs[0].hdr.runtime_op      = DNA_SYSRULE_CHAIN_CONFIG;
        legs[0].hdr.ruleset_version = 7;
    }
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount          = fee;
    in.res_max_total_units = 2000000;
    in.leg_count           = n_legs;
    in.legs                = legs;
    free(e->bytes);
    e->bytes = NULL;
    if (dna_env_encoded_size(legs, n_legs, &e->len) != 0) return -1;
    e->bytes = malloc(e->len);
    if (!e->bytes) return -1;
    size_t used = 0;
    if (dna_env_encode(&in, e->bytes, e->len, &used) != 0 || used != e->len)
        return -1;
    return dna_env_decode(e->bytes, e->len, &e->view) == 0 ? 0 : -1;
}

/* The engine facts one hook call receives. */
typedef struct {
    nodus_rt_auth_verdict_t av;
    int      no_auth;
    uint64_t height;
    uint64_t price[4];
    nodus_rt_read_res_t reads[NODUS_RT_MAX_READS];
    uint16_t n_reads;
} nm_facts_t;

static nm_facts_t g_f;

static void utxo_rec(uint8_t rec[UTXO_REC], const char *owner_hex,
                     uint64_t amount, const uint8_t *token, uint64_t unlock) {
    memset(rec, 0, UTXO_REC);
    memcpy(rec, owner_hex, 128);
    put64(rec + 128, amount);
    if (token) memcpy(rec + 136, token, 64);
    memset(rec + 200, 0x7A, 64);                 /* tx_hash               */
    put64(rec + 268, 1);                         /* block_height          */
    put64(rec + 276, unlock);
}

/* Defaults: one signer = g_owner, height 100, the compiled prices; reads
 * = n_in owned unlocked native coins of `amt[i]`, the pool at 1000, NAME
 * and OWNER absent. */
static void facts_reset(uint8_t n_in, const uint64_t *amt) {
    memset(&g_f, 0, sizeof(g_f));
    g_f.av.n_signers = 1;
    memcpy(g_f.av.signer_fp[0], g_owner, 64);
    g_f.height = 100;
    g_f.price[0] = DNAC_NAME_PRICE_3P_DEFAULT;
    g_f.price[1] = DNAC_NAME_PRICE_4P_DEFAULT;
    g_f.price[2] = DNAC_NAME_PRICE_5P_DEFAULT;
    g_f.price[3] = DNAC_NAME_PRICE_6P_DEFAULT;
    for (uint8_t i = 0; i < n_in; i++) {
        g_f.reads[i].present = 1;
        g_f.reads[i].value_len = UTXO_REC;
        utxo_rec(g_f.reads[i].value, g_owner_hex, amt[i], NULL, 0);
    }
    g_f.reads[n_in].present = 1;
    g_f.reads[n_in].value_len = 8;
    put64(g_f.reads[n_in].value, 1000);
    g_f.n_reads = (uint16_t)(n_in + 3u);
}

static void ctx_of(nodus_rt_exec_ctx_t *ctx) {
    static uint8_t chain_id[DNA_CHAIN_ID_LEN], intent[64], digest[64];
    memset(intent, 0x5C, sizeof(intent));
    memset(ctx, 0, sizeof(*ctx));
    ctx->chain_id            = chain_id;
    ctx->global_height       = g_f.height;
    ctx->epoch               = g_f.height / (uint64_t)DNAC_EPOCH_LENGTH;
    ctx->wire_id             = intent;
    ctx->intent_id           = intent;
    ctx->auth_context_commit = digest;
    ctx->leg_auth_digest     = digest;
    ctx->auth                = g_f.no_auth ? NULL : &g_f.av;
    ctx->token_create_fee    = DNAC_CFG_MIN_TOKEN_CREATE_FEE;
    memcpy(ctx->name_price, g_f.price, sizeof(ctx->name_price));
}

static int run_plan(const nodus_domain_runtime_t *rt, const nm_env_t *e,
                    nodus_rt_read_req_t *reqs, uint16_t *n) {
    nodus_rt_exec_ctx_t ctx;
    ctx_of(&ctx);
    *n = 0;
    return nodus_rt_core_read_plan(rt, &e->view, 0, &ctx, reqs,
                                   NODUS_RT_MAX_READS, n);
}

static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];
static dna_effect_view_t g_ev;

static int run_exec(const nodus_domain_runtime_t *rt, const nm_env_t *e) {
    nodus_rt_exec_ctx_t ctx;
    ctx_of(&ctx);
    size_t rl = 0;
    memset(&g_ev, 0, sizeof(g_ev));
    /* the CORE op-8 leg is always the LAST leg (nm_env) */
    const uint16_t leg = (uint16_t)(e->view.leg_count - 1u);
    int rc = nodus_rt_core_exec(rt, &e->view, leg, &ctx, g_f.reads,
                                g_f.n_reads, g_res, sizeof(g_res), &rl);
    if (rc == 0 && dna_effect_result_decode(g_res, rl, &g_ev) != 0)
        return 99;                   /* an undecodable result: a test FAIL */
    return rc;
}

#define FEE  ((uint64_t)DNAC_MIN_FEE_RAW)
#define P4   ((uint64_t)DNAC_NAME_PRICE_4P_DEFAULT)
#define CHG  700000000ULL

static int t_read_plan(const nodus_domain_runtime_t *g1,
                       const nodus_domain_runtime_t *g2) {
    static nm_env_t e;
    nodus_rt_read_req_t reqs[NODUS_RT_MAX_READS];
    uint16_t n = 0;
    uint8_t ins[14][64];
    for (int i = 0; i < 14; i++) memset(ins[i], 0x10 + i, 64);
    const uint64_t amt[1] = { P4 + FEE + CHG };
    nm_out_t chg = { g_owner_hex, CHG, NULL, 0x5E };

    e.call_len = nm_call(e.call, "punk", P4, 1, ins, 1, &chg);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0, "env");
    facts_reset(1, amt);
    CHECK(run_plan(g2, &e, reqs, &n) == 0 && n == 4, "four reads");
    CHECK(reqs[0].op_id == OP_UTXO && reqs[0].key_len == 64 &&
          memcmp(reqs[0].key, ins[0], 64) == 0, "[0] the input");
    CHECK(reqs[1].op_id == OP_SUPPLY && reqs[1].key_len == 1 &&
          reqs[1].key[0] == SEL_POOL, "[1] the pool");
    CHECK(reqs[2].op_id == OP_NAME && reqs[2].key_len == 4 &&
          memcmp(reqs[2].key, "punk", 4) == 0, "[2] NAME = the name bytes");
    CHECK(reqs[3].op_id == OP_NAMEOWN && reqs[3].key_len == 64 &&
          memcmp(reqs[3].key, g_owner, 64) == 0,
          "[3] OWNER = the verdict's signer_fp[0]");

    /* generation gate */
    CHECK(run_plan(g1, &e, reqs, &n) == -1, "generation 1 refuses");
    CHECK(run_plan(NULL, &e, reqs, &n) == -1, "a NULL runtime refuses");

    /* owner shape */
    g_f.no_auth = 1;
    CHECK(run_plan(g2, &e, reqs, &n) == -1, "no verdict refuses");
    g_f.no_auth = 0;
    g_f.av.n_signers = 2;
    memcpy(g_f.av.signer_fp[1], g_other, 64);
    CHECK(run_plan(g2, &e, reqs, &n) == -1, "two signers refuse");
    facts_reset(1, amt);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_CC_V1, 1, FEE) == 0 &&
          run_plan(g2, &e, reqs, &n) == -1, "auth kind 2 refuses");
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MSIG_V1, 1, FEE) == 0 &&
          run_plan(g2, &e, reqs, &n) == -1, "auth kind 3 refuses");

    /* the name bytes and the call shape */
    static const char *const bad_names[] = {
        "Punk", "ab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "deadbeef",
        "0123456789", "pu-k"
    };
    for (size_t k = 0; k < sizeof(bad_names) / sizeof(bad_names[0]); k++) {
        e.call_len = nm_call(e.call, bad_names[k], P4, 1, ins, 1, &chg);
        CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                     NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0 &&
              run_plan(g2, &e, reqs, &n) == -1,
              "a name the byte rule refuses never reaches a read");
    }
    e.call_len = nm_call(e.call, "punk", P4, 1, ins, 1, &chg);
    e.call[e.call_len++] = 0x00;                 /* one trailing byte     */
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0 &&
          run_plan(g2, &e, reqs, &n) == -1, "exact length: a trailing byte");
    e.call_len = nm_call(e.call, "punk", P4, 1, ins, 1, &chg) - 1;
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0 &&
          run_plan(g2, &e, reqs, &n) == -1, "exact length: one byte short");
    e.call_len = nm_call(e.call, "punk", P4, 0, ins, 1, &chg);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0 &&
          run_plan(g2, &e, reqs, &n) == -1, "no input refused");
    e.call_len = nm_call(e.call, "punk", P4, 14, ins, 1, &chg);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0 &&
          run_plan(g2, &e, reqs, &n) == -1, "14 inputs refused (max 13)");
    e.call_len = nm_call(e.call, "punk", P4, 13, ins, 1, &chg);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0 &&
          run_plan(g2, &e, reqs, &n) == 0 && n == NODUS_RT_MAX_READS,
          "13 inputs fill the read ceiling exactly");
    {
        uint8_t desc[2][64];
        memcpy(desc[0], ins[1], 64);
        memcpy(desc[1], ins[0], 64);
        e.call_len = nm_call(e.call, "punk", P4, 2, desc, 1, &chg);
        CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                     NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0 &&
              run_plan(g2, &e, reqs, &n) == -1,
              "inputs not strictly ascending refused");
    }
    {
        uint8_t tok[64];
        memset(tok, 0x99, sizeof(tok));
        nm_out_t t = { g_owner_hex, CHG, tok, 0x5E };
        e.call_len = nm_call(e.call, "punk", P4, 1, ins, 1, &t);
        CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                     NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0 &&
              run_plan(g2, &e, reqs, &n) == -1,
              "a non-native output refused");
        nm_out_t z = { g_owner_hex, 0, NULL, 0x5E };
        e.call_len = nm_call(e.call, "punk", P4, 1, ins, 1, &z);
        CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                     NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0 &&
              run_plan(g2, &e, reqs, &n) == -1,
              "a zero-amount output refused");
    }
    free(e.bytes);
    e.bytes = NULL;
    return 0;
}

static int t_exec(const nodus_domain_runtime_t *g1,
                  const nodus_domain_runtime_t *g2) {
    static nm_env_t e;
    uint8_t ins[2][64];
    memset(ins[0], 0x10, 64);
    memset(ins[1], 0x11, 64);
    uint64_t amt[2] = { P4 + FEE + CHG, 0 };
    nm_out_t chg = { g_owner_hex, CHG, NULL, 0x5E };

    /* ── the accepted registration, effect by effect ─────────────────── */
    e.call_len = nm_call(e.call, "punk", P4, 1, ins, 1, &chg);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0, "env");
    facts_reset(1, amt);
    CHECK(run_exec(g2, &e) == 0, "the registration applies");
    CHECK(g_ev.effect_count == 4, "exactly four effects");
    CHECK(g_ev.eff[0].op_id == OP_UTXO &&
          g_ev.eff[0].effect_kind == DNA_EFFECT_CREATE, "[0] CREATE change");
    {
        const uint8_t *v = g_ev.buf + g_ev.val_off[0];
        CHECK(g_ev.eff[0].value_len == UTXO_REC &&
              memcmp(v, g_owner_hex, 128) == 0 && get64(v + 128) == CHG,
              "the change coin: owner, amount");
    }
    CHECK(g_ev.eff[1].op_id == OP_NAME &&
          g_ev.eff[1].effect_kind == DNA_EFFECT_CREATE &&
          g_ev.eff[1].precond_tag == DNA_EFFECT_PRE_ABSENT &&
          g_ev.eff[1].key_len == 4 &&
          memcmp(g_ev.buf + g_ev.key_off[1], "punk", 4) == 0,
          "[1] CREATE name PRE_ABSENT, key = the name");
    {
        const uint8_t *v = g_ev.buf + g_ev.val_off[1];
        CHECK(g_ev.eff[1].value_len == 72 && memcmp(v, g_owner, 64) == 0 &&
              get64(v + 64) == 100,
              "the name record = owner ‖ registered_height (the block)");
    }
    CHECK(g_ev.eff[2].op_id == OP_SUPPLY &&
          g_ev.eff[2].effect_kind == DNA_EFFECT_SET &&
          g_ev.eff[2].precond_tag == DNA_EFFECT_PRE_EXISTS_VERSION &&
          g_ev.eff[2].expected_version == 1000 &&
          g_ev.eff[2].key_len == 1 &&
          g_ev.buf[g_ev.key_off[2]] == SEL_POOL &&
          get64(g_ev.buf + g_ev.val_off[2]) == 1000 + FEE + P4,
          "[2] ONE pool SET: += fee + price, bound to the observed value");
    CHECK(g_ev.eff[3].op_id == OP_UTXDEL &&
          g_ev.eff[3].effect_kind == DNA_EFFECT_DELETE &&
          memcmp(g_ev.buf + g_ev.key_off[3], ins[0], 64) == 0,
          "[3] DELETE the input");

    /* unlock = height - 1 is spendable; unlock = height is locked */
    utxo_rec(g_f.reads[0].value, g_owner_hex, amt[0], NULL, 99);
    CHECK(run_exec(g2, &e) == 0, "unlock = height - 1 spends");
    utxo_rec(g_f.reads[0].value, g_owner_hex, amt[0], NULL, 100);
    CHECK(run_exec(g2, &e) == -1, "unlock = height is locked (-1)");

    /* ── the refusal matrix: -1, never -2 ────────────────────────────── */
    facts_reset(1, amt);
    g_f.reads[2].present = 1;
    g_f.reads[2].value_len = 72;
    CHECK(run_exec(g2, &e) == -1, "a taken name is a refusal, not a FAULT");
    facts_reset(1, amt);
    g_f.reads[3].present = 1;
    g_f.reads[3].value_len = 4;
    memcpy(g_f.reads[3].value, "bios", 4);
    CHECK(run_exec(g2, &e) == -1, "an owner who already holds a name");
    facts_reset(1, amt);
    g_f.reads[0].present = 0;
    g_f.reads[0].value_len = 0;
    CHECK(run_exec(g2, &e) == -1, "a missing / spent input");
    facts_reset(1, amt);
    {
        uint8_t tok[64];
        memset(tok, 0x99, sizeof(tok));
        utxo_rec(g_f.reads[0].value, g_owner_hex, amt[0], tok, 0);
    }
    CHECK(run_exec(g2, &e) == -1, "a non-native input");
    facts_reset(1, amt);
    utxo_rec(g_f.reads[0].value, g_other_hex, amt[0], NULL, 0);
    CHECK(run_exec(g2, &e) == -1, "an input the signer does not own");
    facts_reset(1, amt);
    g_f.reads[1].present = 0;
    g_f.reads[1].value_len = 0;
    CHECK(run_exec(g2, &e) == -1, "no pool row (unfunded chain)");
    facts_reset(1, amt);
    utxo_rec(g_f.reads[0].value, g_owner_hex, amt[0] + 1, NULL, 0);
    CHECK(run_exec(g2, &e) == -1, "Σin one above Σout + fee + price");
    utxo_rec(g_f.reads[0].value, g_owner_hex, amt[0] - 1, NULL, 0);
    CHECK(run_exec(g2, &e) == -1, "Σin one below");

    /* wrong declared price (conservation kept, so only the price is off) */
    e.call_len = nm_call(e.call, "punk", P4 + 1, 1, ins, 1, &chg);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0, "env");
    amt[0] = P4 + 1 + FEE + CHG;
    facts_reset(1, amt);
    CHECK(run_exec(g2, &e) == -1, "a declared price above the tier");
    e.call_len = nm_call(e.call, "punk", DNAC_NAME_PRICE_5P_DEFAULT, 1, ins,
                         1, &chg);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0, "env");
    amt[0] = DNAC_NAME_PRICE_5P_DEFAULT + FEE + CHG;
    facts_reset(1, amt);
    CHECK(run_exec(g2, &e) == -1, "a 4-byte name at the 5-byte price");

    /* fee below the floor (gas price 0: the floor alone decides) */
    e.call_len = nm_call(e.call, "punk", P4, 1, ins, 1, &chg);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE - 1) == 0, "env");
    amt[0] = P4 + FEE - 1 + CHG;
    facts_reset(1, amt);
    CHECK(run_exec(g2, &e) == -1, "fee one below DNAC_MIN_FEE_RAW");

    /* two legs (SYSTEM + the CORE op-8 leg): the registration is a
     * single-leg envelope — the exec's leg_count rule refuses it */
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 2, FEE) == 0 &&
          e.view.leg_count == 2 && e.view.leg[1].domain_id == DNA_DOMAIN_CORE,
          "a decodable two-leg envelope (SYSTEM, CORE op 8)");
    amt[0] = P4 + FEE + CHG;
    facts_reset(1, amt);
    CHECK(run_exec(g2, &e) == -1, "a two-leg envelope: exec refuses (-1)");

    /* generation / owner shape */
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0, "env");
    facts_reset(1, amt);
    CHECK(run_exec(g1, &e) == -1, "generation 1 refuses");
    CHECK(run_exec(NULL, &e) == -1, "a NULL runtime refuses");
    g_f.no_auth = 1;
    CHECK(run_exec(g2, &e) == -1, "no verdict: -1 (never the -2 of a "
          "SPEND's missing verdict)");
    g_f.no_auth = 0;
    g_f.av.n_signers = 2;
    memcpy(g_f.av.signer_fp[1], g_other, 64);
    CHECK(run_exec(g2, &e) == -1, "two signers: -1");
    facts_reset(1, amt);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_CC_V1, 1, FEE) == 0 &&
          run_exec(g2, &e) == -1, "auth kind 2: -1");

    /* engine-side breakage: -2 */
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0, "env");
    facts_reset(1, amt);
    g_f.price[2] = DNAC_CFG_MIN_NAME_PRICE - 1u;
    CHECK(run_exec(g2, &e) == -2, "a ctx tier below MIN is the engine's "
          "fault");
    facts_reset(1, amt);
    g_f.price[0] = DNAC_CFG_MAX_NAME_PRICE + 1u;
    CHECK(run_exec(g2, &e) == -2, "a ctx tier above MAX");
    facts_reset(1, amt);
    g_f.n_reads = 3;
    CHECK(run_exec(g2, &e) == -2, "a read count that is not the plan's");

    /* the ctx tiers are what the exec prices from (a voted P4 of 5e9 with
     * a non-monotonic P3: 4 bytes pay max(P4, P5, P6)) */
    e.call_len = nm_call(e.call, "punk", 5000000000ULL, 1, ins, 1, &chg);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0, "env");
    amt[0] = 5000000000ULL + FEE + CHG;
    facts_reset(1, amt);
    g_f.price[0] = 100000000ULL;
    g_f.price[1] = 5000000000ULL;
    g_f.price[2] = 200000000ULL;
    g_f.price[3] = 300000000ULL;
    CHECK(run_exec(g2, &e) == 0, "the voted tier is the price");

    /* a 36-byte name pays the 6+ tier */
    {
        char a36[37];
        memset(a36, 'z', 36);
        a36[36] = '\0';
        e.call_len = nm_call(e.call, a36, DNAC_NAME_PRICE_6P_DEFAULT, 1, ins,
                             1, &chg);
        CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                     NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0, "env");
        amt[0] = DNAC_NAME_PRICE_6P_DEFAULT + FEE + CHG;
        facts_reset(1, amt);
        CHECK(run_exec(g2, &e) == 0 && g_ev.eff[1].key_len == 36,
              "a 36-byte name at P6");
    }

    /* zero change: two inputs, no output, Σin == fee + price exactly */
    e.call_len = nm_call(e.call, "abc", DNAC_NAME_PRICE_3P_DEFAULT, 2, ins,
                         0, NULL);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0, "env");
    amt[0] = DNAC_NAME_PRICE_3P_DEFAULT;
    amt[1] = FEE;
    facts_reset(2, amt);
    CHECK(run_exec(g2, &e) == 0 && g_ev.effect_count == 4 &&
          g_ev.eff[0].op_id == OP_NAME && g_ev.eff[1].op_id == OP_SUPPLY &&
          g_ev.eff[2].op_id == OP_UTXDEL && g_ev.eff[3].op_id == OP_UTXDEL,
          "no change: CREATE name, SET pool, two DELETEs");
    free(e.bytes);
    e.bytes = NULL;
    return 0;
}

static int t_describe_and_owner_key(void) {
    static nm_env_t e;
    static nodus_rt_leg_desc_t d;
    uint8_t ins[1][64], intent[64];
    memset(ins[0], 0x10, 64);
    memset(intent, 0x5C, sizeof(intent));
    nm_out_t chg = { g_owner_hex, CHG, NULL, 0x5E };

    e.call_len = nm_call(e.call, "punk", P4, 1, ins, 1, &chg);
    CHECK(nm_env(&e, DNA_CORERULE_NAME_REGISTER,
                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1, FEE) == 0, "env");
    memset(&d, 0, sizeof(d));
    CHECK(nodus_rt_native_describe_leg(&e.view, 0, 100, intent, &d) == 0,
          "an applied registration is describable");
    CHECK(d.runtime_op == DNA_CORERULE_NAME_REGISTER &&
          d.name_len == 4 && memcmp(d.name, "punk", 4) == 0 &&
          d.name_price == P4, "name and price described");
    CHECK(d.burned == 0, "the price is NOT a burn");
    CHECK(d.n_consumed == 1 && memcmp(d.consumed[0], ins[0], 64) == 0 &&
          d.n_created == 1 && d.created[0].amount == CHG &&
          memcmp(d.created[0].owner_hex, g_owner_hex, 128) == 0,
          "the coins as the call carries them");

    /* the CheckTx owner key */
    nodus_rt_auth_verdict_t av;
    memset(&av, 0, sizeof(av));
    av.n_signers = 1;
    memcpy(av.signer_fp[0], g_owner, 64);
    uint32_t op = 0;
    uint8_t key[64];
    CHECK(nodus_rt_core_name_owner_key(&e.view, 0, &av, &op, key) == 0 &&
          op == OP_NAMEOWN && memcmp(key, g_owner, 64) == 0,
          "(CORE, OWNER op, signer_fp[0])");
    av.n_signers = 2;
    CHECK(nodus_rt_core_name_owner_key(&e.view, 0, &av, &op, key) == -1,
          "two signers: no key (-1)");
    av.n_signers = 1;
    /* a SPEND leg (the transfer section alone) carries no owner key */
    {
        size_t off = 0;
        e.call[off++] = 1;
        memcpy(e.call + off, ins[0], 64);  off += 64;
        e.call[off++] = 1;
        uint8_t seed[32];
        memset(seed, 0x5E, sizeof(seed));
        nodus_v2_xfer_out_put(e.call + off, g_owner_hex, CHG, NULL, seed);
        off += OUT_LEN;
        e.call_len = off;
    }
    CHECK(nm_env(&e, DNA_CORERULE_SPEND, NODUS_RT_AUTHKIND_DSA87_MULTI_V1, 1,
                 FEE) == 0 &&
          nodus_rt_core_name_owner_key(&e.view, 0, &av, &op, key) == 1,
          "a SPEND leg: 1 (no key)");
    free(e.bytes);
    e.bytes = NULL;
    return 0;
}

/* ══ 7. pins header v2: every generation's tuple == the compiled table ═ */

static int t_pins(void) {
    uint32_t n = nodus_v2_pins_generation_count();
    CHECK(n == NODUS_RT_GEN_MAX, "the pins carry every compiled generation");
    for (uint32_t g = 1; g <= n; g++) {
        const nodus_domain_runtime_t *s =
            nodus_runtime_for_generation(g, DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *c =
            nodus_runtime_for_generation(g, DNA_DOMAIN_CORE);
        uint32_t sv = 0, cv = 0;
        uint8_t sh[64], ch[64];
        CHECK(s && c, "compiled generation");
        CHECK(nodus_v2_pins_tuples(g, &sv, sh, &cv, ch) == NODUS_V2_SPEND_OK,
              "pinned tuple");
        CHECK(sv == s->ruleset_version && memcmp(sh, s->ruleset_hash, 64) == 0
              && cv == c->ruleset_version &&
              memcmp(ch, c->ruleset_hash, 64) == 0,
              "pinned (SYSTEM, CORE) == the compiled runtime table");
        nodus_v2_ruleset_id_t rs;
        dna_meter_policy_t pol;
        CHECK(nodus_v2_ruleset_from_pins_gen(g, &rs, &pol) ==
                  NODUS_V2_SPEND_OK &&
              rs.core_ruleset_version == c->ruleset_version &&
              memcmp(rs.core_ruleset_hash, c->ruleset_hash, 64) == 0,
              "the pins ruleset of that generation");
    }
    CHECK(nodus_v2_pins_tuples(0, NULL, NULL, NULL, NULL) != NODUS_V2_SPEND_OK
          && nodus_v2_pins_tuples(n + 1, NULL, NULL, NULL, NULL) !=
                 NODUS_V2_SPEND_OK, "unknown generations refused");
    return 0;
}

/* ══ 8. client decoders over hand-built replies ══════════════════════ */

static uint8_t g_buf[1u << 16];

static void reply_head(cbor_encoder_t *e, const char *method, size_t rkeys) {
    cbor_encoder_init(e, g_buf, sizeof(g_buf));
    cbor_encode_map(e, 4);
    cbor_encode_cstr(e, "t"); cbor_encode_uint(e, 1);
    cbor_encode_cstr(e, "y"); cbor_encode_cstr(e, "r");
    cbor_encode_cstr(e, "q"); cbor_encode_cstr(e, method);
    cbor_encode_cstr(e, "r");
    cbor_encode_map(e, rkeys);
}

/* ruleset_info: `skip` drops one key (1..9), `dup` repeats "tip",
 * `gen` is the generation value. */
static size_t ri_reply(int skip, int dup, uint64_t gen) {
    cbor_encoder_t e;
    uint8_t h1[64], h2[64], h3[64];
    memset(h1, 0x21, 64); memset(h2, 0x22, 64); memset(h3, 0x23, 64);
    reply_head(&e, "dnac_ruleset_info",
               (size_t)(9 - (skip ? 1 : 0) + (dup ? 1 : 0)));
    if (skip != 1) { cbor_encode_cstr(&e, "tip"); cbor_encode_uint(&e, 41); }
    if (dup)       { cbor_encode_cstr(&e, "tip"); cbor_encode_uint(&e, 41); }
    if (skip != 2) { cbor_encode_cstr(&e, "gen"); cbor_encode_uint(&e, gen); }
    if (skip != 3) { cbor_encode_cstr(&e, "sv"); cbor_encode_uint(&e, 7); }
    if (skip != 4) { cbor_encode_cstr(&e, "sh"); cbor_encode_bstr(&e, h1, 64); }
    if (skip != 5) { cbor_encode_cstr(&e, "cv"); cbor_encode_uint(&e, 5); }
    if (skip != 6) { cbor_encode_cstr(&e, "ch"); cbor_encode_bstr(&e, h2, 64); }
    if (skip != 7) { cbor_encode_cstr(&e, "pd"); cbor_encode_bstr(&e, h3, 64); }
    if (skip != 8) { cbor_encode_cstr(&e, "H"); cbor_encode_uint(&e, 4000); }
    if (skip != 9) { cbor_encode_cstr(&e, "d2"); cbor_encode_uint(&e, 77); }
    return cbor_encoder_len(&e);
}

/* name result: `found`; with_row writes owner|name + rh; `rh` value. */
static size_t nr_reply(int is_name_of, int found, int with_row, uint64_t rh,
                       const char *name_val) {
    cbor_encoder_t e;
    reply_head(&e, is_name_of ? "dnac_name_of" : "dnac_name_lookup",
               (size_t)(2 + (with_row ? 2 : 0)));
    cbor_encode_cstr(&e, "found"); cbor_encode_bool(&e, found != 0);
    cbor_encode_cstr(&e, "ch");    cbor_encode_uint(&e, 41);
    if (with_row) {
        if (is_name_of) {
            cbor_encode_cstr(&e, "name"); cbor_encode_cstr(&e, name_val);
        } else {
            cbor_encode_cstr(&e, "owner"); cbor_encode_cstr(&e, g_owner_hex);
        }
        cbor_encode_cstr(&e, "rh"); cbor_encode_uint(&e, rh);
    }
    return cbor_encoder_len(&e);
}

/* fee_info's HF-4 keys beside two pre-HF-4 keys a decoder must skip. */
static size_t np_reply(int with_np, size_t np_n, size_t ns_n, int bad_map) {
    cbor_encoder_t e;
    reply_head(&e, "dnac_fee_info", (size_t)(2 + (with_np ? 1 : 0) + 1));
    cbor_encode_cstr(&e, "f");  cbor_encode_uint(&e, 1000000);
    cbor_encode_cstr(&e, "g");  cbor_encode_uint(&e, 0);
    if (with_np) {
        cbor_encode_cstr(&e, "np");
        cbor_encode_array(&e, np_n);
        for (size_t j = 0; j < np_n; j++)
            cbor_encode_uint(&e, 100000000ULL * (np_n - j));
    }
    cbor_encode_cstr(&e, "ns");
    cbor_encode_array(&e, ns_n);
    for (size_t j = 0; j < ns_n; j++) {
        cbor_encode_map(&e, bad_map ? 4 : 3);
        cbor_encode_cstr(&e, "p"); cbor_encode_uint(&e, 10 + (j % 4));
        cbor_encode_cstr(&e, "v"); cbor_encode_uint(&e, 200000000ULL + j);
        cbor_encode_cstr(&e, "e"); cbor_encode_uint(&e, 5000 + j);
        if (bad_map) { cbor_encode_cstr(&e, "x"); cbor_encode_uint(&e, 1); }
    }
    return cbor_encoder_len(&e);
}

/* a one-item dnac_v3_block page: item code `code`, with effects when
 * `eff`, "nm" when nm != NULL, "pr" when with_pr. */
static size_t v3_reply(uint32_t code, int eff, const char *nm, int with_pr) {
    cbor_encoder_t e;
    uint8_t z64[64];
    memset(z64, 0x11, sizeof(z64));
    reply_head(&e, "dnac_v3_block", 10);
    cbor_encode_cstr(&e, "h");   cbor_encode_uint(&e, 5);
    cbor_encode_cstr(&e, "bid"); cbor_encode_bstr(&e, z64, 64);
    cbor_encode_cstr(&e, "pb");  cbor_encode_bstr(&e, z64, 64);
    cbor_encode_cstr(&e, "tm");  cbor_encode_uint(&e, 1000);
    cbor_encode_cstr(&e, "pa");  cbor_encode_bstr(&e, z64, 32);
    cbor_encode_cstr(&e, "gr");  cbor_encode_bstr(&e, z64, 64);
    cbor_encode_cstr(&e, "ac");  cbor_encode_uint(&e, code == 0 ? 1 : 0);
    cbor_encode_cstr(&e, "n");   cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "tip"); cbor_encode_uint(&e, 9);
    cbor_encode_cstr(&e, "it");  cbor_encode_array(&e, 1);
    cbor_encode_map(&e, (size_t)(3 + (eff ? 2 : 0) + (nm ? 1 : 0) +
                                 (with_pr ? 1 : 0)));
    cbor_encode_cstr(&e, "i"); cbor_encode_uint(&e, 0);
    cbor_encode_cstr(&e, "k"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "c"); cbor_encode_uint(&e, code);
    if (eff) {
        cbor_encode_cstr(&e, "sp");
        cbor_encode_array(&e, 1);
        cbor_encode_bstr(&e, z64, 64);
        cbor_encode_cstr(&e, "cr");
        cbor_encode_array(&e, 0);
    }
    if (nm)      { cbor_encode_cstr(&e, "nm"); cbor_encode_cstr(&e, nm); }
    if (with_pr) { cbor_encode_cstr(&e, "pr"); cbor_encode_uint(&e, P4); }
    return cbor_encoder_len(&e);
}

static int t_decoders(void) {
    size_t len;

    /* dnac_ruleset_info */
    {
        nodus_dnac_ruleset_info_t ri;
        len = ri_reply(0, 0, 2);
        CHECK(nodus_dnac_ruleset_info_decode(g_buf, len, &ri) == 0 &&
              ri.tip == 41 && ri.generation == 2 && ri.sys_version == 7 &&
              ri.core_version == 5 && ri.sys_hash[0] == 0x21 &&
              ri.core_hash[63] == 0x22 && ri.policy_digest[5] == 0x23 &&
              ri.gen2_height == 4000 && ri.d2 == 77,
              "the control decodes every field");
        for (size_t cut = 1; cut < len; cut++)
            CHECK(nodus_dnac_ruleset_info_decode(g_buf, len - cut, &ri) == -1,
                  "a truncated reply is refused");
        for (int s = 1; s <= 9; s++) {
            len = ri_reply(s, 0, 2);
            CHECK(nodus_dnac_ruleset_info_decode(g_buf, len, &ri) == -1,
                  "every key is required");
        }
        len = ri_reply(0, 1, 2);
        CHECK(nodus_dnac_ruleset_info_decode(g_buf, len, &ri) == -1,
              "a duplicate key is refused");
        len = ri_reply(0, 0, 0);
        CHECK(nodus_dnac_ruleset_info_decode(g_buf, len, &ri) == -1,
              "generation 0 is refused");
    }

    /* dnac_name_lookup / dnac_name_of */
    {
        nodus_dnac_name_result_t nr;
        len = nr_reply(0, 1, 1, 12, NULL);
        CHECK(nodus_dnac_name_result_decode(g_buf, len, 0, &nr) == 0 &&
              nr.found && strcmp(nr.owner, g_owner_hex) == 0 &&
              nr.registered_height == 12 && nr.committed_height == 41,
              "lookup: found, owner, rh, ch");
        len = nr_reply(0, 0, 0, 0, NULL);
        CHECK(nodus_dnac_name_result_decode(g_buf, len, 0, &nr) == 0 &&
              !nr.found && nr.committed_height == 41,
              "lookup: not found carries ch only");
        len = nr_reply(0, 1, 0, 0, NULL);
        CHECK(nodus_dnac_name_result_decode(g_buf, len, 0, &nr) == -1,
              "found without the row is refused");
        len = nr_reply(0, 0, 1, 12, NULL);
        CHECK(nodus_dnac_name_result_decode(g_buf, len, 0, &nr) == -1,
              "not found WITH a row is refused");
        len = nr_reply(0, 1, 1, 0, NULL);
        CHECK(nodus_dnac_name_result_decode(g_buf, len, 0, &nr) == -1,
              "rh 0 is refused");
        len = nr_reply(1, 1, 1, 12, "punk");
        CHECK(nodus_dnac_name_result_decode(g_buf, len, 1, &nr) == 0 &&
              nr.found && strcmp(nr.name, "punk") == 0 &&
              nr.registered_height == 12, "name_of: found, name, rh");
        len = nr_reply(1, 1, 1, 12, "Punk");
        CHECK(nodus_dnac_name_result_decode(g_buf, len, 1, &nr) == -1,
              "name_of: an uppercase name is refused");
        len = nr_reply(1, 1, 1, 12, "deadbeef");
        CHECK(nodus_dnac_name_result_decode(g_buf, len, 1, &nr) == -1,
              "name_of: a hex-like name is refused");
    }

    /* dnac_fee_info HF-4 keys */
    {
        static nodus_dnac_name_prices_t np;
        len = np_reply(1, 4, 2, 0);
        CHECK(nodus_dnac_name_prices_decode(g_buf, len, &np) == 0 &&
              np.price[0] == 400000000ULL && np.price[3] == 100000000ULL &&
              np.n_sched == 2 && np.sched[1].param_id == 11 &&
              np.sched[1].value == 200000001ULL &&
              np.sched[1].effective == 5001, "np + ns decode");
        len = np_reply(1, 4, NODUS_DNAC_NAME_SCHED_MAX, 0);
        CHECK(nodus_dnac_name_prices_decode(g_buf, len, &np) == 0 &&
              np.n_sched == NODUS_DNAC_NAME_SCHED_MAX, "exactly MAX rows");
        len = np_reply(1, 4, NODUS_DNAC_NAME_SCHED_MAX + 1, 0);
        CHECK(nodus_dnac_name_prices_decode(g_buf, len, &np) == -1,
              "MAX + 1 rows refused");
        len = np_reply(1, 3, 0, 0);
        CHECK(nodus_dnac_name_prices_decode(g_buf, len, &np) == -1,
              "three prices refused");
        len = np_reply(0, 4, 0, 0);
        CHECK(nodus_dnac_name_prices_decode(g_buf, len, &np) == -1,
              "an older node (no np) is refused — fail closed");
        len = np_reply(1, 4, 1, 1);
        CHECK(nodus_dnac_name_prices_decode(g_buf, len, &np) == -1,
              "a row with a fourth key is refused");
    }

    /* dnac_v3_block "nm" / "pr" */
    {
        nodus_dnac_v3_block_result_t r;
        len = v3_reply(0, 1, "punk", 1);
        CHECK(nodus_dnac_v3_block_decode(g_buf, len, &r) == 0 &&
              r.count == 1 && strcmp(r.items[0].name, "punk") == 0 &&
              r.items[0].name_price == P4 && r.items[0].burned == 0,
              "an applied registration: name and price");
        nodus_client_free_v3_block_result(&r);
        len = v3_reply(0, 1, NULL, 0);
        CHECK(nodus_dnac_v3_block_decode(g_buf, len, &r) == 0 &&
              r.items[0].name[0] == '\0' && r.items[0].name_price == 0,
              "no keys: not a registration (older node shape)");
        nodus_client_free_v3_block_result(&r);
        len = v3_reply(0, 1, "punk", 0);
        CHECK(nodus_dnac_v3_block_decode(g_buf, len, &r) == -1,
              "nm without pr refused");
        len = v3_reply(0, 1, NULL, 1);
        CHECK(nodus_dnac_v3_block_decode(g_buf, len, &r) == -1,
              "pr without nm refused");
        len = v3_reply(7, 0, "punk", 1);
        CHECK(nodus_dnac_v3_block_decode(g_buf, len, &r) == -1,
              "nm / pr on a refused item refused");
        len = v3_reply(0, 1, "PUNK", 1);
        CHECK(nodus_dnac_v3_block_decode(g_buf, len, &r) == -1,
              "an uppercase nm refused");
        len = v3_reply(0, 1, "ab", 1);
        CHECK(nodus_dnac_v3_block_decode(g_buf, len, &r) == -1,
              "a 2-byte nm refused");
    }
    return 0;
}

int main(void) {
    memset(g_owner, 0xA7, sizeof(g_owner));
    memset(g_other, 0xB8, sizeof(g_other));
    hex_of(g_owner, g_owner_hex);
    hex_of(g_other, g_other_hex);

    const nodus_domain_runtime_t *g1 =
        nodus_runtime_for_generation(NODUS_RT_GEN_1, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *g2 =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_CORE);
    if (!g1 || !g2 || g2->generation != NODUS_RT_GEN_2) {
        fprintf(stderr, "test_hf4_names: compiled CORE generations missing\n");
        return 1;
    }

    int failed = 0, n = 0;
    struct { const char *name; int rc; } res[7];
    res[n].name = "bytes_and_price";       res[n++].rc = t_bytes_and_price();
    res[n].name = "name_root_kats";        res[n++].rc = t_name_root();
    res[n].name = "read_plan";             res[n++].rc = t_read_plan(g1, g2);
    res[n].name = "exec_matrix";           res[n++].rc = t_exec(g1, g2);
    res[n].name = "describe_owner_key";    res[n++].rc =
                                               t_describe_and_owner_key();
    res[n].name = "pins_generations";      res[n++].rc = t_pins();
    res[n].name = "client_decoders";       res[n++].rc = t_decoders();
    for (int i = 0; i < n; i++) {
        fprintf(stderr, "%-22s %s\n", res[i].name, res[i].rc ? "FAIL" : "ok");
        if (res[i].rc) failed++;
    }
    fprintf(stderr, "test_hf4_names: %d/%d cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
