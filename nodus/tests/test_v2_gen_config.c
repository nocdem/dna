/**
 * @file nodus/tests/test_v2_gen_config.c
 * @brief O16A — the genesis config TEXT form, the D4 idempotency
 *        comparison, the D3 partial-wipe marker and the D7 payout
 *        fingerprint derivation.
 *
 * Drives the REAL functions: nodus_v2_gen_config_parse_file,
 * nodus_witness_v2_gen_config_validate, _source_commit and _derive.
 * No parallel parser, no re-implemented encoder.
 *
 * Sections:
 *   §1  a golden config file parses to the expected struct, field for
 *       field — including the three constants the file may NOT name
 *   §2  D-I5: the same file parsed twice yields an identical
 *       source_commit, and it equals the in-memory reference's
 *   §3  every refusal, one case each, each naming what it kills
 *   §4  D7 / G7: a well-shaped fingerprint that does not DERIVE from
 *       the payout key is refused; the derived one is accepted
 *   §5  D4 / G4: re-deriving with a different config REFUSES; with the
 *       same config it is the idempotent success it claims to be
 *   §6  D3 / G6: a derivation leaves the partial-wipe marker in the
 *       REAL data directory and leaves no scratch directory behind
 *   §7  D8: a node that RESTARTS on a derived V2 chain is recognised
 *       as holding one — nodus_witness_bootstrap_start reaches DONE
 *       and never enters the legacy DISCOVER state machine
 *
 * §7 — WHAT IT PROVES, WHAT IT NEEDS, WHAT IT LEAVES, HOW IT COULD LIE.
 *
 * PROVES: on a pure-V2 chain, bootstrap_start takes the HAVE_CHAIN
 * branch. If it failed, a V2 node would enter legacy DISCOVER, where it
 * either fails the C-1 seed-count gate (init returns -1) or burns ten
 * attempts and calls exit(2) — every node, at once, on the same rule.
 * It also pins the two facts that make a HEIGHT test unusable as the
 * discriminator: the V2 tip is 0 at genesis, and the legacy `blocks`
 * table exists-and-answers-0 rather than faulting.
 *
 * REQUIRES: nothing beyond a default build. No compile flag, no
 * environment variable, no network, no second process. It derives its
 * own chain from the in-file reference config.
 *
 * LEAVES BEHIND: nothing. Its own mkdtemp directory, removed on the way
 * out; it does not ride §5/§6's directory.
 *
 * HOW IT COULD LIE: two ways, both closed by an assertion. (1) If the
 * scan silently failed to mark the chain a successor, the node would go
 * down the V1 path and a green would mean nothing — so `w->v2_successor`
 * is ASSERTED after the scan, never assigned (the same discipline
 * test_v2_gen.c:305-324 adopted after this exact masking was found).
 * (2) `bootstrap_state != DISCOVER` is satisfied by INIT and by every
 * other state, so the assertion is `== DONE`, and the pre-call state is
 * checked to be INIT — the restart path does not write DONE (only
 * nodus_witness_create_chain_db does, nodus_witness.c:1163), so the
 * result can only have come from bootstrap_start itself.
 *
 * ANTI-VACUITY. §3's cases are constructed so that each isolates ONE
 * rule: the over-long-line case, for example, is a line that would
 * parse perfectly if the length bound were removed, so it cannot pass
 * for a second reason. Where a case is backstopped by another guard the
 * comment says so instead of claiming a uniqueness it does not have.
 *
 * WHAT THESE TESTS WOULD DO BEFORE THIS CHANGE. §1-§3 cover a parser
 * that did not exist. §4 fails on the parent: gen_plan_build validated
 * the fingerprint's SHAPE only. §5 fails on the parent: derive returned
 * 0 on `pe == 1` without comparing source_commit. §6 fails on the
 * parent: the marker was written into the scratch directory, which was
 * then deleted. §7 fails on the parent too, and loudly: with the legacy
 * tip reading 0 the node fell through to the DISCOVER branch, whose C-1
 * gate reads seed_count from a NULL server as 0 and returns -1 — so
 * `bootstrap_start == 0` is already RED there, before the state
 * assertion is reached.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define _DEFAULT_SOURCE   /* mkdtemp under -std=c11 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sqlite3.h>

#include "nodus_v2_gen_config.h"
/* §7 — the restart path (scan), the state machine it feeds, and the V2
 * tip accessor the D8 branch now reads. */
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bootstrap.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_emission.h"  /* DNAC_BLOCKS_PER_YEAR,
                                              * DNAC_DECIMAL_UNIT       */
#include "server/nodus_server.h"             /* the marker name itself —
                                              * asserted through the
                                              * macro so a rename cannot
                                              * leave this test green    */
#include "dnac/dnac.h"

#include "crypto/hash/qgp_sha3.h"

static int g_fail = 0;
static int g_checks = 0;
#define CHECK(cond, msg) do {                                            \
    g_checks++;                                                          \
    if (!(cond)) {                                                       \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,         \
                __LINE__, (msg));                                        \
        g_fail = 1;                                                      \
    } } while (0)
#define OK() do { if (g_fail) return 1; } while (0)

/* ── the §0 composition, identical to test_v2_gen.c's ────────────────── */

#define TREASURY_RAW   93000000000000000ULL          /* 930,000,000 DNAC */
#define N_VAL          ((uint16_t)DNAC_COMMITTEE_SIZE)
#define GOLDEN_CAP     262144u

/* ── small helpers ───────────────────────────────────────────────────── */

static void rmrf(const char *dir) {
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int path_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

static void bin2hex(const uint8_t *b, size_t n, char *out) {
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = hexd[b[i] >> 4];
        out[2 * i + 1] = hexd[b[i] & 0x0F];
    }
    out[2 * n] = 0;
}

/* SHA3-512(src) as 128 lowercase hex chars + NUL — the same shape
 * test_v2_gen.c:94-103 builds and the shape the graduation predicate
 * demands. */
static void hex_lower_fp(const uint8_t *src, size_t src_len, uint8_t *out129) {
    uint8_t d[64];
    qgp_sha3_512(src, src_len, d);
    bin2hex(d, 64, (char *)out129);
}

static int mkdir_tmp(char dir[128], const char *tag) {
    snprintf(dir, 128, "/tmp/test_v2_gen_config_%s_XXXXXX", tag);
    return mkdtemp(dir) ? 0 : -1;
}

/* ── the reference config, in memory ─────────────────────────────────── */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} cfgbox_t;

static void cfg_free(cfgbox_t *b) {
    if (!b) return;
    free(b->cfg);
    free(b->allocs);
    b->cfg = NULL;
    b->allocs = NULL;
}

/**
 * The reference composition: one treasury allocation of TREASURY_RAW
 * plus DNAC_COMMITTEE_SIZE validators each bonding
 * DNAC_SELF_STAKE_AMOUNT — 10^17 raw in total.
 *
 * @param c0_extra added to validator[0]'s commission_bps. Non-zero
 *                 produces a DIFFERENT but equally derivable config,
 *                 which is what §5 needs: commission_bps is a field of
 *                 the canonical encoding (nodus_witness_v2_gen.h:303),
 *                 so changing it changes source_commit and therefore the
 *                 chain.
 */
static int cfg_make(cfgbox_t *b, uint16_t c0_extra) {
    memset(b, 0, sizeof(*b));
    b->cfg    = calloc(1, sizeof(*b->cfg));   /* ~160 KB — never on the stack */
    b->allocs = calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) { cfg_free(b); return -1; }

    nodus_v2_gen_config_t *c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 1ULL;
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = N_VAL;

    for (uint16_t i = 0; i < N_VAL; i++) {
        nodus_v2_gen_validator_t *v = &c->validators[i];
        for (size_t bb = 0; bb < DNAC_PUBKEY_SIZE; bb++) {
            v->pubkey[bb] = (uint8_t)(0x11 * (i + 1) + (bb & 0x3F));
            v->unstake_destination_pubkey[bb] = (uint8_t)(v->pubkey[bb] ^ 0x5A);
        }
        hex_lower_fp(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                     v->unstake_destination_fp);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (i + 1));
    }
    c->validators[0].commission_bps =
        (uint16_t)(c->validators[0].commission_bps + c0_extra);

    {
        nodus_v2_gen_alloc_t *a = &b->allocs[0];
        memset(a->source_id, 0, sizeof(a->source_id));
        a->source_id[0]  = 0x30;
        a->source_id[63] = 0x01;
        uint8_t owner[DNAC_PUBKEY_SIZE];
        for (size_t bb = 0; bb < sizeof(owner); bb++)
            owner[bb] = (uint8_t)(0xA0 + (bb & 0x1F));
        qgp_sha3_512(owner, sizeof(owner), a->dest_binding);
        a->amount = TREASURY_RAW;
    }
    c->n_allocs = 1;
    c->allocs   = b->allocs;
    return 0;
}

/* ── the reference config, as text ───────────────────────────────────── */

/* Serialise a config to the operator text form.
 *
 * Deliberately emits the SINGLE-SPACE `key = value` shape so that §3 can
 * construct an exact needle for any line it wants to mutate. The
 * alignment-padding and trailing-comment forms are exercised too, on the
 * blocks_per_year line, so §1 also proves the parser tolerates them. */
static char *golden_text(const nodus_v2_gen_config_t *c) {
    char *t = malloc(GOLDEN_CAP);
    if (!t) return NULL;
    size_t n = 0;
    char hex[2 * DNAC_PUBKEY_SIZE + 1];

#define EMIT(...) do {                                                   \
        int _w = snprintf(t + n, GOLDEN_CAP - n, __VA_ARGS__);           \
        if (_w < 0 || (size_t)_w >= GOLDEN_CAP - n) { free(t); return NULL; } \
        n += (size_t)_w;                                                 \
    } while (0)

    EMIT("# DNA Chain — Ledger V2 genesis config (test fixture)\n");
    EMIT("total_supply_raw = %llu\n",
         (unsigned long long)c->total_supply_raw);
    EMIT("epoch_length = %llu\n", (unsigned long long)c->epoch_length);
    /* alignment padding + a trailing comment, exercised once */
    EMIT("blocks_per_year     =   %llu     # the tokenomic year\n",
         (unsigned long long)c->blocks_per_year);
    EMIT("decimal_unit = %llu\n", (unsigned long long)c->decimal_unit);
    EMIT("inflation_start_block = %llu\n",
         (unsigned long long)c->inflation_start_block);

    for (uint16_t i = 0; i < c->n_validators; i++) {
        const nodus_v2_gen_validator_t *v = &c->validators[i];
        EMIT("\n[validator]\n");
        bin2hex(v->pubkey, DNAC_PUBKEY_SIZE, hex);
        EMIT("pubkey = %s\n", hex);
        bin2hex(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE, hex);
        EMIT("unstake_destination_pubkey = %s\n", hex);
        EMIT("unstake_destination_fp = %.128s\n",
             (const char *)v->unstake_destination_fp);
        EMIT("self_stake = %llu\n", (unsigned long long)v->self_stake);
        EMIT("commission_bps = %u\n", (unsigned)v->commission_bps);
    }

    for (uint32_t i = 0; i < c->n_allocs; i++) {
        const nodus_v2_gen_alloc_t *a = &c->allocs[i];
        EMIT("\n[allocation]\n");
        bin2hex(a->source_id, NODUS_V2_GEN_SRCID_LEN, hex);
        EMIT("source_id = %s\n", hex);
        bin2hex(a->dest_binding, 64, hex);
        EMIT("dest_binding = %s\n", hex);
        EMIT("amount = %llu\n", (unsigned long long)a->amount);
    }
#undef EMIT
    return t;
}

static int write_text(const char *path, const char *text) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    size_t len = strlen(text);
    int ok = (fwrite(text, 1, len, fp) == len) ? 0 : -1;
    if (fclose(fp) != 0) ok = -1;
    return ok;
}

/* Replace the FIRST occurrence of `needle`. Returns a fresh string, or
 * NULL when the needle is absent — a NULL is a broken test, not a
 * refusal under test, and every caller CHECKs it. */
static char *replace_first(const char *text, const char *needle,
                           const char *repl) {
    const char *at = strstr(text, needle);
    if (!at) return NULL;
    size_t pre = (size_t)(at - text);
    size_t nl = strlen(needle), rl = strlen(repl);
    size_t tail = strlen(at + nl);
    char *out = malloc(pre + rl + tail + 1);
    if (!out) return NULL;
    memcpy(out, text, pre);
    memcpy(out + pre, repl, rl);
    memcpy(out + pre + rl, at + nl, tail + 1);
    return out;
}

/* Write `text` with the first `needle` replaced by `repl`, then assert
 * the parser REFUSES it. `what` names the rule the case isolates. */
static void expect_refusal(const char *dir, const char *golden,
                           const char *needle, const char *repl,
                           const char *what) {
    char path[256];
    snprintf(path, sizeof(path), "%s/mutant.conf", dir);

    char *mutant = replace_first(golden, needle, repl);
    CHECK(mutant != NULL, "mutation needle must be present in the golden "
                          "file — a missing needle is a broken test, not a "
                          "passing one");
    if (!mutant) return;

    CHECK(write_text(path, mutant) == 0, "write mutant");
    nodus_v2_gen_config_t *got = NULL;
    fprintf(stderr, "  -- expecting a refusal: %s\n", what);
    CHECK(nodus_v2_gen_config_parse_file(path, &got) != 0, what);
    CHECK(got == NULL, "a refused parse must not hand back a config");
    nodus_v2_gen_config_free(got);
    free(mutant);
    unlink(path);
}

/* ════════════════════════════════════════════════════════════════════
 * §1 — the golden file parses to the expected struct
 * ══════════════════════════════════════════════════════════════════ */

static int test_golden_roundtrip(void) {
    printf("§1 a golden config file parses to the expected struct\n");

    cfgbox_t ref;
    CHECK(cfg_make(&ref, 0) == 0, "reference config");
    OK();

    char dir[128];
    CHECK(mkdir_tmp(dir, "golden") == 0, "tmpdir");
    OK();

    char *text = golden_text(ref.cfg);
    CHECK(text != NULL, "serialise the golden config");
    OK();

    char path[256];
    snprintf(path, sizeof(path), "%s/genesis.conf", dir);
    CHECK(write_text(path, text) == 0, "write golden");
    OK();

    nodus_v2_gen_config_t *got = NULL;
    CHECK(nodus_v2_gen_config_parse_file(path, &got) == 0,
          "the golden config parses");
    OK();

    /* The three the file may NOT name — set by the parser, and each has
     * exactly one legal value the builder enforces. */
    CHECK(got->config_version == NODUS_V2_GEN_CONFIG_VERSION,
          "config_version is forced to the schema version");
    CHECK(got->claim_start_height == 0,
          "claim_start_height is forced to 0");
    CHECK(got->claim_end_height == UINT64_MAX,
          "claim_end_height is forced to UINT64_MAX");

    /* The five the file MUST name. */
    CHECK(got->total_supply_raw      == ref.cfg->total_supply_raw,
          "total_supply_raw");
    CHECK(got->epoch_length          == ref.cfg->epoch_length,
          "epoch_length");
    CHECK(got->blocks_per_year       == ref.cfg->blocks_per_year,
          "blocks_per_year (parsed through alignment padding + a comment)");
    CHECK(got->decimal_unit          == ref.cfg->decimal_unit,
          "decimal_unit");
    CHECK(got->inflation_start_block == ref.cfg->inflation_start_block,
          "inflation_start_block");

    CHECK(got->n_validators == ref.cfg->n_validators, "n_validators");
    CHECK(got->n_allocs     == ref.cfg->n_allocs,     "n_allocs");
    OK();

    /* Validator blocks are consumed IN FILE ORDER — the canonical
     * pubkey-ASC ordering is the builder's job (gen_plan_build's
     * val_idx), never the parser's, so this is a positional compare. */
    for (uint16_t i = 0; i < ref.cfg->n_validators; i++) {
        const nodus_v2_gen_validator_t *a = &ref.cfg->validators[i];
        const nodus_v2_gen_validator_t *b = &got->validators[i];
        CHECK(memcmp(a->pubkey, b->pubkey, DNAC_PUBKEY_SIZE) == 0,
              "validator pubkey round-trips");
        CHECK(memcmp(a->unstake_destination_pubkey,
                     b->unstake_destination_pubkey, DNAC_PUBKEY_SIZE) == 0,
              "validator payout pubkey round-trips");
        CHECK(memcmp(a->unstake_destination_fp, b->unstake_destination_fp,
                     DNAC_FINGERPRINT_SIZE) == 0,
              "validator payout fingerprint round-trips, NUL included");
        CHECK(a->self_stake     == b->self_stake,     "self_stake");
        CHECK(a->commission_bps == b->commission_bps, "commission_bps");
    }
    for (uint32_t i = 0; i < ref.cfg->n_allocs; i++) {
        const nodus_v2_gen_alloc_t *a = &ref.cfg->allocs[i];
        const nodus_v2_gen_alloc_t *b = &got->allocs[i];
        CHECK(memcmp(a->source_id, b->source_id,
                     NODUS_V2_GEN_SRCID_LEN) == 0, "alloc source_id");
        CHECK(memcmp(a->dest_binding, b->dest_binding, 64) == 0,
              "alloc dest_binding");
        CHECK(a->amount == b->amount, "alloc amount");
    }

    /* A well-formed file is not automatically a derivable one, but this
     * one is — which is what makes §5's derivations possible. */
    CHECK(nodus_witness_v2_gen_config_validate(got) == 0,
          "the golden config is derivable");

    nodus_v2_gen_config_free(got);
    free(text);
    cfg_free(&ref);
    rmrf(dir);
    OK();
    printf("  ok: every field round-trips and the three forced constants "
           "are set\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §2 — D-I5: the parser is a pure function of the file's bytes
 * ══════════════════════════════════════════════════════════════════ */

static int test_determinism_twin(void) {
    printf("§2 D-I5 — the same file twice yields the same source_commit\n");

    cfgbox_t ref;
    CHECK(cfg_make(&ref, 0) == 0, "reference config");
    OK();

    char dir[128];
    CHECK(mkdir_tmp(dir, "twin") == 0, "tmpdir");
    OK();

    char *text = golden_text(ref.cfg);
    CHECK(text != NULL, "serialise");
    OK();
    char path[256];
    snprintf(path, sizeof(path), "%s/genesis.conf", dir);
    CHECK(write_text(path, text) == 0, "write");
    OK();

    nodus_v2_gen_config_t *a = NULL, *b = NULL;
    CHECK(nodus_v2_gen_config_parse_file(path, &a) == 0, "parse 1");
    CHECK(nodus_v2_gen_config_parse_file(path, &b) == 0, "parse 2");
    OK();

    uint8_t ca[NODUS_V2_GEN_SRCCOMMIT_LEN];
    uint8_t cb[NODUS_V2_GEN_SRCCOMMIT_LEN];
    uint8_t cr[NODUS_V2_GEN_SRCCOMMIT_LEN];
    CHECK(nodus_witness_v2_gen_source_commit(a, ca) == 0, "commit 1");
    CHECK(nodus_witness_v2_gen_source_commit(b, cb) == 0, "commit 2");
    CHECK(nodus_witness_v2_gen_source_commit(ref.cfg, cr) == 0,
          "commit of the in-memory reference");
    OK();

    CHECK(memcmp(ca, cb, sizeof(ca)) == 0,
          "two parses of one file produce the SAME source_commit — the "
          "determinism twin for D-I5");
    /* The stronger claim: the TEXT form is a faithful carrier. If the
     * parser dropped, defaulted or re-ordered anything that reaches the
     * canonical encoding, this would differ from the struct that was
     * serialised — and a different source_commit is a different chain
     * id, which is a fleet that cannot join itself. */
    CHECK(memcmp(ca, cr, sizeof(ca)) == 0,
          "the parsed config commits to the SAME digest as the struct it "
          "was serialised from");

    nodus_v2_gen_config_free(a);
    nodus_v2_gen_config_free(b);
    free(text);
    cfg_free(&ref);
    rmrf(dir);
    OK();
    printf("  ok: parse is a pure function of the file bytes\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §3 — the refusals
 * ══════════════════════════════════════════════════════════════════ */

static int test_refusals(void) {
    printf("§3 every malformed config is REFUSED, never repaired\n");

    cfgbox_t ref;
    CHECK(cfg_make(&ref, 0) == 0, "reference config");
    OK();
    char dir[128];
    CHECK(mkdir_tmp(dir, "refuse") == 0, "tmpdir");
    OK();
    char *g = golden_text(ref.cfg);
    CHECK(g != NULL, "serialise");
    OK();

    /* Every needle and every replacement is built from the SAME compiled
     * constant the golden file was written with. A hardcoded "720" would
     * silently stop matching under -DDNAC_EPOCH_LENGTH=<n>, and
     * expect_refusal would then fail on its missing-needle CHECK rather
     * than quietly passing — but building them is cheaper than relying
     * on that. */
    char epoch_line[64], supply_line[80], amount_line[80];
    snprintf(epoch_line, sizeof(epoch_line), "epoch_length = %llu\n",
             (unsigned long long)DNAC_EPOCH_LENGTH);
    snprintf(supply_line, sizeof(supply_line),
             "total_supply_raw = %llu\n",
             (unsigned long long)DNAC_DEFAULT_TOTAL_SUPPLY);
    snprintf(amount_line, sizeof(amount_line), "amount = %llu\n",
             (unsigned long long)TREASURY_RAW);

    /* DUPLICATE KEY. Appending a SECOND identical line means the value
     * is not in dispute — only the repetition is. A parser that resolved
     * duplicates by first-wins or last-wins would produce a struct here
     * and would be a parser another build could disagree with. */
    {
        char dup[160];
        snprintf(dup, sizeof(dup), "%s%s", epoch_line, epoch_line);
        expect_refusal(dir, g, epoch_line, dup,
                       "a duplicate key REFUSES");
    }

    /* UNKNOWN KEY. A one-character typo. Without the rule the struct
     * keeps calloc's zero in epoch_length and the builder then refuses
     * for the WRONG reason ("epoch_length 0 != 720"), pointing the
     * operator at the wrong line. */
    {
        char typo[64];
        snprintf(typo, sizeof(typo), "epoch_lenght = %llu\n",
                 (unsigned long long)DNAC_EPOCH_LENGTH);
        expect_refusal(dir, g, epoch_line, typo,
                       "an unknown key REFUSES");
    }

    /* MISSING REQUIRED KEY — the top-level section, decided at the first
     * [validator] header. */
    expect_refusal(dir, g, epoch_line, "",
                   "a missing required top-level key REFUSES");

    /* A TOP-LEVEL KEY INSIDE A BLOCK is an unknown key in that block,
     * not a reopened top-level scope. The line is ADDED inside the first
     * [validator] block and deliberately LEFT in place at the top, so
     * the top-level section is still complete and the refusal cannot
     * come from the missing-key rule instead. A parser that silently
     * reopened the top-level scope would accept this file — which is
     * exactly the "meaning depends on where the reader thinks a block
     * ends" ambiguity. */
    {
        char moved[256];
        snprintf(moved, sizeof(moved), "[validator]\n%s", epoch_line);
        expect_refusal(dir, g, "[validator]\n", moved,
                       "a top-level key inside a [validator] block "
                       "REFUSES");
    }

    /* INTEGER OUT OF RANGE — 2^64, one past the type. A clamp here would
     * silently change the committed supply; the whole point of the rule
     * is that there is no value to clamp TO. */
    expect_refusal(dir, g, supply_line,
                   "total_supply_raw = 18446744073709551616\n",
                   "an out-of-range integer REFUSES (never clamps)");

    /* INTEGER WITH TRAILING GARBAGE. strtoull would accept this and
     * report the leading digits with an endptr nobody checked. */
    {
        char garb[96];
        snprintf(garb, sizeof(garb), "total_supply_raw = %llux\n",
                 (unsigned long long)DNAC_DEFAULT_TOTAL_SUPPLY);
        expect_refusal(dir, g, supply_line, garb,
                       "an integer with trailing garbage REFUSES");
    }

    /* A SIGN is not a number here. strtoull accepts "+1" and even
     * wraps "-1" to UINT64_MAX. */
    {
        char signed_line[64];
        snprintf(signed_line, sizeof(signed_line), "epoch_length = +%llu\n",
                 (unsigned long long)DNAC_EPOCH_LENGTH);
        expect_refusal(dir, g, epoch_line, signed_line,
                       "a signed integer REFUSES");
    }

    /* UPPERCASE HEX. Accepted by a naive isxdigit check; refused here
     * because the graduation predicate downstream
     * (nodus_witness_v2_epoch.c:93-99) accepts lowercase only, so a
     * config that got this far would derive a chain that HALTS at its
     * first retirement. Mutating dest_binding (not the fingerprint)
     * proves the rule is charset-wide and not a fingerprint special
     * case. */
    {
        char *at = strstr(g, "dest_binding = ");
        CHECK(at != NULL, "dest_binding present");
        if (at) {
            /* "dest_binding = " is 15 bytes, the value 128 → 143. */
            char needle[160], repl[160];
            snprintf(needle, sizeof(needle), "%.143s", at);
            snprintf(repl, sizeof(repl), "%s", needle);
            repl[strlen("dest_binding = ")] = 'A';
            expect_refusal(dir, g, needle, repl,
                           "an UPPERCASE hex character REFUSES");
        }
    }

    /* SHORT HEX and LONG HEX — the length is exact, and neither
     * direction is repaired. A short pubkey that was zero-extended and a
     * long one that was truncated are both a DIFFERENT validator, hence
     * a different chain, reported as success. */
    {
        char short_pk[2 * DNAC_PUBKEY_SIZE + 32];
        char long_pk[2 * DNAC_PUBKEY_SIZE + 32];
        char full_pk[2 * DNAC_PUBKEY_SIZE + 32];
        char hex[2 * DNAC_PUBKEY_SIZE + 1];
        bin2hex(ref.cfg->validators[0].pubkey, DNAC_PUBKEY_SIZE, hex);
        snprintf(full_pk,  sizeof(full_pk),  "pubkey = %s\n", hex);
        snprintf(long_pk,  sizeof(long_pk),  "pubkey = %s0\n", hex);
        hex[2 * DNAC_PUBKEY_SIZE - 1] = 0;
        snprintf(short_pk, sizeof(short_pk), "pubkey = %s\n", hex);
        expect_refusal(dir, g, full_pk, short_pk,
                       "a SHORT hex field REFUSES");
        expect_refusal(dir, g, full_pk, long_pk,
                       "a LONG hex field REFUSES");
    }

    /* AN OVER-LONG LINE. Constructed so that it would parse PERFECTLY
     * if the length bound were removed — the padding is trailing
     * whitespace the trimmer would discard — so this case can only pass
     * for the reason its name gives. */
    {
        size_t pad = 8300;
        char *ov = malloc(pad + 128);
        CHECK(ov != NULL, "alloc");
        if (ov) {
            int w = snprintf(ov, pad + 128, "epoch_length = %llu",
                             (unsigned long long)DNAC_EPOCH_LENGTH);
            memset(ov + w, ' ', pad);
            ov[w + (int)pad] = '\n';
            ov[w + (int)pad + 1] = 0;
            expect_refusal(dir, g, epoch_line, ov,
                           "an over-long line REFUSES (never truncates)");
            free(ov);
        }
    }

    /* A CARRIAGE RETURN. Not normalised: normalisation is a
     * transformation of the operator's bytes, and this parser performs
     * none. Only the line ending changes — the value is untouched — so
     * the case isolates the CR rule. */
    {
        char crlf[64];
        snprintf(crlf, sizeof(crlf), "epoch_length = %llu\r\n",
                 (unsigned long long)DNAC_EPOCH_LENGTH);
        expect_refusal(dir, g, epoch_line, crlf,
                       "a CRLF line ending REFUSES");
    }

    /* AN [allocation] BLOCK MISSING A KEY — decided at EOF, since the
     * allocation block is the last one in the file. */
    expect_refusal(dir, g, amount_line, "",
                   "an incomplete [allocation] block REFUSES");

    /* NAMING A FORCED CONSTANT. It is an unknown key, which is how the
     * operator learns it is not a knob — rather than setting it to the
     * one legal value and being told nothing. Note this ALSO removes
     * epoch_length, so the missing-key rule would refuse it too; the
     * uniqueness this case claims is only that naming the constant is
     * not ACCEPTED, and the comment says so rather than overstating. */
    expect_refusal(dir, g, epoch_line, "claim_start_height = 0\n",
                   "naming claim_start_height REFUSES (it is not settable)");

    /* AN EMPTY VALUE is refused, not read as zero. */
    expect_refusal(dir, g, epoch_line, "epoch_length =\n",
                   "an empty value REFUSES");

    /* AN UNKNOWN BLOCK HEADER. */
    expect_refusal(dir, g, "[allocation]\n", "[allocations]\n",
                   "an unknown block header REFUSES");

    free(g);
    cfg_free(&ref);
    rmrf(dir);
    OK();
    printf("  ok: every malformed config is refused\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §4 — D7 / G7: the payout fingerprint must derive from the payout key
 * ══════════════════════════════════════════════════════════════════ */

static int test_payout_fp_derivation(void) {
    printf("§4 D7 — unstake_destination_fp must derive from "
           "unstake_destination_pubkey\n");

    cfgbox_t ref;
    CHECK(cfg_make(&ref, 0) == 0, "reference config");
    OK();

    /* The ACCEPT half. Without it this section could pass while refusing
     * everything, which proves nothing. */
    CHECK(nodus_witness_v2_gen_config_validate(ref.cfg) == 0,
          "a fingerprint that DOES derive from the payout key is accepted");

    /* The REFUSE half. The wrong fingerprint is deliberately
     * WELL-SHAPED — 128 lowercase hex, NUL at index 128 — because it is
     * SHA3-512 of a different key (the validator's OWN signing pubkey
     * rather than its payout pubkey). Garbage bytes here would be caught
     * by nodus_witness_v2_epoch_val_rec_ok and the case would pass on
     * the parent build without proving anything.
     *
     * The cost of the miss this kills: retirement releases the locked
     * self-bond to the FINGERPRINT alone (nodus_witness_v2_epoch.c:397),
     * so a transcription error strands DNAC_SELF_STAKE_AMOUNT
     * permanently, per validator, with no on-chain recovery. */
    {
        cfgbox_t bad;
        CHECK(cfg_make(&bad, 0) == 0, "config");
        OK();
        hex_lower_fp(bad.cfg->validators[3].pubkey, DNAC_PUBKEY_SIZE,
                     bad.cfg->validators[3].unstake_destination_fp);

        /* State the premise rather than assuming it: the mutant must
         * still pass the SHAPE predicate, or this test is measuring the
         * shape rule a second time. */
        int lowercase_hex = 1;
        for (size_t i = 0; i < 128; i++) {
            uint8_t ch = bad.cfg->validators[3].unstake_destination_fp[i];
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
                lowercase_hex = 0;
        }
        CHECK(lowercase_hex &&
              bad.cfg->validators[3].unstake_destination_fp[128] == 0,
              "the wrong fingerprint is still WELL-SHAPED — so only the "
              "derivation rule can refuse it");

        CHECK(nodus_witness_v2_gen_config_validate(bad.cfg) != 0,
              "a well-shaped fingerprint that does NOT derive from the "
              "payout key REFUSES");
        cfg_free(&bad);
    }

    cfg_free(&ref);
    OK();
    printf("  ok: the payout fingerprint is bound to the payout key\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §5 + §6 — D4 idempotency and the D3 marker, over real derivations
 * ══════════════════════════════════════════════════════════════════ */

static int test_derive_idempotency_and_marker(void) {
    printf("§5/§6 D4 idempotency compares the chain; D3 lands the marker\n");

    cfgbox_t A, B;
    CHECK(cfg_make(&A, 0)  == 0, "config A");
    CHECK(cfg_make(&B, 50) == 0, "config B (validator[0] commission +50)");
    OK();

    /* B must be a DIFFERENT but equally derivable config, or §5 would be
     * measuring an ordinary validation failure. */
    CHECK(nodus_witness_v2_gen_config_validate(A.cfg) == 0, "A derivable");
    CHECK(nodus_witness_v2_gen_config_validate(B.cfg) == 0, "B derivable");
    {
        uint8_t ca[NODUS_V2_GEN_SRCCOMMIT_LEN];
        uint8_t cb[NODUS_V2_GEN_SRCCOMMIT_LEN];
        CHECK(nodus_witness_v2_gen_source_commit(A.cfg, ca) == 0, "commit A");
        CHECK(nodus_witness_v2_gen_source_commit(B.cfg, cb) == 0, "commit B");
        CHECK(memcmp(ca, cb, sizeof(ca)) != 0,
              "A and B commit to DIFFERENT digests");
    }
    OK();

    char dir[128];
    CHECK(mkdir_tmp(dir, "derive") == 0, "tmpdir");
    OK();

    uint8_t chain_a[32];
    memset(chain_a, 0, sizeof(chain_a));
    CHECK(nodus_witness_v2_gen_derive(dir, A.cfg, chain_a) == 0,
          "config A derives a chain");
    OK();

    /* ── §6 — DERIVATION MUST *NOT* ARM THE PARTIAL-WIPE GATE ────────
     *
     * This assertion is the inverse of what an earlier cut of this work
     * asserted, and the inversion is the point.
     *
     * That cut wrote the marker here, reasoning that a derived chain
     * should arm the gate the way a legacy genesis does. It was wrong.
     * The marker does not mean "a chain exists" — it means "this node
     * has completed a normal boot with a chain", because the gate it
     * arms (nodus_server_check_partial_wipe) demands that nodus.db,
     * channels.db and witness_*.db be all-present or all-absent. The
     * builder creates exactly ONE of those three, and the gate runs
     * BEFORE nodus_server_init creates the other two. A marker written
     * here therefore fails the gate on the very next start of a freshly
     * provisioned host — and the refusal's printed remedy is to delete
     * all three databases, i.e. the chain just derived.
     *
     * The write now lives on the success path of nodus_server_init,
     * after all three databases are open. So: after a derivation and
     * before any server has run, the marker MUST be absent.
     *
     * ⚠ WHAT THIS TEST DOES NOT COVER, stated so nobody reads a green
     * run as more than it is: the server-side write itself. Reaching it
     * needs nodus_server_init, which binds sockets and is out of scope
     * for this suite. The gate's own behaviour is covered separately by
     * test_server_partial_wipe_xor; the WRITE is covered by neither.
     * That is uncovered ground, not passing ground. */
    {
        char marker[256], scratch[256];
        snprintf(marker,  sizeof(marker),  "%s/%s", dir,
                 NODUS_PARTIAL_WIPE_GENESIS_MARKER);
        snprintf(scratch, sizeof(scratch), "%s/v2gen.tmp", dir);
        CHECK(!path_exists(marker),
              "derivation does NOT write the partial-wipe marker — the "
              "other two databases do not exist yet, so arming the gate "
              "here would refuse the next start");
        CHECK(!path_exists(scratch),
              "the scratch directory is gone");
    }

    /* ── §5 D4 / G4 — a DIFFERENT config must not report success ────
     * On the parent build this returns 0 and leaves A's chain in place,
     * which is the whole defect: the operator edits the config, re-runs,
     * is told "nothing to derive", and ships a fleet configured against
     * a chain id that no longer matches anything. */
    CHECK(nodus_witness_v2_gen_derive(dir, B.cfg, NULL) != 0,
          "re-deriving with a DIFFERENT config REFUSES");

    /* And the refusal changed nothing: A's chain is still the one here,
     * so the fail-closed promise holds at the directory level too. */
    CHECK(nodus_witness_v2_gen_derive(dir, A.cfg, NULL) == 0,
          "re-deriving with the SAME config is the idempotent success it "
          "claims to be");

    cfg_free(&A);
    cfg_free(&B);
    rmrf(dir);
    OK();
    printf("  ok: idempotency compares the chain, and the marker lands\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §7 — D8: a node holding a V2 chain must not be told it has none
 *
 * The production sequence, in order, with nothing stubbed: derive a real
 * chain, then RESTART on it — nodus_witness_scan_chain_db, which is the
 * same function nodus_witness_init calls at nodus_witness.c:1380 — and
 * then run nodus_witness_bootstrap_start, which init calls at :1443.
 * Deliberately NOT nodus_witness_create_chain_db: that path writes
 * bootstrap_state = DONE itself (nodus_witness.c:1163) and would hand
 * this test its own answer.
 * ══════════════════════════════════════════════════════════════════ */

static int test_bootstrap_start_on_a_v2_chain(void) {
    printf("§7 D8 a restart on a derived V2 chain reaches DONE\n");

    cfgbox_t A;
    CHECK(cfg_make(&A, 0) == 0, "config A");
    OK();

    char dir[128];
    CHECK(mkdir_tmp(dir, "bootstrap") == 0, "tmpdir");
    OK();

    /* out_chain32 is optional and not asserted here — the chain id is
     * §1-§2's subject; this section only needs the chain to exist. */
    CHECK(nodus_witness_v2_gen_derive(dir, A.cfg, NULL) == 0,
          "a real V2 chain is derived into the data directory");
    cfg_free(&A);
    OK();

    /* Multi-MB struct — heap, the same way test_v2_gen.c:299 and
     * test_v2_restart_gate.c:129 build theirs. UINT64_MAX is not
     * cosmetic: a calloc'd handle carries cached_committee_epoch_start
     * == 0, which the committee cache reads as a VALID hit for epoch 0
     * with count 0 (nodus_witness_committee.c:512-529). The witness
     * itself installs UINT64_MAX for exactly this reason
     * (nodus_witness.c:1287; the hazard is spelt out at
     * nodus_witness_v2_gen.c:1361), and without it the refresh inside
     * the HAVE_CHAIN branch would take a fabricated cache hit instead of
     * reading the epoch-0 snapshot the derivation seeded. */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL, "witness alloc");
    OK();
    w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    /* w->server stays NULL — a bootstrap_start that needed a server on
     * this path would fault here rather than pass quietly. */

    CHECK(nodus_witness_scan_chain_db(w) == 0,
          "the derived chain reopens through the RESTART path");
    CHECK(w->db != NULL, "the restart leaves an open handle");
    CHECK(w->v2_successor,
          "production's OWN role derivation calls it a pure V2 successor "
          "— ASSERTED, never assigned: a scan that stopped recognising "
          "the chain must fail here, not route the rest of this test "
          "through the V1 path and report green");
    OK();

    /* ── The two facts that make a HEIGHT test unusable as the
     * discriminator. Both are the reason the branch keys on
     * w->v2_successor instead. */
    {
        uint64_t v2_tip = UINT64_MAX;
        CHECK(nodus_witness_v2_tip_height(w, &v2_tip) == 0 && v2_tip == 0,
              "V2 genesis sits at global_height 0, so the V2 tip of a "
              "freshly derived chain is 0 — a tip test cannot tell it "
              "from an empty table");

        sqlite3_stmt *st = NULL;
        int prc = sqlite3_prepare_v2(
            w->db, "SELECT COALESCE(MAX(height), 0) FROM blocks",
            -1, &st, NULL);
        CHECK(prc == SQLITE_OK,
              "the legacy `blocks` table EXISTS on a derived V2 chain — "
              "every open applies the full base schema "
              "(nodus_witness.c:63, exec at :516) — so chain_tip_height "
              "does not fault into the tip<0 refusal");
        if (prc == SQLITE_OK) {
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_int64(st, 0) == 0,
                  "and what it answers is 0: the confident wrong answer "
                  "that used to send this node into legacy DISCOVER");
            sqlite3_finalize(st);
        }
    }

    CHECK(w->bootstrap_state == (int)NODUS_W_BOOTSTRAP_INIT,
          "the restart path leaves bootstrap_state at INIT — only "
          "nodus_witness_create_chain_db writes DONE (:1163) — so a DONE "
          "below can only have come from bootstrap_start itself");
    OK();

    CHECK(nodus_witness_bootstrap_start(w) == 0,
          "bootstrap_start accepts a node that holds a V2 chain");
    CHECK(w->bootstrap_state == (int)NODUS_W_BOOTSTRAP_DONE,
          "and it ends at DONE. Asserting merely != DISCOVER would be "
          "vacuous: INIT satisfies that, and INIT is where it started");
    CHECK(w->bootstrap_settle_until_ms > 0,
          "the H-4 settle window was armed, so the HAVE_CHAIN branch ran "
          "in full — refresh included — rather than being short-circuited");

    if (w->db) { sqlite3_close(w->db); w->db = NULL; }
    free(w);
    rmrf(dir);
    OK();
    printf("  ok: a V2 chain is recognised as a chain\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== test_v2_gen_config — the V2 genesis config text form ===\n");
    if (test_golden_roundtrip()) goto fail;
    if (test_determinism_twin()) goto fail;
    if (test_refusals()) goto fail;
    if (test_payout_fp_derivation()) goto fail;
    if (test_derive_idempotency_and_marker()) goto fail;
    if (test_bootstrap_start_on_a_v2_chain()) goto fail;
    if (g_fail) goto fail;
    printf("=== PASS (%d checks) ===\n", g_checks);
    return 0;
fail:
    printf("=== FAIL (%d checks) ===\n", g_checks);
    return 1;
}
