/**
 * @file test_transcript_air.c
 * @brief P2a-i2 — transcript control-AIR construction gate (TDD).
 *
 * Design contract: dnac/docs/plans/2026-07-28-p2a-transcript-in-air-design.md
 * v2 §0.5 "The state machine — CONSTRAINT FORMS".
 *
 * (accept) For each of the 8 `dump-transcript-trace` oracle scenarios: replay
 *   the op script through the SHIPPED native challenger (`duplex_challenger.c`,
 *   itself byte-matched to Plonky3), build the honest control-AIR trace from
 *   the per-row snapshots, and require
 *     - every row: dnac_transcript_air_eval_trace == 0 violations,
 *     - every op row: the native post-state == the vector's `state`/`input`/
 *       `output` fields (the replay is pinned to the ORACLE, not to itself),
 *     - every duplexing row: the embedded poseidon2 block's output columns ==
 *       the vector's `duplexings[duplex_index]` entry,
 *     - the final state == the vector's `final_state`.
 *
 * (reject) 20 negatives, at least one per §0.5 "MUST": absorb mislabelled as
 *   squeeze, length tag skipped, rate clear skipped, DS-prefix limb tampered,
 *   sample injected mid-prefix, op after filler, il_flag double-bit, selector
 *   double-bit, poseidon2 block cell tamper, state-copy break, wrong-flag
 *   duplex (duplexing skipped at RATE), reset not applied, is_pow on a
 *   non-sampling row, instance boundary de-authorized, sel_sample with an empty
 *   output buffer, non-boolean bit, broken reconstruction, non-canonical
 *   (value + p) decomposition, the same alias with a lied is-zero witness, and
 *   a PoW row whose low bits are non-zero.
 *
 * Build (via Makefile):
 *   ./build/test_transcript_air tools/vectors/transcript_trace_*.json
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../duplex_challenger.h"
#include "../field_goldilocks.h"
#include "../poseidon2_air_trace.h"
#include "../transcript_air.h"

#define MAX_OPS   64
#define MAX_DUPS  32
#define MAX_ROWS  128
#define TRACE_ELEMS ((size_t)MAX_ROWS * TAIR_WIDTH)

/* Live shielded query-PoW pin (shielded_fri_params.h
 * DNAC_SHIELDED_FRI_QUERY_POW_BITS == 16). Used for scenarios that carry no
 * check_pow op; scenarios that do carry one use THEIR bits (the oracle's
 * pow_nonzero scenario grinds 8 bits). */
#define TAIR_TEST_DEFAULT_POW_BITS 16

static int fails = 0;

/* ══════════════════════════ JSON slurp/scan helpers ═══════════════════════
 * Same sequential-scan idiom as tests/test_duplex_challenger.c — the vectors
 * are emitted by the oracle in a fixed key order, so a forward scan is enough.
 */

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = '\0';
    return buf;
}

static bool find_key(const char *s, size_t *pos, const char *key) {
    const char *hit = strstr(s + *pos, key);
    if (!hit) return false;
    *pos = (size_t)(hit - s) + strlen(key);
    return true;
}

static bool read_quoted(const char *s, size_t *pos, char *out, size_t cap) {
    const char *q = strchr(s + *pos, '"');
    if (!q) return false;
    size_t p = (size_t)(q - s) + 1;
    const char *qe = strchr(s + p, '"');
    if (!qe) return false;
    size_t len = (size_t)(qe - s) - p;
    if (len >= cap) return false;
    memcpy(out, s + p, len);
    out[len] = '\0';
    *pos = (size_t)(qe - s) + 1;
    return true;
}

static bool read_quoted_u64(const char *s, size_t *pos, uint64_t *out) {
    char buf[32];
    if (!read_quoted(s, pos, buf, sizeof(buf))) return false;
    char *end = NULL;
    *out = strtoull(buf, &end, 10);
    return end && *end == '\0';
}

/* `[ "1", "2", ... ]` — quoted decimal u64s. */
static bool read_u64_array(const char *s, size_t *pos, uint64_t *out, size_t cap,
                           size_t *out_n) {
    const char *lb = strchr(s + *pos, '[');
    if (!lb) return false;
    size_t p = (size_t)(lb - s) + 1;
    size_t n = 0;
    for (;;) {
        while (isspace((unsigned char)s[p]) || s[p] == ',') p++;
        if (s[p] == ']') { p++; break; }
        if (s[p] != '"') return false;
        if (n >= cap) return false;
        size_t vp = p;
        if (!read_quoted_u64(s, &vp, &out[n])) return false;
        n++;
        p = vp;
    }
    *pos = p;
    *out_n = n;
    return true;
}

/* `[ 0, 8 ]` — bare decimal integers. */
static bool read_bare_array(const char *s, size_t *pos, uint64_t *out, size_t cap,
                            size_t *out_n) {
    const char *lb = strchr(s + *pos, '[');
    if (!lb) return false;
    size_t p = (size_t)(lb - s) + 1;
    size_t n = 0;
    for (;;) {
        while (isspace((unsigned char)s[p]) || s[p] == ',') p++;
        if (s[p] == ']') { p++; break; }
        if (!isdigit((unsigned char)s[p])) return false;
        if (n >= cap) return false;
        char *end = NULL;
        out[n++] = strtoull(s + p, &end, 10);
        if (!end) return false;
        p = (size_t)(end - s);
    }
    *pos = p;
    *out_n = n;
    return true;
}

/* `: 3` — a bare integer right after a key. */
static bool read_bare_u64(const char *s, size_t *pos, uint64_t *out) {
    size_t p = *pos;
    while (s[p] == ':' || isspace((unsigned char)s[p])) p++;
    if (!isdigit((unsigned char)s[p])) return false;
    char *end = NULL;
    *out = strtoull(s + p, &end, 10);
    if (!end) return false;
    *pos = (size_t)(end - s);
    return true;
}

/* `[ [ "..", x8 ], [ ... ] ]` — the top-level `duplexings` list. */
static bool read_dup_list(const char *s, size_t *pos,
                          uint64_t out[][TAIR_STATE_LANES], size_t cap,
                          size_t *out_n) {
    const char *lb = strchr(s + *pos, '[');
    if (!lb) return false;
    size_t p = (size_t)(lb - s) + 1;
    size_t n = 0;
    for (;;) {
        while (isspace((unsigned char)s[p]) || s[p] == ',') p++;
        if (s[p] == ']') { p++; break; }
        if (s[p] != '[') return false;
        if (n >= cap) return false;
        size_t m = 0, vp = p;
        if (!read_u64_array(s, &vp, out[n], TAIR_STATE_LANES, &m) ||
            m != TAIR_STATE_LANES)
            return false;
        n++;
        p = vp;
    }
    *pos = p;
    *out_n = n;
    return true;
}

/* ══════════════════════════════ vector model ════════════════════════════ */

typedef struct {
    char type[16];
    uint64_t lane, bits, out, witness, ok;
    uint64_t state[TAIR_STATE_LANES];
    uint64_t input[TAIR_RATE];
    size_t n_in;
    uint64_t output[TAIR_RATE];
    size_t n_out;
    uint64_t n_dup, dup_index;
} vec_op_t;

typedef struct {
    char scenario[64];
    uint64_t ds_prefix[TAIR_RATE];
    uint64_t starts[8];
    size_t n_starts;
    vec_op_t ops[MAX_OPS];
    size_t n_ops;
    uint64_t dups[MAX_DUPS][TAIR_STATE_LANES];
    size_t n_dups;
    uint64_t final_state[TAIR_STATE_LANES];
} vec_t;

static bool load_vector(const char *path, vec_t *V) {
    char *json = slurp(path);
    if (!json) { fprintf(stderr, "FAIL: cannot read %s\n", path); return false; }
    memset(V, 0, sizeof(*V));
    size_t pos = 0;
    bool ok = true;
    size_t n = 0;

    ok = ok && find_key(json, &pos, "\"scenario\"") &&
         read_quoted(json, &pos, V->scenario, sizeof(V->scenario));
    ok = ok && find_key(json, &pos, "\"ds_prefix\"") &&
         read_u64_array(json, &pos, V->ds_prefix, TAIR_RATE, &n) && n == TAIR_RATE;
    ok = ok && find_key(json, &pos, "\"instance_starts\"") &&
         read_bare_array(json, &pos, V->starts, 8, &V->n_starts) && V->n_starts >= 1;
    ok = ok && find_key(json, &pos, "\"ops\"");

    while (ok) {
        /* Stop when the next "type" key lies past the top-level "duplexings". */
        const char *nt = strstr(json + pos, "\"type\"");
        const char *nd = strstr(json + pos, "\"duplexings\"");
        if (!nt || (nd && nd < nt)) break;
        if (V->n_ops >= MAX_OPS) { ok = false; break; }
        vec_op_t *o = &V->ops[V->n_ops];
        uint64_t inst = 0;
        pos = (size_t)(nt - json) + strlen("\"type\"");
        ok = ok && read_quoted(json, &pos, o->type, sizeof(o->type)) &&
             find_key(json, &pos, "\"instance\"") && read_bare_u64(json, &pos, &inst) &&
             find_key(json, &pos, "\"lane\"") && read_quoted_u64(json, &pos, &o->lane) &&
             find_key(json, &pos, "\"bits\"") && read_quoted_u64(json, &pos, &o->bits) &&
             find_key(json, &pos, "\"out\"") && read_quoted_u64(json, &pos, &o->out) &&
             find_key(json, &pos, "\"witness\"") &&
             read_quoted_u64(json, &pos, &o->witness) &&
             find_key(json, &pos, "\"ok\"") && read_quoted_u64(json, &pos, &o->ok) &&
             find_key(json, &pos, "\"state\"") &&
             read_u64_array(json, &pos, o->state, TAIR_STATE_LANES, &n) &&
             n == TAIR_STATE_LANES && find_key(json, &pos, "\"input\"") &&
             read_u64_array(json, &pos, o->input, TAIR_RATE, &o->n_in) &&
             find_key(json, &pos, "\"output\"") &&
             read_u64_array(json, &pos, o->output, TAIR_RATE, &o->n_out) &&
             find_key(json, &pos, "\"duplexings\"") &&
             read_bare_u64(json, &pos, &o->n_dup) &&
             find_key(json, &pos, "\"duplex_index\"") &&
             read_bare_u64(json, &pos, &o->dup_index);
        if (ok) V->n_ops++;
    }

    ok = ok && find_key(json, &pos, "\"duplexings\"") &&
         read_dup_list(json, &pos, V->dups, MAX_DUPS, &V->n_dups);
    ok = ok && find_key(json, &pos, "\"final_state\"") &&
         read_u64_array(json, &pos, V->final_state, TAIR_STATE_LANES, &n) &&
         n == TAIR_STATE_LANES;

    free(json);
    if (!ok) fprintf(stderr, "FAIL: malformed vector %s\n", path);
    return ok;
}

/* ══════════════════════════ honest trace builder ═════════════════════════
 * TEST-SIDE by design (P2a-i2 ships no prover): the constraint file must not
 * be able to "help" the witness it checks.
 */

typedef struct {
    uint64_t *trace;
    size_t n_rows;
    int sel_of[MAX_ROWS];
    int dup_of[MAX_ROWS]; /* duplexing index, or -1 */
    int op_of[MAX_ROWS];  /* vector op index, or -1 */
} built_t;

static uint64_t *row_of(uint64_t *t, size_t r) { return t + r * (size_t)TAIR_WIDTH; }

static uint64_t fadd(uint64_t a, uint64_t b) {
    return gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(a), gold_fp_from_u64(b)));
}

/* Little-endian bit decomposition of `x` + the canonicality is-zero witness.
 * Mirrors the AIR's ADAPTATION of assert_bits_canonical (circuit_builder.rs:
 * 1123-1158): p-1 = [32 ones][32 zeros] for Goldilocks, so `isz` indicates
 * "every bit above the trailing-zero run is 1". */
static void write_bits(uint64_t *row, uint64_t x) {
    unsigned trailing = 0;
    const uint64_t c_max = GOLDILOCKS_P - 1u;
    while (((c_max >> trailing) & 1u) == 0u) trailing++;
    uint64_t hi_ones = 0;
    for (size_t i = 0; i < TAIR_BITS; i++) {
        const uint64_t b = (x >> i) & 1u;
        row[tair_bit_off(i)] = b;
        if (i >= trailing) hi_ones += b;
    }
    const uint64_t S = (uint64_t)(64u - trailing) - hi_ones;
    row[TAIR_CANON_ISZ_OFF] = (S == 0) ? 1u : 0u;
    row[TAIR_CANON_INV_OFF] =
        (S == 0) ? 0u : gold_fp_to_u64(gold_fp_inv(gold_fp_from_u64(S)));
}

/* Fill a row's threaded PRE-state columns from a challenger snapshot, plus a
 * VALID dummy permutation witness (the embedded block is evaluated ungated). */
static void write_pre(uint64_t *row, const dnac_duplex_t *c, unsigned prefix_ctr) {
    static const uint64_t z[TAIR_STATE_LANES] = {0};
    memset(row, 0, (size_t)TAIR_WIDTH * sizeof(uint64_t));
    for (size_t i = 0; i < TAIR_STATE_LANES; i++)
        row[tair_state_off(i)] = c->sponge_state[i];
    for (size_t j = 0; j < TAIR_RATE; j++) row[tair_inbuf_off(j)] = c->input_buffer[j];
    row[tair_il_off(c->input_len)] = 1;
    row[tair_ol_off(c->output_len)] = 1;
    row[tair_prefix_off(prefix_ctr)] = 1;
    poseidon2_air_generate_row(z, row + TAIR_PERM_OFF);
}

/* Regenerate the embedded block from whatever preimage its input columns hold
 * (used both by the honest builder and by the "regenerate after tamper"
 * negatives, so a tamper isolates the CONTROL pin rather than tripping the
 * poseidon2 constraints). */
static void regen_perm(uint64_t *row) {
    uint64_t pre[TAIR_STATE_LANES];
    for (size_t i = 0; i < TAIR_STATE_LANES; i++) pre[i] = row[tair_perm_in_off(i)];
    poseidon2_air_generate_row(pre, row + TAIR_PERM_OFF);
}

/* Preimage of the eager duplex inside the 4th observe (duplex_challenger.c:
 * 112-114 -> dc_duplexing :67-89 with num_absorbed == RATE: overwrite, clear
 * VACUOUS, capacity += 4). */
static void set_perm_obs_dup(uint64_t *row, const dnac_duplex_t *c, uint64_t lane) {
    for (size_t j = 0; j < TAIR_RATE - 1; j++)
        row[tair_perm_in_off(j)] = c->input_buffer[j];
    row[tair_perm_in_off(TAIR_RATE - 1)] = lane;
    row[tair_perm_in_off(TAIR_RATE)] =
        fadd(c->sponge_state[TAIR_RATE], (uint64_t)TAIR_RATE);
    for (size_t j = TAIR_RATE + 1; j < TAIR_STATE_LANES; j++)
        row[tair_perm_in_off(j)] = c->sponge_state[j];
    regen_perm(row);
}

/* Preimage of the duplex a sample triggers (duplex_challenger.c:127-129):
 *   absorb (input_len = k > 0): overwrite [0,k), CLEAR [k,RATE), capacity += k;
 *   squeeze (k == 0):           the state, untouched (the :74 guard). */
static void set_perm_sample_dup(uint64_t *row, const dnac_duplex_t *c) {
    const size_t k = c->input_len;
    for (size_t j = 0; j < TAIR_STATE_LANES; j++)
        row[tair_perm_in_off(j)] = c->sponge_state[j];
    if (k > 0) {
        for (size_t j = 0; j < k; j++) row[tair_perm_in_off(j)] = c->input_buffer[j];
        for (size_t j = k; j < TAIR_RATE; j++) row[tair_perm_in_off(j)] = 0;
        row[tair_perm_in_off(TAIR_RATE)] =
            fadd(c->sponge_state[TAIR_RATE], (uint64_t)k);
    }
    regen_perm(row);
}

static bool build_trace(const vec_t *V, built_t *B) {
    memset(B->sel_of, -1, sizeof(B->sel_of));
    memset(B->trace, 0, TRACE_ELEMS * sizeof(uint64_t));
    for (size_t i = 0; i < MAX_ROWS; i++) { B->dup_of[i] = -1; B->op_of[i] = -1; }

    dnac_duplex_t ch;
    dnac_duplex_init(&ch); /* row-0 pre-state: a legal don't-care */
    unsigned pc = 0;
    size_t r = 0, next_start = 0, dup_seen = 0;

    for (size_t i = 0; i < V->n_ops; i++) {
        const vec_op_t *o = &V->ops[i];
        /* The vector's own duplex bookkeeping is CHECKED, not trusted: our
         * running count must agree with `duplex_index` at op entry and with
         * `duplex_index + duplexings` at op exit. */
        if (dup_seen != o->dup_index) return false;

        /* Instance boundary: one sel_start row, then a fresh challenger. The
         * vector's constructor field pins per-instance
         * `DuplexChallenger::new` + the 4 DS observes, i.e. dnac_duplex_init
         * (NOT init_default — the prefix observes are explicit ops). */
        if (next_start < V->n_starts && V->starts[next_start] == (uint64_t)i) {
            if (r >= MAX_ROWS) return false;
            uint64_t *row = row_of(B->trace, r);
            write_pre(row, &ch, pc);
            row[tair_sel_off(TAIR_SEL_START)] = 1;
            B->sel_of[r] = TAIR_SEL_START;
            r++;
            dnac_duplex_init(&ch);
            pc = 0;
            next_start++;
        }

        const bool is_obs = strcmp(o->type, "observe") == 0;
        const bool is_smp = strcmp(o->type, "sample") == 0;
        const bool is_sbits = strcmp(o->type, "sample_bits") == 0;
        const bool is_pow = strcmp(o->type, "check_pow") == 0;
        if (!is_obs && !is_smp && !is_sbits && !is_pow) return false;

        /* check_pow with bits == 0 is a FULL no-op on both sides — no rows at
         * all (duplex_challenger.c:153-155 <-> circuit.rs:416-418). The oracle
         * cross-check below still runs, which is what pins "no state change". */
        const bool pow_noop = (is_pow && o->bits == 0);

        /* ── the observe half (plain observe, or check_pow's witness) ── */
        if (!pow_noop && (is_obs || is_pow)) {
            const uint64_t lane = is_pow ? o->witness : o->lane;
            if (r >= MAX_ROWS) return false;
            uint64_t *row = row_of(B->trace, r);
            write_pre(row, &ch, pc);
            row[TAIR_LANE_OFF] = lane;
            if (ch.input_len == TAIR_RATE - 1) {
                row[tair_sel_off(TAIR_SEL_OBS_DUP)] = 1;
                B->sel_of[r] = TAIR_SEL_OBS_DUP;
                B->dup_of[r] = (int)dup_seen++;
                set_perm_obs_dup(row, &ch, lane);
            } else {
                row[tair_sel_off(TAIR_SEL_OBS)] = 1;
                B->sel_of[r] = TAIR_SEL_OBS;
            }
            B->op_of[r] = (int)i;
            r++;
            dnac_duplex_observe_fp(&ch, gold_fp_from_u64(lane));
            if (pc < TAIR_RATE) pc++;
        }

        /* ── the sampling half ── */
        if (!pow_noop && (is_smp || is_sbits || is_pow)) {
            if (r >= MAX_ROWS) return false;
            uint64_t *row = row_of(B->trace, r);
            write_pre(row, &ch, pc);
            const bool duplexes = (ch.input_len > 0 || ch.output_len == 0);
            if (duplexes) {
                row[tair_sel_off(TAIR_SEL_SAMPLE_DUP)] = 1;
                B->sel_of[r] = TAIR_SEL_SAMPLE_DUP;
                B->dup_of[r] = (int)dup_seen++;
                set_perm_sample_dup(row, &ch);
            } else {
                row[tair_sel_off(TAIR_SEL_SAMPLE)] = 1;
                B->sel_of[r] = TAIR_SEL_SAMPLE;
            }
            /* sample_bits / check_pow are ONE base sample + a mask
             * (duplex_challenger.c:146-148); the AIR exposes all 64 bits and
             * the consumer reads the low `bits`. */
            const uint64_t lane = gold_fp_to_u64(dnac_duplex_sample_fp(&ch));
            if (lane != o->lane) return false; /* oracle pin on the challenge */
            row[TAIR_LANE_OFF] = lane;
            write_bits(row, lane);
            if (is_pow) row[TAIR_ISPOW_OFF] = 1;
            B->op_of[r] = (int)i;
            r++;
        }

        /* ── oracle cross-check: the native replay must match the vector ── */
        if (dup_seen != o->dup_index + o->n_dup) return false;
        for (size_t j = 0; j < TAIR_STATE_LANES; j++)
            if (ch.sponge_state[j] != o->state[j]) return false;
        if (ch.input_len != o->n_in || ch.output_len != o->n_out) return false;
        for (size_t j = 0; j < o->n_in; j++)
            if (ch.input_buffer[j] != o->input[j]) return false;
        for (size_t j = 0; j < o->n_out; j++)
            if (ch.output_buffer[j] != o->output[j]) return false;
    }

    /* Pad with fillers to the next power of two > r (the trace MUST end in a
     * filler: the last row's transition is not evaluated). */
    size_t target = 1;
    while (target < r + 1) target <<= 1;
    if (target > MAX_ROWS) return false;
    while (r < target) {
        uint64_t *row = row_of(B->trace, r);
        write_pre(row, &ch, pc);
        row[tair_sel_off(TAIR_SEL_FILLER)] = 1;
        B->sel_of[r] = TAIR_SEL_FILLER;
        r++;
    }
    B->n_rows = r;

    for (size_t j = 0; j < TAIR_STATE_LANES; j++)
        if (ch.sponge_state[j] != V->final_state[j]) return false;
    return true;
}

/* ═════════════════════════════ helpers/reporting ═════════════════════════ */

static size_t pow_bits_of(const vec_t *V) {
    for (size_t i = 0; i < V->n_ops; i++)
        if (strcmp(V->ops[i].type, "check_pow") == 0 && V->ops[i].bits > 0)
            return (size_t)V->ops[i].bits;
    return TAIR_TEST_DEFAULT_POW_BITS;
}

static int find_row(const built_t *B, int sel, size_t from) {
    for (size_t r = from; r < B->n_rows; r++)
        if (B->sel_of[r] == sel) return (int)r;
    return -1;
}

/* Keep a scenario's built trace + vector for the negative phase. */
static void stash(built_t *db, vec_t *dv, const built_t *sb, const vec_t *sv) {
    memcpy(db->trace, sb->trace, TRACE_ELEMS * sizeof(uint64_t));
    memcpy(db->sel_of, sb->sel_of, sizeof(db->sel_of));
    memcpy(db->dup_of, sb->dup_of, sizeof(db->dup_of));
    memcpy(db->op_of, sb->op_of, sizeof(db->op_of));
    db->n_rows = sb->n_rows;
    memcpy(dv, sv, sizeof(*dv));
}

static uint64_t *clone_trace(const built_t *B) {
    uint64_t *t = (uint64_t *)malloc(TRACE_ELEMS * sizeof(uint64_t));
    if (t) memcpy(t, B->trace, TRACE_ELEMS * sizeof(uint64_t));
    return t;
}

static void expect_reject(const char *name, const uint64_t *trace, size_t n_rows,
                          const dnac_tair_config_t *cfg) {
    const int v = dnac_transcript_air_eval_trace(trace, n_rows, cfg);
    if (v >= 1) printf("  [reject] %-48s caught (%d viol) — OK\n", name, v);
    else { printf("  [reject] %-48s NOT caught — FAIL\n", name); fails++; }
}

static void expect_reject_pair(const char *name, const uint64_t *local,
                               const uint64_t *next, const dnac_tair_config_t *cfg) {
    const int v = dnac_transcript_air_eval_row(local, next, 0, cfg);
    if (v >= 1) printf("  [reject] %-48s caught (%d viol) — OK\n", name, v);
    else { printf("  [reject] %-48s NOT caught — FAIL\n", name); fails++; }
}

/* A minimal (sel_sample -> sel_filler) pair whose popped challenge is exactly
 * `x`. Lets the bit gadget be probed at values the sponge would never emit —
 * in particular an x < 2^32 - 1, the only range where x and x + p are BOTH
 * 64-bit representations (the alias circuit_builder.rs:1103-1106 names). */
static void mk_sample_pair(uint64_t x, uint64_t *local, uint64_t *next) {
    static const uint64_t z[TAIR_STATE_LANES] = {0};
    memset(local, 0, (size_t)TAIR_WIDTH * sizeof(uint64_t));
    memset(next, 0, (size_t)TAIR_WIDTH * sizeof(uint64_t));
    poseidon2_air_generate_row(z, local + TAIR_PERM_OFF);
    poseidon2_air_generate_row(z, next + TAIR_PERM_OFF);

    local[tair_state_off(0)] = x;
    local[tair_il_off(0)] = 1;
    local[tair_ol_off(1)] = 1;
    local[tair_prefix_off(TAIR_RATE)] = 1;
    local[tair_sel_off(TAIR_SEL_SAMPLE)] = 1;
    local[TAIR_LANE_OFF] = x;
    write_bits(local, x);

    next[tair_state_off(0)] = x;
    next[tair_il_off(0)] = 1;
    next[tair_ol_off(0)] = 1;
    next[tair_prefix_off(TAIR_RATE)] = 1;
    next[tair_sel_off(TAIR_SEL_FILLER)] = 1;
}

/* ═════════════════════════════════ main ══════════════════════════════════ */

int main(int argc, char **argv) {
    if (argc < 9) {
        fprintf(stderr,
                "usage: %s <transcript_trace_*.json x8>\n"
                "  (the 8 dump-transcript-trace scenarios)\n",
                argv[0]);
        return 2;
    }

    printf("============================================================\n");
    printf("P2a-i2 transcript control-AIR — WIDTH=%d (%d control + %d perm)\n",
           TAIR_WIDTH, TAIR_PERM_OFF, P2AIR_NUM_COLS);
    printf("============================================================\n");

    /* ── Gate 0: layout binding contract ── */
    if (dnac_transcript_air_layout_check())
        printf("  [accept] column-layout binding contract           OK\n");
    else { printf("  [accept] column-layout binding contract           FAIL\n"); fails++; }

    /* ── Gate 0b: fail-close config ── */
    {
        dnac_tair_config_t bad = {(size_t)TAIR_MAX_NUM_BITS + 1};
        uint64_t *dummy = (uint64_t *)calloc((size_t)TAIR_WIDTH, sizeof(uint64_t));
        if (!dummy) return 2;
        const int v = dnac_transcript_air_eval_row(dummy, NULL, 0, &bad);
        if (v == TAIR_VIOL_BAD_CONFIG)
            printf("  [accept] pow_bits > %d fails closed                OK\n",
                   TAIR_MAX_NUM_BITS);
        else { printf("  [accept] pow_bits > %d fails closed                FAIL\n",
                      TAIR_MAX_NUM_BITS); fails++; }
        free(dummy);
    }

    /* nodus/messenger fixture rule: multi-KB fixtures are heap-allocated. */
    built_t *B = (built_t *)calloc(1, sizeof(built_t));
    built_t *B_basic = (built_t *)calloc(1, sizeof(built_t));
    built_t *B_multi = (built_t *)calloc(1, sizeof(built_t));
    built_t *B_squeeze = (built_t *)calloc(1, sizeof(built_t));
    vec_t *V = (vec_t *)calloc(1, sizeof(vec_t));
    vec_t *V_basic = (vec_t *)calloc(1, sizeof(vec_t));
    vec_t *V_multi = (vec_t *)calloc(1, sizeof(vec_t));
    vec_t *V_squeeze = (vec_t *)calloc(1, sizeof(vec_t));
    if (!B || !B_basic || !B_multi || !B_squeeze || !V || !V_basic || !V_multi ||
        !V_squeeze)
        return 2;
    B->trace = (uint64_t *)calloc(TRACE_ELEMS, sizeof(uint64_t));
    B_basic->trace = (uint64_t *)calloc(TRACE_ELEMS, sizeof(uint64_t));
    B_multi->trace = (uint64_t *)calloc(TRACE_ELEMS, sizeof(uint64_t));
    B_squeeze->trace = (uint64_t *)calloc(TRACE_ELEMS, sizeof(uint64_t));
    if (!B->trace || !B_basic->trace || !B_multi->trace || !B_squeeze->trace) return 2;

    /* ══ PHASE 1 — POSITIVE: all 8 oracle scenarios ══ */
    printf("------------------------------------------------------------\n");
    printf("Phase 1 — honest traces (8 oracle scenarios)\n");
    printf("------------------------------------------------------------\n");
    int scenarios = 0;
    for (int a = 1; a < argc; a++) {
        if (!load_vector(argv[a], V)) { fails++; continue; }
        const dnac_tair_config_t cfg = {pow_bits_of(V)};

        /* Vector's own DS prefix must be the pinned constant (the AIR pins the
         * same limbs; a drift here would silently move every challenge). */
        for (size_t i = 0; i < TAIR_RATE; i++) {
            if (V->ds_prefix[i] != DNAC_DUPLEX_DS_PREFIX[i]) {
                printf("  [accept] %-20s ds_prefix[%zu]              FAIL\n",
                       V->scenario, i);
                fails++;
            }
        }

        if (!build_trace(V, B)) {
            printf("  [accept] %-20s honest trace build          FAIL\n", V->scenario);
            fails++;
            continue;
        }

        const int viol = dnac_transcript_air_eval_trace(B->trace, B->n_rows, &cfg);
        int bad = (viol != 0);

        /* Duplexing rows: the embedded block's OUTPUT columns are the oracle's
         * post-permutation state, and they thread into the next row. */
        int dup_checked = 0;
        for (size_t r = 0; r < B->n_rows; r++) {
            if (B->dup_of[r] < 0) continue;
            if (B->dup_of[r] >= (int)V->n_dups || r + 1 >= B->n_rows) { bad = 1; continue; }
            const uint64_t *row = row_of(B->trace, r);
            const uint64_t *nxt = row_of(B->trace, r + 1);
            const uint64_t *want = V->dups[B->dup_of[r]];
            for (size_t i = 0; i < TAIR_STATE_LANES; i++) {
                if (row[tair_perm_out_off(i)] != want[i]) bad = 1;
                if (nxt[tair_state_off(i)] != want[i]) bad = 1;
            }
            dup_checked++;
        }
        if ((size_t)dup_checked != V->n_dups) bad = 1;

        /* Op rows: the row that CLOSES each op carries the oracle's post-op
         * state in the NEXT row's threaded state columns. */
        for (size_t i = 0; i < V->n_ops; i++) {
            int last = -1;
            for (size_t r = 0; r < B->n_rows; r++)
                if (B->op_of[r] == (int)i) last = (int)r;
            if (last < 0) continue; /* bits==0 check_pow emits no row */
            if ((size_t)last + 1 >= B->n_rows) { bad = 1; continue; }
            const uint64_t *nxt = row_of(B->trace, (size_t)last + 1);
            for (size_t j = 0; j < TAIR_STATE_LANES; j++)
                if (nxt[tair_state_off(j)] != V->ops[i].state[j]) bad = 1;
            /* sample_bits/check_pow: the exposed low bits are the oracle's
             * masked output (the AIR-exposed interface, design §0.5). */
            const vec_op_t *o = &V->ops[i];
            if (o->bits > 0 && strcmp(o->type, "observe") != 0) {
                uint64_t acc = 0;
                const uint64_t *row = row_of(B->trace, (size_t)last);
                for (size_t k = 0; k < (size_t)o->bits; k++)
                    acc |= row[tair_bit_off(k)] << k;
                if (acc != o->out) bad = 1;
                if (strcmp(o->type, "check_pow") == 0 && (acc != 0 || o->ok != 1)) bad = 1;
            }
        }

        if (!bad)
            printf("  [accept] %-20s %2zu rows, %2zu dup    0 viol — OK\n",
                   V->scenario, B->n_rows, V->n_dups);
        else {
            printf("  [accept] %-20s %2zu rows  %d viol / oracle mismatch — FAIL\n",
                   V->scenario, B->n_rows, viol);
            fails++;
        }
        scenarios++;

        if (strcmp(V->scenario, "basic") == 0) stash(B_basic, V_basic, B, V);
        if (strcmp(V->scenario, "multi_instance") == 0) stash(B_multi, V_multi, B, V);
        if (strcmp(V->scenario, "squeeze_chain") == 0) stash(B_squeeze, V_squeeze, B, V);
    }
    if (scenarios != 8) {
        printf("  [accept] expected 8 scenarios, replayed %d      FAIL\n", scenarios);
        fails++;
    }

    /* ══ PHASE 2 — NEGATIVE ══
     * `basic` is the workhorse trace: it carries an obs_dup row, an ABSORB
     * sample_dup (k = 2), plain sample rows, DS-prefix rows and fillers.
     */
    printf("------------------------------------------------------------\n");
    printf("Phase 2 — §0.5 constraint-form negatives\n");
    printf("------------------------------------------------------------\n");
    if (B_basic->n_rows == 0) {
        printf("  FAIL: the `basic` scenario was not among the vectors given\n");
        return 1;
    }
    built_t *const W = B_basic;
    const dnac_tair_config_t cfg = {pow_bits_of(V_basic)};
    if (dnac_transcript_air_eval_trace(W->trace, W->n_rows, &cfg) != 0) {
        printf("  FAIL: workhorse trace is not clean\n");
        return 1;
    }

    const int r_obsdup = find_row(W, TAIR_SEL_OBS_DUP, 0);
    const int r_smp = find_row(W, TAIR_SEL_SAMPLE, 0);
    const int r_fill = find_row(W, TAIR_SEL_FILLER, 0);
    int r_absorb = -1; /* sample_dup on the ABSORB branch (input_len = k > 0) */
    for (size_t r = 0; r < W->n_rows; r++) {
        if (W->sel_of[r] != TAIR_SEL_SAMPLE_DUP) continue;
        if (row_of(W->trace, r)[tair_il_off(0)] == 0) { r_absorb = (int)r; break; }
    }
    int r_prefix = -1; /* a DS-prefix observe row with prefix_ctr < 4 */
    for (size_t r = 0; r < W->n_rows; r++) {
        const uint64_t *row = row_of(W->trace, r);
        if (W->sel_of[r] != TAIR_SEL_OBS) continue;
        if (row[tair_prefix_off(TAIR_RATE)] == 0) { r_prefix = (int)r; break; }
    }
    if (r_obsdup < 0 || r_smp < 0 || r_fill < 0 || r_absorb < 0 || r_prefix < 0 ||
        (size_t)r_fill + 1 >= W->n_rows) {
        printf("  FAIL: workhorse trace lacks a needed row type "
               "(obsdup=%d smp=%d fill=%d absorb=%d prefix=%d)\n",
               r_obsdup, r_smp, r_fill, r_absorb, r_prefix);
        return 1;
    }

    /* N1 — an ABSORB relabelled as a SQUEEZE (the :74 guard bypass: no rate
     * clear, no length tag). The il_flag[0] branch condition is a threaded
     * column, so the claim is unsatisfiable (G-SEC-P2a-2). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_absorb);
        for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) row[tair_il_off(k)] = (k == 0);
        expect_reject("absorb relabelled as squeeze (guard :74)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N2 — length tag skipped (capacity lane loses the += k, :80-82). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_absorb);
        row[tair_perm_in_off(TAIR_RATE)] = row[tair_state_off(TAIR_RATE)];
        regen_perm(row);
        expect_reject("length tag skipped (capacity pin :80-82)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N3 — rate clear skipped (a slot the absorb did not overwrite keeps data,
     * the prefix-free padding break v0.6.2 closed, :76-78). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_absorb);
        row[tair_perm_in_off(TAIR_RATE - 1)] = 0xDEADBEEFu;
        regen_perm(row);
        expect_reject("rate clear skipped (:76-78)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N4 — DS-prefix limb tampered (G-SEC-P2a-3). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_prefix);
        row[TAIR_LANE_OFF] = fadd(row[TAIR_LANE_OFF], 1);
        expect_reject("DS-prefix limb tampered", t, W->n_rows, &cfg);
        free(t);
    }
    /* N5 — a sample injected before the prefix completes. */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_prefix);
        row[tair_sel_off(TAIR_SEL_OBS)] = 0;
        row[tair_sel_off(TAIR_SEL_SAMPLE)] = 1;
        expect_reject("sample injected mid-prefix", t, W->n_rows, &cfg);
        free(t);
    }
    /* N6 — an op AFTER padding started (filler terminality, F8). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_fill + 1);
        row[tair_sel_off(TAIR_SEL_FILLER)] = 0;
        row[tair_sel_off(TAIR_SEL_OBS)] = 1;
        expect_reject("op after filler (terminality)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N7 — il_flag one-hot broken (double bit). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_smp);
        row[tair_il_off(1)] = 1;
        expect_reject("il_flag double-bit (one-hot)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N8 — selector one-hot broken (double bit). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_smp);
        row[tair_sel_off(TAIR_SEL_FILLER)] = 1;
        expect_reject("selector double-bit (one-hot)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N9 — an interior cell of the embedded poseidon2 block (G-SEC-P2a-4:
     * soundness rests on the byte-matched block's own constraints). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_obsdup);
        const size_t off = (size_t)TAIR_PERM_OFF + p2air_beg_sbox_off(0, 0);
        row[off] = fadd(row[off], 1);
        expect_reject("poseidon2 block interior cell tamper", t, W->n_rows, &cfg);
        free(t);
    }
    /* N10 — state copy broken on a NON-duplexing row (F3 threading). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_smp + 1);
        row[tair_state_off(0)] = fadd(row[tair_state_off(0)], 1);
        expect_reject("state copy broken on a sample row", t, W->n_rows, &cfg);
        free(t);
    }
    /* N11 — wrong-flag duplex: an obs_dup relabelled as a plain observe, i.e.
     * a duplexing SKIPPED at the RATE boundary (F2 precondition). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_obsdup);
        row[tair_sel_off(TAIR_SEL_OBS_DUP)] = 0;
        row[tair_sel_off(TAIR_SEL_OBS)] = 1;
        expect_reject("duplexing skipped at RATE (wrong flag)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N12 — the reset a sel_start row forces is not applied. */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, 1); /* row 0 is sel_start */
        row[tair_state_off(0)] = fadd(row[tair_state_off(0)], 1);
        expect_reject("sel_start reset not applied", t, W->n_rows, &cfg);
        free(t);
    }
    /* N13 — is_pow on a NON-sampling row. */
    {
        uint64_t *t = clone_trace(W);
        row_of(t, (size_t)r_obsdup)[TAIR_ISPOW_OFF] = 1;
        expect_reject("is_pow on a non-sampling row", t, W->n_rows, &cfg);
        free(t);
    }

    /* ── i3 round: the forms the round-1 audit found DISCHARGED BUT UNTESTED
     * (each of these constraints could be deleted today without turning the
     * suite red — that is a regression hole, not a code defect), plus the one
     * real second witness the independent hunt constructed. ── */

    /* N20 (i3/A2-F1, the HIGH) — a trace that does NOT end in a filler. The
     * last row gets no transition constraints, so a terminal SAMPLING row's
     * popped challenge would be entirely free: relabel the final filler as a
     * sample and give it an attacker-chosen lane. Caught only by the
     * last-row-filler boundary in eval_trace. */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *last = row_of(t, W->n_rows - 1);
        last[tair_sel_off(TAIR_SEL_FILLER)] = 0;
        last[tair_sel_off(TAIR_SEL_SAMPLE)] = 1;
        last[TAIR_LANE_OFF] = 0x1234u;      /* free — not the sponge's value */
        write_bits(last, 0x1234u);
        expect_reject("trace ends in a sampling row (free challenge)", t,
                      W->n_rows, &cfg);
        free(t);
    }
    /* N20b — the SAME hole in its pure form, and the one that isolates the new
     * boundary: TRUNCATE the honest trace so it ends at a sampling row. No
     * filler exists anywhere after it, so filler-terminality cannot fire and
     * the last-row-filler boundary is the ONLY constraint left to reject it.
     * (Exactly the shape the independent second-witness hunt constructed.) */
    {
        uint64_t *t = clone_trace(W);
        expect_reject("truncated trace ending at a sample row", t,
                      (size_t)r_smp + 1, &cfg);
        free(t);
    }
    /* N21 (A2 §5.3 / transcript_air.c:151) — an op row entered at input_len ==
     * RATE. Unreachable natively (the 4th observe drains eagerly); without the
     * guard, sel_sample_dup at il[4] has NO absorb branch pinning its preimage,
     * so the rate lanes go free. */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_smp);
        for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) row[tair_il_off(k)] = (k == TAIR_RATE);
        expect_reject("op row at input_len == RATE (il[4] guard)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N22 (§5.4) — input_len JUMPS across a sample row (0 -> 2), the shape that
     * fabricates absorbed lanes for the next duplexing. */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *nxt = row_of(t, (size_t)r_smp + 1);
        for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) nxt[tair_il_off(k)] = (k == 2);
        expect_reject("input_len jumped across a sample row", t, W->n_rows, &cfg);
        free(t);
    }
    /* N23 (§5.4) — the input BUFFER mutated across a sample row (same class:
     * the lanes a later absorb reads must be the ones observes wrote). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *nxt = row_of(t, (size_t)r_smp + 1);
        nxt[tair_inbuf_off(0)] = fadd(nxt[tair_inbuf_off(0)], 1);
        expect_reject("input_buffer mutated across a sample row", t, W->n_rows, &cfg);
        free(t);
    }
    /* N24 (transcript_air.c:268) — an observe that does NOT invalidate the
     * output buffer (`duplex_challenger.c:108`): leaving output_len non-zero
     * would let a later sample pop a STALE lane. */
    {
        uint64_t *t = clone_trace(W);
        const int r_obs = find_row(W, TAIR_SEL_OBS, 0);
        if (r_obs < 0 || (size_t)r_obs + 1 >= W->n_rows) {
            printf("  [reject] plain observe row missing                 FAIL\n");
            fails++;
        } else {
            uint64_t *nxt = row_of(t, (size_t)r_obs + 1);
            for (size_t k = 0; k < TAIR_LEN_SLOTS; k++)
                nxt[tair_ol_off(k)] = (k == TAIR_RATE);
            expect_reject("observe did not invalidate the output buffer", t,
                          W->n_rows, &cfg);
        }
        free(t);
    }
    /* N25 (transcript_air.c:301-303) — the eager-duplex row's length tag: the
     * obs_dup twin of N2, which only covered the sample_dup tag. */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_obsdup);
        row[tair_perm_in_off(TAIR_RATE)] = row[tair_state_off(TAIR_RATE)];
        regen_perm(row);
        expect_reject("obs_dup length tag skipped (+4)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N26 (transcript_air.c:167) — trace row 0 is not a sel_start row. */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, 0);
        row[tair_sel_off(TAIR_SEL_START)] = 0;
        row[tair_sel_off(TAIR_SEL_FILLER)] = 1;
        expect_reject("row 0 is not sel_start (boundary)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N27 (transcript_air.c:251-253) — prefix_ctr JUMPED past DS limbs: an
     * observe advancing 0 -> 4 would skip three pinned prefix observes. */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *nxt = row_of(t, (size_t)r_prefix + 1);
        for (size_t k = 0; k < TAIR_PREFIX_SLOTS; k++)
            nxt[tair_prefix_off(k)] = (k == TAIR_RATE);
        expect_reject("prefix_ctr jumped (DS limbs skipped)", t, W->n_rows, &cfg);
        free(t);
    }
    /* N28 (transcript_air.c:339) — the popped challenge is not
     * sponge_state[output_len - 1] (the F10 output_buffer invariant). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_smp);
        row[TAIR_LANE_OFF] = fadd(row[TAIR_LANE_OFF], 1);
        write_bits(row, row[TAIR_LANE_OFF]);
        expect_reject("sample lane != state[output_len-1]", t, W->n_rows, &cfg);
        free(t);
    }

    /* ── multi-instance: a second instance started WITHOUT sel_start ── */
    if (B_multi->n_rows == 0) {
        printf("  [reject] multi_instance trace missing              FAIL\n");
        fails++;
    } else {
        const int r_start2 = find_row(B_multi, TAIR_SEL_START, 1);
        if (r_start2 < 0) {
            printf("  [reject] second sel_start row missing              FAIL\n");
            fails++;
        } else {
            const dnac_tair_config_t cfg_m = {pow_bits_of(V_multi)};
            /* N14 — de-authorize the boundary: relabel it as inert padding, so
             * the zeroed successor state is no longer a constrained reset. */
            uint64_t *t = clone_trace(B_multi);
            uint64_t *row = row_of(t, (size_t)r_start2);
            row[tair_sel_off(TAIR_SEL_START)] = 0;
            row[tair_sel_off(TAIR_SEL_FILLER)] = 1;
            expect_reject("instance 2 started without sel_start", t, B_multi->n_rows,
                          &cfg_m);
            free(t);
        }
    }

    /* ── squeeze_chain: sel_sample claimed while the output buffer is EMPTY ── */
    if (B_squeeze->n_rows == 0) {
        printf("  [reject] squeeze_chain trace missing               FAIL\n");
        fails++;
    } else {
        int r_squeeze = -1;
        for (size_t r = 0; r < B_squeeze->n_rows; r++) {
            if (B_squeeze->sel_of[r] != TAIR_SEL_SAMPLE_DUP) continue;
            const uint64_t *row = row_of(B_squeeze->trace, r);
            if (row[tair_il_off(0)] == 1 && row[tair_ol_off(0)] == 1) {
                r_squeeze = (int)r;
                break;
            }
        }
        if (r_squeeze < 0) {
            printf("  [reject] squeeze-branch row missing                FAIL\n");
            fails++;
        } else {
            /* N15 — the duplex a squeeze REQUIRES (:127-129) is skipped by
             * claiming a plain pop from an empty output buffer. */
            const dnac_tair_config_t cfg_s = {pow_bits_of(V_squeeze)};
            uint64_t *t = clone_trace(B_squeeze);
            uint64_t *row = row_of(t, (size_t)r_squeeze);
            row[tair_sel_off(TAIR_SEL_SAMPLE_DUP)] = 0;
            row[tair_sel_off(TAIR_SEL_SAMPLE)] = 1;
            expect_reject("sel_sample with output_len == 0", t, B_squeeze->n_rows,
                          &cfg_s);
            free(t);
        }
    }

    /* ── bit-decomposition gadget, probed on a synthetic pair ── */
    printf("------------------------------------------------------------\n");
    printf("Phase 3 — sample_bits decomposition (G-DET-P2a-4 / G-SEC-P2a-5)\n");
    printf("------------------------------------------------------------\n");
    {
        const dnac_tair_config_t cfg_b = {8};
        uint64_t *lo = (uint64_t *)calloc((size_t)TAIR_WIDTH, sizeof(uint64_t));
        uint64_t *nx = (uint64_t *)calloc((size_t)TAIR_WIDTH, sizeof(uint64_t));
        if (!lo || !nx) return 2;
        const uint64_t x = 0x1234u; /* < 2^32 - 1 => x + p is a second encoding */

        mk_sample_pair(x, lo, nx);
        {
            const int v = dnac_transcript_air_eval_row(lo, nx, 0, &cfg_b);
            if (v == 0) printf("  [accept] synthetic sample pair                    0 viol — OK\n");
            else { printf("  [accept] synthetic sample pair                    %d viol — FAIL\n", v); fails++; }
        }
        /* N16 — non-boolean bit. */
        mk_sample_pair(x, lo, nx);
        lo[tair_bit_off(5)] = 2;
        expect_reject_pair("non-boolean bit", lo, nx, &cfg_b);
        /* N17 — reconstruction broken (a boolean bit flipped). */
        mk_sample_pair(x, lo, nx);
        lo[tair_bit_off(3)] ^= 1u;
        expect_reject_pair("reconstruction broken (bit flipped)", lo, nx, &cfg_b);
        /* N18 — the NON-CANONICAL second encoding: bits of x + p. Reconstruction
         * still holds (x + p == x in the field); only the `< p` comparison can
         * reject it — the F-S index-shift attack circuit_builder.rs:1103-1106
         * names by hand. */
        mk_sample_pair(x, lo, nx);
        {
            const uint64_t alias = x + GOLDILOCKS_P; /* < 2^64 exactly because x is small */
            uint64_t hi_ones = 0;
            for (size_t i = 0; i < TAIR_BITS; i++) {
                const uint64_t b = (alias >> i) & 1u;
                lo[tair_bit_off(i)] = b;
                if (i >= 32) hi_ones += b;
            }
            const uint64_t S = 32u - hi_ones; /* == 0: every high bit is set */
            lo[TAIR_CANON_ISZ_OFF] = (S == 0);
            lo[TAIR_CANON_INV_OFF] =
                (S == 0) ? 0u : gold_fp_to_u64(gold_fp_inv(gold_fp_from_u64(S)));
            expect_reject_pair("non-canonical decomposition (x + p)", lo, nx, &cfg_b);
        }
        /* N18b — the same alias with a LIED is-zero witness (isz = 0 to dodge
         * the low-bits constraint): the is-zero gadget itself catches it. */
        mk_sample_pair(x, lo, nx);
        {
            const uint64_t alias = x + GOLDILOCKS_P;
            for (size_t i = 0; i < TAIR_BITS; i++)
                lo[tair_bit_off(i)] = (alias >> i) & 1u;
            lo[TAIR_CANON_ISZ_OFF] = 0;
            lo[TAIR_CANON_INV_OFF] = 0;
            expect_reject_pair("non-canonical + lied is-zero witness", lo, nx, &cfg_b);
        }
        /* N19 — PoW row whose exposed low `pow_bits` are NOT zero. */
        mk_sample_pair(x, lo, nx); /* x = 0x1234, low 8 bits = 0x34 != 0 */
        lo[TAIR_ISPOW_OFF] = 1;
        expect_reject_pair("PoW row with non-zero low bits", lo, nx, &cfg_b);
        /* and the honest PoW counterpart is accepted */
        mk_sample_pair(0x1200u, lo, nx); /* low 8 bits zero */
        lo[TAIR_ISPOW_OFF] = 1;
        {
            const int v = dnac_transcript_air_eval_row(lo, nx, 0, &cfg_b);
            if (v == 0) printf("  [accept] PoW row with zero low bits               0 viol — OK\n");
            else { printf("  [accept] PoW row with zero low bits               %d viol — FAIL\n", v); fails++; }
        }
        free(lo);
        free(nx);
    }

    free(B->trace); free(B_basic->trace); free(B_multi->trace); free(B_squeeze->trace);
    free(B); free(B_basic); free(B_multi); free(B_squeeze);
    free(V); free(V_basic); free(V_multi); free(V_squeeze);

    printf("------------------------------------------------------------\n");
    if (fails) { printf("P2a transcript AIR: %d FAIL\n", fails); return 1; }
    printf("P2a transcript AIR: 8 oracle scenarios accepted (state + duplexings\n"
           "  + exposed bits byte-matched) + 30 negatives rejected (25 trace-level\n"
           "  incl. the i3 round's 10, 5 synthetic bit-gadget) — PASS\n");
    return 0;
}
