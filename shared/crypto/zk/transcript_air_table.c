/**
 * @file transcript_air_table.c
 * @brief s3a — the transcript control-AIR's preprocessed op-schedule table:
 *        deterministic generator + static validator + the PIN-1-P2a comparator.
 *
 * See transcript_air_table.h for the full grounding contract (the challenger
 * simulation rules and their `duplex_challenger.c` lines, the four blocks of the
 * composed op order — DS prefix / batch-STARK priming / PCS claimed-eval
 * observes / FRI tail — with their `batch_priming.c`, `batch_verify.c` and
 * `fri_verifier.c` lines, the public-value layout, the PIN derivation and the
 * two composition obligations).
 *
 * Determinism: every function is a pure function of the SCRIPT scalars — fixed
 * -bound loops only, no allocation, no clock, no RNG, no iteration over anything
 * unordered. The simulation reads op KINDS only, never a field value.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "transcript_air_table.h"

#include <string.h>

#include "field_goldilocks.h" /* GOLDILOCKS_P */
#include "poseidon2_mmcs.h"   /* DNAC_P2M_DIGEST_LANES — the observe_digest cost */

/* The pinned reference cfg (transcript_air_table.h DNAC_P2A_REF_*): the inner
 * batch proof's shape, then the FRI-tail scalars. Both halves are the measured
 * shape of scenario `prep_pair` (tools/vectors/batch_proof.json) — see the
 * header. The two instances are identical at this pin; they are written out
 * rather than loop-filled so the array keeps static storage AND stays `const`,
 * which is what lets the accessor hand out a pointer with no initialisation
 * order to reason about (the P2S_MMIX_CFG practice, fri_statement.c:41-78). */
static const dnac_tair_inner_inst_t P2A_REF_INNER[DNAC_P2A_REF_INNER_N] = {
    { DNAC_P2A_REF_INNER_PUBLICS, DNAC_P2A_REF_INNER_MAIN_WIDTH,
      DNAC_P2A_REF_INNER_MAIN_NEXT, DNAC_P2A_REF_INNER_PREP_WIDTH,
      DNAC_P2A_REF_INNER_PREP_NEXT, DNAC_P2A_REF_INNER_NUM_QC,
      DNAC_P2A_REF_INNER_LOOKUPS },
    { DNAC_P2A_REF_INNER_PUBLICS, DNAC_P2A_REF_INNER_MAIN_WIDTH,
      DNAC_P2A_REF_INNER_MAIN_NEXT, DNAC_P2A_REF_INNER_PREP_WIDTH,
      DNAC_P2A_REF_INNER_PREP_NEXT, DNAC_P2A_REF_INNER_NUM_QC,
      DNAC_P2A_REF_INNER_LOOKUPS }
};

/* The pinned instance count is what the initializer above is written out for.
 * If it ever moves, this stops the build instead of silently leaving an
 * instance's shape zeroed (main_width 0, which the cfg gate rejects at runtime
 * — a reject, but one that names nothing). */
typedef char p2a_ref_inner_list_matches_n_assert
    [(DNAC_P2A_REF_INNER_N == 2) ? 1 : -1];

static const dnac_tair_full_cfg_t P2A_REF_FULL_CFG = {
    { P2A_REF_INNER, DNAC_P2A_REF_INNER_N, DNAC_P2A_REF_IS_ZK,
      DNAC_P2A_REF_NRC },
    { DNAC_P2A_REF_R,               DNAC_P2A_REF_LOG_FINAL_POLY_LEN,
      DNAC_P2A_REF_NUM_QUERIES,     DNAC_P2A_REF_LGMH,
      DNAC_P2A_REF_COMMIT_POW_BITS, DNAC_P2A_REF_QUERY_POW_BITS }
};

const dnac_tair_fri_cfg_t *dnac_tair_ref_fri_cfg(void)
{
    return &P2A_REF_FULL_CFG.fri;
}

const dnac_tair_full_cfg_t *dnac_tair_ref_full_cfg(void)
{
    return &P2A_REF_FULL_CFG;
}

/* ==========================================================================
 * Script gate — ONE place, so rows(), row(), generate() and validate() can
 * never disagree about what they accept. Returns 0 on reject.
 * ======================================================================== */
static int tair_script_check(const dnac_tair_script_t *s)
{
    if (s == NULL || s->ops == NULL || s->instance_starts == NULL) return 0;
    if (s->n_ops == 0 || s->n_ops > TAIR_TBL_MAX_STEPS) return 0;
    if (s->n_starts == 0 || s->n_starts > TAIR_TBL_MAX_STARTS) return 0;

    /* Trace row 0 MUST be a `sel_start` row — the AIR's own boundary constraint
     * (transcript_air.c:166-167), so the first start sits before op 0. */
    if (s->instance_starts[0] != 0) return 0;
    for (size_t j = 0; j < s->n_starts; j++) {
        if (s->instance_starts[j] >= s->n_ops) return 0;
        if (j > 0 && s->instance_starts[j] <= s->instance_starts[j - 1]) return 0;
    }

    for (size_t k = 0; k < s->n_ops; k++) {
        const dnac_tair_op_t *o = &s->ops[k];
        if (o->kind != DNAC_TAIR_OP_OBSERVE && o->kind != DNAC_TAIR_OP_SAMPLE) {
            return 0;
        }
        if (o->kind == DNAC_TAIR_OP_OBSERVE) {
            /* An observe carries no PoW modifier and exports no bits: the AIR's
             * `is_pow` is a modifier on a SAMPLING row only
             * (transcript_air.c:157) and the bit block is gated by `g_sampling`
             * (:180-187). */
            if (o->is_pow || o->pow_bits != 0 || o->num_bits != 0) return 0;
        } else {
            if (o->is_pow != 0 && o->is_pow != 1) return 0;
            if (!o->is_pow && o->pow_bits != 0) return 0;
            /* `check_witness(0)` emits NO ops at all (duplex_challenger.c:
             * 153-155), so an is_pow op with 0 bits could not have been produced
             * by the native path. */
            if (o->is_pow && (o->pow_bits == 0 ||
                              o->pow_bits > TAIR_TBL_MAX_OP_BITS)) {
                return 0;
            }
            if (o->num_bits > TAIR_TBL_MAX_OP_BITS) return 0;
        }
    }

    /* Total bits must not overflow the public block. The binding cap is the ROW
     * bound below, not TAIR_TBL_MAX_STEPS, so the real ceiling is 126 ops x 32
     * bits = 4032 — far from wrapping; kept fail-close. */
    size_t bits = 0;
    for (size_t k = 0; k < s->n_ops; k++) {
        if (s->ops[k].num_bits > (size_t)-1 - bits) return 0;
        bits += s->ops[k].num_bits;
    }
    if (s->n_ops > (size_t)-1 - bits) return 0;

    /* Scheduled rows must fit the padded-height bound WITH the terminal row. */
    const size_t sched = s->n_starts + s->n_ops;
    if (sched + 1 > TAIR_TBL_MAX_ROWS) return 0;
    return 1;
}

/* Round up to a power of two, minimum TAIR_TBL_MIN_ROWS. 0 on overflow
 * (unreachable at the bounds above; kept fail-close). */
static size_t tair_pad_pow2(size_t used)
{
    size_t h = TAIR_TBL_MIN_ROWS;
    while (h < used) {
        if (h > (size_t)-1 / 2) return 0;
        h <<= 1;
    }
    return h;
}

/* ==========================================================================
 * The challenger simulation — the ONE place the row TYPE is decided.
 *
 * State is the two LENGTHS only; values never enter the schedule. Every branch
 * cites the native line it mirrors (duplex_challenger.c, byte-matched to
 * Plonky3 82cfad73 / v0.6.2 11cc5849).
 * ======================================================================== */
typedef struct {
    size_t in_len;  /* dnac_duplex_t::input_len  */
    size_t out_len; /* dnac_duplex_t::output_len */
} tair_sim_t;

/* `dnac_duplex_init` memsets the WHOLE struct (:91-94): both lengths to 0. */
static inline void tair_sim_reset(tair_sim_t *m) { m->in_len = 0; m->out_len = 0; }

/* Advance the machine by one op and return the row TYPE it produces, or
 * SIZE_MAX if the op is unreachable from this state (fail-close). */
static size_t tair_sim_step(tair_sim_t *m, const dnac_tair_op_t *op)
{
    if (op->kind == DNAC_TAIR_OP_OBSERVE) {
        /* :108 — any buffered output is now invalid. */
        m->out_len = 0;
        /* :109 — a full input buffer aborts natively; here it is unreachable
         * because the 4th observe drains eagerly, so treat it as fail-close. */
        if (m->in_len >= (size_t)DNAC_DUPLEX_RATE) return (size_t)-1;
        m->in_len++; /* :110 */
        if (m->in_len == (size_t)DNAC_DUPLEX_RATE) {
            /* :112-114 eager duplex -> dc_duplexing :67-89: input_len drained
             * to 0 (:73), output refilled to RATE (:85-88). */
            m->in_len = 0;
            m->out_len = (size_t)DNAC_DUPLEX_RATE;
            return TAIR_TBL_TYPE_OBS_DUP;
        }
        return TAIR_TBL_TYPE_OBS;
    }

    /* SAMPLE. :127 — pending input OR empty output forces a duplexing. */
    size_t type;
    if (m->in_len > 0 || m->out_len == 0) {
        m->in_len = 0;
        m->out_len = (size_t)DNAC_DUPLEX_RATE;
        type = TAIR_TBL_TYPE_SAMPLE_DUP;
    } else {
        type = TAIR_TBL_TYPE_SAMPLE;
    }
    if (m->out_len == 0) return (size_t)-1; /* unreachable; fail-close */
    m->out_len--;                           /* :131 — LIFO pop */
    return type;
}

/* ==========================================================================
 * Shape accessors
 * ======================================================================== */

size_t dnac_tair_sched_rows(const dnac_tair_script_t *s)
{
    if (!tair_script_check(s)) return 0;
    return s->n_starts + s->n_ops;
}

size_t dnac_tair_table_rows(const dnac_tair_script_t *s)
{
    const size_t sched = dnac_tair_sched_rows(s);
    if (sched == 0) return 0;
    /* +1 = the mandatory terminal filler row (transcript_air.c:444-460). */
    return tair_pad_pow2(sched + 1);
}

size_t dnac_tair_total_bits(const dnac_tair_script_t *s)
{
    if (!tair_script_check(s)) return 0;
    size_t bits = 0;
    for (size_t k = 0; k < s->n_ops; k++) bits += s->ops[k].num_bits;
    return bits;
}

size_t dnac_tair_num_publics(const dnac_tair_script_t *s)
{
    if (!tair_script_check(s)) return 0;
    return s->n_ops + dnac_tair_total_bits(s);
}

size_t dnac_tair_op_bit_off(const dnac_tair_script_t *s, size_t k)
{
    if (!tair_script_check(s) || k >= s->n_ops) return (size_t)-1;
    if (s->ops[k].num_bits == 0) return (size_t)-1;
    size_t off = s->n_ops;
    for (size_t i = 0; i < k; i++) off += s->ops[i].num_bits;
    return off;
}

dnac_tair_table_status_t dnac_tair_script_pow_bits(const dnac_tair_script_t *s,
                                                   size_t *out_bits)
{
    if (out_bits == NULL || !tair_script_check(s)) {
        return DNAC_TAIR_TABLE_ERR_PARAM;
    }
    size_t bits = 0;
    int seen = 0;
    for (size_t k = 0; k < s->n_ops; k++) {
        if (!s->ops[k].is_pow) continue;
        if (!seen) {
            bits = s->ops[k].pow_bits;
            seen = 1;
        } else if (s->ops[k].pow_bits != bits) {
            /* The AIR carries ONE cfg->pow_bits (transcript_air.c:204-205); two
             * grinding widths in one instance are out of contract. */
            return DNAC_TAIR_TABLE_ERR_PARAM;
        }
    }
    *out_bits = bits;
    return DNAC_TAIR_TABLE_OK;
}

/* ==========================================================================
 * Op emission primitives — ONE place, so every block writes a fully
 * initialized op and no field is left to a caller's memset.
 * ======================================================================== */

static void tair_push_obs(dnac_tair_op_t *ops, size_t *n)
{
    memset(&ops[*n], 0, sizeof(ops[*n]));
    ops[*n].kind = DNAC_TAIR_OP_OBSERVE;
    (*n)++;
}

static void tair_push_smp(dnac_tair_op_t *ops, size_t *n, int is_pow,
                          size_t pow_bits, size_t num_bits)
{
    memset(&ops[*n], 0, sizeof(ops[*n]));
    ops[*n].kind = DNAC_TAIR_OP_SAMPLE;
    ops[*n].is_pow = is_pow;
    ops[*n].pow_bits = pow_bits;
    ops[*n].num_bits = num_bits;
    (*n)++;
}

/** `dnac_batch_observe_usize` is TWO base observes — the value, then a zero
 *  second coefficient (batch_priming.c:26-27). */
static void tair_push_usize(dnac_tair_op_t *ops, size_t *n)
{
    tair_push_obs(ops, n);
    tair_push_obs(ops, n);
}

/** A commitment digest is DNAC_P2M_DIGEST_LANES base observes
 *  (`dnac_batch_observe_commit`, batch_priming.c:34-36). */
static void tair_push_commit(dnac_tair_op_t *ops, size_t *n)
{
    for (size_t i = 0; i < (size_t)DNAC_P2M_DIGEST_LANES; i++) {
        tair_push_obs(ops, n);
    }
}

/** An fp2 sample is TWO base pops, c0 first (duplex_challenger.c:134-140). */
static void tair_push_smp_fp2(dnac_tair_op_t *ops, size_t *n)
{
    tair_push_smp(ops, n, 0, 0, 0);
    tair_push_smp(ops, n, 0, 0, 0);
}

/** An fp2 observe is TWO base observes, c0 first (transcript.c:79-82 ->
 *  duplex_challenger.c:117-122). */
static void tair_push_obs_fp2(dnac_tair_op_t *ops, size_t *n)
{
    tair_push_obs(ops, n);
    tair_push_obs(ops, n);
}

/* ==========================================================================
 * BLOCK 1 — the batch-STARK priming (batch_priming.c:208-282)
 * ======================================================================== */

/* Derived presence flags. `dnac_batch_priming_run` REQUIRES each of these to
 * match the corresponding commitment's presence (batch_priming.c:243-248), so
 * they are computed from the instance shapes rather than carried as free cfg
 * fields — a cfg cannot describe a priming run the native would reject. */
typedef struct {
    int    any_lookups;   /* -> the permutation commit is present  :246-248 */
    size_t lookup_insts;  /* -> one observed terminal each          :182-192 */
    int    any_prep;      /* -> the preprocessed commit is present
                             (batch_verify.c:149 with :187)                 */
} tair_priming_flags_t;

static void tair_priming_flags(const dnac_tair_priming_cfg_t *cfg,
                               tair_priming_flags_t *out)
{
    out->any_lookups = 0;
    out->lookup_insts = 0;
    out->any_prep = 0;
    for (size_t i = 0; i < cfg->n; i++) {
        if (cfg->insts[i].num_lookups > 0) {
            out->any_lookups = 1;
            out->lookup_insts++;
        }
        if (cfg->insts[i].preprocessed_width > 0) out->any_prep = 1;
    }
}

static int tair_priming_cfg_check(const dnac_tair_priming_cfg_t *cfg)
{
    if (cfg == NULL || cfg->insts == NULL) return 0;
    if (cfg->n == 0 || cfg->n > TAIR_TBL_MAX_INNER_INSTANCES) return 0;
    if (cfg->is_zk != 0 && cfg->is_zk != 1) return 0;
    /* A non-ZK proof consumes no rand entry at all, so a non-zero codeword count
     * could not describe one (batch_verify.c:437-444: `if (is_zk)` gates the
     * whole BV_TAIL body). */
    if (!cfg->is_zk && cfg->num_random_codewords != 0) return 0;
    if (cfg->num_random_codewords > TAIR_TBL_MAX_INNER_LANES) return 0;

    for (size_t i = 0; i < cfg->n; i++) {
        const dnac_tair_inner_inst_t *d = &cfg->insts[i];
        /* main_width 0 is rejected outright by the verifier
         * (batch_verify.c:174-177), and num_quotient_chunks 0 by the priming
         * itself (batch_priming.c:236-238). */
        if (d->main_width == 0 || d->main_width > TAIR_TBL_MAX_INNER_LANES) {
            return 0;
        }
        if (d->num_quotient_chunks == 0 ||
            d->num_quotient_chunks > TAIR_TBL_MAX_INNER_LANES) {
            return 0;
        }
        if (d->num_publics > TAIR_TBL_MAX_INNER_LANES) return 0;
        if (d->preprocessed_width > TAIR_TBL_MAX_INNER_LANES) return 0;
        if (d->num_lookups > TAIR_TBL_MAX_INNER_LANES) return 0;
        if (d->main_next != 0 && d->main_next != 1) return 0;
        if (d->prep_next != 0 && d->prep_next != 1) return 0;
        /* `prep_next` off a zero-width preprocessed matrix is a shape the
         * verifier rejects: pw == 0 forces BOTH opened lengths to 0
         * (batch_priming.c:352-355). */
        if (d->preprocessed_width == 0 && d->prep_next) return 0;
    }
    return 1;
}

/** Op count of BLOCK 1, assuming `cfg` already passed `tair_priming_cfg_check`. */
static size_t tair_priming_ops(const dnac_tair_priming_cfg_t *cfg)
{
    tair_priming_flags_t f;
    size_t n = 0;

    tair_priming_flags(cfg, &f);

    /* a. observe_count_and_bindings (batch_priming.c:39-58). */
    n += 2;                 /* observe_usize(num_instances)             :47 */
    n += 8 * cfg->n;        /* 4 usize per instance                  :52-55 */
    /* b. observe_main (:60-82). */
    n += (size_t)DNAC_P2M_DIGEST_LANES;              /* the commit     :72 */
    for (size_t i = 0; i < cfg->n; i++) {
        n += cfg->insts[i].num_publics;              /*             :77-79 */
    }
    /* c. observe_preprocessed (:84-101). */
    n += 2 * cfg->n;                                 /* the widths  :94-96 */
    if (f.any_prep) n += (size_t)DNAC_P2M_DIGEST_LANES;   /*       :97-99 */
    /* d. sample_perm_challenges (:103-153): ZERO ops with no lookups
     *    (:137-139), else alpha and beta as two fp2 pops (:143-144). */
    if (f.any_lookups) n += 4;
    /* e. observe_perm_and_sample_alpha (:155-196). */
    if (f.any_lookups) {
        n += (size_t)DNAC_P2M_DIGEST_LANES;          /* the commit    :181 */
        n += 2 * f.lookup_insts;                     /* terminals :182-192 */
    }
    n += 2;                                          /* alpha         :194 */
    /* f-h. */
    n += (size_t)DNAC_P2M_DIGEST_LANES;              /* quotient      :276 */
    if (cfg->is_zk) n += (size_t)DNAC_P2M_DIGEST_LANES; /* random :277-279 */
    n += 2;                                          /* zeta          :280 */
    return n;
}

static void tair_emit_priming(const dnac_tair_priming_cfg_t *cfg,
                              dnac_tair_op_t *ops, size_t *n)
{
    tair_priming_flags_t f;
    tair_priming_flags(cfg, &f);

    tair_push_usize(ops, n);                                    /* :47 */
    for (size_t i = 0; i < cfg->n; i++) {
        tair_push_usize(ops, n); /* log_ext_degree                 :52 */
        tair_push_usize(ops, n); /* log_degree                     :53 */
        tair_push_usize(ops, n); /* width                          :54 */
        tair_push_usize(ops, n); /* num_quotient_chunks            :55 */
    }
    tair_push_commit(ops, n);                                   /* :72 */
    for (size_t i = 0; i < cfg->n; i++) {
        for (size_t j = 0; j < cfg->insts[i].num_publics; j++) {
            tair_push_obs(ops, n);                           /* :77-79 */
        }
    }
    for (size_t i = 0; i < cfg->n; i++) tair_push_usize(ops, n); /* :95 */
    if (f.any_prep) tair_push_commit(ops, n);                /* :97-99 */
    if (f.any_lookups) {
        tair_push_smp_fp2(ops, n); /* the batch alpha              :143 */
        tair_push_smp_fp2(ops, n); /* the batch beta               :144 */
        tair_push_commit(ops, n);  /* the permutation commit       :181 */
        for (size_t i = 0; i < cfg->n; i++) {
            if (cfg->insts[i].num_lookups == 0) continue;    /* :185-187 */
            tair_push_obs_fp2(ops, n); /* this AIR's terminal      :191 */
        }
    }
    tair_push_smp_fp2(ops, n);                                 /* :194 */
    tair_push_commit(ops, n);                                  /* :276 */
    if (cfg->is_zk) tair_push_commit(ops, n);              /* :277-279 */
    tair_push_smp_fp2(ops, n);                                 /* :280 */
}

/* ==========================================================================
 * BLOCK 2 — the PCS claimed-eval observe round (batch_verify.c:637-647)
 * ======================================================================== */

/**
 * Total claimed-eval LANES the observe round walks. This is exactly the arena
 * length `batch_verify.c:432-488` computes, because :637-647 observes every
 * `claimed_evals[k]` of every point of every matrix of every round, and
 * `num_claimed_evals` is the BASE length plus the rand tail (:516).
 *
 * Assumes `cfg` already passed `tair_priming_cfg_check`.
 */
static size_t tair_pcs_lanes(const dnac_tair_priming_cfg_t *cfg)
{
    const size_t nrc = cfg->num_random_codewords;
    size_t lanes = 0;

    if (cfg->is_zk) { /* round 0: random @ zeta, random_len == 2 (:446-451) */
        lanes += cfg->n * (2 + nrc);
    }
    for (size_t i = 0; i < cfg->n; i++) { /* round 1: main       (:452-459) */
        const dnac_tair_inner_inst_t *d = &cfg->insts[i];
        lanes += (d->main_next ? 2u : 1u) * (d->main_width + nrc);
    }
    for (size_t i = 0; i < cfg->n; i++) { /* round 2: quotient   (:460-465) */
        lanes += cfg->insts[i].num_quotient_chunks * (2 + nrc);
    }
    for (size_t i = 0; i < cfg->n; i++) { /* round 3: prep       (:466-474) */
        const dnac_tair_inner_inst_t *d = &cfg->insts[i];
        if (d->preprocessed_width == 0) continue;
        /* The tail is pinned to ZERO on a preprocessed point (:468 / :471). */
        lanes += (d->prep_next ? 2u : 1u) * d->preprocessed_width;
    }
    for (size_t i = 0; i < cfg->n; i++) { /* round 4: perm       (:475-481) */
        const dnac_tair_inner_inst_t *d = &cfg->insts[i];
        size_t perm_len;
        if (d->num_lookups == 0) continue;
        /* aux_width = num_lookups + 1 (batch_priming.c:321-326); the opened
         * permutation length is aux_width * DIMENSION (batch_verify.c:247). */
        perm_len = (d->num_lookups + 1) * 2;
        lanes += 2 * (perm_len + nrc);
    }
    return lanes;
}

static void tair_emit_pcs(const dnac_tair_priming_cfg_t *cfg,
                          dnac_tair_op_t *ops, size_t *n)
{
    /* ⚠ Every op of this block is an OBSERVE, so the round / matrix / point /
     * claimed-eval NESTING of batch_verify.c:637-647 is not reproduced here: a
     * script records op KINDS, and any nesting with the same total emits the
     * identical sequence. What is load-bearing is the COUNT and the block's
     * position between the priming's zeta pop and the FRI tail's alpha pop. */
    const size_t lanes = tair_pcs_lanes(cfg);
    for (size_t k = 0; k < lanes; k++) tair_push_obs_fp2(ops, n);
}

size_t dnac_tair_priming_num_ops(const dnac_tair_priming_cfg_t *cfg)
{
    if (!tair_priming_cfg_check(cfg)) return 0;
    return tair_priming_ops(cfg);
}

size_t dnac_tair_pcs_num_ops(const dnac_tair_priming_cfg_t *cfg)
{
    if (!tair_priming_cfg_check(cfg)) return 0;
    return 2 * tair_pcs_lanes(cfg);
}

/* ==========================================================================
 * BLOCK 3 — FRI-tail expansion (the op order is fri_verifier.c:693-737)
 * ======================================================================== */

static int tair_fri_cfg_check(const dnac_tair_fri_cfg_t *cfg)
{
    if (cfg == NULL) return 0;
    if (cfg->R == 0 || cfg->R > TAIR_TBL_MAX_STEPS) return 0;
    if (cfg->log_final_poly_len > 5) return 0; /* 1<<5 coefficients already
                                                * exceeds the op budget below */
    if (cfg->num_queries == 0 || cfg->num_queries > TAIR_TBL_MAX_STEPS) return 0;
    /* lgmh in [1, 32]: the native FRI verifier rejects lgmh > 32
     * (fri_verifier.c:689-691, GOLDILOCKS_TWO_ADICITY), and a zero-bit index
     * sample would export nothing. */
    if (cfg->lgmh == 0 || cfg->lgmh > TAIR_TBL_MAX_OP_BITS) return 0;
    if (cfg->commit_pow_bits > TAIR_TBL_MAX_OP_BITS) return 0;
    if (cfg->query_pow_bits > TAIR_TBL_MAX_OP_BITS) return 0;
    /* One AIR cfg->pow_bits covers every PoW row (transcript_air.c:204-205), so
     * two DIFFERENT non-zero grinding widths in one instance fail closed. */
    if (cfg->commit_pow_bits != 0 && cfg->query_pow_bits != 0 &&
        cfg->commit_pow_bits != cfg->query_pow_bits) {
        return 0;
    }
    return 1;
}

/**
 * RAW op count of the FRI tail, the DS prefix included iff `with_ds`. 0 iff the
 * cfg is rejected. NO length bound is applied here — the callers apply
 * TAIR_TBL_MAX_STEPS to the WHOLE script they are building, which is the only
 * script that has to fit.
 */
static size_t tair_fri_tail_ops(const dnac_tair_fri_cfg_t *cfg, int with_ds)
{
    if (!tair_fri_cfg_check(cfg)) return 0;

    const size_t digest_lanes = (size_t)DNAC_P2M_DIGEST_LANES; /* 4 */
    const size_t final_lanes = (size_t)2 << cfg->log_final_poly_len;
    /* check_witness cost, DERIVED from duplex_challenger.c:151-158: bits == 0
     * returns at :153-155 with NO state change (0 ops); bits > 0 observes the
     * witness (:156) and takes one base pop through sample_bits (:157, :146). */
    const size_t commit_pow_ops = (cfg->commit_pow_bits == 0) ? 0 : 2;
    const size_t query_pow_ops = (cfg->query_pow_bits == 0) ? 0 : 2;

    return (with_ds ? (size_t)DNAC_DUPLEX_RATE : 0) /* 1. DS prefix observes */
           + 2                            /* 2. alpha (fp2 = 2 pops) */
           + cfg->R * (digest_lanes + commit_pow_ops + 2) /* 3.      */
           + final_lanes                  /* 4. final poly           */
           + cfg->R                       /* 5. log_arity observes   */
           + query_pow_ops                /* 6. query PoW            */
           + cfg->num_queries;            /* 7. index samples        */
}

/** Emit the FRI tail, the DS prefix included iff `with_ds`. `cfg` must already
 *  have passed `tair_fri_cfg_check`. */
static void tair_emit_fri_tail(const dnac_tair_fri_cfg_t *cfg,
                               dnac_tair_op_t *ops, size_t *n, int with_ds)
{
    /* 1 — the DS prefix (duplex_challenger.c:96-103). Emitted ONLY for a
     *     standalone run; in a composed script the prefix belongs to BLOCK 0
     *     and `dnac_transcript_init_from_duplex` adds none (transcript.c:48). */
    if (with_ds) {
        for (size_t i = 0; i < (size_t)DNAC_DUPLEX_RATE; i++) {
            tair_push_obs(ops, n);
        }
    }
    /* 2 — alpha, an fp2 sample = c0 then c1 (duplex_challenger.c:134-140). */
    tair_push_smp_fp2(ops, n);
    /* 3 — the commit-phase loop (fri_verifier.c:700-708). */
    for (size_t r = 0; r < cfg->R; r++) {
        for (size_t i = 0; i < (size_t)DNAC_P2M_DIGEST_LANES; i++) {
            tair_push_obs(ops, n);
        }
        if (cfg->commit_pow_bits != 0) {
            tair_push_obs(ops, n); /* the witness (duplex_challenger.c:156) */
            tair_push_smp(ops, n, 1, cfg->commit_pow_bits, 0); /* :157 */
        }
        tair_push_smp_fp2(ops, n); /* beta c0, c1 */
    }
    /* 4 — the final polynomial (fri_verifier.c:711-713). */
    {
        const size_t final_lanes = (size_t)2 << cfg->log_final_poly_len;
        for (size_t i = 0; i < final_lanes; i++) tair_push_obs(ops, n);
    }
    /* 5 — the per-round log_arity (fri_verifier.c:717-720). */
    for (size_t r = 0; r < cfg->R; r++) tair_push_obs(ops, n);
    /* 6 — the query PoW (fri_verifier.c:723). */
    if (cfg->query_pow_bits != 0) {
        tair_push_obs(ops, n);
        tair_push_smp(ops, n, 1, cfg->query_pow_bits, 0);
    }
    /* 7 — one index sample per query (fri_verifier.c:737). */
    for (size_t q = 0; q < cfg->num_queries; q++) {
        tair_push_smp(ops, n, 0, 0, cfg->lgmh);
    }
}

size_t dnac_tair_fri_num_ops(const dnac_tair_fri_cfg_t *cfg)
{
    const size_t n = tair_fri_tail_ops(cfg, 1);
    if (n == 0 || n > TAIR_TBL_MAX_STEPS) return 0;
    return n;
}

/* Finish a built script: pin the single instance start, gate the whole shape
 * through `tair_script_check`, and publish. Shared by both builders so neither
 * can accept a shape the other would reject. */
static dnac_tair_table_status_t tair_finish_script(dnac_tair_op_t *ops_out,
                                                   size_t n, size_t *starts_out,
                                                   dnac_tair_script_t *out)
{
    dnac_tair_script_t built;

    starts_out[0] = 0; /* ONE transcript instance */
    built.ops = ops_out;
    built.n_ops = n;
    built.instance_starts = starts_out;
    built.n_starts = 1;
    if (!tair_script_check(&built)) return DNAC_TAIR_TABLE_ERR_PARAM;

    *out = built;
    return DNAC_TAIR_TABLE_OK;
}

dnac_tair_table_status_t dnac_tair_fri_build_script(
    const dnac_tair_fri_cfg_t *cfg, dnac_tair_op_t *ops_out, size_t ops_cap,
    size_t *starts_out, dnac_tair_script_t *out)
{
    if (ops_out == NULL || starts_out == NULL || out == NULL) {
        return DNAC_TAIR_TABLE_ERR_PARAM;
    }
    const size_t want = dnac_tair_fri_num_ops(cfg);
    if (want == 0) return DNAC_TAIR_TABLE_ERR_PARAM;
    if (ops_cap < want) return DNAC_TAIR_TABLE_ERR_CAPACITY;

    size_t n = 0;
    tair_emit_fri_tail(cfg, ops_out, &n, 1);
    if (n != want) return DNAC_TAIR_TABLE_ERR_PARAM; /* unreachable; fail-close */

    return tair_finish_script(ops_out, n, starts_out, out);
}

/* ==========================================================================
 * The COMPOSED script — BLOCKS 0-3
 * ======================================================================== */

size_t dnac_tair_full_num_ops(const dnac_tair_full_cfg_t *cfg)
{
    if (cfg == NULL) return 0;
    if (!tair_priming_cfg_check(&cfg->priming)) return 0;

    const size_t tail = tair_fri_tail_ops(&cfg->fri, 0);
    if (tail == 0) return 0; /* the cfg gate rejected the FRI half */

    const size_t n = (size_t)DNAC_DUPLEX_RATE      /* BLOCK 0 — DS prefix */
                     + tair_priming_ops(&cfg->priming)      /* BLOCK 1    */
                     + 2 * tair_pcs_lanes(&cfg->priming)    /* BLOCK 2    */
                     + tail;                                 /* BLOCK 3    */
    if (n == 0 || n > TAIR_TBL_MAX_STEPS) return 0;
    return n;
}

dnac_tair_table_status_t dnac_tair_full_build_script(
    const dnac_tair_full_cfg_t *cfg, dnac_tair_op_t *ops_out, size_t ops_cap,
    size_t *starts_out, dnac_tair_script_t *out)
{
    if (ops_out == NULL || starts_out == NULL || out == NULL) {
        return DNAC_TAIR_TABLE_ERR_PARAM;
    }
    const size_t want = dnac_tair_full_num_ops(cfg);
    if (want == 0) return DNAC_TAIR_TABLE_ERR_PARAM;
    if (ops_cap < want) return DNAC_TAIR_TABLE_ERR_CAPACITY;

    size_t n = 0;
    /* BLOCK 0 — the DS prefix, ONCE for the whole run. `dnac_duplex_init_default`
     * absorbs the four limbs (duplex_challenger.c:96-103) at the sponge's
     * creation (batch_verify.c:321); nothing re-prefixes it afterwards, because
     * `dnac_transcript_init_from_duplex` copies the state verbatim
     * (batch_verify.c:632 -> transcript.c:43-50). */
    for (size_t i = 0; i < (size_t)DNAC_DUPLEX_RATE; i++) {
        tair_push_obs(ops_out, &n);
    }
    tair_emit_priming(&cfg->priming, ops_out, &n);          /* BLOCK 1 */
    tair_emit_pcs(&cfg->priming, ops_out, &n);              /* BLOCK 2 */
    tair_emit_fri_tail(&cfg->fri, ops_out, &n, 0);          /* BLOCK 3 */

    if (n != want) return DNAC_TAIR_TABLE_ERR_PARAM; /* unreachable; fail-close */

    return tair_finish_script(ops_out, n, starts_out, out);
}

dnac_tair_table_status_t dnac_tair_ref_script(dnac_tair_op_t *ops_out,
                                              size_t ops_cap,
                                              size_t *starts_out,
                                              dnac_tair_script_t *out)
{
    return dnac_tair_full_build_script(dnac_tair_ref_full_cfg(), ops_out,
                                       ops_cap, starts_out, out);
}

/* ==========================================================================
 * Row record — the single source both the cell writer and the tests read
 * ======================================================================== */

dnac_tair_table_status_t dnac_tair_table_row(const dnac_tair_script_t *s,
                                             size_t row, dnac_tair_row_t *out)
{
    if (out == NULL || !tair_script_check(s)) return DNAC_TAIR_TABLE_ERR_PARAM;
    const size_t rows = dnac_tair_table_rows(s);
    if (rows == 0 || row >= rows) return DNAC_TAIR_TABLE_ERR_PARAM;

    memset(out, 0, sizeof(*out));
    out->step = (size_t)-1;
    out->bit_off = (size_t)-1;

    /* Walk the schedule from the top. Fixed-bound (rows <= 128), pure, and it
     * reuses the SAME simulation the generator does, so a row decoded on its own
     * and a row written by `dnac_tair_table_generate` cannot disagree. */
    tair_sim_t m;
    tair_sim_reset(&m);
    size_t r = 0, next_start = 0, bit_off = s->n_ops;

    for (size_t k = 0; k < s->n_ops; k++) {
        if (next_start < s->n_starts && s->instance_starts[next_start] == k) {
            if (r == row) {
                out->type = TAIR_TBL_TYPE_START;
                return DNAC_TAIR_TABLE_OK;
            }
            r++;
            tair_sim_reset(&m); /* dnac_duplex_init, :91-94 */
            next_start++;
        }
        const dnac_tair_op_t *op = &s->ops[k];
        const size_t type = tair_sim_step(&m, op);
        if (type == (size_t)-1) return DNAC_TAIR_TABLE_ERR_PARAM;
        if (r == row) {
            out->type = type;
            out->step = k;
            out->is_pow = op->is_pow;
            out->num_bits = op->num_bits;
            out->bit_off = (op->num_bits > 0) ? bit_off : (size_t)-1;
            return DNAC_TAIR_TABLE_OK;
        }
        r++;
        bit_off += op->num_bits;
    }

    /* Padding — filler rows, typed (NOT all-zero): CT-1 equates the table's type
     * block with the main selectors on EVERY row, and a padding row's main
     * selector IS `sel_filler` (transcript_air.c:407-421). */
    out->type = TAIR_TBL_TYPE_FILLER;
    return DNAC_TAIR_TABLE_OK;
}

/* ==========================================================================
 * Generator
 * ======================================================================== */

dnac_tair_table_status_t dnac_tair_table_generate(const dnac_tair_script_t *s,
                                                  uint64_t *out,
                                                  size_t out_cells)
{
    if (out == NULL || !tair_script_check(s)) return DNAC_TAIR_TABLE_ERR_PARAM;
    const size_t rows = dnac_tair_table_rows(s);
    if (rows == 0) return DNAC_TAIR_TABLE_ERR_PARAM;
    if (out_cells < rows * TAIR_TBL_COLS) return DNAC_TAIR_TABLE_ERR_CAPACITY;

    /* Every cell defaults to 0: only the row's own type lane, its `is_pow` and
     * its one-hot position are set. */
    memset(out, 0, rows * TAIR_TBL_COLS * sizeof(uint64_t));

    for (size_t r = 0; r < rows; r++) {
        dnac_tair_row_t rec;
        const dnac_tair_table_status_t st = dnac_tair_table_row(s, r, &rec);
        if (st != DNAC_TAIR_TABLE_OK) return st;

        uint64_t *row = &out[r * TAIR_TBL_COLS];
        row[tair_tbl_col_type(rec.type)] = 1;
        row[TAIR_TBL_COL_IS_POW] = (uint64_t)(rec.is_pow ? 1 : 0);
        if (rec.step != (size_t)-1) row[tair_tbl_col_pos(rec.step)] = 1;
    }
    return DNAC_TAIR_TABLE_OK;
}

/* ==========================================================================
 * Static validator — structural, NOT a memcmp against the generator (that
 * would be circular). Check order is the header's contract.
 * ======================================================================== */

#define TAIR_FAIL(d)                                                          \
    do {                                                                      \
        if (out_defect) *out_defect = (d);                                    \
        return DNAC_TAIR_TABLE_ERR_SCHEDULE;                                  \
    } while (0)

/* Decode the row-type lane set on row `r`, or SIZE_MAX if not exactly one. */
static size_t tair_cell_type(const uint64_t *row)
{
    size_t seen = (size_t)-1, count = 0;
    for (size_t t = 0; t < TAIR_TBL_NUM_TYPES; t++) {
        if (row[tair_tbl_col_type(t)] == 1) {
            seen = t;
            count++;
        }
    }
    return (count == 1) ? seen : (size_t)-1;
}

dnac_tair_table_status_t dnac_tair_table_validate(
    const dnac_tair_script_t *s, const uint64_t *cells, size_t rows,
    dnac_tair_table_defect_t *out_defect)
{
    if (out_defect) *out_defect = DNAC_TAIR_DEFECT_NONE;
    if (cells == NULL || !tair_script_check(s)) return DNAC_TAIR_TABLE_ERR_PARAM;
    const size_t exp_rows = dnac_tair_table_rows(s);
    if (exp_rows == 0 || rows != exp_rows) return DNAC_TAIR_TABLE_ERR_PARAM;

    const size_t cols = TAIR_TBL_COLS;

    /* 1 — canonicality. Non-canonical preprocessed cells alias mod p (the
     *     OBL-2 class, mmcs_air.h:93-94). */
    for (size_t r = 0; r < rows; r++) {
        for (size_t c = 0; c < cols; c++) {
            if (cells[r * cols + c] >= GOLDILOCKS_P) {
                TAIR_FAIL(DNAC_TAIR_DEFECT_CANONICAL);
            }
        }
    }

    /* 2 — booleanity. This table has NO field literals, so EVERY cell is 0/1.
     *     Nothing on the verify path checks this (batch_verify.c:722-727 hands
     *     the window to air_eval raw), so it is checked here and frozen by the
     *     root pin. */
    for (size_t r = 0; r < rows; r++) {
        for (size_t c = 0; c < cols; c++) {
            if (cells[r * cols + c] > 1) TAIR_FAIL(DNAC_TAIR_DEFECT_BOOLEAN);
        }
    }

    /* 3 — exactly one row type per row. */
    for (size_t r = 0; r < rows; r++) {
        if (tair_cell_type(&cells[r * cols]) == (size_t)-1) {
            TAIR_FAIL(DNAC_TAIR_DEFECT_TYPE_EXCLUSIVE);
        }
    }

    /* 4 — TERMINALITY: the LAST row must be a filler row. The AIR's final row
     *     gets NO transition constraints, so every effect a row pins on its
     *     successor is void there — the i3 shipped-HIGH (transcript_air.c:
     *     444-460). The pinned table is what makes it structurally true.
     *
     *     ⚠ EVALUATED BEFORE the machine walk, and that ordering is load-bearing
     *     (header contract): the walk's own "padding is terminal" rule would
     *     otherwise claim every typed LAST row as a MACHINE defect and this
     *     check could never fire. */
    if (tair_cell_type(&cells[(rows - 1) * cols]) != TAIR_TBL_TYPE_FILLER) {
        TAIR_FAIL(DNAC_TAIR_DEFECT_TERMINAL);
    }

    /* 5 — MACHINE legality: re-simulate `input_len` / `output_len` from the
     *     CELLS and require every _OBS vs _OBS_DUP and _SAMPLE vs _SAMPLE_DUP
     *     label to be the one duplex_challenger.c would produce. This is the
     *     check that makes the table's row types load-bearing rather than
     *     decorative: a schedule claiming a plain observe where the buffer is
     *     about to fill, or a plain pop from an empty output buffer, is a
     *     schedule the native run never produces.
     *
     *     Also enforced here: filler rows are TERMINAL (once padding starts it
     *     never stops — the AIR's own rule, transcript_air.c:420) and a start
     *     row resets the machine (:91-94). */
    size_t n_ops_seen = 0, n_starts_seen = 0;
    {
        tair_sim_t m;
        tair_sim_reset(&m);
        int in_pad = 0;
        for (size_t r = 0; r < rows; r++) {
            const size_t t = tair_cell_type(&cells[r * cols]);
            if (in_pad && t != TAIR_TBL_TYPE_FILLER) {
                TAIR_FAIL(DNAC_TAIR_DEFECT_MACHINE);
            }
            if (t == TAIR_TBL_TYPE_FILLER) {
                in_pad = 1;
                continue;
            }
            if (t == TAIR_TBL_TYPE_START) {
                tair_sim_reset(&m);
                n_starts_seen++;
                continue;
            }
            /* An op row. Its KIND is implied by the label; simulate and compare
             * the label the machine produces. */
            dnac_tair_op_t probe;
            memset(&probe, 0, sizeof(probe));
            probe.kind = (t == TAIR_TBL_TYPE_OBS || t == TAIR_TBL_TYPE_OBS_DUP)
                             ? DNAC_TAIR_OP_OBSERVE
                             : DNAC_TAIR_OP_SAMPLE;
            const size_t want = tair_sim_step(&m, &probe);
            if (want == (size_t)-1 || want != t) {
                TAIR_FAIL(DNAC_TAIR_DEFECT_MACHINE);
            }
            n_ops_seen++;
        }
    }

    /* 6 — SCRIPT agreement: the run the cells describe must be the one the cfg
     *     asked for. The root binds the TABLE, never the script argument
     *     (OBL-P2a-T1), so the AIR's public-slot arithmetic is only correct when
     *     the two agree — checked here, once, instead of assumed. */
    if (n_ops_seen != s->n_ops || n_starts_seen != s->n_starts) {
        TAIR_FAIL(DNAC_TAIR_DEFECT_SCRIPT);
    }
    {
        size_t k = 0, next_start = 0;
        for (size_t r = 0; r < rows; r++) {
            const size_t t = tair_cell_type(&cells[r * cols]);
            if (t == TAIR_TBL_TYPE_FILLER) break;
            if (t == TAIR_TBL_TYPE_START) {
                if (next_start >= s->n_starts ||
                    s->instance_starts[next_start] != k) {
                    TAIR_FAIL(DNAC_TAIR_DEFECT_SCRIPT);
                }
                next_start++;
                continue;
            }
            if (k >= s->n_ops) TAIR_FAIL(DNAC_TAIR_DEFECT_SCRIPT);
            const int is_obs =
                (t == TAIR_TBL_TYPE_OBS || t == TAIR_TBL_TYPE_OBS_DUP);
            const int want_obs = (s->ops[k].kind == DNAC_TAIR_OP_OBSERVE);
            if (is_obs != want_obs) TAIR_FAIL(DNAC_TAIR_DEFECT_SCRIPT);
            k++;
        }
        if (k != s->n_ops || next_start != s->n_starts) {
            TAIR_FAIL(DNAC_TAIR_DEFECT_SCRIPT);
        }
    }

    /* 7 — op-step one-hot: the k-th op row carries pos[k] = 1 and nothing else;
     *     start and filler rows carry an all-zero one-hot. This is what makes
     *     `pos` index == public slot true, and therefore what makes CT-3/CT-4
     *     read the RIGHT public lane. */
    {
        size_t k = 0;
        for (size_t r = 0; r < rows; r++) {
            const uint64_t *row = &cells[r * cols];
            const size_t t = tair_cell_type(row);
            const int is_op =
                (t != TAIR_TBL_TYPE_START && t != TAIR_TBL_TYPE_FILLER);
            for (size_t c = 0; c < TAIR_TBL_MAX_STEPS; c++) {
                const uint64_t want = (is_op && c == k) ? 1u : 0u;
                if (row[tair_tbl_col_pos(c)] != want) {
                    TAIR_FAIL(DNAC_TAIR_DEFECT_POS_ONEHOT);
                }
            }
            if (is_op) k++;
        }
    }

    /* 8 — is_pow: set exactly on the script's PoW sampling rows, nowhere else.
     *     (The AIR ALSO forbids `is_pow` off a sampling row in the MAIN trace,
     *     transcript_air.c:157; CT-2 then carries that to the table.) */
    {
        size_t k = 0;
        for (size_t r = 0; r < rows; r++) {
            const uint64_t *row = &cells[r * cols];
            const size_t t = tair_cell_type(row);
            const int is_op =
                (t != TAIR_TBL_TYPE_START && t != TAIR_TBL_TYPE_FILLER);
            if (is_op && k >= s->n_ops) TAIR_FAIL(DNAC_TAIR_DEFECT_ISPOW);
            const uint64_t want =
                (is_op && s->ops[k].is_pow) ? 1u : 0u;
            if (row[TAIR_TBL_COL_IS_POW] != want) {
                TAIR_FAIL(DNAC_TAIR_DEFECT_ISPOW);
            }
            if (is_op) k++;
        }
    }

    return DNAC_TAIR_TABLE_OK;
}

#undef TAIR_FAIL

/* ==========================================================================
 * PIN-1-P2a comparator
 * ======================================================================== */

dnac_tair_table_status_t dnac_tair_prep_root_check(const uint64_t lanes[4])
{
    if (lanes == NULL) return DNAC_TAIR_TABLE_ERR_PARAM;

    /* An UNFILLED placeholder pin must never accept anything — least of all the
     * all-zero root it would otherwise match. Compiles away once the
     * ORCHESTRATOR fills the constant from `--print-roots`. */
    if (DNAC_P2A_PREP_ROOT_UNFILLED) {
        return DNAC_TAIR_TABLE_ERR_ROOT_MISMATCH;
    }

    static const uint64_t pinned[4] = DNAC_P2A_PREP_ROOT;
    for (int k = 0; k < 4; k++) {
        if (lanes[k] != pinned[k]) return DNAC_TAIR_TABLE_ERR_ROOT_MISMATCH;
    }
    return DNAC_TAIR_TABLE_OK;
}
