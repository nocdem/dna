/**
 * @file transcript_air.c
 * @brief P2a — DuplexChallenger-as-a-control-AIR: constraint evaluation.
 *
 * Every block below names the design-doc §0.5 archetype it discharges and the
 * `duplex_challenger.c` (native, byte-matched) line whose semantics it mirrors.
 * Upstream semantic reference is P3rec @ b36339709a7a67ee9760fb578b3d4339fd983709
 * `recursion/src/challenger/circuit.rs`.
 *
 * See transcript_air.h for the layout contract, the INLINE-embedding decision,
 * the degree budget, and the one labelled ADAPTATION (bit canonicality).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "transcript_air.h"

#include "field_goldilocks.h"
#include "poseidon2_air.h"

/* ── local field shorthands (conf_action_fold.c / poseidon2_air.c idiom) ──── */
static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

/** Assert a constraint residual is zero; count the violation otherwise. */
static inline void az(int *v, gold_fp_t residual) {
    if (!gold_fp_is_zero(residual)) (*v)++;
}

/** Booleanity under a gate: gate * x * (x - 1) == 0 (degree 3). */
static inline void az_bool_gated(int *v, gold_fp_t gate, gold_fp_t x) {
    az(v, mul(gate, mul(x, sub(x, gold_fp_one()))));
}

bool dnac_transcript_air_layout_check(void) {
    if (TAIR_STATE_OFF != 0) return false;
    if (TAIR_INBUF_OFF != TAIR_STATE_OFF + TAIR_STATE_LANES) return false;
    if (TAIR_ILFLAG_OFF != TAIR_INBUF_OFF + TAIR_RATE) return false;
    if (TAIR_OLFLAG_OFF != TAIR_ILFLAG_OFF + TAIR_LEN_SLOTS) return false;
    if (TAIR_SEL_OFF != TAIR_OLFLAG_OFF + TAIR_LEN_SLOTS) return false;
    if (TAIR_PREFIX_OFF != TAIR_SEL_OFF + TAIR_NUM_SEL) return false;
    if (TAIR_LANE_OFF != TAIR_PREFIX_OFF + TAIR_PREFIX_SLOTS) return false;
    if (TAIR_ISPOW_OFF != TAIR_LANE_OFF + 1) return false;
    if (TAIR_CANON_ISZ_OFF != TAIR_ISPOW_OFF + 1) return false;
    if (TAIR_CANON_INV_OFF != TAIR_CANON_ISZ_OFF + 1) return false;
    if (TAIR_BIT_OFF != TAIR_CANON_INV_OFF + 1) return false;
    if (TAIR_PERM_OFF != TAIR_BIT_OFF + TAIR_BITS) return false;
    if (TAIR_WIDTH != TAIR_PERM_OFF + P2AIR_NUM_COLS) return false;
    /* Accessors land inside their own blocks. */
    if (tair_state_off(TAIR_STATE_LANES - 1) != (size_t)TAIR_INBUF_OFF - 1) return false;
    if (tair_inbuf_off(TAIR_RATE - 1) != (size_t)TAIR_ILFLAG_OFF - 1) return false;
    if (tair_il_off(TAIR_LEN_SLOTS - 1) != (size_t)TAIR_OLFLAG_OFF - 1) return false;
    if (tair_ol_off(TAIR_LEN_SLOTS - 1) != (size_t)TAIR_SEL_OFF - 1) return false;
    if (tair_sel_off(TAIR_NUM_SEL - 1) != (size_t)TAIR_PREFIX_OFF - 1) return false;
    if (tair_prefix_off(TAIR_PREFIX_SLOTS - 1) != (size_t)TAIR_LANE_OFF - 1) return false;
    if (tair_bit_off(TAIR_BITS - 1) != (size_t)TAIR_PERM_OFF - 1) return false;
    if (tair_perm_in_off(0) != (size_t)TAIR_PERM_OFF) return false;
    if (tair_perm_out_off(TAIR_STATE_LANES - 1) != (size_t)TAIR_WIDTH - 1) return false;
    /* Selector index space is exactly [0, TAIR_NUM_SEL). */
    if (TAIR_SEL_FILLER != TAIR_NUM_SEL - 1) return false;
    if (TAIR_MAX_NUM_BITS > TAIR_BITS) return false;
    return true;
}

int dnac_transcript_air_eval_row(const uint64_t *local, const uint64_t *next,
                                 int is_first_row,
                                 const dnac_tair_config_t *cfg) {
    if (!local || !cfg) return TAIR_VIOL_BAD_CONFIG;
    if (cfg->pow_bits > TAIR_MAX_NUM_BITS) return TAIR_VIOL_BAD_CONFIG;

    /* ADAPTATION guard (see transcript_air.h): the is-zero realization of
     * `assert_bits_canonical` (circuit_builder.rs:1123-1158) is equivalent to
     * upstream's running-product loop ONLY when p-1 = [ones][trailing zeros],
     * the shape upstream itself assumes (:1119-1121). Verify it rather than
     * assume it; a field that breaks the shape fails closed. */
    const uint64_t c_max = GOLDILOCKS_P - 1u; /* largest canonical value, p-1 */
    unsigned trailing = 0;
    while (trailing < 64 && ((c_max >> trailing) & 1u) == 0u) trailing++;
    if (trailing == 0 || trailing >= 64) return TAIR_VIOL_BAD_CONFIG;
    for (unsigned i = trailing; i < 64; i++)
        if (((c_max >> i) & 1u) == 0u) return TAIR_VIOL_BAD_CONFIG;

    int v = 0;
    const gold_fp_t one = gold_fp_one();
    const gold_fp_t zero = gold_fp_zero();

    /* ══ Column reads ═════════════════════════════════════════════════════ */
    gold_fp_t sel[TAIR_NUM_SEL], il[TAIR_LEN_SLOTS], ol[TAIR_LEN_SLOTS];
    gold_fp_t pc[TAIR_PREFIX_SLOTS];
    for (size_t s = 0; s < TAIR_NUM_SEL; s++) sel[s] = fp(local[tair_sel_off(s)]);
    for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) {
        il[k] = fp(local[tair_il_off(k)]);
        ol[k] = fp(local[tair_ol_off(k)]);
    }
    for (size_t k = 0; k < TAIR_PREFIX_SLOTS; k++) pc[k] = fp(local[tair_prefix_off(k)]);

    const gold_fp_t s_start = sel[TAIR_SEL_START];
    const gold_fp_t s_obs = sel[TAIR_SEL_OBS];
    const gold_fp_t s_obsd = sel[TAIR_SEL_OBS_DUP];
    const gold_fp_t s_smp = sel[TAIR_SEL_SAMPLE];
    const gold_fp_t s_smpd = sel[TAIR_SEL_SAMPLE_DUP];
    const gold_fp_t s_fill = sel[TAIR_SEL_FILLER];

    const gold_fp_t g_observe = add(s_obs, s_obsd);   /* rows that observe a lane */
    const gold_fp_t g_sampling = add(s_smp, s_smpd);  /* rows that pop a challenge */
    const gold_fp_t g_op = add(g_observe, g_sampling);/* rows that touch the sponge */

    const gold_fp_t lane = fp(local[TAIR_LANE_OFF]);
    const gold_fp_t is_pow = fp(local[TAIR_ISPOW_OFF]);

    /* ══ A. Structural: one-hot encodings (design §0.5 "Columns", F1/F8) ═══
     * Counters are ONE-HOT columns, not annotations: each flag boolean and the
     * slot sum exactly 1. il_flag[0] is thereby the is-zero gadget for the
     * absorb/squeeze guard (`duplex_challenger.c:74`, :127) with no inverse
     * hint. Same for the row-type selectors, sel_filler included. */
    {
        gold_fp_t sum = zero;
        for (size_t s = 0; s < TAIR_NUM_SEL; s++) {
            az_bool_gated(&v, one, sel[s]);
            sum = add(sum, sel[s]);
        }
        az(&v, sub(sum, one));
    }
    {
        gold_fp_t isum = zero, osum = zero, psum = zero;
        for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) {
            az_bool_gated(&v, one, il[k]);
            az_bool_gated(&v, one, ol[k]);
            isum = add(isum, il[k]);
            osum = add(osum, ol[k]);
        }
        az(&v, sub(isum, one));
        az(&v, sub(osum, one));
        for (size_t k = 0; k < TAIR_PREFIX_SLOTS; k++) {
            az_bool_gated(&v, one, pc[k]);
            psum = add(psum, pc[k]);
        }
        az(&v, sub(psum, one));
    }

    /* A2 — input_len == RATE is UNREACHABLE as a row-entry state: the native
     * observe duplexes eagerly the instant the buffer fills, so it drains to 0
     * within the same call (`duplex_challenger.c:112-114`). Without this
     * constraint a prover could enter sel_sample_dup with il_flag[4] = 1, where
     * NO absorb branch (k in 1..3) pins the permutation preimage — the rate
     * lanes would be free. Load-bearing, DNAC-owned (design §0.5 calls the
     * 0..4 range "structural"; this is that structure discharged). */
    az(&v, mul(g_op, il[TAIR_RATE]));

    /* A3 — is_pow modifier: boolean, and only a sampling row may carry it
     * (design §0.5 check_pow_witness: PoW is a sample_bits row, not a new
     * archetype; `duplex_challenger.c:156-157`). */
    az_bool_gated(&v, one, is_pow);
    az(&v, mul(is_pow, sub(one, g_sampling)));

    /* ══ B. Embedded poseidon2_air block — UNGATED (design §0.5 F4) ════════
     * Binding is by COLUMN IDENTITY: the pins below reference these very cells.
     * Evaluating the block unconditionally mirrors the shipped inline precedent
     * (`conf_action_fold.c:133-134`, :190-192) and leaves no gate to aim at;
     * non-duplexing rows carry a valid dummy permutation witness. */
    v += poseidon2_air_eval_row(local + TAIR_PERM_OFF);

    /* ══ C. Boundary: trace row 0 MUST be sel_start (design §0.5 F3/F6) ════ */
    if (is_first_row) az(&v, sub(one, s_start));

    /* ══ D. Sampling rows: canonical bit exposure (design §0.5 "sample_bits
     * rows", G-DET-P2a-4 / G-SEC-P2a-5). All THREE properties are AIR-owned —
     * booleanity, reconstruction, and `< p` — per the F9-corrected grounding
     * (upstream constrains all three itself: booleanity
     * `circuit_builder.rs:1213`, reconstruction :1099-1101, canonicality
     * :1107-1109 whose doc comment names the F-S index-shift attack). ══════ */
    {
        gold_fp_t recomp = zero, weight = one;
        gold_fp_t hi_ones = zero, low_sum = zero;
        for (size_t i = 0; i < TAIR_BITS; i++) {
            const gold_fp_t b = fp(local[tair_bit_off(i)]);
            az_bool_gated(&v, g_sampling, b); /* booleanity */
            recomp = add(recomp, mul(b, weight));
            weight = add(weight, weight); /* 2^i, doubled in-field */
            if (i < trailing) low_sum = add(low_sum, b);
            else hi_ones = add(hi_ones, b);
        }
        /* Reconstruction: sum b_i 2^i == the popped challenge lane. */
        az(&v, mul(g_sampling, sub(recomp, lane)));

        /* Canonicality `< p`, ADAPTATION of assert_bits_canonical (see header).
         * S == 0 iff every bit above the trailing-zero run of p-1 is 1, i.e.
         * iff the high prefix equals p-1's. `isz` is that is-zero indicator. */
        const gold_fp_t S = sub(fp((uint64_t)(64u - trailing)), hi_ones);
        const gold_fp_t isz = fp(local[TAIR_CANON_ISZ_OFF]);
        const gold_fp_t inv = fp(local[TAIR_CANON_INV_OFF]);
        az_bool_gated(&v, g_sampling, isz);
        az(&v, mul(g_sampling, sub(mul(S, inv), sub(one, isz))));
        az(&v, mul(g_sampling, mul(S, isz)));
        /* If the high prefix equals p-1, every low bit must be zero — the one
         * constraint the trailing-zero run collapses into (:1148-1157). */
        az(&v, mul(g_sampling, mul(isz, low_sum)));

        /* PoW: the exposed low `pow_bits` of the challenge are zero
         * (`duplex_challenger.c:157` sample_bits(bits) == 0 <-> circuit.rs:409-430). */
        for (size_t i = 0; i < cfg->pow_bits; i++)
            az(&v, mul(is_pow, fp(local[tair_bit_off(i)])));
    }

    /* ══ E. DS-prefix, row-local half (design §0.5 "DS-prefix rows", F6) ═══
     * While prefix_ctr < 4 the only admissible rows are the prefix observes
     * themselves and an instance reset. A sample/sample_dup/filler row here is
     * unsatisfiable — that is what makes a prefix-skip or a mid-prefix squeeze
     * impossible (G-SEC-P2a-3). `sel_start` is admitted because its own
     * prefix_ctr is the INHERITED (don't-care) value; the reset it forces on the
     * next row is what actually starts the count. */
    {
        const gold_fp_t pre_active = sub(one, pc[4]);
        az(&v, mul(pre_active, sub(one, add(g_observe, s_start))));
        /* The observed lane IS the pinned DS limb for the current counter value
         * (`duplex_challenger.c:32-37`, applied at :96-103). */
        for (size_t k = 0; k < TAIR_RATE; k++)
            az(&v, mul(g_observe, mul(pc[k], sub(lane, fp(DNAC_DUPLEX_DS_PREFIX[k])))));
    }

    if (!next) return v; /* last row: no transition constraints */

    /* ── next-row reads ─────────────────────────────────────────────────── */
    gold_fp_t nil_[TAIR_LEN_SLOTS], nol[TAIR_LEN_SLOTS], npc[TAIR_PREFIX_SLOTS];
    for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) {
        nil_[k] = fp(next[tair_il_off(k)]);
        nol[k] = fp(next[tair_ol_off(k)]);
    }
    for (size_t k = 0; k < TAIR_PREFIX_SLOTS; k++) npc[k] = fp(next[tair_prefix_off(k)]);

    /* ══ F. sel_start — instance boundary (design §0.5, F3/F6) ═════════════
     * The ONLY row type that may zero the state. Mirrors `dnac_duplex_init`
     * (`duplex_challenger.c:91-94`: memset of the whole struct). State
     * inheritance across instances is therefore unsatisfiable, not merely
     * discouraged. (Per design §0.5 the reset list is exactly these four items;
     * input_buffer is deliberately NOT reset — cells at or above input_len are
     * provably never read, since every absorb reads only buffer[0..input_len)
     * and each of those was written by an observe since the last drain.) */
    for (size_t i = 0; i < TAIR_STATE_LANES; i++)
        az(&v, mul(s_start, fp(next[tair_state_off(i)])));
    az(&v, mul(s_start, sub(one, nil_[0])));
    az(&v, mul(s_start, sub(one, nol[0])));
    az(&v, mul(s_start, sub(one, npc[0])));

    /* ══ G. DS-prefix counter threading (design §0.5, F6) ══════════════════ */
    {
        /* Observe rows advance the counter, saturating at 4. */
        for (size_t k = 0; k < TAIR_RATE; k++)
            az(&v, mul(g_observe, mul(pc[k], sub(one, npc[k + 1]))));
        az(&v, mul(g_observe, mul(pc[4], sub(one, npc[4]))));
        /* Every other non-reset row copies it. */
        const gold_fp_t g_copy = add(g_sampling, s_fill);
        for (size_t k = 0; k < TAIR_PREFIX_SLOTS; k++)
            az(&v, mul(g_copy, sub(npc[k], pc[k])));
    }

    /* ══ H. sel_obs — observe, input_len < 3 (design §0.5) ═════════════════
     * Native: `dnac_duplex_observe_fp` (`duplex_challenger.c:105-115`) —
     * output invalidated (:108), lane appended at input_len (:110), NO duplex
     * because the buffer does not reach RATE. Upstream `circuit.rs:337-349`. */
    {
        /* Precondition (F2): a 4th observe is sel_obs_dup, never sel_obs. */
        az(&v, mul(s_obs, il[3]));
        /* Any buffered output is now invalid (:108). */
        az(&v, mul(s_obs, sub(one, nol[0])));
        /* input_buffer'[input_len] = lane, other lanes copied — witness-indexed
         * write realized as an il_flag one-hot product (F10). */
        for (size_t j = 0; j < TAIR_RATE; j++) {
            const gold_fp_t nb = fp(next[tair_inbuf_off(j)]);
            const gold_fp_t b = fp(local[tair_inbuf_off(j)]);
            az(&v, mul(s_obs, mul(il[j], sub(nb, lane))));
            az(&v, mul(s_obs, mul(sub(one, il[j]), sub(nb, b))));
        }
        /* input_len' = input_len + 1 (il_flag[4] entry excluded by A2). */
        for (size_t j = 0; j < TAIR_RATE; j++)
            az(&v, mul(s_obs, mul(il[j], sub(one, nil_[j + 1]))));
        /* Sponge untouched (F3 threading). */
        for (size_t i = 0; i < TAIR_STATE_LANES; i++)
            az(&v, mul(s_obs, sub(fp(next[tair_state_off(i)]), fp(local[tair_state_off(i)]))));
    }

    /* ══ I. sel_obs_dup — 4th observe + eager duplex, ONE row (design §0.5,
     * F2) ═════════════════════════════════════════════════════════════════
     * Native: the duplex fires INSIDE the 4th observe
     * (`duplex_challenger.c:112-114` -> `dc_duplexing` :67-89). num_absorbed
     * is 4, so the rate clear (:76-78) is VACUOUS and the length tag (:80-82)
     * is `state[RATE] += 4` — a field ADD, not a store. */
    {
        /* Precondition (F2). */
        az(&v, mul(s_obsd, sub(one, il[3])));
        /* Permutation preimage: the three buffered lanes + this lane overwrite
         * state[0..4] (:70-72); capacity lane carries the +4 length tag; the
         * remaining capacity lanes pass through. */
        for (size_t j = 0; j < TAIR_RATE - 1; j++)
            az(&v, mul(s_obsd, sub(fp(local[tair_perm_in_off(j)]),
                                   fp(local[tair_inbuf_off(j)]))));
        az(&v, mul(s_obsd, sub(fp(local[tair_perm_in_off(TAIR_RATE - 1)]), lane)));
        az(&v, mul(s_obsd, sub(fp(local[tair_perm_in_off(TAIR_RATE)]),
                               add(fp(local[tair_state_off(TAIR_RATE)]),
                                   fp((uint64_t)TAIR_RATE)))));
        for (size_t j = TAIR_RATE + 1; j < TAIR_STATE_LANES; j++)
            az(&v, mul(s_obsd, sub(fp(local[tair_perm_in_off(j)]),
                                   fp(local[tair_state_off(j)]))));
        /* sponge_state' = perm(preimage) — the embedded block's own constraints
         * (evaluated in B) are what make `out` a real permutation image. */
        for (size_t i = 0; i < TAIR_STATE_LANES; i++)
            az(&v, mul(s_obsd, sub(fp(next[tair_state_off(i)]),
                                   fp(local[tair_perm_out_off(i)]))));
        /* Buffer thread: the observe wrote lane at slot 3 (:110); the duplex
         * clears the LENGTH (:73) but leaves the buffer contents. */
        for (size_t j = 0; j < TAIR_RATE - 1; j++)
            az(&v, mul(s_obsd, sub(fp(next[tair_inbuf_off(j)]),
                                   fp(local[tair_inbuf_off(j)]))));
        az(&v, mul(s_obsd, sub(fp(next[tair_inbuf_off(TAIR_RATE - 1)]), lane)));
        /* input_len' = 0; output_len' = RATE (refill, :85-88). */
        az(&v, mul(s_obsd, sub(one, nil_[0])));
        az(&v, mul(s_obsd, sub(one, nol[TAIR_RATE])));
    }

    /* ══ J. sel_sample — pop only (design §0.5) ════════════════════════════
     * Native: `dnac_duplex_sample_fp` (`duplex_challenger.c:124-132`) takes the
     * NO-duplex path exactly when the input buffer is empty AND the output
     * buffer is not (:127). LIFO pop from the END (:131).
     *
     * output_buffer has no columns of its own: between duplexings
     * output_buffer[i] == sponge_state[i], because the refill IS
     * output_buffer = sponge_state[0..RATE] (:85-88) and every non-duplex row
     * copies the sponge. The pop therefore reads sponge_state[output_len - 1]
     * directly (design §0.5 F10 invariant). */
    {
        /* Preconditions (F2), as constraints on threaded columns. */
        az(&v, mul(s_smp, sub(one, il[0])));
        az(&v, mul(s_smp, ol[0]));
        for (size_t k = 1; k < TAIR_LEN_SLOTS; k++) {
            /* challenge = sponge_state[output_len - 1] (one-hot select). */
            az(&v, mul(s_smp, mul(ol[k], sub(lane, fp(local[tair_state_off(k - 1)])))));
            /* output_len' = output_len - 1. */
            az(&v, mul(s_smp, mul(ol[k], sub(one, nol[k - 1]))));
        }
        /* Sponge + buffer + input_len all threaded unchanged. */
        for (size_t i = 0; i < TAIR_STATE_LANES; i++)
            az(&v, mul(s_smp, sub(fp(next[tair_state_off(i)]), fp(local[tair_state_off(i)]))));
        for (size_t j = 0; j < TAIR_RATE; j++)
            az(&v, mul(s_smp, sub(fp(next[tair_inbuf_off(j)]), fp(local[tair_inbuf_off(j)]))));
        az(&v, mul(s_smp, sub(one, nil_[0])));
    }

    /* ══ K. sel_sample_dup — duplex then pop, ONE row (design §0.5) ════════
     * Native: `dnac_duplex_sample_fp` :127-129 duplexes when input is pending
     * OR output is empty, then pops. The branch condition is il_flag[0] — a
     * real threaded column, never a hint (G-SEC-P2a-2).
     *   absorb (input_len = k > 0): overwrite state[0..k) with the buffer
     *     (:70-72), CLEAR rate slots [k, RATE) (:76-78), ADD the length tag k
     *     into state[RATE] (:80-82);
     *   squeeze (k == 0): permute the state UNTOUCHED — no clear, no tag; that
     *     is precisely what the `num_absorbed > 0` guard (:74) buys. */
    {
        /* Precondition (F2): NOT(buffer empty AND output non-empty) — the
         * complement of sel_sample's precondition, so the two archetypes
         * partition the sampling rows. */
        az(&v, mul(s_smpd, mul(il[0], sub(one, ol[0]))));

        /* Rate lanes of the preimage. */
        for (size_t j = 0; j < TAIR_RATE; j++) {
            const gold_fp_t pin = fp(local[tair_perm_in_off(j)]);
            /* squeeze branch: state passes through untouched. */
            az(&v, mul(s_smpd, mul(il[0], sub(pin, fp(local[tair_state_off(j)])))));
            /* absorb branch, num_absorbed = k in 1..RATE-1 (k == RATE is
             * excluded by A2; k == RATE can only arise inside sel_obs_dup). */
            for (size_t k = 1; k < TAIR_RATE; k++) {
                if (j < k) /* absorbed lane */
                    az(&v, mul(s_smpd, mul(il[k], sub(pin, fp(local[tair_inbuf_off(j)])))));
                else /* rate clear */
                    az(&v, mul(s_smpd, mul(il[k], pin)));
            }
        }
        /* Capacity lane: squeeze passes through, absorb adds the length tag. */
        {
            const gold_fp_t cap_in = fp(local[tair_perm_in_off(TAIR_RATE)]);
            const gold_fp_t cap = fp(local[tair_state_off(TAIR_RATE)]);
            az(&v, mul(s_smpd, mul(il[0], sub(cap_in, cap))));
            for (size_t k = 1; k < TAIR_RATE; k++)
                az(&v, mul(s_smpd, mul(il[k], sub(cap_in, add(cap, fp((uint64_t)k))))));
        }
        /* Remaining capacity lanes pass through in BOTH branches. */
        for (size_t j = TAIR_RATE + 1; j < TAIR_STATE_LANES; j++)
            az(&v, mul(s_smpd, sub(fp(local[tair_perm_in_off(j)]),
                                   fp(local[tair_state_off(j)]))));
        /* sponge_state' = perm(preimage). */
        for (size_t i = 0; i < TAIR_STATE_LANES; i++)
            az(&v, mul(s_smpd, sub(fp(next[tair_state_off(i)]),
                                   fp(local[tair_perm_out_off(i)]))));
        /* The refill sets output_len = RATE and output_buffer = state'[0..RATE)
         * (:85-88); the LIFO pop then takes index RATE-1 of the POST state and
         * leaves output_len' = RATE - 1. */
        az(&v, mul(s_smpd, sub(lane, fp(local[tair_perm_out_off(TAIR_RATE - 1)]))));
        az(&v, mul(s_smpd, sub(one, nol[TAIR_RATE - 1])));
        /* input_len' = 0 (:73); buffer contents survive the drain. */
        az(&v, mul(s_smpd, sub(one, nil_[0])));
        for (size_t j = 0; j < TAIR_RATE; j++)
            az(&v, mul(s_smpd, sub(fp(next[tair_inbuf_off(j)]), fp(local[tair_inbuf_off(j)]))));
    }

    /* ══ L. sel_filler — inert and TERMINAL (design §0.5, F8) ══════════════
     * Padding is a CONSTRAINED row type, not an absence: it copies every piece
     * of threaded state, observes nothing, exposes nothing, and once padding
     * starts it never stops — so a filler cannot inject an absorb mid-stream. */
    {
        for (size_t i = 0; i < TAIR_STATE_LANES; i++)
            az(&v, mul(s_fill, sub(fp(next[tair_state_off(i)]), fp(local[tair_state_off(i)]))));
        for (size_t j = 0; j < TAIR_RATE; j++)
            az(&v, mul(s_fill, sub(fp(next[tair_inbuf_off(j)]), fp(local[tair_inbuf_off(j)]))));
        for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) {
            az(&v, mul(s_fill, sub(nil_[k], il[k])));
            az(&v, mul(s_fill, sub(nol[k], ol[k])));
        }
        az(&v, mul(s_fill, sub(one, fp(next[tair_sel_off(TAIR_SEL_FILLER)]))));
    }

    return v;
}

int dnac_transcript_air_eval_trace(const uint64_t *trace, size_t n_rows,
                                   const dnac_tair_config_t *cfg) {
    if (!trace || n_rows == 0) return TAIR_VIOL_BAD_CONFIG;
    int total = 0;
    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *local = trace + r * (size_t)TAIR_WIDTH;
        const uint64_t *next = (r + 1 < n_rows) ? local + TAIR_WIDTH : NULL;
        const int v = dnac_transcript_air_eval_row(local, next, r == 0, cfg);
        if (v >= TAIR_VIOL_BAD_CONFIG) return TAIR_VIOL_BAD_CONFIG;
        total += v;
    }
    return total;
}
