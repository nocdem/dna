/**
 * @file stark_prover.h
 * @brief C STARK prover — stage S1: RangeProofAir witness-trace builder.
 *
 * First stage of the C prover for the M3a RangeProofAir circuit (the AUDITED
 * 2026-07 mint-fixed 52-bit range + balance AIR, width 56, publics
 * [claimed_input_sum, committed_fee, n_real]). Port of the oracle's
 * `generate_range_proof_trace` (tools/plonky3_oracle/src/main.rs::generate_range_proof_trace),
 * which produces the trace handed unmodified to `p3_uni_stark::prove`
 * (Plonky3 82cfad73 uni-stark/src/prover.rs::prove).
 *
 * Column-layout binding contract (oracle main.rs RangeProofAir column offsets; extends the
 * range_air.h / sum_balance.h contracts):
 *
 *   Cols 0..RANGE_AIR_BITS-1        = little-endian amount bits (range_air)
 *   Col  RANGE_AIR_AMOUNT_OFF (52)  = amount                    (range_air)
 *   Col  SUM_BALANCE_ACC_OFF  (53)  = running amount sum        (sum_balance)
 *   Col  STARK_PROVER_IS_REAL_OFF   = 1 real row / 0 padding    (54)
 *   Col  STARK_PROVER_CNT_OFF       = running is_real count     (55)
 *   Total width = STARK_PROVER_RANGE_PROOF_WIDTH (56).
 *
 * Padding rows (row >= n_real; oracle main.rs::generate_range_proof_trace (padding arm)): bits and amount
 * are zero, is_real is zero, and acc / cnt stay FLAT at their last real-row
 * values.
 *
 * SCOPE. This stage is DETERMINISTIC: it is the pre-randomization witness.
 * The is_zk=1 hiding transform (random codeword columns + doubled domain,
 * Plonky3 fri/src/hiding_pcs.rs:110-129) happens inside the PCS commit and
 * belongs to later prover stages (S2/S4) — S1 output MUST NOT be randomized.
 *
 * Determinism: prover runs client-side only (never in consensus); this
 * builder is a pure function of its arguments. Byte-match KAT:
 * tools/vectors/prover_trace_range_zk.json (tests/test_prover_trace.c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_STARK_PROVER_H
#define DNAC_ZK_STARK_PROVER_H

#include <stddef.h>
#include <stdint.h>

#include "merkle_smt.h"
#include "range_air.h"
#include "sum_balance.h"
#include "transcript.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Column-layout binding contract (extends range_air + sum_balance)
 * ========================================================================== */

/** Offset of the is_real flag cell (oracle RangeProofAir COL_IS_REAL = 54). */
#define STARK_PROVER_IS_REAL_OFF        (SUM_BALANCE_ACC_OFF + (size_t)1)

/** Offset of the running-count cell (oracle RangeProofAir COL_CNT = 55). */
#define STARK_PROVER_CNT_OFF            (SUM_BALANCE_ACC_OFF + (size_t)2)

/** Combined RangeProofAir trace width (oracle RANGE_PROOF_WIDTH = 56). */
#define STARK_PROVER_RANGE_PROOF_WIDTH  (SUM_BALANCE_WIDTH + (size_t)2)

/** Maximum trace height = SUM_BALANCE_MAX_OUTPUTS (2^10; oracle
 *  RANGE_PROOF_MAX_DEGREE_BITS, wrap-safety bound). */
#define STARK_PROVER_MAX_HEIGHT         SUM_BALANCE_MAX_OUTPUTS

/** Maximum BASE trace width the parametric stages accept (size_t-overflow
 *  guard bound, NOT a protocol constant). Raised 2026-07-15 from the
 *  RangeProofAir width (56) to cover the B1 Stage-2 combined conf AIR
 *  (CONF_ROOT_WIDTH = 614); 640 matches DNAC_STARK_MAX_MAIN_WIDTH. With
 *  height <= 2^10 and per_row <= 640 + 2*num_random, every height*per_row
 *  product stays far below SIZE_MAX. */
#define DNAC_PROVER_MAX_TRACE_WIDTH     ((size_t)640)

/* ============================================================================
 * Status codes (separate from every existing zk status enum)
 * ========================================================================== */

typedef enum {
    DNAC_PROVER_OK = 0,
    /** NULL pointer / height not a power of two / height 0 or > MAX_HEIGHT /
     *  n_real 0 or > height. Power-of-two is required because
     *  p3_uni_stark::prove takes log2_strict_usize(height) (prover.rs::prove log2_strict_usize). */
    DNAC_PROVER_ERR_PARAM = 1,
    /** An amount is >= 2^RANGE_AIR_BITS (oracle generate_range_proof_trace
     *  amount < 2^RANGE_AIR_BITS assert;
     *  fail-close — never canonicalize/truncate an out-of-range amount). */
    DNAC_PROVER_ERR_RANGE = 2,
    /** A supplied random field element is >= Goldilocks p (fail-close;
     *  Plonky3 draws are rejection-sampled canonical, goldilocks.rs:184-193). */
    DNAC_PROVER_ERR_NONCANONICAL = 3,
    /** The end-to-end self-verify (prime + dnac_fri_verify) unexpectedly
     *  failed — an internal inconsistency; the prover rejects its own proof. */
    DNAC_PROVER_ERR_VERIFY = 4,
} dnac_prover_status_t;

/* ============================================================================
 * S1 — witness trace builder
 * ========================================================================== */

/**
 * Build the deterministic RangeProofAir witness trace.
 *
 * Port of oracle `generate_range_proof_trace` (main.rs::generate_range_proof_trace): zeroes
 * the buffer (Goldilocks::zero_vec, field.rs:386), fills bit/amount/acc via
 * the existing range_air/sum_balance builders for the n_real real rows, sets
 * is_real=1 and cnt=row+1 on real rows, and keeps acc/cnt flat (is_real=0,
 * amount=0) on padding rows.
 *
 * @param amounts   n_real output amounts, each < 2^RANGE_AIR_BITS.
 * @param n_real    number of real rows, in [1, height].
 * @param height    trace height: power of two, <= STARK_PROVER_MAX_HEIGHT.
 * @param out_trace height * STARK_PROVER_RANGE_PROOF_WIDTH cells, overwritten.
 * @param out_total optional (may be NULL): Sum(amounts) — < 2^62, so the
 *                  Goldilocks sum equals the integer sum (sum_balance.h bound).
 */
dnac_prover_status_t dnac_prover_build_range_proof_trace(
    const uint64_t *amounts,
    size_t n_real,
    size_t height,
    uint64_t *out_trace,
    uint64_t *out_total);

/* ============================================================================
 * S2 — is_zk trace randomization + coset LDE (bit-reversed rows)
 * ========================================================================== */

/**
 * is_zk=1 trace randomization (HidingFriPcs::commit, Plonky3 82cfad73
 * fri/src/hiding_pcs.rs:110-129 + matrix/src/dense.rs:573-597): interleave the
 * base trace with random rows and append random codeword columns —
 * `with_random_cols(width + 2*num_random)` followed by the width :=
 * width + num_random reshape. Net layout, per base row i:
 *
 *   out row 2i   = base row i (width cells) ++ rand[i-th block, 0..num_random)
 *   out row 2i+1 = rand[i-th block, num_random..width+2*num_random)
 *
 * where rand consumes width + 2*num_random values PER BASE ROW, row-major
 * left-to-right (dense.rs:588-593) — exactly the oracle's `random_draws`
 * order. Randomness is CALLER-SUPPLIED (design pin D1 Option B): the KAT
 * feeds the oracle-dumped SmallRng(seed=1) draws; production feeds OS entropy
 * (getrandom) — hiding, not soundness, depends on it. Every supplied value
 * must be canonical (< p), as Plonky3's draws are (goldilocks.rs:184-193).
 *
 * @param base       height x width row-major base matrix.
 * @param height     base height (>= 1).
 * @param width      base width (>= 1).
 * @param num_random random codeword columns (>= 1; M3a: 4).
 * @param rand_vals  height * (width + 2*num_random) canonical field elements
 *                   in draw order.
 * @param out        (2*height) x (width + num_random) cells, overwritten.
 */
dnac_prover_status_t dnac_prover_randomize_trace(
    const uint64_t *base,
    size_t height,
    size_t width,
    size_t num_random,
    const uint64_t *rand_vals,
    uint64_t *out);

/**
 * Per-column coset LDE with bit-reversed row storage — the commit-side
 * transform of TwoAdicFriPcs::commit (Plonky3 82cfad73
 * fri/src/two_adic_pcs.rs:301-325):
 *
 *   per column: iNTT(log2 height) -> zero-pad coefficients to
 *   height<<log_blowup (dft/src/traits.rs:254-261) -> coeff[j] *= shift^j
 *   (traits.rs:83-91) -> forward NTT(log2(height<<log_blowup));
 *   then permute ROWS by 5-bit (log2 lde_height) reversal
 *   (two_adic_pcs.rs:318 bit_reverse_rows, matrix/src/util.rs:36-57).
 *
 * For the trace commit the shift is GENERATOR / domain.shift() = 7/1 = 7
 * (two_adic_pcs.rs:313, goldilocks.rs:400) and log_blowup = fri.log_blowup
 * (NO extra +1 under is_zk — the height doubling comes from the
 * randomization reshape; hiding_pcs.rs:131 delegates unchanged).
 *
 * @param mat        height x width row-major evaluations (canonical).
 * @param height     power of two, >= 2.
 * @param width      >= 1.
 * @param log_blowup >= 1 (M3a: 2).
 * @param shift      canonical coset shift (M3a: 7).
 * @param out        (height << log_blowup) x width cells, overwritten;
 *                   rows stored in bit-reversed order.
 */
dnac_prover_status_t dnac_prover_coset_lde_bitrev(
    const uint64_t *mat,
    size_t height,
    size_t width,
    unsigned log_blowup,
    uint64_t shift,
    uint64_t *out);

/* ============================================================================
 * S3 — matrix commit (Merkle tree BUILD over the bit-reversed LDE)
 * ========================================================================== */

/**
 * Commit a row-major field matrix: serialize each row as canonical u64 LE
 * (8 bytes/element, columns left-to-right — Plonky3 82cfad73
 * merkle-tree/src/merkle_tree.rs:302-322 leaf hashing over the row via the
 * u8-serializing SHA3-512 hasher) and build the binary SHA3-512 Merkle tree
 * via the existing oracle-byte-matched dnac_merkle_commit (leaf =
 * SHA3-512(row bytes), parent = SHA3-512(left ‖ right), cap_height=0 ⇒
 * commitment = single 64-byte root). The matrix must arrive ALREADY
 * bit-reversed (S2 output) — no reordering happens here
 * (two_adic_pcs.rs:317-324: bit_reverse_rows precedes mmcs.commit).
 *
 * On success *out_tree owns the tree (keep it: the FRI query stage opens
 * rows/paths from it); free with dnac_merkle_tree_free. out_root receives
 * the 64-byte commitment (== proof.commitments.trace for the trace commit).
 *
 * @param mat      height x width row-major canonical field elements.
 * @param height   power of two, >= 2 (Merkle build requirement).
 * @param width    >= 1.
 * @param out_root 64-byte commitment digest.
 * @param out_tree owned tree handle (required — the prover must retain it).
 */
dnac_prover_status_t dnac_prover_commit_matrix(
    const uint64_t *mat,
    size_t height,
    size_t width,
    uint8_t out_root[DNAC_MERKLE_DIGEST_BYTES],
    dnac_merkle_tree_t **out_tree);

/* ============================================================================
 * S5 — Fiat-Shamir to alpha (prover-side transcript sequencer)
 * ========================================================================== */

/**
 * Drive the prover transcript from its INITIAL state to the STARK constraint
 * challenge alpha — the prover half of the sequence the verifier replays in
 * stark_priming.c steps (1)-(7) (Plonky3 82cfad73 uni-stark/src/prover.rs:
 * 161-163 observe instance scalars, :167 observe trace commitment, :173
 * observe public values, :195 sample alpha; byte semantics
 * serializing_challenger.rs:254-259/301-311 + hash_challenger.rs:51-57).
 *
 * The caller creates the transcript with dnac_transcript_init_default() and
 * MUST keep the SAME object alive through the later prover stages (S6-S11
 * continue on this exact state: the quotient-commit observe is next).
 * dnac_stark_prime_transcript is NOT reused: it requires the full proof
 * upfront, which does not exist at prover time (design pin D4 — the audited
 * verifier-side sequencer stays untouched).
 *
 * For M3a: log_ext_degree=3 (= proof degree_bits), log_degree=2 (base),
 * preprocessed_width=0, publics [claimed=107, fee=7, n_real=4]; pre-alpha
 * input buffer = init(25) || 3 x le64 || trace_root(64) || 3 x le64 = 137 B.
 *
 * @param t                 live transcript at the INITIAL (init_default) state.
 * @param log_ext_degree    prover.rs:45 log_degree + is_zk (M3a: 3).
 * @param log_degree        base log2(trace height) (M3a: 2).
 * @param preprocessed_width 0 for RangeProofAir (no preprocessed columns).
 * @param trace_root        64-byte S3 trace commitment.
 * @param publics           base-field public values, AIR order.
 * @param n_publics         number of public values (M3a: 3).
 * @param out_alpha         sampled constraint-fold challenge (Goldilocks^2).
 */
dnac_prover_status_t dnac_prover_fs_to_alpha(
    dnac_transcript_t *t,
    uint64_t log_ext_degree,
    uint64_t log_degree,
    uint64_t preprocessed_width,
    const uint8_t trace_root[DNAC_MERKLE_DIGEST_BYTES],
    const uint64_t *publics,
    size_t n_publics,
    gold_fp2_t *out_alpha);

/* ============================================================================
 * S6 — quotient polynomial computation (prover.rs:200-235 / :399-513)
 * ========================================================================== */

/**
 * Lagrange selectors of the size-2^log_n natural trace domain (shift ONE),
 * evaluated over the size-2^log_coset coset shift*K in NATURAL order — port
 * of Plonky3 82cfad73 commit/src/domain.rs:277-317 selectors_on_coset:
 *
 *   zh[k]            = shift^n * g_rate^k − 1        (k mod 2^rate_bits cycle)
 *   x[i]             = shift * g_coset^i
 *   is_first_row[i]  = zh[i%] / (x[i] − 1)
 *   is_last_row[i]   = zh[i%] / (x[i] − gN^{n−1})    (gN^{n−1} = gN^{-1})
 *   is_transition[i] = x[i] − gN^{-1}
 *   inv_vanishing[i] = 1 / zh[i%]
 *
 * All outputs length 2^log_coset, base-field canonical. Requires
 * log_coset > log_n (coset shift != ONE, domain.rs:278-280) and a canonical
 * nonzero shift.
 */
dnac_prover_status_t dnac_prover_quotient_selectors(
    unsigned log_n,
    unsigned log_coset,
    uint64_t shift,
    uint64_t *is_first_row,
    uint64_t *is_last_row,
    uint64_t *is_transition,
    uint64_t *inv_vanishing);

/**
 * Extract the trace rows over the quotient domain from the committed
 * bit-reversed LDE (two_adic_pcs.rs:366-374 + hiding_pcs.rs:263-279): output
 * row j (natural quotient order) = stored row reverse_bits(j*stride) of the
 * bit-reversed LDE, columns 0..out_width (the HidingFriPcs truncation of the
 * random codeword columns), stride = lde_height / q_rows.
 *
 * M3a: lde 32x60 -> quotient trace 16x56 (stride 2, drop 4 random cols).
 */
dnac_prover_status_t dnac_prover_trace_on_quotient_domain(
    const uint64_t *lde_bitrev,
    size_t lde_height,
    size_t lde_width,
    size_t q_rows,
    size_t out_width,
    uint64_t *out);

/**
 * Domain-wide quotient evaluation for the AUDITED RangeProofAir (61
 * constraints, oracle main.rs:10148-10192 pinned emission order — the SAME
 * formulas the GREEN verifier-side air_eval checks at one point, here run
 * over every quotient-domain row in the base field). Per row i
 * (prover.rs:457-513, scalar equivalent of the packed loop):
 *
 *   local = trace_q row i;  next = trace_q row (i + next_step) mod q_rows
 *   fold the 61 constraints with descending alpha powers via Horner
 *   (acc = acc*alpha + C_j — identical to the verifier fold, folder.rs:216)
 *   out[i] = acc * inv_vanishing[i]
 *
 * trace_q is the 16x56 NATURAL-order output of
 * dnac_prover_trace_on_quotient_domain; publics = [claimed, fee, n_real];
 * out_q holds q_rows fp2 values as (c0,c1) u64 pairs.
 */
dnac_prover_status_t dnac_prover_quotient_values_range_zk(
    const uint64_t *trace_q,
    size_t q_rows,
    size_t next_step,
    const uint64_t publics[3],
    gold_fp2_t alpha,
    const uint64_t *is_first_row,
    const uint64_t *is_last_row,
    const uint64_t *is_transition,
    const uint64_t *inv_vanishing,
    uint64_t *out_q);

/**
 * Flatten + round-robin chunk split (prover.rs:235 flatten_to_base +
 * domain.rs:213-246 split_evals): the fp2 quotient values ARE the 2-column
 * base flat matrix (row i = [c0,c1]); chunk c (c in 0..num_chunks) takes
 * global rows {c, c+num_chunks, c+2*num_chunks, ...} in order. out_chunks =
 * num_chunks consecutive (rows/num_chunks)x2 row-major matrices.
 */
dnac_prover_status_t dnac_prover_quotient_split(
    const uint64_t *flat,
    size_t rows,
    size_t num_chunks,
    uint64_t *out_chunks);

/* ============================================================================
 * S7 — quotient blinding + per-chunk LDE + ONE multi-matrix commit
 * ========================================================================== */

/**
 * The quotient-COMMIT transform of HidingFriPcs (Plonky3 82cfad73
 * fri/src/hiding_pcs.rs:169-261 get_quotient_ldes + inner mmcs commit),
 * eprint 2024/1037 randomization:
 *
 *   1. round-robin split of the 16x2 flat quotient into num_chunks (4)
 *      chunk-eval matrices 4x2 on the split cosets shift_i = q_shift * k^i
 *      (k = two_adic_generator(log2(q_rows)); domain.rs:199-246);
 *   2. Lagrange constants: cis = batch_inv over i of
 *      prod_{j != i} ((shift_i/shift_j)^h − 1)  (get_zp_cis,
 *      hiding_pcs.rs:451-469; Z_D(x) = (x/shift)^size − 1);
 *      mul_coeffs[j] = cis[j] / cis[last];
 *   3. widen each chunk with num_random codeword columns (caller-supplied
 *      draws, chunk-major then row-major — pin D1-B);
 *   4. blinding block: all_random[c][k] = caller draws for c < last; LAST
 *      block DERIVED: -= mul_coeffs[j]*block_j (sum cancels so recomposition
 *      at zeta is unchanged, hiding_pcs.rs:194-208);
 *   5. per chunk: coset LDE with added_bits = log_blowup+1 and
 *      lde_shift = GENERATOR/shift_i (natural order), PLUS the evaluation of
 *      v_H(X)*t_c(X) built from the blinding block (vanishing-poly coeff
 *      trick, hiding_pcs.rs:229-247: coeff[r] = −7^r·t, coeff[h+r] = p·7^r·t,
 *      p = lde_shift^h; plain forward DFT), elementwise add, bit-reverse rows;
 *   6. ONE SHA3-512 multi-matrix commit over the num_chunks 32x6 matrices
 *      (equal height ⇒ leaf = concatenated rows; existing Phase 2A
 *      dnac_merkle_batch_commit, byte-matched to MerkleTreeMmcs).
 *
 * codeword_rand: num_chunks * rows_per_chunk * num_random values (M3a: 64).
 * blinding_rand: (num_chunks−1) * rows_per_chunk * (2+num_random) (M3a: 72).
 * Both canonical; KAT feeds the oracle-dumped SmallRng(1) draws (stream
 * position = after the trace commit's 256), production feeds OS entropy.
 *
 * out_chunk_ldes (required): num_chunks * lde_height * (2+num_random) cells —
 * the final bit-reversed blinded LDEs (also the S12 open source).
 * out_tree: the batch tree (keep for FRI query openings; free with
 * dnac_merkle_batch_tree_free).
 */
dnac_prover_status_t dnac_prover_quotient_commit(
    const uint64_t *quotient_flat,
    size_t q_rows,
    size_t num_chunks,
    size_t num_random,
    unsigned log_blowup,
    uint64_t q_shift,
    const uint64_t *codeword_rand,
    const uint64_t *blinding_rand,
    uint64_t *out_chunk_ldes,
    uint8_t out_root[DNAC_MERKLE_DIGEST_BYTES],
    dnac_merkle_batch_tree_t **out_tree);

/* ============================================================================
 * S8 — randomization-poly commit + Fiat-Shamir to zeta
 * ========================================================================== */

/**
 * Commit the is_zk randomization matrix R (Plonky3 82cfad73
 * hiding_pcs.rs:404-424 get_opt_randomization_poly_commitment): R is a
 * height x width matrix of caller-supplied random field elements (M3a: 8x6 =
 * 48 values, row-major draw order per DenseMatrix::rand, dense.rs:527-533;
 * width = num_random_codewords + 2), committed via the PLAIN inner PCS —
 * coset LDE (blowup log_blowup, shift GENERATOR=7 on the natural
 * ext-trace domain) + bit-reversed rows + single-matrix SHA3-512 Merkle.
 * Pure reuse of the S2 LDE + S3 commit machinery; its generation touches the
 * transcript nowhere (the ROOT is observed later, in fs_to_zeta).
 *
 * out_lde (required): (height<<log_blowup) x width bit-reversed LDE — the
 * S9/S12 open source. out_tree: keep for FRI query openings.
 */
dnac_prover_status_t dnac_prover_random_commit(
    const uint64_t *r_draws,
    size_t height,
    size_t width,
    unsigned log_blowup,
    uint64_t *out_lde,
    uint8_t out_root[DNAC_MERKLE_DIGEST_BYTES],
    dnac_merkle_tree_t **out_tree);

/**
 * Drive the prover transcript from the post-alpha state to zeta (Plonky3
 * 82cfad73 prover.rs:257 observe quotient commit, :284-286 observe random
 * commit [is_zk only, ORDER LOAD-BEARING: after quotient, before zeta],
 * :299 sample zeta, :300-302 zeta_next = zeta * g where g generates the
 * INITIAL size-2^base_degree_bits trace subgroup — NOT the zk-extended or
 * LDE domain). Identical byte sequence to the verifier replay in
 * stark_priming.c steps (8)-(11). random_root may be NULL for is_zk=0
 * (observe skipped).
 */
dnac_prover_status_t dnac_prover_fs_to_zeta(
    dnac_transcript_t *t,
    const uint8_t quotient_root[DNAC_MERKLE_DIGEST_BYTES],
    const uint8_t *random_root,
    uint64_t base_degree_bits,
    gold_fp2_t *out_zeta,
    gold_fp2_t *out_zeta_next);

/* ============================================================================
 * S9 — open at zeta (barycentric interpolation + transcript observe)
 * ========================================================================== */

/**
 * Open one committed bit-reversed LDE matrix at one point via barycentric
 * interpolation over the first h = height>>log_blowup rows (Plonky3 82cfad73
 * fri/src/two_adic_pcs.rs:505-543): the low coset g·K_h in bit-reversed order.
 * Per column, evaluates the unique degree-<h interpolant at z using the
 * audited lagrange kernel (fri_fold.c, two_adic_pcs.rs:220-260). The
 * interpolation points are xs[i] = GENERATOR·w_h^{bitrev(i)} (GENERATOR=7,
 * w_h = two_adic_generator(log2 h)), matching two_adic_pcs.rs:485-491.
 *
 * out_opened: `width` fp2 values, one per column (column-order == the
 * committed matrix's, i.e. base cols then random codeword cols).
 *
 * @param lde_bitrev  height x width row-major canonical LDE (bit-reversed rows).
 * @param height      LDE height (power of two).
 * @param width       matrix width.
 * @param log_blowup  so h = height >> log_blowup (>= 1 rows).
 * @param z           evaluation point (zeta or zeta_next).
 * @param out_opened  width fp2 outputs.
 */
dnac_prover_status_t dnac_prover_open_matrix_at(
    const uint64_t *lde_bitrev,
    size_t height,
    size_t width,
    unsigned log_blowup,
    gold_fp2_t z,
    gold_fp2_t *out_opened);

/**
 * Observe an opened fp2 vector into the transcript, element by element
 * (challenger observe_algebra_slice == per-element observe_algebra_element,
 * challenger/src/lib.rs:114-118; c0 then c1 each). The prover observes the
 * MERGED (base ++ random codeword) vectors in round order [random, trace,
 * quotient] (two_adic_pcs.rs:546); this helper observes one vector.
 */
void dnac_prover_observe_opened(dnac_transcript_t *t, const gold_fp2_t *opened,
                                size_t n);

/* ============================================================================
 * S10 — FRI commit phase (reduced-opening build + fold/commit + final poly)
 * ========================================================================== */

/** Max FRI commit-phase rounds and final-poly length the prover supports
 *  (M3a: 1 round, final_poly 4 — these bounds cover the M3a params with slack). */
#define DNAC_PROVER_MAX_FRI_ROUNDS 32
#define DNAC_PROVER_MAX_FINAL_POLY 256

/**
 * One committed input round for the reduced-opening build: its bit-reversed
 * LDE matrix (height x width, canonical u64) plus the MERGED opened vectors at
 * each opening point (opened[p] has `width` fp2 values). Rounds are supplied
 * in order [random, trace, quotient chunk 0..k].
 */
typedef struct {
    const uint64_t *lde_bitrev; /* height x width row-major */
    size_t height;
    size_t width;
    size_t num_points;                 /* 1 (zeta) or 2 (zeta, zeta_next) */
    const gold_fp2_t *points;          /* num_points opening points */
    const gold_fp2_t *const *opened;   /* num_points merged vectors, width each */
} dnac_prover_fri_input_round_t;

/**
 * Build the FRI initial reduced-opening codeword (Plonky3 82cfad73
 * fri/src/two_adic_pcs.rs:595-658; prover analogue of the verifier's
 * fri_open_input). For each round/matrix/point, accumulate
 *   ro[x] += alpha^{num_reduced} · (Mred(z) − Mred(x)) · 1/(z − coset[x])
 * where Mred compresses the matrix columns with ascending alpha powers and
 * num_reduced accumulates matrix widths across points. coset[x] = GENERATOR·
 * w_H^x bit-reversed. M3a: all rounds height 2^log_height ⇒ one output vector.
 *
 * @param rounds       ordered input rounds.
 * @param n_rounds     number of rounds.
 * @param log_height   log2 of the (common) LDE height.
 * @param alpha        FRI batch challenge (S9 output).
 * @param out_ro       2^log_height fp2 outputs (bit-reversed codeword).
 */
dnac_prover_status_t dnac_prover_fri_reduced_openings(
    const dnac_prover_fri_input_round_t *rounds,
    size_t n_rounds,
    unsigned log_height,
    gold_fp2_t alpha,
    gold_fp2_t *out_ro);

/** Result of the commit phase: layer roots + betas + final poly, plus the
 *  retained per-layer leaf matrices + trees (for the S12 query openings). */
typedef struct {
    size_t num_rounds;
    uint8_t roots[DNAC_PROVER_MAX_FRI_ROUNDS][DNAC_MERKLE_DIGEST_BYTES];
    gold_fp2_t betas[DNAC_PROVER_MAX_FRI_ROUNDS];
    unsigned log_arities[DNAC_PROVER_MAX_FRI_ROUNDS];
    /* retained for S12: pre-fold layer matrix (height_r x arity fp2) + tree */
    gold_fp2_t *layer_leaves[DNAC_PROVER_MAX_FRI_ROUNDS];
    size_t layer_heights[DNAC_PROVER_MAX_FRI_ROUNDS]; /* rows */
    unsigned layer_log_arities[DNAC_PROVER_MAX_FRI_ROUNDS];
    dnac_merkle_tree_t *layer_trees[DNAC_PROVER_MAX_FRI_ROUNDS];
    size_t final_poly_len;
    gold_fp2_t final_poly[DNAC_PROVER_MAX_FINAL_POLY];
} dnac_prover_fri_result_t;

/** Release the retained layer matrices + trees held in a result. */
void dnac_prover_fri_result_free(dnac_prover_fri_result_t *res);

/**
 * FRI commit phase (Plonky3 82cfad73 fri/src/prover.rs:180-257): while the
 * codeword length exceeds blowup·final_poly_len, reinterpret it as a height×
 * arity matrix, ExtensionMmcs-commit it (SHA3-512 Merkle over flattened fp2
 * rows), observe the root, grind(commit PoW=0), sample beta, fold with beta.
 * Then truncate to final_poly_len, bit-reverse, inverse-NTT to coefficients,
 * and observe them; finally observe each round's log_arity and grind the query
 * PoW (0). PoW bits MUST be 0 (grinding for >0 is unimplemented — fail-close).
 *
 * @param ro          reduced-opening codeword (2^log_height fp2, consumed).
 * @param ro_len      codeword length (power of two).
 * @param log_blowup  FRI blowup bits (M3a: 2).
 * @param log_final_poly_len  (M3a: 2 ⇒ final_poly_len 4).
 * @param max_log_arity (M3a: 1).
 * @param t           live transcript (post FRI-alpha); advanced through the
 *                    commit phase + final-poly + log_arity observes + query grind.
 * @param res         output (caller frees via dnac_prover_fri_result_free).
 */
dnac_prover_status_t dnac_prover_fri_commit_phase(
    gold_fp2_t *ro,
    size_t ro_len,
    unsigned log_blowup,
    unsigned log_final_poly_len,
    unsigned max_log_arity,
    dnac_transcript_t *t,
    dnac_prover_fri_result_t *res);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_STARK_PROVER_H */
