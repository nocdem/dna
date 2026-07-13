# shared/crypto/zk/Makefile
#
# Build + test harness for DNAC v3 ZK primitives.
#
# 2026-05-23 NUKE (first): 11 invented (kafadan) modules + their tests removed.
# 2026-05-23 evening: 5 more kafadan modules (transcript, merkle_smt, fri_fold,
# fri_commit, fri_query) + their tests + their vectors deleted per
# SUBAGENT_AUDIT_2026_05_23.md (12 parallel independent audit).
#
# See [[feedback_no_kafadan_crypto]] memory.
#
# Remaining test binaries are all reference-grounded:
#   - keccak_ref          → OpenSSL + NIST KAT + spec re-derivation (strongest)
#   - keccak_p3_*         → direct port of Plonky3 keccak-air (commit 82cfad73)
#   - field_goldilocks    → Plonky3 source structural match + g32 hex-verified
#   - ntt_goldilocks      → Plonky3 Radix2Dit direct call + brute-force DFT
#   - range_air           → real Plonky3 u64_to_bits_le helper call
#   - sum_balance         → fib_air idiom (I constraint DNAC-original from § 6.1)
#   - sponge_sha3_512     → FIPS-202 + Plonky3 sha3 crate + keccak_ref triple
#
# Usage:
#   make            — build all test binaries
#   make test       — build + run all tests
#   make clean      — remove build artifacts
#
# Dependencies: gcc, libcrypto (OpenSSL).

CC      ?= gcc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Wno-unused-parameter
INCLUDES = -I. -I/opt/dna/shared
LDLIBS   = -lcrypto

# DNAC's qgp_sha3 (linked directly rather than via libdna).
SHA3_SRC = /opt/dna/shared/crypto/hash/qgp_sha3.c

# Transcript + its SHA3-512-over-keccak_p3 backend. fri_verifier.c calls the
# oracle-grounded dnac_transcript_* primitives once the F4 transcript flow is
# present, so any target linking fri_verifier.c must also link this stack.
TRANSCRIPT_STACK = transcript.c sponge_sha3_512.c keccak_p3_cols.c keccak_p3_trace.c keccak_ref.c field_goldilocks.c

# Everything fri_verifier.c links against. As of F5 it also calls dnac_merkle_*
# (MMCS verify), so merkle_smt.c (+ its qgp_sha3/OpenSSL backend via _LDADD) is
# part of every fri_verifier test target.
FRI_VERIFIER_STACK = fri_verifier.c $(TRANSCRIPT_STACK) merkle_smt.c zk_field_helpers.c fri_fold.c
FRI_VERIFIER_LDADD = $(SHA3_SRC) $(LDLIBS)

# Proof wire codec links the full FRI verifier stack (dnac_fri_verify_wire calls
# dnac_fri_verify; the codec test verifies decoded proofs end-to-end).
FRI_PROOF_CODEC_STACK = fri_proof_codec.c $(FRI_VERIFIER_STACK)

BUILD = build

TESTS = \
    $(BUILD)/test_field_goldilocks \
    $(BUILD)/test_field_goldilocks_ext \
    $(BUILD)/test_two_adic_gens \
    $(BUILD)/test_keccak_ref \
    $(BUILD)/test_ntt_goldilocks \
    $(BUILD)/test_keccak_p3 \
    $(BUILD)/test_range_air \
    $(BUILD)/test_air_column_layout_range_air \
    $(BUILD)/test_sum_balance \
    $(BUILD)/test_air_column_layout_sum_balance \
    $(BUILD)/test_ntt_goldilocks_oracle \
    $(BUILD)/test_sponge_sha3_512 \
    $(BUILD)/test_zk_field_helpers \
    $(BUILD)/test_primitive_oracle \
    $(BUILD)/test_fri_fold \
    $(BUILD)/test_fri_fold_row_oracle \
    $(BUILD)/test_fri_fold_matrix_loga1_oracle \
    $(BUILD)/test_fri_fold_matrix_oracle \
    $(BUILD)/test_transcript_oracle \
    $(BUILD)/test_merkle_mmcs \
    $(BUILD)/test_merkle_mmcs_batch \
    $(BUILD)/test_fri_verifier_shape \
    $(BUILD)/test_fri_verifier_transcript \
    $(BUILD)/test_fri_verifier_mmcs_calls \
    $(BUILD)/test_fri_verifier_verify_query \
    $(BUILD)/test_fri_verifier_terminal_horner \
    $(BUILD)/test_fri_verifier_valid \
    $(BUILD)/test_fri_verifier_rollin \
    $(BUILD)/test_fri_proof_codec \
    $(BUILD)/test_stark_priming \
    $(BUILD)/test_stark_priming_zk \
    $(BUILD)/test_fri_verify_zk \
    $(BUILD)/test_stark_proof_codec \
    $(BUILD)/test_stark_priming_integrated \
    $(BUILD)/test_stark_constraints_primitives \
    $(BUILD)/test_stark_verify_constraints \
    $(BUILD)/test_range_proof_air

.PHONY: all test clean gen-fri-proof-wire gen-stark-proof-wire

all: $(BUILD) $(TESTS)

$(BUILD):
	@mkdir -p $(BUILD)

# Field-base test.
$(BUILD)/test_field_goldilocks: tests/test_field_goldilocks.c field_goldilocks.c field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_field_goldilocks.c field_goldilocks.c -o $@

# Field-ext test.
$(BUILD)/test_field_goldilocks_ext: tests/test_field_goldilocks_ext.c field_goldilocks.c field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_field_goldilocks_ext.c field_goldilocks.c -o $@

# Two-adic generators sanity check.
$(BUILD)/test_two_adic_gens: tests/test_two_adic_gens.c field_goldilocks.c field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_two_adic_gens.c field_goldilocks.c -o $@

# Standalone Keccak / SHA3-512 reference.
$(BUILD)/test_keccak_ref: tests/test_keccak_ref.c keccak_ref.c keccak_ref.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_keccak_ref.c keccak_ref.c $(SHA3_SRC) $(LDLIBS) -o $@

# NTT/iNTT over Goldilocks (brute-force DFT validation).
$(BUILD)/test_ntt_goldilocks: tests/test_ntt_goldilocks.c ntt_goldilocks.c field_goldilocks.c ntt_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_ntt_goldilocks.c ntt_goldilocks.c field_goldilocks.c -o $@

# Plonky3-style Keccak-f AIR — direct port of Plonky3 keccak-air crate (commit 82cfad73).
$(BUILD)/test_keccak_p3: tests/test_keccak_p3.c keccak_p3_cols.c keccak_p3_trace.c keccak_p3_air.c keccak_ref.c field_goldilocks.c keccak_p3_cols.h keccak_p3_trace.h keccak_p3_air.h keccak_ref.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_keccak_p3.c keccak_p3_cols.c keccak_p3_trace.c keccak_p3_air.c keccak_ref.c field_goldilocks.c -o $@

# Range AIR — keccak-air bit-decomp + recomposition port (Plonky3 commit 82cfad73).
$(BUILD)/test_range_air: tests/test_range_air.c range_air.c field_goldilocks.c range_air.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_range_air.c range_air.c field_goldilocks.c -o $@

# Range AIR column-layout BINDING contract (design doc § 9 F7).
$(BUILD)/test_air_column_layout_range_air: tests/test_air_column_layout_range_air.c range_air.c field_goldilocks.c range_air.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_air_column_layout_range_air.c range_air.c field_goldilocks.c -o $@

# Sum balance AIR — fib_air unified-trace accumulator port (Plonky3 commit 82cfad73).
$(BUILD)/test_sum_balance: tests/test_sum_balance.c sum_balance.c range_air.c field_goldilocks.c sum_balance.h range_air.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_sum_balance.c sum_balance.c range_air.c field_goldilocks.c -o $@

# Sum balance AIR column-layout BINDING contract (design doc § 9 F7).
$(BUILD)/test_air_column_layout_sum_balance: tests/test_air_column_layout_sum_balance.c sum_balance.c range_air.c field_goldilocks.c sum_balance.h range_air.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_air_column_layout_sum_balance.c sum_balance.c range_air.c field_goldilocks.c -o $@

# NTT/iNTT Plonky3 oracle byte-match (closes Sub-sprint 3.5a gap).
$(BUILD)/test_ntt_goldilocks_oracle: tests/test_ntt_goldilocks_oracle.c ntt_goldilocks.c field_goldilocks.c ntt_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_ntt_goldilocks_oracle.c ntt_goldilocks.c field_goldilocks.c -o $@

# FIPS-202 SHA3-512 sponge over keccak_p3 backend (Sprint 3.3b.7 rework — Option B).
$(BUILD)/test_sponge_sha3_512: tests/test_sponge_sha3_512.c sponge_sha3_512.c keccak_p3_cols.c keccak_p3_trace.c keccak_ref.c field_goldilocks.c sponge_sha3_512.h keccak_p3_cols.h keccak_p3_trace.h keccak_ref.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_sponge_sha3_512.c sponge_sha3_512.c keccak_p3_cols.c keccak_p3_trace.c keccak_ref.c field_goldilocks.c $(SHA3_SRC) $(LDLIBS) -o $@

# Phase A — zk_field_helpers (bits_u64, log2_strict_usize, reverse_bits_len_u64,
# gold_fp_halve, gold_fp2_halve, gold_fp_from_usize). Plonky3 commit 82cfad73.
$(BUILD)/test_zk_field_helpers: tests/test_zk_field_helpers.c zk_field_helpers.c field_goldilocks.c zk_field_helpers.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_zk_field_helpers.c zk_field_helpers.c field_goldilocks.c -o $@

# Phase C — primitive oracle gate. Loads tools/vectors/primitive_ops.json and
# byte-matches reverse_slice_index_bits_fp/fp2 + extended_pow against Plonky3.
$(BUILD)/test_primitive_oracle: tests/test_primitive_oracle.c zk_field_helpers.c field_goldilocks.c zk_field_helpers.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_primitive_oracle.c zk_field_helpers.c field_goldilocks.c -o $@

# Phase D.1 — lagrange_interpolate_at_fp_fp2 sanity tests (Plonky3 fri/src/two_adic_pcs.rs:220-260).
$(BUILD)/test_fri_fold: tests/test_fri_fold.c fri_fold.c zk_field_helpers.c field_goldilocks.c fri_fold.h zk_field_helpers.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_fold.c fri_fold.c zk_field_helpers.c field_goldilocks.c -o $@

# Phase D.2 — fri_fold_row oracle byte-match gate (Plonky3 fri/src/two_adic_pcs.rs:109-132).
$(BUILD)/test_fri_fold_row_oracle: tests/test_fri_fold_row_oracle.c fri_fold.c zk_field_helpers.c field_goldilocks.c fri_fold.h zk_field_helpers.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_fold_row_oracle.c fri_fold.c zk_field_helpers.c field_goldilocks.c -o $@

# Phase D.3 — fri_fold_matrix log_arity==1 oracle byte-match gate (Plonky3 fri/src/two_adic_pcs.rs:135-162).
$(BUILD)/test_fri_fold_matrix_loga1_oracle: tests/test_fri_fold_matrix_loga1_oracle.c fri_fold.c zk_field_helpers.c field_goldilocks.c fri_fold.h zk_field_helpers.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_fold_matrix_loga1_oracle.c fri_fold.c zk_field_helpers.c field_goldilocks.c -o $@

# Phase D.4 — fri_fold_matrix log_arity>1 generic oracle byte-match gate (Plonky3 fri/src/two_adic_pcs.rs:163-213).
$(BUILD)/test_fri_fold_matrix_oracle: tests/test_fri_fold_matrix_oracle.c fri_fold.c zk_field_helpers.c field_goldilocks.c fri_fold.h zk_field_helpers.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_fold_matrix_oracle.c fri_fold.c zk_field_helpers.c field_goldilocks.c -o $@

# Phase T3 — transcript C oracle replay against tools/vectors/transcript.json.
# Compile with -DDNAC_TRANSCRIPT_TESTING=1 to expose the snapshot inspection
# helpers in transcript.h. Links against sponge_sha3_512 (+ its keccak_p3
# permutation backend) for SHA3-512 one-shot, plus field_goldilocks for
# canonicalization. See docs/plans/2026-05-26-transcript-design.md § 15.
$(BUILD)/test_transcript_oracle: tests/test_transcript_oracle.c transcript.c sponge_sha3_512.c keccak_p3_cols.c keccak_p3_trace.c keccak_ref.c field_goldilocks.c transcript.h sponge_sha3_512.h keccak_p3_cols.h keccak_p3_trace.h keccak_ref.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_TRANSCRIPT_TESTING=1 $(INCLUDES) tests/test_transcript_oracle.c transcript.c sponge_sha3_512.c keccak_p3_cols.c keccak_p3_trace.c keccak_ref.c field_goldilocks.c -o $@

# Stage M3 — Merkle/MMCS C oracle replay against tools/vectors/merkle_mmcs.json.
# Links merkle_smt.c plus the OpenSSL-backed qgp_sha3_512 one-shot for both the
# leaf and parent hash. Per design doc § 6 and the post-2026-05-27 Strategy C
# resolution; oracle vectors produced by plonky3_oracle/src/main.rs (PW=[u64;1],
# DIGEST_ELEMS=8) and wire-byte-identical to the C-side uint8_t[64] format.
$(BUILD)/test_merkle_mmcs: tests/test_merkle_mmcs.c merkle_smt.c merkle_smt.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_merkle_mmcs.c merkle_smt.c $(SHA3_SRC) $(LDLIBS) -o $@

# Phase 2A — same-height multi-matrix batch oracle replay against
# tools/vectors/merkle_mmcs_batch_same_height.json. Exercises the new
# dnac_merkle_batch_commit/open/verify additive API alongside an in-test
# regression against the existing single-matrix path for num_matrices == 1.
$(BUILD)/test_merkle_mmcs_batch: tests/test_merkle_mmcs_batch.c merkle_smt.c merkle_smt.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_merkle_mmcs_batch.c merkle_smt.c $(SHA3_SRC) $(LDLIBS) -o $@

# Phase F3 — FRI verifier pre-transcript shape-check prefix. Replays the
# applicable shape cases from tools/vectors/fri_verifier_errors.json (6 run,
# 13 deferred to F4-F7). Compiled with -DDNAC_FRI_TESTING=1 to expose the
# test-only dnac_fri_test_shape_prefix hook (NOT production verifier API).
# Phase F3 — shape-check prefix. Links the full fri_verifier stack (fri_verifier.c
# references dnac_transcript_* + dnac_merkle_* from later phases in the same TU).
$(BUILD)/test_fri_verifier_shape: tests/test_fri_verifier_shape.c fri_verifier.h $(FRI_VERIFIER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_FRI_TESTING=1 $(INCLUDES) tests/test_fri_verifier_shape.c $(FRI_VERIFIER_STACK) $(FRI_VERIFIER_LDADD) -o $@

# Phase F4 — transcript flow. Replays the 18 transcript milestones from
# tools/vectors/fri_verifier_transcript_milestones.json against
# dnac_fri_test_transcript_flow (verifier.rs:143-268 Fiat-Shamir sequence).
# Needs DNAC_FRI_TESTING + DNAC_TRANSCRIPT_TESTING (buffer snapshot hooks).
$(BUILD)/test_fri_verifier_transcript: tests/test_fri_verifier_transcript.c fri_verifier.h $(FRI_VERIFIER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_FRI_TESTING=1 -DDNAC_TRANSCRIPT_TESTING=1 $(INCLUDES) tests/test_fri_verifier_transcript.c $(FRI_VERIFIER_STACK) $(FRI_VERIFIER_LDADD) -o $@

# Phase F5 Part A — MMCS verify_batch call replay. Replays the 8 captured calls
# from tools/vectors/fri_verifier_mmcs_calls.json through dnac_merkle_verify
# (verifier.rs:446-455 commit-phase + 589-597 input).
$(BUILD)/test_fri_verifier_mmcs_calls: tests/test_fri_verifier_mmcs_calls.c fri_verifier.h $(FRI_VERIFIER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_FRI_TESTING=1 $(INCLUDES) tests/test_fri_verifier_mmcs_calls.c $(FRI_VERIFIER_STACK) $(FRI_VERIFIER_LDADD) -o $@

# Phase F5 Part B — verify_query isolated shape errors. Replays the 3 cases from
# tools/vectors/fri_verifier_verify_query.json (verifier.rs:378-398 + 483-497).
$(BUILD)/test_fri_verifier_verify_query: tests/test_fri_verifier_verify_query.c fri_verifier.h $(FRI_VERIFIER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_FRI_TESTING=1 $(INCLUDES) tests/test_fri_verifier_verify_query.c $(FRI_VERIFIER_STACK) $(FRI_VERIFIER_LDADD) -o $@

# Phase F6 — terminal Horner / final-poly check. Replays the 173 cases from
# tools/vectors/fri_verifier_terminal_horner.json (verifier.rs:308-325): x from
# log_global_max_height, reverse-order Horner over fp2, FinalPolyMismatch compare.
$(BUILD)/test_fri_verifier_terminal_horner: tests/test_fri_verifier_terminal_horner.c fri_verifier.h $(FRI_VERIFIER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_FRI_TESTING=1 $(INCLUDES) tests/test_fri_verifier_terminal_horner.c $(FRI_VERIFIER_STACK) $(FRI_VERIFIER_LDADD) -o $@

# Phase F7 — integrated FRI verifier. Verifies the locked V6 valid proof
# end-to-end (verify_fri / open_input / verify_query / terminal Horner ->
# DNAC_FRI_OK) and replays the integrated-reachable public error vectors.
# Takes both the valid proof and the milestone vector (the latter supplies the
# primed "top of verify_fri" transcript seed).
$(BUILD)/test_fri_verifier_valid: tests/test_fri_verifier_valid.c fri_verifier.h $(FRI_VERIFIER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_FRI_TESTING=1 $(INCLUDES) tests/test_fri_verifier_valid.c $(FRI_VERIFIER_STACK) $(FRI_VERIFIER_LDADD) -o $@

# Phase F1.6 — multi-reduced-opening ROLL-IN. Verifies a 2-commitment (heights
# 2^4 + 2^2) proof end-to-end (DNAC_FRI_OK), then proves the verify_query roll-in
# (verifier.rs:477-480) is EXERCISED: independent fold trace (via fri_fold_row_fp2)
# recomputes folded_before/after and matches the Plonky3-anchored vector. The
# vector carries its own primed transcript seed, so only one file is needed.
$(BUILD)/test_fri_verifier_rollin: tests/test_fri_verifier_rollin.c fri_verifier.h $(FRI_VERIFIER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_FRI_TESTING=1 $(INCLUDES) tests/test_fri_verifier_rollin.c $(FRI_VERIFIER_STACK) $(FRI_VERIFIER_LDADD) -o $@

# Proof wire codec — roundtrip (decode->verify->encode==wire) + negative cases.
# Uses only the production codec + verifier APIs (no DNAC_FRI_TESTING hooks).
$(BUILD)/test_fri_proof_codec: tests/test_fri_proof_codec.c fri_proof_codec.h fri_proof_codec.c $(FRI_VERIFIER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_proof_codec.c $(FRI_PROOF_CODEC_STACK) $(FRI_VERIFIER_LDADD) -o $@

# P3/P4 — STARK/PCS transcript priming helper replay. Primes a transcript through
# uni-stark verifier.rs:360-391 + two_adic_pcs.rs:687-693 from the REAL
# p3_uni_stark::prove vector (stark_priming.json) and byte-matches the
# verify_fri-entry seed + sampled alpha/zeta/zeta_next. -DDNAC_TRANSCRIPT_TESTING=1
# exposes the input_buf/output_buf snapshot accessors. Production helper uses only
# the public transcript API; no FRI verifier / constraint code. Per
# docs/plans/2026-05-30-pcs-transcript-priming-design.md.
$(BUILD)/test_stark_priming: tests/test_stark_priming.c stark_priming.h stark_priming.c transcript.h transcript.c field_goldilocks.h field_goldilocks.c merkle_smt.h | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_TRANSCRIPT_TESTING=1 $(INCLUDES) tests/test_stark_priming.c stark_priming.c transcript.c sponge_sha3_512.c keccak_p3_cols.c keccak_p3_trace.c keccak_ref.c field_goldilocks.c -o $@

# M2 — is_zk=1 (hiding) STARK/PCS transcript priming replay. Same helper +
# stack as the non-ZK test, driven by the M1 sandbox confidential vector
# (stark_priming_zk.json) — a REAL is_zk=1 p3_uni_stark::prove over HidingFriPcs.
# Byte-matches the primed transcript (288 B) + alpha/zeta/zeta_next through the
# is_zk augmentation (random-commit observe + random opened round first).
$(BUILD)/test_stark_priming_zk: tests/test_stark_priming_zk.c stark_priming.h stark_priming.c transcript.h transcript.c field_goldilocks.h field_goldilocks.c merkle_smt.h | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_TRANSCRIPT_TESTING=1 $(INCLUDES) tests/test_stark_priming_zk.c stark_priming.c transcript.c sponge_sha3_512.c keccak_p3_cols.c keccak_p3_trace.c keccak_ref.c field_goldilocks.c -o $@

# M2b — end-to-end is_zk=1 FRI verification. Builds dnac_fri_proof_t + 3-round
# coms (random/trace/quotient, merged opened values) from stark_priming_zk.json
# and runs dnac_stark_prime_transcript(is_zk=1) -> dnac_fri_verify == DNAC_FRI_OK.
# Ground-truth gate: validates the is_zk transcript + merge against the REAL
# Plonky3 HidingFriPcs verifier (not just the oracle's own Shadow).
$(BUILD)/test_fri_verify_zk: tests/test_fri_verify_zk.c fri_verifier.h stark_priming.h stark_priming.c $(FRI_VERIFIER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_verify_zk.c stark_priming.c $(FRI_VERIFIER_STACK) $(FRI_VERIFIER_LDADD) -o $@

# P5 — additive DZKS STARK/PCS wire wrapper around the EXISTING DZKF FRI wire.
# Roundtrip (decode -> field checks -> re-encode == wire) + the inner DZKF decodes
# via the existing fri_proof_codec (unchanged) + 8 malformed-reject cases. Links
# both codecs. Per docs/plans/2026-05-30-pcs-transcript-priming-design.md § 8.
$(BUILD)/test_stark_proof_codec: tests/test_stark_proof_codec.c stark_proof_codec.h stark_proof_codec.c fri_proof_codec.h $(FRI_PROOF_CODEC_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_stark_proof_codec.c stark_proof_codec.c $(FRI_PROOF_CODEC_STACK) $(FRI_VERIFIER_LDADD) -o $@

# P6 — integrated guard: DZKS -> inner DZKF -> dnac_stark_prime_transcript ->
# dnac_fri_verify, end-to-end on the production stack (priming + FRI only; no
# STARK constraint check). Permanent regression guard for the FRI terminal
# domain_index fix: REQUIRES a log_final_poly_len>0 vector (FibonacciAir) to
# reach DNAC_FRI_OK. Production APIs only — no DNAC_*_TESTING hooks. Per
# docs/plans/2026-05-30-pcs-transcript-priming-design.md (P6).
$(BUILD)/test_stark_priming_integrated: tests/test_stark_priming_integrated.c stark_proof_codec.h stark_proof_codec.c stark_priming.h stark_priming.c fri_proof_codec.h $(FRI_PROOF_CODEC_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_stark_priming_integrated.c stark_proof_codec.c stark_priming.c $(FRI_PROOF_CODEC_STACK) $(FRI_VERIFIER_LDADD) -o $@

# S3 — generic STARK constraint-check primitives (selectors_at_point + recompose
# num_qc=1 + alpha-fold ops + final OOD check). AIR-INDEPENDENT; no AIR eval, no
# full verify glue (S4). Replays the real-Plonky3 S2 vectors. Links only
# field_goldilocks (fp2) — no SHA3/FRI/transcript. Per
# docs/plans/2026-05-30-stark-constraint-check-implementation-design.md (S3).
$(BUILD)/test_stark_constraints_primitives: tests/test_stark_constraints_primitives.c stark_constraints.h stark_constraints.c field_goldilocks.h field_goldilocks.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_stark_constraints_primitives.c stark_constraints.c field_goldilocks.c -o $@

# S4 — verify_constraints glue + FibonacciAir/SquareAir air_eval, end-to-end vs the
# real-Plonky3 S2 vectors (FIRST C<->Plonky3 verify_constraints agreement). The two
# AIR callbacks are TEST fixtures in the test; the generic glue is in
# stark_constraints.c. Links only field_goldilocks (no SHA3/FRI). Per
# docs/plans/2026-05-30-stark-constraint-check-implementation-design.md (S4).
$(BUILD)/test_stark_verify_constraints: tests/test_stark_verify_constraints.c stark_constraints.h stark_constraints.c field_goldilocks.h field_goldilocks.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_stark_verify_constraints.c stark_constraints.c field_goldilocks.c -o $@

# S5.x — C range_proof_air air_eval (range-only + combined, ADDITIVE) vs the real-
# Plonky3 S5.1 oracle vectors. The two air_eval callbacks are TEST fixtures; the
# generic dnac_stark_verify_constraints glue (S4) is reused unchanged. Links only
# field_goldilocks. CONFIDENTIAL use BLOCKED on B1 (asserted from flags; B6/B7
# closed by the 2026-07 52-bit + is_real/cnt soundness fix). Per
# docs/plans/2026-05-30-dnac-range-proof-air-regrounding.md (S5.x).
$(BUILD)/test_range_proof_air: tests/test_range_proof_air.c stark_constraints.h stark_constraints.c field_goldilocks.h field_goldilocks.c range_air.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_range_proof_air.c stark_constraints.c field_goldilocks.c -o $@

# Regenerate the DZKS wrapper vectors from their priming vectors via the C codec
# (the generator is polymorphic on has_trace_next, driven by the JSON's trace_next
# being an array vs null). Manual (vectors committed + hash-pinned); run after a
# wrapper/wire change. Each run GATEs dnac_fri_verify==DNAC_FRI_OK before writing.
#   stark_proof_wire.json          <- FibonacciAir (main_next=true, 2 trace points)
#   stark_proof_wire_no_next.json  <- SquareAir    (main_next=false, 1 trace point)
gen-stark-proof-wire: | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tools/gen_stark_proof_wire.c stark_proof_codec.c stark_priming.c $(FRI_PROOF_CODEC_STACK) $(FRI_VERIFIER_LDADD) -o $(BUILD)/gen_stark_proof_wire
	$(BUILD)/gen_stark_proof_wire tools/vectors/stark_priming.json tools/vectors/stark_proof_wire.json
	$(BUILD)/gen_stark_proof_wire tools/vectors/stark_priming_no_next.json tools/vectors/stark_proof_wire_no_next.json

# Regenerate tools/vectors/fri_proof_wire.json from the locked FRI vectors via
# the C codec. Manual (vector is committed); run after a codec/wire change.
gen-fri-proof-wire: | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tools/gen_fri_proof_wire.c $(FRI_PROOF_CODEC_STACK) $(FRI_VERIFIER_LDADD) -o $(BUILD)/gen_fri_proof_wire
	$(BUILD)/gen_fri_proof_wire tools/vectors/fri_verifier_valid.json tools/vectors/fri_verifier_transcript_milestones.json tools/vectors/fri_verifier_rollin.json tools/vectors/fri_proof_wire.json

test: all
	@echo "============================================================"
	@echo "Sprint 1.2 — field_goldilocks (base)"
	@echo "============================================================"
	@$(BUILD)/test_field_goldilocks tools/vectors/field_ops.json
	@echo
	@echo "============================================================"
	@echo "Sprint 1.3 — field_goldilocks (Goldilocks² extension)"
	@echo "============================================================"
	@$(BUILD)/test_field_goldilocks_ext tools/vectors/field_ext.json
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 2.1a — two-adic generators"
	@echo "============================================================"
	@$(BUILD)/test_two_adic_gens tools/vectors/two_adic_gens.json
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.3a — Standalone Keccak-f[1600] + SHA3-512"
	@echo "============================================================"
	@$(BUILD)/test_keccak_ref
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.5a — NTT/iNTT (brute-force DFT)"
	@echo "============================================================"
	@$(BUILD)/test_ntt_goldilocks
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.4r — Plonky3-style Keccak-f AIR (direct port)"
	@echo "============================================================"
	@$(BUILD)/test_keccak_p3
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.1 (rework) — range_air bit-decomp port"
	@echo "============================================================"
	@$(BUILD)/test_range_air tools/vectors/range_air.json
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.1 (rework) — F7 column-layout BINDING contract"
	@echo "============================================================"
	@$(BUILD)/test_air_column_layout_range_air
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.2 (rework) — sum_balance fib_air accumulator port"
	@echo "============================================================"
	@$(BUILD)/test_sum_balance tools/vectors/sum_balance.json
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.2 (rework) — F7 column-layout BINDING contract"
	@echo "============================================================"
	@$(BUILD)/test_air_column_layout_sum_balance
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.5a (gap closure) — NTT Plonky3 Radix2Dit oracle"
	@echo "============================================================"
	@$(BUILD)/test_ntt_goldilocks_oracle tools/vectors/ntt_goldilocks.json
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.3b.7 (rework) — SHA3-512 sponge over keccak_p3"
	@echo "============================================================"
	@$(BUILD)/test_sponge_sha3_512 tools/vectors/sha3_512_sponge.json
	@echo
	@echo "============================================================"
	@echo "Phase A — zk_field_helpers (Plonky3 commit 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_zk_field_helpers
	@echo
	@echo "============================================================"
	@echo "Phase C — primitive oracle (reverse_slice_index_bits + extended_pow)"
	@echo "============================================================"
	@$(BUILD)/test_primitive_oracle tools/vectors/primitive_ops.json
	@echo
	@echo "============================================================"
	@echo "Phase D.1 — lagrange_interpolate_at_fp_fp2 sanity"
	@echo "============================================================"
	@$(BUILD)/test_fri_fold
	@echo
	@echo "============================================================"
	@echo "Phase D.2 — fri_fold_row oracle byte-match (Plonky3 commit 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_fri_fold_row_oracle tools/vectors/fri_fold_row.json
	@echo
	@echo "============================================================"
	@echo "Phase D.3 — fri_fold_matrix log_arity==1 oracle byte-match"
	@echo "============================================================"
	@$(BUILD)/test_fri_fold_matrix_loga1_oracle tools/vectors/fri_fold_matrix_loga1.json
	@echo
	@echo "============================================================"
	@echo "Phase D.4 — fri_fold_matrix log_arity>1 generic oracle byte-match"
	@echo "============================================================"
	@$(BUILD)/test_fri_fold_matrix_oracle tools/vectors/fri_fold_matrix.json
	@echo
	@echo "============================================================"
	@echo "Phase T3 — DNAC transcript C oracle replay (Plonky3 commit 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_transcript_oracle tools/vectors/transcript.json
	@echo
	@echo "============================================================"
	@echo "Stage M3 — DNAC Merkle/MMCS C oracle replay (Strategy C, Plonky3 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_merkle_mmcs tools/vectors/merkle_mmcs.json
	@echo
	@echo "============================================================"
	@echo "Phase 2A — DNAC Merkle/MMCS same-height multi-matrix batch"
	@echo "(Plonky3 commit 82cfad73, design § 1.4)"
	@echo "============================================================"
	@$(BUILD)/test_merkle_mmcs_batch tools/vectors/merkle_mmcs_batch_same_height.json
	@echo
	@echo "============================================================"
	@echo "Phase F3 — FRI verifier shape-check prefix (Plonky3 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_fri_verifier_shape tools/vectors/fri_verifier_errors.json
	@echo
	@echo "============================================================"
	@echo "Phase F4 — FRI verifier transcript flow (Plonky3 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_fri_verifier_transcript tools/vectors/fri_verifier_transcript_milestones.json
	@echo
	@echo "============================================================"
	@echo "Phase F5 Part A — FRI MMCS verify_batch call replay (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_fri_verifier_mmcs_calls tools/vectors/fri_verifier_mmcs_calls.json
	@echo
	@echo "============================================================"
	@echo "Phase F5 Part B — verify_query isolated shape errors (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_fri_verifier_verify_query tools/vectors/fri_verifier_verify_query.json
	@echo
	@echo "============================================================"
	@echo "Phase F6 — FRI terminal Horner / final-poly check (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_fri_verifier_terminal_horner tools/vectors/fri_verifier_terminal_horner.json
	@echo
	@echo "============================================================"
	@echo "Phase F7 — integrated FRI verifier: V6 valid proof end-to-end (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_fri_verifier_valid tools/vectors/fri_verifier_valid.json tools/vectors/fri_verifier_transcript_milestones.json
	@echo
	@echo "============================================================"
	@echo "Phase F1.6 — FRI multi-reduced-opening ROLL-IN (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_fri_verifier_rollin tools/vectors/fri_verifier_rollin.json
	@echo
	@echo "============================================================"
	@echo "Proof wire codec — roundtrip + negative malformed cases"
	@echo "============================================================"
	@$(BUILD)/test_fri_proof_codec tools/vectors/fri_proof_wire.json
	@echo
	@echo "============================================================"
	@echo "Phase B8 P3/P4 — STARK/PCS transcript priming replay (real p3_uni_stark::prove, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_stark_priming tools/vectors/stark_priming.json
	@echo
	@echo "============================================================"
	@echo "M2 — is_zk=1 (hiding) STARK/PCS priming replay (real HidingFriPcs prove, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_stark_priming_zk tools/vectors/stark_priming_zk.json
	@echo
	@echo "============================================================"
	@echo "M2b — end-to-end is_zk=1 FRI verify (dnac_fri_verify on HidingFriPcs proof, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_fri_verify_zk tools/vectors/stark_priming_zk.json
	@echo
	@echo "============================================================"
	@echo "M3a — is_zk=1 over the AUDITED RangeProofAir (hidden amounts), end-to-end FRI verify"
	@echo "============================================================"
	@$(BUILD)/test_fri_verify_zk tools/vectors/range_proof_air_zk.json
	@echo
	@echo "============================================================"
	@echo "Phase B8 P5 — additive DZKS STARK/PCS wire wrapper (around existing DZKF, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_stark_proof_codec tools/vectors/stark_proof_wire.json
	@echo
	@echo "============================================================"
	@echo "Phase B8 P6 — integrated DZKS->DZKF->priming->dnac_fri_verify (82cfad73)"
	@echo "  FibonacciAir (main_next=true): log_final_poly_len>0 terminal-index guard"
	@echo "  SquareAir    (main_next=false): trace_next-absent / 1-trace-point path"
	@echo "============================================================"
	@$(BUILD)/test_stark_priming_integrated tools/vectors/stark_proof_wire.json tools/vectors/stark_proof_wire_no_next.json
	@echo
	@echo "============================================================"
	@echo "Phase B8 S3 — generic STARK constraint-check primitives (82cfad73)"
	@echo "  selectors_at_point + recompose(num_qc=1) + alpha-fold + final check"
	@echo "  byte-matched vs real-Plonky3 verify_constraints S2 vectors"
	@echo "============================================================"
	@$(BUILD)/test_stark_constraints_primitives tools/vectors/stark_verify_constraints.json tools/vectors/stark_verify_constraints_no_next.json
	@echo
	@echo "============================================================"
	@echo "Phase B8 S4 — verify_constraints glue + fib/square air_eval (82cfad73)"
	@echo "  FIRST end-to-end C<->Plonky3 verify_constraints agreement"
	@echo "  + per-constraint trace localization + negative (OOD/SHAPE) cases"
	@echo "============================================================"
	@$(BUILD)/test_stark_verify_constraints tools/vectors/stark_verify_constraints.json tools/vectors/stark_verify_constraints_no_next.json
	@echo
	@echo "============================================================"
	@echo "Phase B8 S5.x — DNAC range_proof_air C air_eval (ADDITIVE, 82cfad73)"
	@echo "  range-only (53) + combined range+balance+is_real/cnt (61) vs real-Plonky3 vectors"
	@echo "  CONFIDENTIAL use BLOCKED on B1 (B6/B7 closed by 52-bit + is_real/cnt fix)"
	@echo "============================================================"
	@$(BUILD)/test_range_proof_air tools/vectors/range_air_only.json tools/vectors/range_proof_air.json
	@echo
	@echo "============================================================"
	@echo "ALL REMAINING (grounded) GATES: GREEN"
	@echo "Modules verified by SUBAGENT_AUDIT_2026_05_23.md (12 parallel"
	@echo "independent audit). fri_fold + transcript + merkle_smt ports"
	@echo "active and oracle-grounded against Plonky3 82cfad73."
	@echo "fri_verifier still pending; fri_commit/fri_query split"
	@echo "rejected/deleted (replaced by the upcoming fri_verifier port)."
	@echo "============================================================"

clean:
	rm -rf $(BUILD)
