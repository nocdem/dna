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

# Everything the C prover (stark_prover.c) links against: trace builders
# (range_air/sum_balance), NTT + helpers (S2 LDE), Merkle build (S3), and the
# transcript stack (S5+ Fiat-Shamir; TRANSCRIPT_STACK carries field_goldilocks).
PROVER_STACK = stark_prover.c sum_balance.c range_air.c ntt_goldilocks.c zk_field_helpers.c merkle_smt.c fri_fold.c $(TRANSCRIPT_STACK)

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
    $(BUILD)/test_range_proof_air \
    $(BUILD)/test_conf_root_verify \
    $(BUILD)/test_prover_conf \
    $(BUILD)/test_zk_entropy \
    $(BUILD)/test_prover_trace \
    $(BUILD)/test_prover_s2_lde \
    $(BUILD)/test_prover_s3_commit \
    $(BUILD)/test_prover_s5_alpha \
    $(BUILD)/test_prover_s6_quotient \
    $(BUILD)/test_prover_s7_commit \
    $(BUILD)/test_prover_s8_zeta \
    $(BUILD)/test_prover_s9_open \
    $(BUILD)/test_prover_s10_fri \
    $(BUILD)/test_prover_s11_query \
    $(BUILD)/test_prover_s13_verify \
    $(BUILD)/test_prover_prove \
    $(BUILD)/test_poseidon2_goldilocks \
    $(BUILD)/test_poseidon2_air_cols \
    $(BUILD)/test_poseidon2_air_trace \
    $(BUILD)/test_poseidon2_air \
    $(BUILD)/test_conf_balance_air \
    $(BUILD)/test_conf_commit_air \
    $(BUILD)/test_conf_root_air \
    $(BUILD)/test_conf_txbind

.PHONY: all test clean gen-fri-proof-wire gen-stark-proof-wire bench-prover

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

# FP1.2 — Poseidon2-Goldilocks width-8 permutation, byte-match vs the real
# default_goldilocks_poseidon2_8().permute (Plonky3 82cfad73). Grounded port.
$(BUILD)/test_poseidon2_goldilocks: tests/test_poseidon2_goldilocks.c poseidon2_goldilocks.c field_goldilocks.c poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_poseidon2_goldilocks.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# FP1c.1 — Poseidon2 AIR column-layout binding contract (Poseidon2Cols<8,7,1,4,22>,
# Plonky3 poseidon2-air/src/columns.rs @ 82cfad73). Structural gate.
$(BUILD)/test_poseidon2_air_cols: tests/test_poseidon2_air_cols.c poseidon2_air_cols.c poseidon2_air_cols.h poseidon2_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_poseidon2_air_cols.c poseidon2_air_cols.c -o $@

# FP1c.2 — Poseidon2 AIR trace-row generation byte-match vs the real Plonky3
# generate_trace_rows (poseidon2-air/src/generation.rs @ 82cfad73).
$(BUILD)/test_poseidon2_air_trace: tests/test_poseidon2_air_trace.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c poseidon2_air_trace.h poseidon2_air_cols.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_poseidon2_air_trace.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# FP1c.3 — Poseidon2 AIR constraint evaluation. Accept real Plonky3 traces (0
# violations) + reject every single-column tamper (poseidon2-air/src/air.rs @ 82cfad73).
$(BUILD)/test_poseidon2_air: tests/test_poseidon2_air.c poseidon2_air.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c poseidon2_air.h poseidon2_air_cols.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_poseidon2_air.c poseidon2_air.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# B1 Stage-1 — confidential balance-conservation + selector AIR (DNAC-original,
# is_zk=0). Construction gate: honest trace accepted + every SEC-1/SEC-2 attack
# rejected (incl. the re-red-team padding-MINT). Settles the "build-to-settle"
# balance/selector layer.
$(BUILD)/test_conf_balance_air: tests/test_conf_balance_air.c conf_balance_air.c field_goldilocks.c conf_balance_air.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_balance_air.c conf_balance_air.c field_goldilocks.c -o $@

# B1 Stage-1 increment 2 — VC value-commitment composition. conf_balance + the
# FP1c Poseidon2 block via the SEC-2 same-window copy (amount == VC.inputs[0]).
$(BUILD)/test_conf_commit_air: tests/test_conf_commit_air.c conf_commit_air.c conf_balance_air.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c conf_commit_air.h conf_balance_air.h poseidon2_air.h poseidon2_air_trace.h poseidon2_air_cols.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_commit_air.c conf_commit_air.c conf_balance_air.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# B1 Stage-1 increment 3 — commitment-set-root CA accumulator (capacity-IV sponge
# fold, is_real-gated). Binds the ordered {c_i} to one root; verifier recompute.
$(BUILD)/test_conf_root_air: tests/test_conf_root_air.c conf_root_air.c conf_commit_air.c conf_balance_air.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c conf_root_air.h conf_commit_air.h conf_balance_air.h poseidon2_air.h poseidon2_air_trace.h poseidon2_air_cols.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_root_air.c conf_root_air.c conf_commit_air.c conf_balance_air.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# B1 Stage-1 — tx_binding (SEC-5 mechanism): grounded rejection map (challenger
# convention) + sandbox sighash (SHA3-512) + tx-bound root (fold into commitment root).
$(BUILD)/test_conf_txbind: tests/test_conf_txbind.c conf_txbind.c conf_root_air.c conf_commit_air.c conf_balance_air.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c keccak_ref.c conf_txbind.h conf_root_air.h field_goldilocks.h keccak_ref.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_txbind.c conf_txbind.c conf_root_air.c conf_commit_air.c conf_balance_air.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c keccak_ref.c $(SHA3_SRC) $(LDLIBS) -o $@

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

$(BUILD)/test_conf_root_verify: tests/test_conf_root_verify.c stark_constraints.h stark_constraints.c conf_root_fold.h conf_root_fold.c poseidon2_goldilocks.h poseidon2_goldilocks.c field_goldilocks.h field_goldilocks.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_root_verify.c stark_constraints.c conf_root_fold.c poseidon2_goldilocks.c field_goldilocks.c -o $@

CONF_AIR_STACK = conf_root_air.c conf_commit_air.c conf_balance_air.c conf_txbind.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c

# Production CSPRNG (G2): self-contained getrandom(2)/urandom, dependency-free
# (the parked zk stack must not drag in the platform logging chain). PROVER-side
# only — tests exercise it structurally, never for byte-stable values.
$(BUILD)/test_zk_entropy: tests/test_zk_entropy.c zk_entropy.h zk_entropy.c field_goldilocks.h field_goldilocks.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_zk_entropy.c zk_entropy.c field_goldilocks.c -o $@

$(BUILD)/test_prover_conf: tests/test_prover_conf.c stark_prover_conf.h stark_prover_conf.c conf_root_fold.h conf_root_fold.c stark_constraints.c zk_entropy.c $(CONF_AIR_STACK) $(PROVER_STACK) fri_verifier.c stark_priming.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_conf.c stark_prover_conf.c conf_root_fold.c stark_constraints.c zk_entropy.c $(CONF_AIR_STACK) $(PROVER_STACK) fri_verifier.c stark_priming.c $(SHA3_SRC) $(LDLIBS) -o $@

# S1 (C prover) — RangeProofAir witness-trace builder byte-match KAT vs the
# oracle's generate_range_proof_trace dump (the exact p3_uni_stark::prove input
# matrix, PRE-is_zk-randomization). Reuses the range_air/sum_balance builders;
# stark_prover.c adds is_real/cnt + padding-flat semantics + fail-close guards.
# Per dnac/docs/plans/2026-07-13-c-stark-prover-design.md (S1).
$(BUILD)/test_prover_trace: tests/test_prover_trace.c stark_prover.h $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_trace.c $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

# S2 (C prover) — is_zk trace randomization (hiding_pcs.rs:110-129 interleave,
# oracle-dumped SmallRng(1) draws as KAT input, D1 Option B) + per-column coset
# LDE (iNTT -> zero-pad -> shift^j -> NTT, blowup 2, shift 7) + bit-reversed
# rows, byte-matched against the REAL committed matrix extracted from
# pcs.commit (oracle gates G1-G4). Per the S2 stage spec.
$(BUILD)/test_prover_s2_lde: tests/test_prover_s2_lde.c stark_prover.h $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_s2_lde.c $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

# S3 (C prover) — Merkle BUILD over the bit-reversed LDE: canonical-u64-LE row
# serialization + existing oracle-byte-matched dnac_merkle_commit; root must
# equal the REAL proof.commitments.trace from the S2 vector (gates G1-G3).
# Includes the full S1->S2->S3 chain replay + open/verify roundtrip (S12 prep).
$(BUILD)/test_prover_s3_commit: tests/test_prover_s3_commit.c stark_prover.h $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_s3_commit.c $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

# S5 (C prover) — prover-side Fiat-Shamir to alpha: drives the EXISTING
# transcript.c with the prover.rs:161-195 observe/sample sequence and
# byte-matches the REAL p3 alpha from range_proof_air_zk.json, on the trace
# root rebuilt by the C S1->S2->S3 chain (cross-vector tie). Pin D4: the
# audited verifier-side stark_priming.c is NOT touched.
$(BUILD)/test_prover_s5_alpha: tests/test_prover_s5_alpha.c stark_prover.h $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_s5_alpha.c $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

# S6 (C prover) — quotient computation: selectors-on-coset (domain.rs:277-317),
# trace-on-quotient-domain gather (stride+bitrev un-reverse, random cols
# truncated), 61-constraint domain-wide Horner fold with descending alpha
# powers + Z_H division (prover.rs:399-513), round-robin chunk split
# (domain.rs:213-246) — every cell byte-matched vs the REAL pub
# p3_uni_stark::prover::quotient_values output. The hardest prover stage.
$(BUILD)/test_prover_s6_quotient: tests/test_prover_s6_quotient.c stark_prover.h $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_s6_quotient.c $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

# S7 (C prover) — quotient blinding + per-chunk LDE(blowup+1) + ONE 4-matrix
# SHA3-512 batch commit (hiding_pcs.rs:169-261 get_quotient_ldes + inner mmcs
# commit): eprint 2024/1037 randomization with the derived last blinding block
# (recomposition-preserving). Randomness = oracle-dumped SmallRng(1) draws at
# stream position 256 (D1-B). Root must equal the REAL
# proof.commitments.quotient_chunks — the full-chain S1->S7 gate.
$(BUILD)/test_prover_s7_commit: tests/test_prover_s7_commit.c stark_prover.h $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_s7_commit.c $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

# S8 (C prover) — randomization-poly commit (plain inner PCS: S2 LDE + S3
# Merkle on the 8x6 R matrix, hiding_pcs.rs:404-424) + FS to zeta (observe
# quotient root -> observe random root -> sample zeta; zeta_next = zeta * g of
# the INITIAL trace subgroup, prover.rs:257-302). Full chain S1->S8 must
# reproduce the REAL zeta/zeta_next from range_proof_air_zk.json.
$(BUILD)/test_prover_s8_zeta: tests/test_prover_s8_zeta.c stark_prover.h $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_s8_zeta.c $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

# S9 (C prover) — open at zeta: barycentric interpolation of every committed
# LDE column over the low coset g*K_8 (first h=height>>log_blowup bit-reversed
# rows, two_adic_pcs.rs:505-543) via the audited fri_fold lagrange kernel;
# observe the MERGED opened vectors [random, trace@zeta, trace@zeta_next,
# quotient x4] and sample the FRI batch alpha. Full chain S1->S9 must match the
# REAL merged opened values + FRI alpha from range_proof_air_zk / the S9 dump.
$(BUILD)/test_prover_s9_open: tests/test_prover_s9_open.c stark_prover.h $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_s9_open.c $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

# S10 (C prover) — FRI commit phase: reduced-opening codeword build
# (two_adic_pcs.rs:595-658, alpha-batched across rounds) + fold/commit loop
# (fri/prover.rs:180-257: ExtensionMmcs layer commit + beta sample + fold) +
# final poly (truncate/bitrev/inverse-NTT). Byte-matches the REAL FRI
# commit-phase roots, betas (replayed), and final_poly.
$(BUILD)/test_prover_s10_fri: tests/test_prover_s10_fri.c stark_prover.h $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_s10_fri.c $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

# S11+S12 (C prover) — query index sampling (sample_bits(5) after the commit
# phase == the REAL indices) + FRI query openings (open the retained input +
# commit-phase trees at each index, verify each path against its root). The
# full query-proof byte-match is deferred to S13's end-to-end dnac_fri_verify.
$(BUILD)/test_prover_s11_query: tests/test_prover_s11_query.c stark_prover.h $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_s11_query.c $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

# S13 (C prover) — MILESTONE: the full C prover S1->S12 assembles its own
# priming input + 3-round coms + dnac_fri_proof_t, then dnac_stark_prime_transcript
# + dnac_fri_verify == DNAC_FRI_OK. Rust-free, end-to-end. Links the prover stack
# PLUS the verifier + priming (fri_verifier.c, stark_priming.c) as the consumer.
$(BUILD)/test_prover_s13_verify: tests/test_prover_s13_verify.c stark_prover.h fri_verifier.h stark_priming.h $(PROVER_STACK) fri_verifier.c stark_priming.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_s13_verify.c $(PROVER_STACK) fri_verifier.c stark_priming.c $(SHA3_SRC) $(LDLIBS) -o $@

# P1 (C prover) — library-level dnac_prover_prove on ARBITRARY instances: the
# instance-generic prove + assemble + self-verify (stark_prover_prove.c). Proves
# both M3a (1 FRI round) and a height-8 instance (2 FRI rounds, 6-bit indices),
# exercising the multi-round FRI commit phase + generalized answer_query.
$(BUILD)/test_prover_prove: tests/test_prover_prove.c stark_prover_prove.h stark_prover_prove.c stark_prover.h fri_verifier.h stark_priming.h fri_proof_codec.h stark_proof_codec.h $(PROVER_STACK) fri_verifier.c stark_priming.c fri_proof_codec.c stark_proof_codec.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_prove.c stark_prover_prove.c $(PROVER_STACK) fri_verifier.c stark_priming.c fri_proof_codec.c stark_proof_codec.c $(SHA3_SRC) $(LDLIBS) -o $@

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

# P2 — prover perf bench (manual, NOT in `make test`; like the gen-* targets).
# Measures prove_ms + verify_ms + wire proof size across instance heights.
#   make bench-prover && ./build/bench_prover
bench-prover: | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tools/bench_prover.c stark_prover_prove.c $(PROVER_STACK) fri_verifier.c stark_priming.c fri_proof_codec.c stark_proof_codec.c $(SHA3_SRC) $(LDLIBS) -o $(BUILD)/bench_prover
	$(BUILD)/bench_prover

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
	@echo "B1 Stage-2 — COMBINED conf AIR is_zk=1 end-to-end FRI verify (width 614, num_qc=8)"
	@echo "  h=8 full + h=16 padded instances (real p3 prove, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_fri_verify_zk tools/vectors/conf_root_air_zk.json
	@$(BUILD)/test_fri_verify_zk tools/vectors/conf_root_air_zk_h16.json
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
	@echo "B1 Stage-2 — C constraint layer vs REAL Plonky3 verifier fns (82cfad73)"
	@echo "  selectors + split-domain shifts + N-chunk recompose (num_qc=8, width 614)"
	@echo "============================================================"
	@echo "-- h=8 full instance --"
	@$(BUILD)/test_conf_root_verify tools/vectors/conf_root_air_zk.json
	@echo "-- h=16 padded instance --"
	@$(BUILD)/test_conf_root_verify tools/vectors/conf_root_air_zk_h16.json
	@echo
	@echo "============================================================"
	@echo "B1 Stage-2 — pure-C conf PROVER byte-match vs the REAL Plonky3 proof"
	@echo "  S1-S12 over the combined AIR (width 614, num_qc=8, 17 publics);"
	@echo "  zeta + 3 roots + final_poly byte-match + self-verify (FRI + N-chunk)"
	@echo "============================================================"
	@$(BUILD)/test_prover_conf tools/vectors/conf_root_air_zk.json tools/vectors/smallrng_goldilocks.json
	@$(BUILD)/test_prover_conf tools/vectors/conf_root_air_zk_h16.json tools/vectors/smallrng_goldilocks.json
	@echo
	@echo "============================================================"
	@echo "S1 (C prover) — RangeProofAir witness-trace builder byte-match KAT"
	@echo "  vs oracle generate_range_proof_trace (p3_uni_stark::prove input, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_prover_trace tools/vectors/prover_trace_range_zk.json
	@echo
	@echo "============================================================"
	@echo "S2 (C prover) — is_zk randomize + coset LDE + bit-rev byte-match KAT"
	@echo "  vs the REAL committed trace matrix (HidingFriPcs commit, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_prover_s2_lde tools/vectors/prover_s2_lde_zk.json
	@echo
	@echo "============================================================"
	@echo "S3 (C prover) — Merkle BUILD: root == REAL proof.commitments.trace"
	@echo "  (S1->S2->S3 chain end-to-end + open/verify roundtrip, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_prover_s3_commit tools/vectors/prover_s2_lde_zk.json
	@echo
	@echo "============================================================"
	@echo "S5 (C prover) — FS to alpha: C transcript drive == REAL p3 alpha"
	@echo "  (prover.rs:161-195 sequence on the C-built trace root, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_prover_s5_alpha tools/vectors/prover_s2_lde_zk.json tools/vectors/range_proof_air_zk.json
	@echo
	@echo "============================================================"
	@echo "S6 (C prover) — quotient: C domain-wide fold == REAL p3 quotient_values"
	@echo "  (selectors + trace gather + 61-constraint alpha fold + Z_H^-1 + split)"
	@echo "============================================================"
	@$(BUILD)/test_prover_s6_quotient tools/vectors/prover_s6_quotient_zk.json tools/vectors/prover_s2_lde_zk.json
	@echo
	@echo "============================================================"
	@echo "S7 (C prover) — quotient blinding + 4-matrix commit: full chain S1->S7"
	@echo "  root == REAL proof.commitments.quotient_chunks (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_prover_s7_commit tools/vectors/prover_s7_quotient_commit_zk.json tools/vectors/prover_s2_lde_zk.json
	@echo
	@echo "============================================================"
	@echo "S8 (C prover) — R commit + FS to zeta: full chain S1->S8 zeta =="
	@echo "  REAL p3 zeta/zeta_next (random observe order load-bearing, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_prover_s8_zeta tools/vectors/prover_s8_random_zk.json tools/vectors/prover_s7_quotient_commit_zk.json tools/vectors/prover_s2_lde_zk.json tools/vectors/range_proof_air_zk.json
	@echo
	@echo "============================================================"
	@echo "S9 (C prover) — open at zeta: barycentric opened values + FRI alpha"
	@echo "  full chain S1->S9 == REAL merged opened values (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_prover_s9_open tools/vectors/prover_s9_open_zk.json tools/vectors/prover_s8_random_zk.json tools/vectors/prover_s7_quotient_commit_zk.json tools/vectors/prover_s2_lde_zk.json tools/vectors/range_proof_air_zk.json
	@echo
	@echo "============================================================"
	@echo "S10 (C prover) — FRI commit phase: reduced-opening + fold/commit + final poly"
	@echo "  == REAL commit-phase roots / betas / final_poly (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_prover_s10_fri tools/vectors/prover_s10_fri_zk.json tools/vectors/prover_s8_random_zk.json tools/vectors/prover_s7_quotient_commit_zk.json tools/vectors/prover_s2_lde_zk.json
	@echo
	@echo "============================================================"
	@echo "S11+S12 (C prover) — query indices + Merkle query openings"
	@echo "  indices == REAL [4,23]; openings verify vs retained roots (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_prover_s11_query tools/vectors/prover_s11_indices_zk.json tools/vectors/prover_s8_random_zk.json tools/vectors/prover_s7_quotient_commit_zk.json tools/vectors/prover_s2_lde_zk.json
	@echo
	@echo "============================================================"
	@echo "S13 (C prover) — MILESTONE: pure-C prove -> dnac_fri_verify == DNAC_FRI_OK"
	@echo "============================================================"
	@$(BUILD)/test_prover_s13_verify tools/vectors/prover_s8_random_zk.json tools/vectors/prover_s7_quotient_commit_zk.json tools/vectors/prover_s2_lde_zk.json
	@echo
	@echo "============================================================"
	@echo "P1 (C prover) — dnac_prover_prove on ARBITRARY instances"
	@echo "  M3a (1 FRI round) + height-8 (2 FRI rounds, 6-bit indices) -> C verify OK"
	@echo "============================================================"
	@$(BUILD)/test_prover_prove tools/vectors/prover_full_a.json tools/vectors/prover_full_b.json tools/vectors/prover_full_c.json
	@echo
	@echo "============================================================"
	@echo "FP1.2 — Poseidon2-Goldilocks width-8 permutation (grounded port)"
	@echo "  byte-match vs real default_goldilocks_poseidon2_8().permute (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_poseidon2_goldilocks tools/vectors/poseidon2_goldilocks.json
	@echo
	@echo "============================================================"
	@echo "FP1c.1 — Poseidon2 AIR column layout binding (Poseidon2Cols<8,7,1,4,22>)"
	@echo "============================================================"
	@$(BUILD)/test_poseidon2_air_cols
	@echo
	@echo "============================================================"
	@echo "FP1c.2 — Poseidon2 AIR trace-row byte-match (real generate_trace_rows, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_poseidon2_air_trace tools/vectors/poseidon2_air_trace.json
	@echo
	@echo "============================================================"
	@echo "FP1c.3 — Poseidon2 AIR constraint eval (accept real trace + tamper-reject, 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_poseidon2_air tools/vectors/poseidon2_air_trace.json
	@echo
	@echo "============================================================"
	@echo "B1 Stage-1 — confidential balance/selector AIR (construction gate, is_zk=0)"
	@echo "  honest accepted + SEC-1/SEC-2 attacks rejected (padding-MINT closed)"
	@echo "============================================================"
	@$(BUILD)/test_conf_balance_air
	@echo
	@echo "============================================================"
	@echo "B1 Stage-1 inc.2 — VC value-commitment composition (SEC-2 amount==commitment)"
	@echo "  honest + c-check + SEC-2 attacks rejected (same-window copy, is_zk=0)"
	@echo "============================================================"
	@$(BUILD)/test_conf_commit_air
	@echo
	@echo "============================================================"
	@echo "B1 Stage-1 inc.3 — commitment-set-root CA accumulator (capacity-IV fold)"
	@echo "  honest + verifier recompute + order-forgery + attacks rejected (is_zk=0)"
	@echo "============================================================"
	@$(BUILD)/test_conf_root_air
	@echo
	@echo "============================================================"
	@echo "B1 Stage-1 — tx_binding (SEC-5 mechanism: rejection map + tx-bound root)"
	@echo "============================================================"
	@$(BUILD)/test_conf_txbind
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
