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
# M5 gate: the KAT-only test exports (dnac_batch_prove_forged_fs_testonly,
# dnac_agg_prover_proof_wire_encode_testonly, ...) exist ONLY in this
# standalone test build — consensus builds (nodus/messenger CMake) do not
# define this, so those symbols cannot be reached from consensus. d4.d: the
# unpinned dnac_fri_verify_wire entry this flag used to gate is DELETED, not
# merely compiled out.
CFLAGS  += -DDNAC_ZK_ENABLE_TEST_WIRE
INCLUDES = -I. -I/opt/dna/shared
LDLIBS   = -lcrypto

# DNAC's qgp_sha3 (linked directly rather than via libdna).
SHA3_SRC = /opt/dna/shared/crypto/hash/qgp_sha3.c

# Transcript — P1c Poseidon2 DuplexChallenger backend (SHA3 HashChallenger +
# sponge_sha3_512 RETIRED at the P1c clean cutover, G-SEC-P1-5). Any target
# linking fri_verifier.c / a prover must link this stack.
TRANSCRIPT_STACK = transcript.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c

# Everything fri_verifier.c links against. P1c: the MMCS is the Poseidon2
# poseidon2_mmcs.c (SHA3 merkle_smt RETIRED).
FRI_VERIFIER_STACK = fri_verifier.c $(TRANSCRIPT_STACK) poseidon2_mmcs.c zk_field_helpers.c fri_fold.c
FRI_VERIFIER_LDADD = $(SHA3_SRC) $(LDLIBS)

# (d4.d: FRI_PROOF_CODEC_STACK RETIRED — its only consumers were the v3 codec /
# priming / DZKS tests, all deleted with the v3 uni-stark pipeline. The v4
# codec is linked directly by the recipes that need it.)

# Everything the C prover (stark_prover.c) links against: trace builders
# (range_air/sum_balance), NTT + helpers (S2 LDE), Merkle build (S3), and the
# transcript stack (S5+ Fiat-Shamir; TRANSCRIPT_STACK carries field_goldilocks).
PROVER_STACK = stark_prover.c sum_balance.c range_air.c ntt_goldilocks.c zk_field_helpers.c poseidon2_mmcs.c fri_fold.c $(TRANSCRIPT_STACK)

# P1c: poseidon2_goldilocks.c removed (TRANSCRIPT_STACK carries it — see the
# CONF_AIR_STACK note further down).
ACTION_AIR_STACK = conf_action_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c

# Dual-mode S4b.4 — the aggregate prover's full link set.
# d4.c-2: the agg prover DELEGATES to dnac_batch_prove, so the batched
# prover/verify/priming + LogUp stack link into every AGG_PROVER_SRCS consumer.
# d4.d: stark_priming.c DROPPED (the v3 uni-stark priming has no caller left —
# the batched pipeline primes through batch_priming.c), and the definition MOVED
# UP HERE from its old home below test_prover_agg. Reason: make expands a
# prerequisite list when it READS the rule, so a recipe that names
# $(AGG_PROVER_SRCS) as a prerequisite while the variable is still undefined
# gets an EMPTY prerequisite list — silently. test_batch_shielded_agg (defined
# ~300 lines above the old definition) hit exactly that, which is why it used to
# name 5 sources by hand and miss the other 25.
AGG_PROVER_SRCS = stark_prover_agg.c conf_action_agg_fold.c conf_action_fold.c poseidon2_fold.c stark_constraints.c $(ACTION_AIR_STACK) $(PROVER_STACK) fri_verifier.c fri_proof_codec.c shielded_fri_params.c zk_entropy.c batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c

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
    $(BUILD)/test_zk_field_helpers \
    $(BUILD)/test_primitive_oracle \
    $(BUILD)/test_fri_fold \
    $(BUILD)/test_fri_fold_row_oracle \
    $(BUILD)/test_fri_fold_matrix_loga1_oracle \
    $(BUILD)/test_fri_fold_matrix_oracle \
    $(BUILD)/test_fri_verifier_shape \
    $(BUILD)/test_fri_verifier_transcript \
    $(BUILD)/test_fri_verifier_mmcs_calls \
    $(BUILD)/test_fri_verifier_verify_query \
    $(BUILD)/test_fri_verifier_terminal_horner \
    $(BUILD)/test_fri_verifier_valid \
    $(BUILD)/test_fri_verifier_rollin \
    $(BUILD)/test_stark_constraints_primitives \
    $(BUILD)/test_stark_verify_constraints \
    $(BUILD)/test_range_proof_air \
    $(BUILD)/test_conf_root_verify \
    $(BUILD)/test_conf_action_verify \
    $(BUILD)/test_conf_action_agg_verify \
    $(BUILD)/test_prover_agg \
    $(BUILD)/test_prover_shielded_production \
    $(BUILD)/test_shielded_verify \
    $(BUILD)/test_prover_salted_commit \
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
    $(BUILD)/test_poseidon2_goldilocks \
    $(BUILD)/test_duplex_challenger \
    $(BUILD)/test_poseidon2_mmcs \
    $(BUILD)/test_poseidon2_air_cols \
    $(BUILD)/test_poseidon2_air_trace \
    $(BUILD)/test_poseidon2_air \
    $(BUILD)/test_conf_balance_air \
    $(BUILD)/test_conf_commit_air \
    $(BUILD)/test_conf_root_air \
    $(BUILD)/test_conf_txbind \
    $(BUILD)/test_note_commit \
    $(BUILD)/test_shielded_domsep \
    $(BUILD)/test_shielded_fri_params \
    $(BUILD)/test_conf_action_air \
    $(BUILD)/test_conf_action_agg_air \
    $(BUILD)/test_conf_membership_air \
    $(BUILD)/test_conf_nullifier_air \
    $(BUILD)/test_logup \
    $(BUILD)/test_logup_bus \
    $(BUILD)/test_batch_priming \
    $(BUILD)/test_poseidon2_mmcs_mixed \
    $(BUILD)/test_batch_verify \
    $(BUILD)/test_batch_prover \
    $(BUILD)/test_batch_wire \
    $(BUILD)/test_batch_shielded_agg

# ── PREREQ HYGIENE (d4.d, 2026-07-26) ───────────────────────────────────────
# A source on a recipe's command line that is NOT among its prerequisites means
# `make` will not relink when that source changes: the incremental build then
# runs a STALE binary — i.e. old code silently passing as green. That is the
# forbidden non-determinism class in root CLAUDE.md, and it has bitten this
# tree before (d4.c: three AGG_PROVER_SRCS consumers had no batch_*.c prereqs).
#
# $(SHA3_SRC) is on 18 recipe command lines and was in none of their
# prerequisite lists. One global line fixes every current AND future test
# binary, instead of 18 edits that the next recipe would forget:
$(TESTS): $(SHA3_SRC)

.PHONY: all test clean bench-prover

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

# P1a — Poseidon2 DuplexChallenger byte-match (oracle scenario replay).
$(BUILD)/test_duplex_challenger: tests/test_duplex_challenger.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c duplex_challenger.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_duplex_challenger.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# P2L-a — LogUp lookup gadget byte-match (aux traces, residual streams,
# cumulative sums, global-sum verdicts, constraint degrees vs the REAL
# p3-lookup LogUpGadget; tools/vectors/logup.json).
$(BUILD)/test_logup: tests/test_logup.c tests/logup_test_util.h logup.c field_goldilocks.c logup.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_logup.c logup.c field_goldilocks.c -o $@

# P2L-b — interaction/bus layer byte-match (builder replay -> column
# assignment, per-bus challenge memo vs the REAL sample_perm_challenges +
# duplex draw replay, per-bus global-sum grouping incl. the F3 cross-bus
# cancellation trap; tools/vectors/logup_bus.json).
$(BUILD)/test_logup_bus: tests/test_logup_bus.c tests/logup_test_util.h logup_bus.c logup.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c logup_bus.h logup.h duplex_challenger.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_logup_bus.c logup_bus.c logup.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# P2L-c — batch-stark priming + proof-shape byte-match (verifier-order
# transcript milestones on the C duplex, memo challenges, alpha/zeta, shape
# accept + mutation rejects; tools/vectors/batch_priming.json).
$(BUILD)/test_batch_priming: tests/test_batch_priming.c tests/logup_test_util.h batch_priming.c logup_bus.c logup.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c batch_priming.h logup_bus.h logup.h duplex_challenger.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_batch_priming.c batch_priming.c logup_bus.c logup.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# P2L-d d1a — MIXED-height Poseidon2 MMCS byte-match (layer injection vs the
# REAL MerkleTreeMmcs/HidingMmcs; tools/vectors/poseidon2_mmcs_mixed.json).
$(BUILD)/test_poseidon2_mmcs_mixed: tests/test_poseidon2_mmcs_mixed.c tests/logup_test_util.h poseidon2_mmcs.c logup.c poseidon2_goldilocks.c field_goldilocks.c poseidon2_mmcs.h logup.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_poseidon2_mmcs_mixed.c poseidon2_mmcs.c logup.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# P2L-d d2 — batched STARK verify end-to-end vs the REAL prove_batch
# vectors (batch priming + N2 round assembly + hiding merge + PCS observe +
# dnac_fri_verify incl. mixed-height batches + constraint check at zeta with
# LogUp residual folds + per-bus sums; tools/vectors/batch_proof.json).
$(BUILD)/test_batch_verify: tests/test_batch_verify.c tests/batch_test_util.h tests/logup_test_util.h batch_verify.c batch_priming.c logup_bus.c logup.c stark_constraints.c $(FRI_VERIFIER_STACK) batch_verify.h batch_priming.h logup_bus.h logup.h stark_constraints.h fri_verifier.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_batch_verify.c batch_verify.c batch_priming.c logup_bus.c logup.c stark_constraints.c $(FRI_VERIFIER_STACK) -o $@

# P2L-d d3 — batched STARK prover byte-match vs the REAL prove_batch vectors
# (mixed-height commits, aux traces, lookup'd quotient via serial Horner,
# N2 opening rounds, per-height FRI reduced openings + roll-in commit phase,
# query openings; self-verify = dnac_batch_verify; the fib_zk scenario
# consumes the oracle's SmallRng(1) zk_rng stream; batch_proof.json).
$(BUILD)/test_batch_prover: tests/test_batch_prover.c tests/batch_test_util.h tests/logup_test_util.h batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c stark_constraints.c fri_verifier.c $(PROVER_STACK) batch_prover.h batch_verify.h batch_priming.h logup_bus.h logup.h stark_constraints.h fri_verifier.h stark_prover.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_batch_prover.c batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c stark_constraints.c fri_verifier.c $(PROVER_STACK) -o $@

# P2L-d d4.b — the DZKF v4 batched-proof wire codec: decode the oracle's
# wire_v4 bytes, verify the DECODED package end-to-end (dnac_batch_verify —
# NO opening points on the wire, zeta is sampled), re-encode byte-match
# (C encoder == the oracle's independent second encoder), prove-from-scratch
# -> encode -> oracle byte-match, + fail-close decode negatives
# (magic/version/truncation/noncanonical/flag/length/trailing).
$(BUILD)/test_batch_wire: tests/test_batch_wire.c tests/batch_test_util.h tests/logup_test_util.h fri_proof_codec.c fri_proof_codec.h shielded_fri_params.c batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c stark_constraints.c fri_verifier.c $(PROVER_STACK) batch_prover.h batch_verify.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_batch_wire.c fri_proof_codec.c shielded_fri_params.c batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c stark_constraints.c fri_verifier.c $(PROVER_STACK) -o $@

# P2L-d d4.c-1 — the FIRST validation of the SALTED batched prover: the v3
# aggregate Action AIR fixtures re-proved via dnac_batch_prove (salt_elems=2)
# byte-matched against the REAL Plonky3 prove_batch shielded-agg vectors
# (tools/vectors/batch_shielded_agg.json + smallrng_goldilocks.json draw stream).
# Links via AGG_PROVER_SRCS, which carries stark_prover_agg.c + the
# ACTION/PROVER stacks + fri_verifier/codec/shielded_fri_params/zk_entropy AND
# (since d4.c-2) the batched prover/verify/priming + LogUp stack.
# d4.d PREREQ FIX: the prerequisite list used to name only 5 of those sources
# while the command line linked all of them, so edits to stark_prover_agg.c /
# fri_verifier.c / fri_proof_codec.c / batch_verify.c … did NOT relink this
# binary (stale-binary hazard — the same defect class d4.c fixed on the other
# three AGG_PROVER_SRCS consumers, which spell their sources out via the
# expanded stacks). The prerequisite is now the SAME variable the command uses,
# so the two can no longer drift apart.
$(BUILD)/test_batch_shielded_agg: tests/test_batch_shielded_agg.c $(AGG_PROVER_SRCS) stark_prover_agg.h batch_prover.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_batch_shielded_agg.c $(AGG_PROVER_SRCS) $(SHA3_SRC) $(LDLIBS) -o $@

# P1b — Poseidon2 MMCS byte-match (plain + hiding trees, oracle replay;
# note_commit.c linked for the note_sponge_hash8 bridge KAT).
$(BUILD)/test_poseidon2_mmcs: tests/test_poseidon2_mmcs.c poseidon2_mmcs.c note_commit.c poseidon2_goldilocks.c field_goldilocks.c poseidon2_mmcs.h note_commit.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_poseidon2_mmcs.c poseidon2_mmcs.c note_commit.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# S0 dual-mode — note-commitment + Merkle-compress PaddingFreeSponge<8,4,4>
# byte-match vs Plonky3 (tools/vectors/note_commit_sponge.json).
$(BUILD)/test_note_commit: tests/test_note_commit.c note_commit.c poseidon2_goldilocks.c field_goldilocks.c note_commit.h shielded_domsep.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_note_commit.c note_commit.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# S0 dual-mode — shielded DOMSEP derivation + canonicity + distinctness (SHA3).
$(BUILD)/test_shielded_domsep: tests/test_shielded_domsep.c field_goldilocks.c shielded_domsep.h conf_commit_air.h conf_root_air.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_shielded_domsep.c field_goldilocks.c $(SHA3_SRC) $(LDLIBS) -o $@

# S0 dual-mode — the pinned consensus FRI parameter set + exact params_eq.
# d4.d: the third assertion (v3 wire substitution-guard reject) retired with
# dnac_fri_verify_wire_shielded; that guard is covered on the v4 path by
# test_shielded_verify T-R6. The test now needs ONLY the pinned params TU.
$(BUILD)/test_shielded_fri_params: tests/test_shielded_fri_params.c shielded_fri_params.h shielded_fri_params.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_shielded_fri_params.c shielded_fri_params.c -o $@

# S1a/S1b/S1c dual-mode C1 — phase-counter + freeze-carry + note-commitment
# (is_zk=0 construction gate). S1c composes poseidon2-air + the S0 note_commit
# sponge (cm byte-match) → links the poseidon2 + sponge stack.
$(BUILD)/test_conf_action_air: tests/test_conf_action_air.c conf_action_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c conf_action_air.h note_commit.h shielded_domsep.h poseidon2_air.h poseidon2_air_cols.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_action_air.c conf_action_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# Dual-mode S4a — aggregate Action AIR construction gate (C1 reused + phases).
$(BUILD)/test_conf_action_agg_air: tests/test_conf_action_agg_air.c conf_action_agg_air.c conf_action_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c conf_action_agg_air.h conf_action_air.h conf_membership_air.h conf_nullifier_air.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_action_agg_air.c conf_action_agg_air.c conf_action_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# S2 dual-mode C3 — Poseidon2 Merkle-path membership construction gate (is_zk=0).
$(BUILD)/test_conf_membership_air: tests/test_conf_membership_air.c conf_membership_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c conf_membership_air.h note_commit.h poseidon2_air.h poseidon2_air_cols.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_membership_air.c conf_membership_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# S3 dual-mode C4 — nullifier-PRF construction gate (is_zk=0). SHA3 for the
# DOMSEP derivation check is compile-time; links poseidon2 stack.
$(BUILD)/test_conf_nullifier_air: tests/test_conf_nullifier_air.c conf_nullifier_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c conf_nullifier_air.h note_commit.h shielded_domsep.h poseidon2_air.h poseidon2_air_cols.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_nullifier_air.c conf_nullifier_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

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
# (P1c: test_sponge_sha3_512 RETIRED with the SHA3 transcript backend.)

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
# (P1c: test_transcript_oracle RETIRED — successor: test_duplex_challenger.)

# P1 — query-PoW grind unit test (dnac_transcript_grind, Plonky3 grinding_challenger).
# (P1c: test_transcript_grind RETIRED — grind covered by test_duplex_challenger.)

# Stage M3 — Merkle/MMCS C oracle replay against tools/vectors/merkle_mmcs.json.
# Links merkle_smt.c plus the OpenSSL-backed qgp_sha3_512 one-shot for both the
# leaf and parent hash. Per design doc § 6 and the post-2026-05-27 Strategy C
# resolution; oracle vectors produced by plonky3_oracle/src/main.rs (PW=[u64;1],
# DIGEST_ELEMS=8) and wire-byte-identical to the C-side uint8_t[64] format.
# (P1c: test_merkle_mmcs RETIRED with merkle_smt — successor: test_poseidon2_mmcs.)

# Phase 2A — same-height multi-matrix batch oracle replay against
# tools/vectors/merkle_mmcs_batch_same_height.json. Exercises the new
# dnac_merkle_batch_commit/open/verify additive API alongside an in-test
# regression against the existing single-matrix path for num_matrices == 1.
# (P1c: test_merkle_mmcs_batch RETIRED with merkle_smt.)

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
	$(CC) $(CFLAGS) -DDNAC_FRI_TESTING=1 -DDNAC_TRANSCRIPT_TESTING=1 $(INCLUDES) tests/test_fri_verifier_valid.c $(FRI_VERIFIER_STACK) $(FRI_VERIFIER_LDADD) -o $@

# Phase F1.6 — multi-reduced-opening ROLL-IN. Verifies a 2-commitment (heights
# 2^4 + 2^2) proof end-to-end (DNAC_FRI_OK), then proves the verify_query roll-in
# (verifier.rs:477-480) is EXERCISED: independent fold trace (via fri_fold_row_fp2)
# recomputes folded_before/after and matches the Plonky3-anchored vector. The
# vector carries its own primed transcript seed, so only one file is needed.
$(BUILD)/test_fri_verifier_rollin: tests/test_fri_verifier_rollin.c fri_verifier.h $(FRI_VERIFIER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) -DDNAC_FRI_TESTING=1 -DDNAC_TRANSCRIPT_TESTING=1 $(INCLUDES) tests/test_fri_verifier_rollin.c $(FRI_VERIFIER_STACK) $(FRI_VERIFIER_LDADD) -o $@

# (d4.d: test_fri_proof_codec / test_stark_priming / test_stark_priming_zk /
# test_fri_verify_zk / test_stark_proof_codec / test_stark_priming_integrated
# RETIRED with the v3 uni-stark pipeline they exercised. The DZKF wire is now
# covered by test_batch_wire (v4 codec, incl. the v3/v4 cross-version
# rejects), the transcript by test_batch_priming, and the end-to-end
# prove->verify chain by test_batch_prover / test_batch_shielded_agg /
# test_shielded_verify.)

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

$(BUILD)/test_conf_root_verify: tests/test_conf_root_verify.c stark_constraints.h stark_constraints.c conf_root_fold.h conf_root_fold.c poseidon2_fold.h poseidon2_fold.c poseidon2_goldilocks.h poseidon2_goldilocks.c field_goldilocks.h field_goldilocks.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_root_verify.c stark_constraints.c conf_root_fold.c poseidon2_fold.c poseidon2_goldilocks.c field_goldilocks.c -o $@

$(BUILD)/test_conf_action_verify: tests/test_conf_action_verify.c stark_constraints.h stark_constraints.c conf_action_fold.h conf_action_fold.c conf_action_air.h poseidon2_fold.h poseidon2_fold.c poseidon2_goldilocks.h poseidon2_goldilocks.c field_goldilocks.h field_goldilocks.c shielded_domsep.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_action_verify.c stark_constraints.c conf_action_fold.c poseidon2_fold.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# Dual-mode S4b — aggregate Action AIR fold vs REAL is_zk=1 proof (C1 reuse).
$(BUILD)/test_conf_action_agg_verify: tests/test_conf_action_agg_verify.c stark_constraints.h stark_constraints.c conf_action_agg_fold.h conf_action_agg_fold.c conf_action_fold.h conf_action_fold.c conf_action_agg_air.h conf_action_air.h conf_membership_air.h conf_nullifier_air.h poseidon2_fold.h poseidon2_fold.c poseidon2_goldilocks.h poseidon2_goldilocks.c field_goldilocks.h field_goldilocks.c shielded_domsep.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conf_action_agg_verify.c stark_constraints.c conf_action_agg_fold.c conf_action_fold.c poseidon2_fold.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# P1c: poseidon2_goldilocks.c REMOVED (now carried by TRANSCRIPT_STACK — every
# user of this stack also links PROVER_STACK ⊃ TRANSCRIPT_STACK; double-listing
# is a duplicate-symbol link error). keccak_ref.c ADDED (conf_txbind consumer;
# it used to arrive via the retired SHA3 TRANSCRIPT_STACK).
CONF_AIR_STACK = conf_root_air.c conf_commit_air.c conf_balance_air.c conf_txbind.c keccak_ref.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c

# Production CSPRNG (G2): self-contained getrandom(2)/urandom, dependency-free
# (the parked zk stack must not drag in the platform logging chain). PROVER-side
# only — tests exercise it structurally, never for byte-stable values.
$(BUILD)/test_zk_entropy: tests/test_zk_entropy.c zk_entropy.h zk_entropy.c field_goldilocks.h field_goldilocks.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_zk_entropy.c zk_entropy.c field_goldilocks.c -o $@

# (d4.d: test_prover_conf / test_prover_action RETIRED with the v3
# single-instance provers stark_prover_conf.c / stark_prover_action.c. The
# aggregate prover — the only one with a live consumer — survives below and
# now delegates to dnac_batch_prove.)

# ACTION_AIR_STACK and AGG_PROVER_SRCS are defined at the top of this file (with
# the other stacks) — they must exist before the FIRST rule that names them as a
# prerequisite, and test_batch_shielded_agg sits well above this point.

# Dual-mode S4b.4 — aggregate prover byte-match vs REAL is_zk=1 proof (21 publics).
$(BUILD)/test_prover_agg: tests/test_prover_agg.c stark_prover_agg.h stark_prover_agg.c conf_action_agg_fold.h conf_action_agg_fold.c conf_action_fold.h conf_action_fold.c conf_action_agg_air.h poseidon2_fold.h poseidon2_fold.c stark_constraints.c $(ACTION_AIR_STACK) $(PROVER_STACK) fri_verifier.c fri_proof_codec.c fri_proof_codec.h shielded_fri_params.c zk_entropy.c batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_agg.c $(AGG_PROVER_SRCS) $(SHA3_SRC) $(LDLIBS) -o $@

$(BUILD)/test_prover_shielded_production: tests/test_prover_shielded_production.c stark_prover_agg.h stark_prover_agg.c conf_action_agg_fold.h conf_action_agg_fold.c conf_action_fold.h conf_action_fold.c conf_action_agg_air.h poseidon2_fold.h poseidon2_fold.c stark_constraints.c $(ACTION_AIR_STACK) $(PROVER_STACK) fri_verifier.c fri_proof_codec.c fri_proof_codec.h shielded_fri_params.c shielded_fri_params.h zk_entropy.c batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_shielded_production.c $(AGG_PROVER_SRCS) $(SHA3_SRC) $(LDLIBS) -o $@

# ── Phase-C C2.1: consensus shielded verify (wire-recomputed statement). ──
# Links the LIBDNA sighash source (dnac/src/transaction/serialize.c — the
# single dnac_tx_shielded_sighash source of truth, G-DET-2; same standalone-
# compile precedent as nodus-cli, nodus/CMakeLists.txt:806-822) — never a
# re-implementation.
DNAC_INCLUDES = -I/opt/dna/dnac/include
DNAC_SIGHASH_SRCS = /opt/dna/dnac/src/transaction/serialize.c \
                    /opt/dna/dnac/src/ledger/chain_def_codec.c \
                    /opt/dna/shared/dnac/chain_config_wire.c

# conf_txbind.c pulls conf_root_air (bound-root fold); keccak_ref comes via
# the transcript stack already in AGG_PROVER_SRCS.
# P1c: + keccak_ref.c (conf_txbind's SHA3; used to arrive via the retired SHA3 transcript stack).
CONF_TXBIND_DEPS = conf_root_air.c conf_commit_air.c conf_balance_air.c keccak_ref.c

$(BUILD)/test_shielded_verify: tests/test_shielded_verify.c shielded_verify.c shielded_verify.h conf_txbind.c conf_txbind.h $(CONF_TXBIND_DEPS) stark_prover_agg.h stark_prover_agg.c conf_action_agg_fold.h conf_action_agg_fold.c conf_action_fold.c poseidon2_fold.c stark_constraints.c $(ACTION_AIR_STACK) $(PROVER_STACK) fri_verifier.c fri_proof_codec.c shielded_fri_params.c zk_entropy.c batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c $(DNAC_SIGHASH_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) $(DNAC_INCLUDES) tests/test_shielded_verify.c shielded_verify.c conf_txbind.c $(CONF_TXBIND_DEPS) $(AGG_PROVER_SRCS) $(DNAC_SIGHASH_SRCS) $(SHA3_SRC) $(LDLIBS) -o $@

$(BUILD)/test_prover_salted_commit: tests/test_prover_salted_commit.c stark_prover.h $(CONF_AIR_STACK) $(PROVER_STACK) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_prover_salted_commit.c $(CONF_AIR_STACK) $(PROVER_STACK) $(SHA3_SRC) $(LDLIBS) -o $@

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
# root rebuilt by the C S1->S2->S3 chain (cross-vector tie). Pin D4 (the
# then-separate verifier-side priming was not touched by this stage; that v3
# priming module is retired as of d4.d).
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

# (d4.d: test_prover_s13_verify and test_prover_prove RETIRED — both drove the
# v3 uni-stark assemble+verify chain through stark_priming.c /
# stark_prover_prove.c. The equivalent end-to-end pure-C prove -> verify
# milestone on the shipping pipeline is test_batch_prover (self-verify inside
# dnac_batch_prove) and test_batch_shielded_agg.
#
# The gen-stark-proof-wire / gen-fri-proof-wire vector generators are gone with
# the v3 wire they emitted; their outputs — stark_proof_wire{,_no_next}.json and
# fri_proof_wire.json — were deleted with their last consumers.)

# P2 — prover perf bench (manual, NOT in `make test`).
# Measures prove_ms + verify_ms + DZKF v4 wire size across instance heights on
# the BATCHED pipeline (dnac_batch_prove / dnac_batch_verify).
#   make bench-prover && ./build/bench_prover
BENCH_PROVER_SRCS = batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c stark_constraints.c fri_verifier.c fri_proof_codec.c $(PROVER_STACK)
bench-prover: tools/bench_prover.c tests/batch_test_util.h tests/logup_test_util.h $(BENCH_PROVER_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tools/bench_prover.c $(BENCH_PROVER_SRCS) -o $(BUILD)/bench_prover
	$(BUILD)/bench_prover

test: all
	@echo "============================================================"
	@echo "[0] Vector integrity — sha256sum -c .expected_hashes"
	@echo "============================================================"
	@cd tools/vectors && sha256sum -c --quiet .expected_hashes
	@echo "vector hashes OK"
	@echo
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
	@echo "Phase A — zk_field_helpers (Plonky3 commit 82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_zk_field_helpers
	@echo
	@echo "============================================================"
	@echo "Phase A.2 — zk_entropy (G2 prover CSPRNG, rejection-sampled canonical)"
	@echo "============================================================"
	@$(BUILD)/test_zk_entropy
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
	@echo "B1 Stage-2 M3b — pure-C SALTED trace-commit byte-match vs REAL proof"
	@echo "  leaf = committed row || SALT_ELEMS salts; the salted-prover primitive"
	@echo "============================================================"
	@$(BUILD)/test_prover_salted_commit tools/vectors/conf_root_air_salted.json tools/vectors/smallrng_goldilocks.json
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
	@echo "FP1.2 — Poseidon2-Goldilocks width-8 permutation (grounded port)"
	@echo "  byte-match vs real default_goldilocks_poseidon2_8().permute (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_poseidon2_goldilocks tools/vectors/poseidon2_goldilocks.json
	@echo
	@echo "============================================================"
	@echo "P1a — Poseidon2 DuplexChallenger<Gold,Perm,8,4> (grounded port)"
	@echo "  byte-match vs real DuplexChallenger over default_goldilocks_poseidon2_8 (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_duplex_challenger tools/vectors/duplex_challenger.json
	@echo
	@echo "============================================================"
	@echo "P1b — Poseidon2 MMCS (PaddingFreeSponge hasher + TruncatedPermutation compressor)"
	@echo "  byte-match vs real MerkleTreeMmcs + MerkleTreeHidingMmcs (82cfad73, cap 0)"
	@echo "============================================================"
	@$(BUILD)/test_poseidon2_mmcs tools/vectors/poseidon2_mmcs.json
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
	@echo "S0 dual-mode — shielded DOMSEP derivation + canonicity + distinctness"
	@echo "============================================================"
	@$(BUILD)/test_shielded_domsep
	@echo
	@echo "============================================================"
	@echo "S0 dual-mode — pinned consensus FRI params (216-bit) + exact params_eq"
	@echo "  the substitution guard itself is gated on the v4 path by"
	@echo "  test_shielded_verify T-R6 (TEST-params proof -> ERR_FRI)"
	@echo "============================================================"
	@$(BUILD)/test_shielded_fri_params
	@echo
	@echo "============================================================"
	@echo "S0 dual-mode — note-commitment + Merkle-compress PaddingFreeSponge<8,4,4>"
	@echo "  byte-match vs real Plonky3 PaddingFreeSponge (82cfad73)"
	@echo "============================================================"
	@$(BUILD)/test_note_commit tools/vectors/note_commit_sponge.json
	@echo
	@echo "============================================================"
	@echo "S1 C1 COMPLETE — φ-counter+freeze-carry+note-commitment+balance+carries+cond-3"
	@echo "  in-circuit cm byte-matches S0; §4b MINT + THEFT + non-conservation + all rejected"
	@echo "============================================================"
	@$(BUILD)/test_conf_action_air
	@echo
	@echo "============================================================"
	@echo "S4a.1 dual-mode AGGREGATE scaffold — C1 reused (gather/scatter) +"
	@echo "  forced is_nf=[φ==D+1] phase selector; membership+nullifier: S4a.2/3"
	@echo "============================================================"
	@$(BUILD)/test_conf_action_agg_air
	@echo
	@echo "============================================================"
	@echo "S1e.3 dual-mode C1 fold — fp2 verifier-fold vs REAL is_zk=1 proof"
	@echo "  folded*inv_van == quotient(zeta) (width 813, num_qc=8) + negatives"
	@echo "============================================================"
	@$(BUILD)/test_conf_action_verify tools/vectors/conf_action_air_zk.json
	@echo
	@echo "============================================================"
	@echo "S4b.3 dual-mode AGGREGATE fold — fp2 verifier-fold vs REAL is_zk=1 proof"
	@echo "  folded*inv_van == quotient(zeta) (width 1936, num_qc=8) + negatives"
	@echo "============================================================"
	@$(BUILD)/test_conf_action_agg_verify tools/vectors/conf_action_agg_air_zk.json
	@echo
	@echo "============================================================"
	@echo "S4b.4 dual-mode AGGREGATE PROVER — pure-C prove byte-match vs REAL Plonky3"
	@echo "  zeta + 3 roots + final_poly + 21 publics byte-match + self-verify"
	@echo "============================================================"
	@$(BUILD)/test_prover_agg tools/vectors/batch_shielded_agg.json tools/vectors/smallrng_goldilocks.json
	@echo
	@echo "  S4b.6 multi-input KAT — 2 INPUT notes (level-0 siblings, one anchor):"
	@$(BUILD)/test_prover_agg tools/vectors/batch_shielded_agg.json tools/vectors/smallrng_goldilocks.json 2in
	@echo
	@echo "  S4b.6 boundary KAT — 4 INPUT notes (one depth-4 tree, N_input=MAX_INPUTS=4):"
	@$(BUILD)/test_prover_agg tools/vectors/batch_shielded_agg.json tools/vectors/smallrng_goldilocks.json 4in
	@echo
	@echo "  P4 SALTED KAT — M3b MerkleTreeHidingMmcs aggregate (salted leaves byte-match):"
	@$(BUILD)/test_prover_agg tools/vectors/batch_shielded_agg.json tools/vectors/smallrng_goldilocks.json --salted
	@echo
	@echo "  Phase-P tail (c) — h=256 SALTED 4-input KAT (3 FRI rounds, N_input=MAX_INPUTS):"
	@$(BUILD)/test_prover_agg tools/vectors/batch_shielded_agg.json tools/vectors/smallrng_goldilocks.json 4in --salted
	@echo
	@echo "============================================================"
	@echo "Phase-P — PRODUCTION shielded prover gate (pinned params, DZKF v4)"
	@echo "  OS-entropy SALTED h=1024 proof, 100 queries + 16-bit query-PoW,"
	@echo "  serialized and accepted by dnac_agg_prover_wire_selfcheck_shielded"
	@echo "  (v4 encode -> decode -> param pin -> dnac_batch_verify)"
	@echo "============================================================"
	@$(BUILD)/test_prover_shielded_production
	@echo
	@echo "============================================================"
	@echo "Phase-C C2.1 — CONSENSUS shielded verify (wire-recomputed statement)"
	@echo "  production proof ACCEPT + 13 distinct fail-close rejects incl. the"
	@echo "  CRIT-1 FRI-passes-but-constraint-fails isolator"
	@echo "============================================================"
	@$(BUILD)/test_shielded_verify
	@echo
	@echo "============================================================"
	@echo "S2 dual-mode C3 — Poseidon2 Merkle-path membership (is_zk=0)"
	@echo "  honest path accepted (root byte-matches S0) + 9 attacks rejected"
	@echo "============================================================"
	@$(BUILD)/test_conf_membership_air
	@echo
	@echo "============================================================"
	@echo "S3 dual-mode C4 — nullifier-PRF (ρ=CRH(cm,pos), nf=PRF(nk,ρ))"
	@echo "  honest accepted + Faerie-Gold/key-binding soundness + 9 attacks rejected"
	@echo "============================================================"
	@$(BUILD)/test_conf_nullifier_air
	@echo
	@echo "============================================================"
	@echo "P2L-a — LogUp lookup gadget (p3-lookup LogUpGadget grounded port)"
	@echo "  aux traces + residual streams + cumulative sums + global-sum"
	@echo "  verdicts + degrees byte-matched vs Plonky3 82cfad73 (logup.json)"
	@echo "============================================================"
	@$(BUILD)/test_logup tools/vectors/logup.json
	@echo
	@echo "============================================================"
	@echo "P2L-b — LogUp interaction/bus layer (builder + memo + per-bus grouping)"
	@echo "  column assignment + challenge memo (real sample_perm_challenges) +"
	@echo "  per-bus global sums incl. the F3 cross-bus trap (logup_bus.json)"
	@echo "============================================================"
	@$(BUILD)/test_logup_bus tools/vectors/logup_bus.json
	@echo
	@echo "============================================================"
	@echo "P2L-c — batch-stark priming + proof shape (verifier-order transcript)"
	@echo "  full N1 order milestones on the C duplex vs real prove/verify_batch"
	@echo "  runs + shape accept/mutation gates (batch_priming.json)"
	@echo "============================================================"
	@$(BUILD)/test_batch_priming tools/vectors/batch_priming.json
	@echo
	@echo "============================================================"
	@echo "P2L-d d1a — MIXED-height Poseidon2 MMCS (layer injection)"
	@echo "  commit/open/verify byte-match vs real MerkleTreeMmcs/HidingMmcs"
	@echo "  incl. scrambled insertion order (poseidon2_mmcs_mixed.json)"
	@echo "============================================================"
	@$(BUILD)/test_poseidon2_mmcs_mixed tools/vectors/poseidon2_mmcs_mixed.json
	@echo
	@echo "============================================================"
	@echo "P2L-d d2 — batched STARK verify (end-to-end vs real prove_batch)"
	@echo "  batch priming + N2 rounds + hiding merge + FRI (mixed-height) +"
	@echo "  constraints at zeta with LogUp folds + per-bus sums (batch_proof.json)"
	@echo "============================================================"
	@$(BUILD)/test_batch_verify tools/vectors/batch_proof.json
	@echo
	@echo "============================================================"
	@echo "P2L-d d3 — batched STARK prover (byte-match vs real prove_batch)"
	@echo "  mixed-height commits + aux traces + lookup'd quotient + N2 opens"
	@echo "  + per-height FRI reduced openings/roll-in + query openings +"
	@echo "  self-verify; fib_zk = SmallRng(1) zk_rng stream (batch_proof.json)"
	@echo "============================================================"
	@$(BUILD)/test_batch_prover tools/vectors/batch_proof.json
	@echo
	@echo "============================================================"
	@echo "P2L-d d4.b — DZKF v4 batched-proof wire codec"
	@echo "  decode + verify(decoded) + re-encode byte-match + prove->encode"
	@echo "  byte-match vs the oracle's wire_v4 + decode negatives"
	@echo "============================================================"
	@$(BUILD)/test_batch_wire tools/vectors/batch_proof.json
	@echo
	@echo "============================================================"
	@echo "P2L-d d4.c-1 — SALTED batched prover (dnac_batch_prove, SE=2)"
	@echo "  the v3 agg fixtures re-proved via prove_batch as 1-instance"
	@echo "  is_zk=1 batches; byte-match commits+alpha/zeta+opened+FRI+SALTS"
	@echo "  vs the REAL Plonky3 shielded-aggregate vectors"
	@echo "============================================================"
	@$(BUILD)/test_batch_shielded_agg tools/vectors/batch_shielded_agg.json tools/vectors/smallrng_goldilocks.json
	@echo
	@echo "============================================================"
	@echo "ALL GATES: GREEN"
	@echo "P1c (2026-07-22): proof-internal hash = Poseidon2 (DuplexChallenger"
	@echo "transcript + PaddingFreeSponge/TruncatedPermutation MMCS), all"
	@echo "vectors regenerated + byte-matched against Plonky3 82cfad73."
	@echo "============================================================"

clean:
	rm -rf $(BUILD)
