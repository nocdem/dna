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
    $(BUILD)/test_native_verify_v3 \
    $(BUILD)/test_native_verify_v3_proofs \
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
    $(BUILD)/test_shielded_tree \
    $(BUILD)/test_conf_nullifier_air \
    $(BUILD)/test_logup \
    $(BUILD)/test_logup_bus \
    $(BUILD)/test_batch_priming \
    $(BUILD)/test_poseidon2_mmcs_mixed \
    $(BUILD)/test_batch_verify \
    $(BUILD)/test_batch_prover \
    $(BUILD)/test_batch_wire \
    $(BUILD)/test_batch_shielded_agg \
    $(BUILD)/test_transcript_air_table \
    $(BUILD)/test_transcript_air \
    $(BUILD)/test_mmcs_air_table \
    $(BUILD)/test_mmcs_air \
    $(BUILD)/test_fri_air_table \
    $(BUILD)/test_fri_air \
    $(BUILD)/test_fri_oi_air_table \
    $(BUILD)/test_fri_oi_air \
    $(BUILD)/test_mmcs_mixed_air_table \
    $(BUILD)/test_mmcs_mixed_air \
    $(BUILD)/test_transcript_air_fold \
    $(BUILD)/test_mmcs_air_fold \
    $(BUILD)/test_mmcs_mixed_air_fold \
    $(BUILD)/test_fri_air_fold \
    $(BUILD)/test_fri_oi_air_fold \
    $(BUILD)/test_fri_statement

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
# F7 (P2a design §4.3): links TRANSCRIPT_STACK so Gate A can pin its local DS
# literal to transcript.c's exported DNAC_TRANSCRIPT_PROD_INIT_STATE.
$(BUILD)/test_duplex_challenger: tests/test_duplex_challenger.c $(TRANSCRIPT_STACK) transcript.h duplex_challenger.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_duplex_challenger.c $(TRANSCRIPT_STACK) -o $@

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

# P2b PIN slice — the preprocessed row-type table generator + PIN-1 (pinned
# preprocessed root + runtime KAT binding constant to generator) + PIN-2
# evidence (prep_next = 1 is load-bearing: the same proof verified with a
# prep_next = 0 descriptor is REJECTED). Links the batched prover/verifier
# stack because T4 proves + verifies a real one-instance batch whose
# PREPROCESSED matrix is the generated table. Same source set as
# test_batch_prover (which uses $(PROVER_STACK) ⊃ $(TRANSCRIPT_STACK)), plus
# mmcs_air_table.c. Prerequisites list exactly what the command line links —
# the d4.d AGG_PROVER_SRCS stale-binary lesson.
$(BUILD)/test_mmcs_air_table: tests/test_mmcs_air_table.c mmcs_air_table.c mmcs_air_table.h batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c stark_constraints.c fri_verifier.c $(PROVER_STACK) batch_prover.h batch_verify.h shielded_fri_params.h poseidon2_mmcs.h stark_prover.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_mmcs_air_table.c mmcs_air_table.c batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c stark_constraints.c fri_verifier.c $(PROVER_STACK) -o $@

# P2b AIR slice 1 — the same-height binary MMCS-verify control AIR. Honest
# traces are built test-side by NATIVE REPLAY (dnac_p2_mmcs_commit/open_batch/
# verify + hash_iter/compress + poseidon2_air_generate_row — the byte-match is
# INHERITED from the P1b/FP1c gates, not re-proved here) and must eval to 0
# violations; 22 negatives, at least one per design §0.5 constraint form, plus
# the fail-close configs, must each be caught.
#
# Sources are named LITERALLY, not through a stack variable — no ordering
# hazard of the AGG_PROVER_SRCS class (a variable still undefined when make
# reads the rule expands to an EMPTY prerequisite list, silently). Every source
# on the command line is also a prerequisite, so an edit to any of them relinks.
$(BUILD)/test_mmcs_air: tests/test_mmcs_air.c mmcs_air.c mmcs_air_table.c poseidon2_mmcs.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c mmcs_air.h mmcs_air_table.h poseidon2_mmcs.h poseidon2_air.h poseidon2_air_trace.h poseidon2_air_cols.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_mmcs_air.c mmcs_air.c mmcs_air_table.c poseidon2_mmcs.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# P2c PIN slice — the FRI fold-walk AIR's preprocessed row-type table generator
# + its structural static validator + PIN-1-P2c (pinned preprocessed root +
# runtime KAT binding constant to generator). No AIR and no prove/verify round
# trip in this slice, so the link set is the PROVER stack only: the KAT runs the
# SHIPPED preprocessed-commit pipeline (dnac_prover_coset_lde_bitrev from
# stark_prover.c, then dnac_p2_mmcs_commit_mixed from poseidon2_mmcs.c — both in
# $(PROVER_STACK), which also carries $(TRANSCRIPT_STACK)/field_goldilocks).
# shielded_fri_params.h is included for its MACROS only (the compile-time drift
# pins), so shielded_fri_params.c is deliberately NOT linked.
#
# Prerequisites list exactly what the command line links — the d4.d
# AGG_PROVER_SRCS stale-binary lesson. $(PROVER_STACK) is defined at the TOP of
# this file, well above this rule, so it cannot expand to an empty list.
$(BUILD)/test_fri_air_table: tests/test_fri_air_table.c fri_air_table.c fri_air_table.h $(PROVER_STACK) shielded_fri_params.h poseidon2_mmcs.h stark_prover.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_air_table.c fri_air_table.c $(PROVER_STACK) -o $@

# P2c AIR slice 1 — the FRI fold-walk control AIR. Honest traces are built
# TEST-SIDE by NATIVE REPLAY (fri_fold_row_fp2 + the roll-in addition + the
# two-adic generator ladder — the byte-match is INHERITED from the Phase D.2 /
# two-adic-gens gates, not re-proved here) and must eval to 0 violations; each
# accept also cross-checks every phase's x0 against the NATIVE closed form
# g_{lgmh-r}^{rev(idx>>(r+1), lgmh-1-r)}, which is what validates the design's
# DERIVED x0 recurrence independently of the AIR. 37 negatives (24 exact-count
# pinned, 11 fail-close, 2 caught-without-count), including the four MANDATORY
# FLEET 020 catches (t1 SIGN, FREE f_init, handoff-as-copy, last fold phase
# free), plus 8 fail-close cfg gates.
#
# This AIR embeds NO permutation (the fold walk is hash-free), so the link set
# is small and named LITERALLY, not through a stack variable — no ordering
# hazard of the AGG_PROVER_SRCS class (a variable still undefined when make
# reads the rule expands to an EMPTY prerequisite list, silently). Every source
# on the command line is also a prerequisite, so an edit to any of them
# relinks. fri_fold.c is the native fold oracle the test replays; it needs
# zk_field_helpers.c (shifted_powers / reverse_slice_index_bits /
# reverse_bits_len_u64, which the test also calls directly).
$(BUILD)/test_fri_air: tests/test_fri_air.c fri_air.c fri_air_table.c fri_fold.c zk_field_helpers.c field_goldilocks.c fri_air.h fri_air_table.h fri_fold.h zk_field_helpers.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_air.c fri_air.c fri_air_table.c fri_fold.c zk_field_helpers.c field_goldilocks.c -o $@

# P2c open_input PIN slice — the preprocessed ROW-TYPE table for the FRI
# reduced-opening accumulation AIR. Wired EXACTLY like test_fri_air_table: the
# generator + static validator + PIN-1-OI root KAT via the SHIPPED LDE->commit
# pipeline. Prerequisites list exactly what the command line links —
# $(PROVER_STACK) is defined at the TOP of this file, above this rule, so it
# cannot expand to an empty list (the d4.d AGG_PROVER_SRCS stale-binary lesson).
$(BUILD)/test_fri_oi_air_table: tests/test_fri_oi_air_table.c fri_oi_air_table.c fri_oi_air_table.h $(PROVER_STACK) shielded_fri_params.h poseidon2_mmcs.h stark_prover.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_oi_air_table.c fri_oi_air_table.c $(PROVER_STACK) -o $@

# P2c open_input AIR slice — the FRI reduced-opening accumulation control AIR.
# Honest traces are built TEST-SIDE by NATIVE-FORMULA REPLAY of fri_open_input
# (x_h = GENERATOR*two_adic_generator(h)^rev, fri_verifier.c:423-431; the per-
# height ro += alpha_pow*(p_z-p_x)/(z-x) accumulation, :469-476) and must eval
# to 0 violations; every accept cross-checks x_h a SECOND way (7*g^{2^cum} from
# the MSB-first chain state) at every store row. 32 negatives incl. the six
# MANDATORY A2 catches (C3f one-sided carry, C2e HOLD, C2a seed, C5 lb-zero,
# C1c booleanity, h_max gate). Embeds NO permutation (hash-free), so the link
# set is small and named LITERALLY (no AGG_PROVER_SRCS ordering hazard); reverse
# _bits is inlined test-side so nothing beyond the AIR + its table + the field
# is linked.
$(BUILD)/test_fri_oi_air: tests/test_fri_oi_air.c fri_oi_air.c fri_oi_air_table.c field_goldilocks.c fri_oi_air.h fri_oi_air_table.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_oi_air.c fri_oi_air.c fri_oi_air_table.c field_goldilocks.c -o $@

# P2b slice 2 PIN — the preprocessed ROW-TYPE table for the MIXED-HEIGHT
# MMCS-verify AIR. Wired EXACTLY like test_fri_oi_air_table: the generator +
# static validator + PIN-1-MMIX root KAT via the SHIPPED LDE->commit pipeline.
# Prerequisites list exactly what the command line links — $(PROVER_STACK) is
# defined at the TOP of this file, above this rule, so it cannot expand to an
# empty list (the d4.d AGG_PROVER_SRCS stale-binary lesson).
$(BUILD)/test_mmcs_mixed_air_table: tests/test_mmcs_mixed_air_table.c mmcs_mixed_air_table.c mmcs_mixed_air_table.h $(PROVER_STACK) shielded_fri_params.h poseidon2_mmcs.h stark_prover.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_mmcs_mixed_air_table.c mmcs_mixed_air_table.c $(PROVER_STACK) -o $@

# P2b slice 2 — the mixed-height MMCS-verify control AIR. Wired EXACTLY like
# test_mmcs_air (slice 1): the AIR + its preprocessed table + the poseidon2
# leaf/compress primitives + the embedded 180-col poseidon2_air block. Sources
# are named LITERALLY, not through a stack variable — every source on the command
# line is also a prerequisite, so an edit to any of them relinks (the d4.d
# AGG_PROVER_SRCS stale-binary lesson).
$(BUILD)/test_mmcs_mixed_air: tests/test_mmcs_mixed_air.c mmcs_mixed_air.c mmcs_mixed_air_table.c poseidon2_mmcs.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c mmcs_mixed_air.h mmcs_mixed_air_table.h poseidon2_mmcs.h poseidon2_air.h poseidon2_air_trace.h poseidon2_air_cols.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_mmcs_mixed_air.c mmcs_mixed_air.c mmcs_mixed_air_table.c poseidon2_mmcs.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# Composition s1a — the FOLD-FORM evaluators of the two hash-free P2c AIRs.
#
# Each test INCLUDES the shipped u64 gate's translation unit (tests/test_fri_air.c
# / tests/test_fri_oi_air.c, with their main() renamed out of the way) so the
# honest-trace builder, the fixtures, the configs and the tamper recipes are the
# SAME code, not a fork — the property under test is "the fold form accepts
# EXACTLY what the u64 form accepts", which a copy could not establish. That is
# why the shipped test .c is BOTH a prerequisite and (transitively) on the
# command line: an edit to it must relink these binaries (the d4.d
# AGG_PROVER_SRCS stale-binary lesson).
#
# stark_constraints.c is the folder/fold-helper implementation (the capture
# instrumentation the count + equivalence checks read). No permutation is
# embedded in either AIR, so the link set stays small and is named LITERALLY.
$(BUILD)/test_fri_air_fold: tests/test_fri_air_fold.c tests/test_fri_air.c tests/fold_test_util_b.h fri_air_fold.c fri_air.c fri_air_table.c stark_constraints.c fri_fold.c zk_field_helpers.c field_goldilocks.c fri_air_fold.h fri_air.h fri_air_table.h stark_constraints.h fri_fold.h zk_field_helpers.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_air_fold.c fri_air_fold.c fri_air.c fri_air_table.c stark_constraints.c fri_fold.c zk_field_helpers.c field_goldilocks.c -o $@

$(BUILD)/test_fri_oi_air_fold: tests/test_fri_oi_air_fold.c tests/test_fri_oi_air.c tests/fold_test_util_b.h fri_oi_air_fold.c fri_oi_air.c fri_oi_air_table.c stark_constraints.c field_goldilocks.c fri_oi_air_fold.h fri_oi_air.h fri_oi_air_table.h stark_constraints.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_oi_air_fold.c fri_oi_air_fold.c fri_oi_air.c fri_oi_air_table.c stark_constraints.c field_goldilocks.c -o $@

# ── s1b+s1c COMPOSITION ENTRY (fri_statement) ───────────────────────────────
# The entry binds FOUR s1a fold AIRs (mmix, mmcs, fri, oi — s1c added oi) into
# one batched instance set, so this recipe links the whole batch prove+verify
# stack: the test PROVES the four instances (prover side is test-side by design
# — no prover enters the lib) and then runs the entry over the result. It also
# #includes the five SHIPPED u64
# gates for their honest-trace builders (with every shared file-scope name
# macro-renamed, see the test's header), which is why those five .c files are
# prerequisites here as well.
# fri_statement.c itself links NOTHING from the prover: the LDE + Merkle commit
# half of the pin pipeline is test-side on purpose (fri_statement.h documents
# why), so the consensus verify surface stays prover-free.
# s3b adds the FIFTH instance: the transcript control AIR, its preprocessed
# op-schedule table and its fold-form evaluator. duplex_challenger.c /
# poseidon2_goldilocks.c / field_goldilocks.c / poseidon2_mmcs.c are already on
# the line through $(PROVER_STACK) -> $(TRANSCRIPT_STACK), so only the three
# transcript translation units are new here.
FRI_STATEMENT_SRCS = fri_statement.c fri_air_fold.c fri_air.c fri_air_table.c \
    fri_oi_air_fold.c fri_oi_air.c fri_oi_air_table.c \
    mmcs_air_fold.c mmcs_air.c mmcs_air_table.c mmcs_mixed_air_fold.c \
    mmcs_mixed_air.c mmcs_mixed_air_table.c transcript_air_fold.c \
    transcript_air.c transcript_air_table.c poseidon2_fold.c poseidon2_air.c \
    poseidon2_air_trace.c poseidon2_air_cols.c stark_constraints.c \
    batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c \
    fri_verifier.c $(PROVER_STACK)

FRI_STATEMENT_HDRS = fri_statement.h fri_air_fold.h fri_air.h fri_air_table.h \
    fri_oi_air_fold.h fri_oi_air.h fri_oi_air_table.h \
    mmcs_air_fold.h mmcs_air.h mmcs_air_table.h mmcs_mixed_air_fold.h \
    mmcs_mixed_air.h mmcs_mixed_air_table.h transcript_air_fold.h \
    transcript_air.h transcript_air_table.h duplex_challenger.h \
    stark_constraints.h \
    batch_prover.h batch_verify.h batch_priming.h logup_bus.h logup.h \
    fri_verifier.h stark_prover.h poseidon2_mmcs.h field_goldilocks.h

$(BUILD)/test_fri_statement: tests/test_fri_statement.c tests/test_fri_air.c tests/test_mmcs_air.c tests/test_mmcs_mixed_air.c tests/test_fri_oi_air.c tests/test_transcript_air.c tests/logup_test_util.h $(FRI_STATEMENT_SRCS) $(FRI_STATEMENT_HDRS) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_statement.c $(FRI_STATEMENT_SRCS) $(FRI_VERIFIER_LDADD) -o $@

# ── s1a FOLD-form evaluators (composition slice 1a) ─────────────────────────
# Each of the three tests below is an EQUIVALENCE gate: it #includes the SHIPPED
# u64 AIR test (for its honest-trace builder, with that file's `main` renamed
# out of the way) and folds the very same trace through the new fp2 `air_eval`.
# The shipped .c therefore appears ONLY as a prerequisite, never on the command
# line — it is textually included by the fold test, so compiling it separately
# would duplicate every symbol. It IS listed as a prerequisite so an edit to the
# shipped test relinks the fold test (the d4.d stale-binary lesson).
#
# Link sets = the shipped test's link set + the fold module + stark_constraints.c
# (the folder helpers) + poseidon2_fold.c (the shared 180-col block emission).

# s1a/A — transcript control-AIR, fold form. Takes the same 8 oracle vectors as
# test_transcript_air (they are the honest traces being folded).
$(BUILD)/test_transcript_air_fold: tests/test_transcript_air_fold.c tests/test_transcript_air.c tests/fold_test_util.h transcript_air_fold.c transcript_air.c transcript_air_table.c stark_constraints.c poseidon2_fold.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_mmcs.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c transcript_air_fold.h transcript_air.h transcript_air_table.h stark_constraints.h poseidon2_fold.h poseidon2_air.h poseidon2_air_trace.h poseidon2_air_cols.h poseidon2_mmcs.h duplex_challenger.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_transcript_air_fold.c transcript_air_fold.c transcript_air.c transcript_air_table.c stark_constraints.c poseidon2_fold.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_mmcs.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# s1a/B — same-height MMCS control-AIR, fold form (no vector files).
$(BUILD)/test_mmcs_air_fold: tests/test_mmcs_air_fold.c tests/test_mmcs_air.c tests/fold_test_util.h mmcs_air_fold.c mmcs_air.c mmcs_air_table.c stark_constraints.c poseidon2_fold.c poseidon2_mmcs.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c mmcs_air_fold.h mmcs_air.h mmcs_air_table.h stark_constraints.h poseidon2_fold.h poseidon2_mmcs.h poseidon2_air.h poseidon2_air_trace.h poseidon2_air_cols.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_mmcs_air_fold.c mmcs_air_fold.c mmcs_air.c mmcs_air_table.c stark_constraints.c poseidon2_fold.c poseidon2_mmcs.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# s1a/C — mixed-height MMCS control-AIR, fold form (no vector files).
$(BUILD)/test_mmcs_mixed_air_fold: tests/test_mmcs_mixed_air_fold.c tests/test_mmcs_mixed_air.c tests/fold_test_util.h mmcs_mixed_air_fold.c mmcs_mixed_air.c mmcs_mixed_air_table.c stark_constraints.c poseidon2_fold.c poseidon2_mmcs.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c mmcs_mixed_air_fold.h mmcs_mixed_air.h mmcs_mixed_air_table.h stark_constraints.h poseidon2_fold.h poseidon2_mmcs.h poseidon2_air.h poseidon2_air_trace.h poseidon2_air_cols.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_mmcs_mixed_air_fold.c mmcs_mixed_air_fold.c mmcs_mixed_air.c mmcs_mixed_air_table.c stark_constraints.c poseidon2_fold.c poseidon2_mmcs.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

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

# F1b+F1c — consensus-side depth-24 incremental note-commitment Merkle tree.
# The BRIDGE KAT (T3) feeds an extracted (leaf,pos,siblings) to
# conf_membership_air_generate and asserts its anchor == shielded_tree_root
# byte-for-byte, so this links the SAME poseidon2 + S0 note_commit stack as
# test_conf_membership_air, plus shielded_tree.c. Sources are named LITERALLY
# and every one is also a prerequisite, so an edit to any of them relinks (the
# d4.d AGG_PROVER_SRCS stale-binary lesson).
$(BUILD)/test_shielded_tree: tests/test_shielded_tree.c shielded_tree.c conf_membership_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c shielded_tree.h conf_membership_air.h note_commit.h poseidon2_air.h poseidon2_air_cols.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_shielded_tree.c shielded_tree.c conf_membership_air.c note_commit.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_goldilocks.c field_goldilocks.c -o $@

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
                    /opt/dna/shared/dnac/chain_config_wire.c \
                    /opt/dna/shared/dnac/tx_wire.c

# conf_txbind.c pulls conf_root_air (bound-root fold); keccak_ref comes via
# the transcript stack already in AGG_PROVER_SRCS.
# P1c: + keccak_ref.c (conf_txbind's SHA3; used to arrive via the retired SHA3 transcript stack).
CONF_TXBIND_DEPS = conf_root_air.c conf_commit_air.c conf_balance_air.c keccak_ref.c

$(BUILD)/test_shielded_verify: tests/test_shielded_verify.c shielded_verify.c shielded_verify.h conf_txbind.c conf_txbind.h $(CONF_TXBIND_DEPS) stark_prover_agg.h stark_prover_agg.c conf_action_agg_fold.h conf_action_agg_fold.c conf_action_fold.c poseidon2_fold.c stark_constraints.c $(ACTION_AIR_STACK) $(PROVER_STACK) fri_verifier.c fri_proof_codec.c shielded_fri_params.c zk_entropy.c batch_prover.c batch_verify.c batch_priming.c logup_bus.c logup.c $(DNAC_SIGHASH_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) $(DNAC_INCLUDES) tests/test_shielded_verify.c shielded_verify.c conf_txbind.c $(CONF_TXBIND_DEPS) $(AGG_PROVER_SRCS) $(DNAC_SIGHASH_SRCS) $(SHA3_SRC) $(LDLIBS) -o $@

# ── Ledger V2 S9 W3: the NATIVE stateless V3 verifier ──────────────────────
# native_verify_v3.c sits ABOVE shielded_verify.c: it decodes a whole V3
# transaction, applies the per-type native rules the policy-neutral codec does
# not own, and forwards the type-11 proof verdict to
# dnac_shielded_verify_statement — so this binary needs the SAME link set as
# test_shielded_verify (that entry's whole chain) plus the new TU.
#
# $(DNAC_SIGHASH_SRCS) carries shared/dnac/tx_wire.c (the V3 header/section/leg
# codec + sighash_v5 + the leg commitment) and $(DNAC_INCLUDES) is what resolves
# "dnac/dnac.h" / "dnac/transaction.h" / "dnac/safe_math.h". Both are defined
# just above, with test_shielded_verify.
#
# NO signature source is linked, and none is needed: the type-12 verifier is a
# caller-supplied function pointer (native_verify_v3.h SEAM 1) and this gate
# supplies a deterministic stub. Pulling qgp_dilithium.c in here would drag the
# whole vendored dsa library plus `randombytes` — the dependency nodus's own
# build calls circular (nodus/CMakeLists.txt:449).
#
# Prerequisites list exactly what the command line links (the d4.d
# AGG_PROVER_SRCS stale-binary lesson): $(AGG_PROVER_SRCS) is defined at the TOP
# of this file, well above this rule, so it cannot expand to an empty list.
$(BUILD)/test_native_verify_v3: tests/test_native_verify_v3.c native_verify_v3.c native_verify_v3.h shielded_verify.c shielded_verify.h conf_txbind.c conf_txbind.h $(CONF_TXBIND_DEPS) $(AGG_PROVER_SRCS) $(DNAC_SIGHASH_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) $(DNAC_INCLUDES) tests/test_native_verify_v3.c native_verify_v3.c shielded_verify.c conf_txbind.c $(CONF_TXBIND_DEPS) $(AGG_PROVER_SRCS) $(DNAC_SIGHASH_SRCS) $(SHA3_SRC) $(LDLIBS) -o $@

# ── S9 CORRECTION PASS: the REAL-PROOF gate for types 11/12/13 ────────────
# Same link set as test_native_verify_v3 — it exercises the same entry — but
# this binary PROVES at runtime (dnac_agg_prover_prove_production), which is why
# it is zk-ONLY: the prover is absent from libnodus, so a proof-generating gate
# cannot ride the dual-build test. No tracked vector is read or written.
$(BUILD)/test_native_verify_v3_proofs: tests/test_native_verify_v3_proofs.c native_verify_v3.c native_verify_v3.h shielded_verify.c shielded_verify.h conf_txbind.c conf_txbind.h $(CONF_TXBIND_DEPS) $(AGG_PROVER_SRCS) $(DNAC_SIGHASH_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) $(DNAC_INCLUDES) tests/test_native_verify_v3_proofs.c native_verify_v3.c shielded_verify.c conf_txbind.c $(CONF_TXBIND_DEPS) $(AGG_PROVER_SRCS) $(DNAC_SIGHASH_SRCS) $(SHA3_SRC) $(LDLIBS) -o $@

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

# P2a-i2 — transcript control-AIR (DuplexChallenger as a row-AIR). Honest
# traces built test-side from the 8 dump-transcript-trace oracle scenarios
# (native challenger replay, cross-checked against the vectors' state /
# duplexings / exposed-bit fields) must eval to 0 violations; 20 negatives, at
# least one per design §0.5 "MUST", must each be caught.
#
# Sources are named LITERALLY, not through a stack variable — no ordering
# hazard of the AGG_PROVER_SRCS class (a variable still undefined when make
# reads the rule expands to an EMPTY prerequisite list, silently). Every source
# on the command line is also a prerequisite, so an edit to any of them relinks.
$(BUILD)/test_transcript_air: tests/test_transcript_air.c transcript_air.c transcript_air_table.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_mmcs.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c transcript_air.h transcript_air_table.h poseidon2_air.h poseidon2_air_trace.h poseidon2_air_cols.h poseidon2_mmcs.h duplex_challenger.h poseidon2_goldilocks.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_transcript_air.c transcript_air.c transcript_air_table.c poseidon2_air.c poseidon2_air_trace.c poseidon2_air_cols.c poseidon2_mmcs.c duplex_challenger.c poseidon2_goldilocks.c field_goldilocks.c -o $@

# s3a PIN slice — the transcript AIR's preprocessed OP-SCHEDULE table:
# deterministic generator (challenger simulation), structural static validator,
# the PIN-1-P2a root KAT through the SHIPPED LDE->commit pipeline, and the
# `--print-roots` workflow the ORCHESTRATOR fills DNAC_P2A_PREP_ROOT_LANE* from.
# Wired EXACTLY like test_fri_air_table: $(PROVER_STACK) is defined at the TOP of
# this file, well above this rule, so it cannot expand to an empty list.
$(BUILD)/test_transcript_air_table: tests/test_transcript_air_table.c transcript_air_table.c transcript_air_table.h transcript_air.h $(PROVER_STACK) shielded_fri_params.h poseidon2_mmcs.h stark_prover.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_transcript_air_table.c transcript_air_table.c $(PROVER_STACK) -o $@

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
	@echo "Ledger V2 S9 W3 — NATIVE stateless V3 verifier (types 11/12/13)"
	@echo "  per-type count windows + boundary equalities + checked"
	@echo "  transparent arithmetic + leg commitment + sighash_v5 binding"
	@echo "  + type-12 signature hook + in-TX nullifier dedup."
	@echo "  ZERO production callers (native_verify_v3.h six-stop proof);"
	@echo "  types 12/13 stop at the documented PROOF_DEFERRED seam."
	@echo "============================================================"
	@$(BUILD)/test_native_verify_v3
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
	@echo "s3a PIN slice — transcript AIR preprocessed OP-SCHEDULE table"
	@echo "  generator determinism + the challenger-simulation schedule +"
	@echo "  the structural static validator (machine legality, script"
	@echo "  agreement, op-step one-hot, is_pow, terminality) + the pinned"
	@echo "  preprocessed root KAT (constant vs generator)"
	@echo "  (root is the {0,0,0,0} PLACEHOLDER — the KAT is RED by design"
	@echo "   until the ORCHESTRATOR fills it from --print-roots)"
	@echo "============================================================"
	@$(BUILD)/test_transcript_air_table
	@echo
	@echo "============================================================"
	@echo "P2a-i2 + s3a — transcript control-AIR (DuplexChallenger as a row-AIR)"
	@echo "  8 oracle scenarios: honest trace 0 viol + state/duplexings/"
	@echo "  exposed-bit byte-match, each against its OWN pinned op-schedule"
	@echo "  table; design-§0.5 constraint-form negatives + the s3a CT-1..CT-4"
	@echo "  table/publics negatives"
	@echo "============================================================"
	@$(BUILD)/test_transcript_air tools/vectors/transcript_trace_basic.json tools/vectors/transcript_trace_multi_instance.json tools/vectors/transcript_trace_partial_absorb.json tools/vectors/transcript_trace_pow_nonzero.json tools/vectors/transcript_trace_pow_zero_bits.json tools/vectors/transcript_trace_rate_boundary.json tools/vectors/transcript_trace_sample_bits_32.json tools/vectors/transcript_trace_squeeze_chain.json
	@echo
	@echo "============================================================"
	@echo "P2b PIN slice — preprocessed row-type table + PIN-1 + PIN-2"
	@echo "  deterministic generator + schedule shape (leaf perms derived"
	@echo "  from the PaddingFreeSponge schedule) + the pinned preprocessed"
	@echo "  root KAT (constant vs generator) + a real prove/verify round"
	@echo "  trip whose prep_next = 0 flip MUST be rejected"
	@echo "============================================================"
	@$(BUILD)/test_mmcs_air_table
	@echo
	@echo "============================================================"
	@echo "P2b slice 1 — MMCS-verify control AIR (same-height binary walk)"
	@echo "  native commit/open/verify replay -> honest trace 0 viol, both"
	@echo "  sponge residue classes x 2 non-palindromic indices; 22"
	@echo "  design-§0.5 constraint-form negatives + fail-close configs"
	@echo "============================================================"
	@$(BUILD)/test_mmcs_air
	@echo
	@echo "============================================================"
	@echo "P2c PIN slice — FRI fold-walk preprocessed row-type table"
	@echo "  deterministic generator (leaf lgmh 13 + recursion lgmh 19 +"
	@echo "  the extremal lgmh 32 shapes) + the structural static"
	@echo "  validator (typed prefix, counts, C3 multiplication-count"
	@echo "  identity, pair gates, roll-in placement, G_j literals) +"
	@echo "  the pinned preprocessed root KAT (constant vs generator)"
	@echo "  (root FILLED 2026-07-29; on a future re-pin it reverts to the"
	@echo "  {0,0,0,0} placeholder and this KAT goes RED by design)"
	@echo "============================================================"
	@$(BUILD)/test_fri_air_table
	@echo
	@echo "============================================================"
	@echo "P2c slice 1 — FRI fold-walk control AIR (arity-2, lfpl 0)"
	@echo "  native-replay honest walks (leaf lgmh 13 x 3 index vectors +"
	@echo "  recursion lgmh 19 + a hand-checked lgmh 4) at 0 violations,"
	@echo "  each with the x0 CLOSED-FORM cross-check that validates the"
	@echo "  design's derived recurrence independently of the AIR;"
	@echo "  37 constraint-form negatives (24 exact-count pinned, 11"
	@echo "  fail-close, 2 caught; incl. the four MANDATORY FLEET 020"
	@echo "  catches) + 8 eval-entry cfg gates"
	@echo "============================================================"
	@$(BUILD)/test_fri_air
	@echo
	@echo "============================================================"
	@echo "P2c open_input PIN slice — FRI reduced-opening preprocessed table"
	@echo "  deterministic generator (ref lgmh 4 H={4,2} + a wider lgmh 6"
	@echo "  H={6,4,2} shape) — chain with INTERLEAVED capture blocks of"
	@echo "  different lengths + DESCENDING accumulation groups + padding —"
	@echo "  the structural static validator (primary schedule, capture"
	@echo "  sub-flags, group-start/closeout/final, height + step one-hots,"
	@echo "  G_j literals) + the pinned preprocessed root KAT"
	@echo "  (root FILLED 2026-07-29; on a future re-pin it reverts to the"
	@echo "  {0,0,0,0} placeholder and the KAT goes RED by design)"
	@echo "============================================================"
	@$(BUILD)/test_fri_oi_air_table
	@echo
	@echo "============================================================"
	@echo "P2c open_input slice — FRI reduced-opening accumulation AIR"
	@echo "  native x_h + accumulation replay (ref lgmh 4 H={4,2} + a wider"
	@echo "  lgmh 6 H={6,4,2} + a 2-batch-lb cfg) at 0 violations, each with"
	@echo "  the x_h closed-form cross-check (7*g^{2^cum} == GENERATOR*"
	@echo "  two_adic_generator(h)^rev) at every store row; 32 negatives"
	@echo "  (16 exact-count pinned, 1 caught, 15 fail-close) incl. the SIX"
	@echo "  MANDATORY A2 catches: C3f one-sided carry, C2e register HOLD,"
	@echo "  C2a seed anchor, C5 lb per-batch zero, C1c booleanity, h_max gate"
	@echo "============================================================"
	@$(BUILD)/test_fri_oi_air
	@echo
	@echo "============================================================"
	@echo "P2b slice 2 PIN — mixed-height MMCS-verify preprocessed table"
	@echo "  deterministic generator (ref heights {8,2} salt 2 + a wider"
	@echo "  {16,4,2} shape) — tallest-group leaf + per-level compress with"
	@echo "  OPTIONAL interleaved inject blocks (leaf-hash of the injecting"
	@echo "  group + inject-compress) + final + padding — the structural"
	@echo "  static validator (primary schedule, has_inject, level + group +"
	@echo "  step one-hots) + the pinned preprocessed root KAT"
	@echo "  (root FILLED 2026-07-29; on a future re-pin it reverts to the"
	@echo "  {0,0,0,0} placeholder and the KAT goes RED by design)"
	@echo "============================================================"
	@$(BUILD)/test_mmcs_mixed_air_table
	@echo
	@echo "============================================================"
	@echo "P2b slice 2 — mixed-height MMCS-verify control AIR"
	@echo "  native commit/open/verify_mixed replay -> honest trace 0 viol"
	@echo "  (REF {8,2} + WIDE {16,4,2} two inject blocks + MG {8,8,2}"
	@echo "  two-matrix tallest group + INJ2 multi-row inject group),"
	@echo "  leaf/compress/inject digests"
	@echo "  cross-checked; N-order (the running<->rows combine-order catch)"
	@echo "  + 18 more constraint-form negatives + 6 fail-close eval gates"
	@echo "============================================================"
	@$(BUILD)/test_mmcs_mixed_air
	@echo
	@echo "============================================================"
	@echo "s1a — FOLD-form evaluators (composition slice 1a)"
	@echo "  each AIR's u64 evaluator transcribed into the batch-STARK"
	@echo "  air_eval (fp2 alpha-fold) form, then proved EQUIVALENT on the"
	@echo "  SHIPPED honest traces: T-EQ (all captured residuals zero),"
	@echo "  T-CNT (uniform, formula-matching step count, Poseidon2 block"
	@echo "  count MEASURED not asserted), T-NEG (tampers from the u64"
	@echo "  suites still caught) and T-TERM (the is_last_row boundary that"
	@echo "  carries each u64 eval_trace terminality gate)"
	@echo "============================================================"
	@$(BUILD)/test_transcript_air_fold tools/vectors/transcript_trace_basic.json tools/vectors/transcript_trace_multi_instance.json tools/vectors/transcript_trace_partial_absorb.json tools/vectors/transcript_trace_pow_nonzero.json tools/vectors/transcript_trace_pow_zero_bits.json tools/vectors/transcript_trace_rate_boundary.json tools/vectors/transcript_trace_sample_bits_32.json tools/vectors/transcript_trace_squeeze_chain.json
	@echo
	@$(BUILD)/test_mmcs_air_fold
	@echo
	@$(BUILD)/test_mmcs_mixed_air_fold
	@echo
	@echo "============================================================"
	@echo "s1a — FRI fold-walk control AIR in FOLD (batch-STARK) form"
	@echo "  the u64 evaluator's constraint set transcribed to the"
	@echo "  dnac_stark_folder_t callback: 5 honest walks accepted with"
	@echo "  ZERO non-zero residuals, 14 tampers whose non-zero count"
	@echo "  matches the u64 violation count EXACTLY (incl. the four"
	@echo "  MANDATORY FLEET 020 catches), the terminality gate re-proved"
	@echo "  as a live is_last_row boundary, + bind/descriptor/shape-rail"
	@echo "============================================================"
	@$(BUILD)/test_fri_air_fold
	@echo
	@echo "============================================================"
	@echo "s1a — FRI open_input accumulation AIR in FOLD form"
	@echo "  same transcription gate: 5 honest walks at zero residual,"
	@echo "  13 tampers with EXACT u64-count agreement (incl. the A2"
	@echo "  closures N-F1 one-sided carry and N-F2 ungated x_reg HOLD),"
	@echo "  terminality-as-constraint, + bind/descriptor/shape-rail"
	@echo "============================================================"
	@$(BUILD)/test_fri_oi_air_fold
	@echo
	@echo "============================================================"
	@echo "s1b — the FRI-verify statement ENTRY (composition)"
	@echo "  the pinned 3-cfg set (mmix + mmcs round-0 + fri) re-derived"
	@echo "  FROM the prep_pair fixture, the composed preprocessed-root"
	@echo "  pin + its per-table tamper negatives, the aliased publics"
	@echo "  compared against the shipped builders' own, canonicality"
	@echo "  ordering, + the NULL/map rails; RT-1 honest round-trip"
	@echo "  (3-instance prove -> entry) + N-PIN2 / N-ALIAS / N-CFG."
	@echo "  Green in BOTH pin states: with DNAC_P2S_PREP_ROOT at its"
	@echo "  placeholder the pin-dependent checks assert the reject."
	@echo "============================================================"
	@$(BUILD)/test_fri_statement
	@echo
	@echo "============================================================"
	@echo "ALL GATES: GREEN"
	@echo "P1c (2026-07-22): proof-internal hash = Poseidon2 (DuplexChallenger"
	@echo "transcript + PaddingFreeSponge/TruncatedPermutation MMCS), all"
	@echo "vectors regenerated + byte-matched against Plonky3 82cfad73."
	@echo "============================================================"

clean:
	rm -rf $(BUILD)
