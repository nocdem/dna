# shared/crypto/zk/Makefile
#
# Standalone build + test harness for the DNAC v3 ZK primitives (Faz 1).
# Not integrated into messenger/build yet — that's a later step once primitives
# stabilize (per design doc § 8 Faz 1).
#
# Usage:
#   make            — build all 4 test binaries
#   make test       — build + run all 4 tests
#   make clean      — remove build artifacts
#
# Dependencies: gcc, libcrypto (OpenSSL).
#
# The test runners assume tools/vectors/*.json exists. Regenerate via:
#   make -C tools oracle-dump      (requires Rust toolchain)
#   ... or run_tests.sh which handles the whole pipeline.

CC      ?= gcc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Wno-unused-parameter
INCLUDES = -I. -I/opt/dna/shared
LDLIBS   = -lcrypto

# Common dependency: DNAC's qgp_sha3 (we link directly rather than via libdna).
SHA3_SRC = /opt/dna/shared/crypto/hash/qgp_sha3.c

# Build output dir.
BUILD = build

# Test binaries to produce.
TESTS = \
    $(BUILD)/test_field_goldilocks \
    $(BUILD)/test_field_goldilocks_ext \
    $(BUILD)/test_merkle_smt \
    $(BUILD)/test_transcript \
    $(BUILD)/test_two_adic_gens \
    $(BUILD)/test_fri_fold \
    $(BUILD)/test_fri_commit \
    $(BUILD)/test_fri_e2e \
    $(BUILD)/test_range_air \
    $(BUILD)/test_sum_balance \
    $(BUILD)/test_keccak_ref \
    $(BUILD)/test_keccak_air_bits \
    $(BUILD)/test_keccak_air_theta \
    $(BUILD)/test_keccak_air_rho_pi \
    $(BUILD)/test_keccak_air_chi \
    $(BUILD)/test_keccak_air_iota \
    $(BUILD)/test_keccak_air_f1600 \
    $(BUILD)/test_keccak_air_sha3_512

.PHONY: all test clean

all: $(BUILD) $(TESTS)

$(BUILD):
	@mkdir -p $(BUILD)

# Field-base test: depends on field_goldilocks.c only.
$(BUILD)/test_field_goldilocks: tests/test_field_goldilocks.c field_goldilocks.c field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_field_goldilocks.c field_goldilocks.c -o $@

# Field-ext test: same impl, different JSON.
$(BUILD)/test_field_goldilocks_ext: tests/test_field_goldilocks_ext.c field_goldilocks.c field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_field_goldilocks_ext.c field_goldilocks.c -o $@

# Merkle test: needs SHA3-512.
$(BUILD)/test_merkle_smt: tests/test_merkle_smt.c merkle_smt.c merkle_smt.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_merkle_smt.c merkle_smt.c $(SHA3_SRC) $(LDLIBS) -o $@

# Transcript test: needs SHA3-512 + field_goldilocks (for fp2 challenge return).
$(BUILD)/test_transcript: tests/test_transcript.c transcript.c field_goldilocks.c transcript.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_transcript.c transcript.c field_goldilocks.c $(SHA3_SRC) $(LDLIBS) -o $@

# Two-adic generators sanity check (Sub-sprint 2.1).
$(BUILD)/test_two_adic_gens: tests/test_two_adic_gens.c field_goldilocks.c field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_two_adic_gens.c field_goldilocks.c -o $@

# FRI arity-2 fold (Sub-sprint 2.1).
$(BUILD)/test_fri_fold: tests/test_fri_fold.c fri_fold.c field_goldilocks.c fri_fold.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_fold.c fri_fold.c field_goldilocks.c -o $@

# FRI multi-layer commit (Sub-sprint 2.2). Pulls in merkle_smt + transcript + fri_fold.
$(BUILD)/test_fri_commit: tests/test_fri_commit.c fri_commit.c fri_fold.c merkle_smt.c transcript.c field_goldilocks.c fri_commit.h fri_fold.h merkle_smt.h transcript.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_commit.c fri_commit.c fri_fold.c merkle_smt.c transcript.c field_goldilocks.c $(SHA3_SRC) $(LDLIBS) -o $@

# FRI end-to-end prove+verify self-test (Sub-sprint 2.3).
$(BUILD)/test_fri_e2e: tests/test_fri_e2e.c fri_query.c fri_commit.c fri_fold.c merkle_smt.c transcript.c field_goldilocks.c fri_query.h fri_commit.h fri_fold.h merkle_smt.h transcript.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_fri_e2e.c fri_query.c fri_commit.c fri_fold.c merkle_smt.c transcript.c field_goldilocks.c $(SHA3_SRC) $(LDLIBS) -o $@

# Range AIR self-test (Sub-sprint 3.1).
$(BUILD)/test_range_air: tests/test_range_air.c range_air.c field_goldilocks.c range_air.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_range_air.c range_air.c field_goldilocks.c -o $@

# Sum-balance AIR self-test (Sub-sprint 3.2).
$(BUILD)/test_sum_balance: tests/test_sum_balance.c sum_balance.c range_air.c field_goldilocks.c sum_balance.h range_air.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_sum_balance.c sum_balance.c range_air.c field_goldilocks.c -o $@

# Standalone Keccak / SHA3-512 reference (Sub-sprint 3.3a).
$(BUILD)/test_keccak_ref: tests/test_keccak_ref.c keccak_ref.c keccak_ref.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_keccak_ref.c keccak_ref.c $(SHA3_SRC) $(LDLIBS) -o $@

# Keccak-AIR bit decomposition + XOR primitives (Sub-sprint 3.3b.1).
$(BUILD)/test_keccak_air_bits: tests/test_keccak_air_bits.c keccak_air_bits.c field_goldilocks.c keccak_air_bits.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_keccak_air_bits.c keccak_air_bits.c field_goldilocks.c -o $@

# Keccak θ step AIR encoding (Sub-sprint 3.3b.2).
$(BUILD)/test_keccak_air_theta: tests/test_keccak_air_theta.c keccak_air_theta.c keccak_air_bits.c keccak_ref.c field_goldilocks.c keccak_air_theta.h keccak_air_bits.h keccak_ref.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_keccak_air_theta.c keccak_air_theta.c keccak_air_bits.c keccak_ref.c field_goldilocks.c -o $@

# Keccak ρ + π step AIR encoding (Sub-sprint 3.3b.3).
$(BUILD)/test_keccak_air_rho_pi: tests/test_keccak_air_rho_pi.c keccak_air_rho_pi.c keccak_air_bits.c keccak_ref.c field_goldilocks.c keccak_air_rho_pi.h keccak_air_theta.h keccak_air_bits.h keccak_ref.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_keccak_air_rho_pi.c keccak_air_rho_pi.c keccak_air_bits.c keccak_ref.c field_goldilocks.c -o $@

# Keccak χ step AIR encoding (Sub-sprint 3.3b.4).
$(BUILD)/test_keccak_air_chi: tests/test_keccak_air_chi.c keccak_air_chi.c keccak_air_bits.c keccak_ref.c field_goldilocks.c keccak_air_chi.h keccak_air_theta.h keccak_air_bits.h keccak_ref.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_keccak_air_chi.c keccak_air_chi.c keccak_air_bits.c keccak_ref.c field_goldilocks.c -o $@

# Keccak ι step AIR encoding (Sub-sprint 3.3b.5).
$(BUILD)/test_keccak_air_iota: tests/test_keccak_air_iota.c keccak_air_iota.c keccak_air_bits.c keccak_ref.c field_goldilocks.c keccak_air_iota.h keccak_air_theta.h keccak_air_bits.h keccak_ref.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_keccak_air_iota.c keccak_air_iota.c keccak_air_bits.c keccak_ref.c field_goldilocks.c -o $@

# Full 24-round Keccak-f[1600] AIR assembly (Sub-sprint 3.3b.6).
$(BUILD)/test_keccak_air_f1600: tests/test_keccak_air_f1600.c keccak_air_f1600.c keccak_air_theta.c keccak_air_rho_pi.c keccak_air_chi.c keccak_air_iota.c keccak_air_bits.c keccak_ref.c field_goldilocks.c keccak_air_f1600.h keccak_air_theta.h keccak_air_rho_pi.h keccak_air_chi.h keccak_air_iota.h keccak_air_bits.h keccak_ref.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_keccak_air_f1600.c keccak_air_f1600.c keccak_air_theta.c keccak_air_rho_pi.c keccak_air_chi.c keccak_air_iota.c keccak_air_bits.c keccak_ref.c field_goldilocks.c -o $@

# Single-block SHA3-512 AIR e2e (Sub-sprint 3.3b.7).
$(BUILD)/test_keccak_air_sha3_512: tests/test_keccak_air_sha3_512.c keccak_air_sha3_512.c keccak_air_f1600.c keccak_air_theta.c keccak_air_rho_pi.c keccak_air_chi.c keccak_air_iota.c keccak_air_bits.c keccak_ref.c field_goldilocks.c keccak_air_sha3_512.h keccak_air_f1600.h keccak_air_theta.h keccak_air_rho_pi.h keccak_air_chi.h keccak_air_iota.h keccak_air_bits.h keccak_ref.h field_goldilocks.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_keccak_air_sha3_512.c keccak_air_sha3_512.c keccak_air_f1600.c keccak_air_theta.c keccak_air_rho_pi.c keccak_air_chi.c keccak_air_iota.c keccak_air_bits.c keccak_ref.c field_goldilocks.c -o $@

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
	@echo "Sprint 1.4 — merkle_smt (SHA3-512 binary tree)"
	@echo "============================================================"
	@$(BUILD)/test_merkle_smt tools/vectors/merkle.json
	@echo
	@echo "============================================================"
	@echo "Sprint 1.5 — transcript (Fiat-Shamir)"
	@echo "============================================================"
	@$(BUILD)/test_transcript tools/vectors/transcript.json
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 2.1a — two-adic generators (validate gold_fp_two_adic_generator)"
	@echo "============================================================"
	@$(BUILD)/test_two_adic_gens tools/vectors/two_adic_gens.json
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 2.1b — FRI arity-2 fold"
	@echo "============================================================"
	@$(BUILD)/test_fri_fold tools/vectors/fri_fold.json
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 2.2 — FRI multi-layer commit phase"
	@echo "============================================================"
	@$(BUILD)/test_fri_commit tools/vectors/fri_commit.json
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 2.3 — FRI end-to-end prove+verify + tamper rejection"
	@echo "============================================================"
	@$(BUILD)/test_fri_e2e
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.1 — Range AIR (64-bit decomposition + constraints)"
	@echo "============================================================"
	@$(BUILD)/test_range_air
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.2 — Sum-balance AIR (multi-output composition)"
	@echo "============================================================"
	@$(BUILD)/test_sum_balance
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.3a — Standalone Keccak-f[1600] + SHA3-512"
	@echo "============================================================"
	@$(BUILD)/test_keccak_ref
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.3b.1 — Keccak-AIR bit decomp + XOR primitives"
	@echo "============================================================"
	@$(BUILD)/test_keccak_air_bits
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.3b.2 — Keccak θ (theta) step AIR encoding"
	@echo "============================================================"
	@$(BUILD)/test_keccak_air_theta
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.3b.3 — Keccak ρ + π (rotation + permutation) AIR"
	@echo "============================================================"
	@$(BUILD)/test_keccak_air_rho_pi
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.3b.4 — Keccak χ (chi) step AIR (non-linear)"
	@echo "============================================================"
	@$(BUILD)/test_keccak_air_chi
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.3b.5 — Keccak ι (iota) step AIR"
	@echo "============================================================"
	@$(BUILD)/test_keccak_air_iota
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.3b.6 — Full 24-round Keccak-f[1600] AIR"
	@echo "============================================================"
	@$(BUILD)/test_keccak_air_f1600
	@echo
	@echo "============================================================"
	@echo "Sub-sprint 3.3b.7 — SHA3-512 single-block AIR e2e"
	@echo "============================================================"
	@$(BUILD)/test_keccak_air_sha3_512
	@echo
	@echo "============================================================"
	@echo "ALL SPRINTS THROUGH 3.3b.7 (Faz 3.3b COMPLETE) GATE: ALL GREEN"
	@echo "============================================================"

clean:
	rm -rf $(BUILD)
