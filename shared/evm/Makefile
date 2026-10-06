# shared/evm/Makefile — standalone build of the Nodus EVM engine (phase 1).
#
# Design: docs/plans/2026-10-04-nodus-evm-engine-design.md (local).
#
# Targets:
#   make lib            — build/libevm.a from $(SRCS)
#   make deps           — build/libevm_deps.a: the vendored precompile
#                         libraries (third_party/{blst,c-kzg-4844,mcl,
#                         secp256k1,ripemd160}, pinned in each PINNED.md)
#                         + the
#                         embedded KZG trusted setup, and
#                         build/gmp/install/lib/libgmp.a (third_party/gmp,
#                         the pinned release tarball, configured and built
#                         here); every libevm.a consumer links both
#   make statetest      — link the state-test runner, test_rlp_mpt and
#                         test_precompile (tests/Makefile.statetest)
#   make conformance FIXTURES=<fixtures/state_tests dir>
#                       — the official Prague state tests (20-byte mode)
#   make differential FIXTURES=<fixtures/state_tests dir>
#                       — the same cases at addr_bytes 20 and 32, compared
#                         (Nodus-derived, self-consistent; not official)
#   make test_u256      — build/test_u256 (oracle vectors, default build)
#   make test-portable  — build/test_u256_portable (-DEVM_U256_PORTABLE:
#                         forces the portable 64x64 multiply, no __int128)
#   make test_addr32    — build/test_addr32 (32-byte address mode, design
#                         §2; links libevm.a + keccak + the in-memory
#                         backend; vectors in tests/addr32_vectors.h)
#   make test_nodus_profile — build/test_nodus_profile (chain integration
#                         design §3-§5: BUDGET, wei_destroyed, tickets,
#                         evm_tx_prevalidate; linked like test_addr32)
#   make test_solc_exec — build/test_solc_exec: execution evidence for the
#                         Nodus EVM solc (32-byte addresses). Runs the
#                         COMMITTED bytecode under
#                         ../../nodus/tools/evm/solc/tests/exec/out/
#                         (four compiler configurations) in 32-byte mode;
#                         no solc needed; linked like test_addr32
#   make test_example_token — build/test_example_token: the developer
#                         pack's example token runs as an ERC-20-style
#                         token in 32-byte mode. Runs the COMMITTED
#                         bytecode under ../../nodus/tools/evm/examples/
#                         out/ (two compiler configurations); no solc
#                         needed; linked like test_addr32
#   make test_trie     — build/test_trie: the Nodus EVM state trie (trie/,
#                         SHA3-512 MPT, design 2026-10-04-nodus-evm-chain-
#                         integration-design.md §6) against the committed
#                         oracle vectors trie/trie_vectors.h
#   make trie-vectors FIXTURES=<fixtures/state_tests dir>
#                       — regenerate the COMMITTED trie/trie_vectors.h with
#                         trie/trie_oracle.py (needs python3 and the
#                         official fixtures for the oracle's self-check)
#   make trie-vectors-check FIXTURES=<dir>
#                       — regenerate into build/ and compare with the
#                         committed header
#   make test           — check the committed addr32 vectors against their
#                         oracle, then build and run the u256 test binaries,
#                         test_addr32, test_nodus_profile, test_solc_exec,
#                         test_example_token and test_trie
#                         (test_trie uses the committed trie vectors;
#                         checking them against the oracle needs FIXTURES,
#                         so it is trie-vectors-check, not part of
#                         `make test`)
#   make vectors        — generate build/u256_vectors.h with the Python
#                         oracle (needs python3; a prerequisite of the tests)
#   make addr32-vectors — regenerate the COMMITTED tests/addr32_vectors.h
#                         from tests/addr32_oracle.py (needs python3)
#   make addr32-vectors-check — regenerate into build/ and compare with the
#                         committed header (fails on any difference)
#   make bench          — build/evm_bench: the Nodus EVM measurement gate's
#                         bare-engine bench (bench/evm_bench.c +
#                         bench/evm_bench_wl.c, the worst-case workloads
#                         shared with nodus/tests/bench/bench_evm_apply.c;
#                         linked like test_addr32). Built, never run by
#                         `make test`: ./build/evm_bench [--gas N]
#                         [--reps R] [--only a,b] [--list]
#   make clean
#
# Extending: add the new engine source to SRCS (evm_state.c, evm_interp.c,
# evm_tx.c, evm_precompile.c, ...) and a test binary rule next to test_u256.
# The portable variant uses separate object names (*.p.o) so the two builds
# never share an object compiled with the other's flags.

CC      ?= cc
CXX     ?= c++
BUILD   := build

# ── vendored precompile libraries (third_party/*/PINNED.md) ──────────
# Compiled with their own flags, never with ours; archived separately in
# $(BUILD)/libevm_deps.a, plus GMP's own $(GMP_LIB). Link order for a
# consumer:
#   libevm.a libevm_deps.a $(GMP_LIB) -lcrypto -lstdc++ -lpthread
# (operator decision D2, 2026-10-05: libsecp256k1 and GMP are vendored;
# the 0x02 / 0x03 digests come from blst's blst_sha256 and the vendored
# RIPEMD-160, never from OpenSSL. -lcrypto is the system OpenSSL for the
# shared SHA3-512, crypto/hash/qgp_sha3.c, that libevm.a's ticket ids use.)
BLST_DIR := third_party/blst
CKZG_DIR := third_party/c-kzg-4844
MCL_DIR  := third_party/mcl
SECP_DIR := third_party/secp256k1
GMP_DIR  := third_party/gmp
RMD_DIR  := third_party/ripemd160

# blst: c-kzg's own blst flag (__BLST_PORTABLE__: run-time CPUID dispatch
# between the ADX and plain assembly), not build.sh's build-host ADX probe.
BLST_CFLAGS := -O2 -fno-builtin -fPIC -Wall -Wextra -D__BLST_PORTABLE__
CKZG_CFLAGS := -O2 -fPIC -Wall -Wextra -I$(CKZG_DIR)/src -I$(BLST_DIR)/bindings
# mcl: plain C++ (no Xbyak JIT, no LLVM/bint assembly, no AVX-512 MSM, no
# GMP, no -mbmi2/-madx), 256-bit Fp/Fr for BN_SNARK1 (alt_bn128).
MCL_CXXFLAGS := -O3 -fPIC -DNDEBUG -Wall -Wextra -I$(MCL_DIR)/include \
                -DMCL_FP_BIT=256 -DMCL_FR_BIT=256 -DMCL_DONT_USE_XBYAK \
                -DMCL_BINT_ASM=0 -DMCL_MSM=0

# libsecp256k1 v0.8.0 (third_party/secp256k1/PINNED.md): upstream's three
# library units with upstream's default table sizes and the recovery
# module; portable C field arithmetic (no USE_ASM_X86_64).
# -Wno-unused-function is upstream's own (CMakeLists.txt try_append_c_flags):
# its single-unit build keeps static helpers other modules use.
SECP_CFLAGS := -O2 -fPIC -Wall -Wextra -Wno-unused-function \
               -I$(SECP_DIR)/include -I$(SECP_DIR)/src \
               -DENABLE_MODULE_RECOVERY=1 -DECMULT_WINDOW_SIZE=15 \
               -DCOMB_BLOCKS=43 -DCOMB_TEETH=6 \
               -DSECP256K1_NO_API_VISIBILITY_ATTRIBUTES

# RIPEMD-160 from trezor-crypto (third_party/ripemd160/PINNED.md):
# upstream's -std=gnu11 (crypto/Makefile), our usual -O2 -fPIC and warning
# level. No NDEBUG: its asserts stay live, as upstream builds them.
RMD_CFLAGS := -O2 -fPIC -std=gnu11 -Wall -Wextra -I$(RMD_DIR)

DEP_OBJS := $(BUILD)/deps/blst_server.o $(BUILD)/deps/blst_assembly.o \
            $(BUILD)/deps/ckzg.o $(BUILD)/deps/mcl_fp.o \
            $(BUILD)/deps/mcl_bn_c256.o $(BUILD)/deps/kzg_trusted_setup.o \
            $(BUILD)/deps/secp256k1.o $(BUILD)/deps/secp256k1_pre_ecmult.o \
            $(BUILD)/deps/secp256k1_pre_ecmult_gen.o \
            $(BUILD)/deps/ripemd160.o $(BUILD)/deps/memzero.o

# GMP 6.3.0 (third_party/gmp/PINNED.md): the signed upstream release
# tarball, sha256-checked before extraction, configured for a generic
# triple (x86-64: --enable-fat, run-time CPU dispatch; elsewhere portable
# C), installed under $(BUILD)/gmp/install. Its gmp.h is the one our
# sources include (-I ahead of the system /usr/include/gmp.h).
GMP_VERSION := 6.3.0
GMP_SHA256  := a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898
GMP_TARBALL := $(GMP_DIR)/gmp-$(GMP_VERSION).tar.xz
GMP_BUILD   := $(BUILD)/gmp
GMP_PREFIX  := $(abspath $(GMP_BUILD))/install
GMP_LIB     := $(GMP_BUILD)/install/lib/libgmp.a
GMP_INC     := $(GMP_BUILD)/install/include
GMP_ARCH    := $(shell uname -m)
ifeq ($(GMP_ARCH),x86_64)
GMP_CPU_OPTS := --enable-fat
else
GMP_CPU_OPTS := --disable-assembly
endif
GMP_CONFIGURE := --build=$(GMP_ARCH)-unknown-linux-gnu \
                 --host=$(GMP_ARCH)-unknown-linux-gnu \
                 --enable-static --disable-shared --with-pic --disable-cxx \
                 $(GMP_CPU_OPTS)

# Our sources see the vendored public headers only.
DEP_INCS := -I$(BLST_DIR)/bindings -I$(CKZG_DIR)/src -I$(MCL_DIR)/include \
            -I$(SECP_DIR)/include -I$(RMD_DIR) -I$(GMP_INC)
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -O2 -I. -I.. $(DEP_INCS)

SRCS    := evm_u256.c evm_state.c evm_interp.c evm_tx.c evm_precompile.c
OBJS    := $(SRCS:%.c=$(BUILD)/%.o)
POBJS   := $(SRCS:%.c=$(BUILD)/%.p.o)
HDRS    := $(wildcard *.h)

# Test-only support for binaries that run the engine (test_addr32):
# keccak256.c is shared code compiled with its own flags — it uses GNU
# `##__VA_ARGS__` in the QGP_LOG macros, which -Wpedantic flags under ISO C
# (same rule as tests/Makefile.statetest). The precompiles link the vendored
# build/libevm_deps.a (blst, c-kzg-4844, mcl, libsecp256k1, RIPEMD-160; mcl
# is the one C++ dependency, decision 2026-10-04-nodus-evm-kurultay-k1 #5) and $(GMP_LIB),
# then EVM_SYSLIBS.
KECCAK_CFLAGS := -std=gnu11 -Wall -Wextra -O2 -I..
EVM_SYSLIBS   ?= -lcrypto -lstdc++ -lpthread
TBUILD        := $(BUILD)/t
# qgp_sha3.c (shared SHA3-512, OpenSSL EVP) is what libevm.a's ticket ids
# use (evm_state.c evm_st_add_ticket); every libevm.a consumer links it.
# Same shared-code rule as keccak256.c: compiled with KECCAK_CFLAGS.
ADDR32_SUPPORT := $(TBUILD)/evm_membackend.o $(TBUILD)/evm_mpt.o \
                  $(TBUILD)/evm_rlp.o $(TBUILD)/evm_test_qgp_shim.o \
                  $(TBUILD)/keccak256.o $(TBUILD)/qgp_sha3.o

# Nodus EVM state trie (trie/). evm_trie.c + evm_trie_rlp.c are the production
# sources; evm_trie_full.c is the test-only full-rebuild cross-check. The
# test links qgp_sha3.c (SHA3-512 via OpenSSL, -lcrypto) and, for the
# keccak mode of evm_trie_full, keccak256.c + the qgp shim.
TRIE_BUILD := $(BUILD)/trie
TRIE_HDRS  := $(wildcard trie/*.h)
TRIE_OBJS  := $(TRIE_BUILD)/evm_trie.o $(TRIE_BUILD)/evm_trie_rlp.o \
              $(TRIE_BUILD)/evm_trie_full.o $(TRIE_BUILD)/test_trie.o \
              $(TRIE_BUILD)/qgp_sha3.o $(TBUILD)/keccak256.o \
              $(TBUILD)/evm_test_qgp_shim.o

.PHONY: all lib deps test_u256 test-portable test test_addr32 \
        test_nodus_profile test_solc_exec test_example_token vectors addr32-vectors \
        addr32-vectors-check \
        statetest conformance differential clean test_trie trie-vectors trie-vectors-check \
        bench

all: lib deps test_u256 test-portable

lib: $(BUILD)/libevm.a

deps: $(BUILD)/libevm_deps.a

$(BUILD)/deps:
	mkdir -p $(BUILD)/deps

$(BUILD)/deps/blst_server.o: $(BLST_DIR)/src/server.c | $(BUILD)/deps
	$(CC) $(BLST_CFLAGS) -c $< -o $@

$(BUILD)/deps/blst_assembly.o: $(BLST_DIR)/build/assembly.S | $(BUILD)/deps
	$(CC) $(BLST_CFLAGS) -c $< -o $@

$(BUILD)/deps/ckzg.o: $(CKZG_DIR)/src/ckzg.c | $(BUILD)/deps
	$(CC) $(CKZG_CFLAGS) -c $< -o $@

$(BUILD)/deps/mcl_fp.o: $(MCL_DIR)/src/fp.cpp | $(BUILD)/deps
	$(CXX) $(MCL_CXXFLAGS) -c $< -o $@

$(BUILD)/deps/mcl_bn_c256.o: $(MCL_DIR)/src/bn_c256.cpp | $(BUILD)/deps
	$(CXX) $(MCL_CXXFLAGS) -c $< -o $@

# The mainnet KZG trusted setup, embedded as bytes (no run-time file path).
# evm_precompile.c checks its sha256 against third_party/c-kzg-4844/PINNED.md.
$(BUILD)/deps/kzg_trusted_setup.c: $(CKZG_DIR)/src/trusted_setup.txt | $(BUILD)/deps
	xxd -i -n evm_kzg_trusted_setup_txt $< > $@

$(BUILD)/deps/kzg_trusted_setup.o: $(BUILD)/deps/kzg_trusted_setup.c
	$(CC) -O0 -fPIC -c $< -o $@

$(BUILD)/deps/secp256k1.o: $(SECP_DIR)/src/secp256k1.c | $(BUILD)/deps
	$(CC) $(SECP_CFLAGS) -c $< -o $@

$(BUILD)/deps/secp256k1_pre_ecmult.o: $(SECP_DIR)/src/precomputed_ecmult.c | $(BUILD)/deps
	$(CC) $(SECP_CFLAGS) -c $< -o $@

$(BUILD)/deps/secp256k1_pre_ecmult_gen.o: $(SECP_DIR)/src/precomputed_ecmult_gen.c | $(BUILD)/deps
	$(CC) $(SECP_CFLAGS) -c $< -o $@

$(BUILD)/deps/ripemd160.o: $(RMD_DIR)/ripemd160.c $(RMD_DIR)/ripemd160.h \
                           $(RMD_DIR)/memzero.h | $(BUILD)/deps
	$(CC) $(RMD_CFLAGS) -c $< -o $@

$(BUILD)/deps/memzero.o: $(RMD_DIR)/memzero.c $(RMD_DIR)/memzero.h | $(BUILD)/deps
	$(CC) $(RMD_CFLAGS) -c $< -o $@

$(BUILD)/libevm_deps.a: $(DEP_OBJS) $(GMP_LIB)
	rm -f $@
	ar rcs $@ $(DEP_OBJS)

# GMP: verify the pinned tarball, extract, configure, build, install — all
# inside $(BUILD)/gmp. A fresh tree each time (the tarball is the input).
$(GMP_LIB): $(GMP_TARBALL)
	rm -rf $(GMP_BUILD)
	mkdir -p $(GMP_BUILD)
	echo "$(GMP_SHA256)  $(GMP_TARBALL)" | sha256sum -c -
	tar -xJf $(GMP_TARBALL) -C $(GMP_BUILD)
	cd $(GMP_BUILD)/gmp-$(GMP_VERSION) && \
	    ./configure --prefix=$(GMP_PREFIX) CC="$(CC)" $(GMP_CONFIGURE)
	$(MAKE) -C $(GMP_BUILD)/gmp-$(GMP_VERSION)
	$(MAKE) -C $(GMP_BUILD)/gmp-$(GMP_VERSION) install

$(GMP_INC)/gmp.h: $(GMP_LIB)
	test -f $@

# evm_interp.c (blob base fee) and evm_precompile.c (modexp) include gmp.h
$(BUILD)/evm_interp.o $(BUILD)/evm_precompile.o \
$(BUILD)/evm_interp.p.o $(BUILD)/evm_precompile.p.o: $(GMP_INC)/gmp.h

test_u256: $(BUILD)/test_u256

test-portable: $(BUILD)/test_u256_portable

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: %.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.p.o: %.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -DEVM_U256_PORTABLE -c $< -o $@

$(BUILD)/libevm.a: $(OBJS)
	rm -f $@
	ar rcs $@ $(OBJS)

$(BUILD)/libevm_portable.a: $(POBJS)
	rm -f $@
	ar rcs $@ $(POBJS)

# The oracle vector header is GENERATED into build/ (15 MB, not committed);
# the generator is deterministic (fixed seed), so every build gets the same bytes.
$(BUILD)/u256_vectors.h: tests/u256_oracle.py | $(BUILD)
	python3 tests/u256_oracle.py $@

$(BUILD)/test_u256: tests/test_u256.c $(BUILD)/u256_vectors.h $(BUILD)/libevm.a
	$(CC) $(CFLAGS) -I$(BUILD) -Itests tests/test_u256.c $(BUILD)/libevm.a -o $@

$(BUILD)/test_u256_portable: tests/test_u256.c $(BUILD)/u256_vectors.h $(BUILD)/libevm_portable.a
	$(CC) $(CFLAGS) -DEVM_U256_PORTABLE -I$(BUILD) -Itests tests/test_u256.c $(BUILD)/libevm_portable.a -o $@

test_addr32: $(BUILD)/test_addr32

$(TBUILD):
	mkdir -p $(TBUILD)

$(TBUILD)/%.o: tests/%.c $(HDRS) $(wildcard tests/*.h) | $(TBUILD)
	$(CC) $(CFLAGS) -Itests -c $< -o $@

$(TBUILD)/keccak256.o: ../crypto/hash/keccak256.c | $(TBUILD)
	$(CC) $(KECCAK_CFLAGS) -c $< -o $@

$(TBUILD)/qgp_sha3.o: ../crypto/hash/qgp_sha3.c | $(TBUILD)
	$(CC) $(KECCAK_CFLAGS) -c $< -o $@

$(BUILD)/test_addr32: $(TBUILD)/test_addr32.o $(ADDR32_SUPPORT) $(BUILD)/libevm.a \
                      $(BUILD)/libevm_deps.a
	$(CC) $(CFLAGS) -o $@ $(TBUILD)/test_addr32.o $(ADDR32_SUPPORT) \
	      $(BUILD)/libevm.a $(BUILD)/libevm_deps.a $(GMP_LIB) $(EVM_SYSLIBS)

test_nodus_profile: $(BUILD)/test_nodus_profile

$(BUILD)/test_nodus_profile: $(TBUILD)/test_nodus_profile.o $(ADDR32_SUPPORT) \
                             $(BUILD)/libevm.a $(BUILD)/libevm_deps.a
	$(CC) $(CFLAGS) -o $@ $(TBUILD)/test_nodus_profile.o $(ADDR32_SUPPORT) \
	      $(BUILD)/libevm.a $(BUILD)/libevm_deps.a $(GMP_LIB) $(EVM_SYSLIBS)

# Nodus EVM solc execution evidence: runs the committed bytecode in
# ../../nodus/tools/evm/solc/tests/exec/out/ (regenerated only by that
# directory's build.sh); a missing .hex is a failure.
test_solc_exec: $(BUILD)/test_solc_exec

$(BUILD)/test_solc_exec: $(TBUILD)/test_solc_exec.o $(ADDR32_SUPPORT) \
                         $(BUILD)/libevm.a $(BUILD)/libevm_deps.a
	$(CC) $(CFLAGS) -o $@ $(TBUILD)/test_solc_exec.o $(ADDR32_SUPPORT) \
	      $(BUILD)/libevm.a $(BUILD)/libevm_deps.a $(GMP_LIB) $(EVM_SYSLIBS)

# Developer pack example token: runs the committed bytecode in
# ../../nodus/tools/evm/examples/out/ (regenerated only by that directory's
# build.sh); a missing .hex is a failure.
test_example_token: $(BUILD)/test_example_token

$(BUILD)/test_example_token: $(TBUILD)/test_example_token.o $(ADDR32_SUPPORT) \
                             $(BUILD)/libevm.a $(BUILD)/libevm_deps.a
	$(CC) $(CFLAGS) -o $@ $(TBUILD)/test_example_token.o $(ADDR32_SUPPORT) \
	      $(BUILD)/libevm.a $(BUILD)/libevm_deps.a $(GMP_LIB) $(EVM_SYSLIBS)

# Nodus EVM measurement gate (design 2026-10-04-nodus-evm-chain-integration-design.md
# §8): the bare-engine bench. Same link line as test_addr32 (the in-memory
# backend + keccak + qgp_sha3 + libevm.a + libevm_deps.a + GMP_LIB +
# EVM_SYSLIBS).
BBUILD := $(BUILD)/bench
BENCH_OBJS := $(BBUILD)/evm_bench.o $(BBUILD)/evm_bench_wl.o

bench: $(BUILD)/evm_bench

$(BBUILD):
	mkdir -p $(BBUILD)

$(BBUILD)/%.o: bench/%.c bench/evm_bench_wl.h $(HDRS) $(wildcard tests/*.h) \
               | $(BBUILD)
	$(CC) $(CFLAGS) -Itests -Ibench -c $< -o $@

$(BUILD)/evm_bench: $(BENCH_OBJS) $(ADDR32_SUPPORT) $(BUILD)/libevm.a \
                    $(BUILD)/libevm_deps.a
	$(CC) $(CFLAGS) -o $@ $(BENCH_OBJS) $(ADDR32_SUPPORT) \
	      $(BUILD)/libevm.a $(BUILD)/libevm_deps.a $(GMP_LIB) $(EVM_SYSLIBS)

# tests/addr32_vectors.h is COMMITTED (small, reviewed with the test); it is
# only rewritten on request. The check target proves it matches its oracle.
addr32-vectors:
	python3 tests/addr32_oracle.py tests/addr32_vectors.h

addr32-vectors-check: | $(BUILD)
	python3 tests/addr32_oracle.py $(BUILD)/addr32_vectors.check.h
	cmp $(BUILD)/addr32_vectors.check.h tests/addr32_vectors.h

test_trie: $(BUILD)/test_trie

$(TRIE_BUILD):
	mkdir -p $(TRIE_BUILD)

$(TRIE_BUILD)/%.o: trie/%.c $(TRIE_HDRS) | $(TRIE_BUILD)
	$(CC) $(CFLAGS) -Itrie -c $< -o $@

$(TRIE_BUILD)/qgp_sha3.o: ../crypto/hash/qgp_sha3.c ../crypto/hash/qgp_sha3.h \
                          | $(TRIE_BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_trie: $(TRIE_OBJS)
	$(CC) $(CFLAGS) -o $@ $(TRIE_OBJS) -lcrypto

# trie/trie_vectors.h is COMMITTED; the oracle refuses to write unless its
# unsubstituted code reproduces official post-state roots from $(FIXTURES).
trie-vectors:
	python3 trie/trie_oracle.py $(FIXTURES) trie/trie_vectors.h

trie-vectors-check: | $(BUILD)
	python3 trie/trie_oracle.py $(FIXTURES) $(BUILD)/trie_vectors.check.h
	cmp $(BUILD)/trie_vectors.check.h trie/trie_vectors.h

test: addr32-vectors-check $(BUILD)/test_u256 $(BUILD)/test_u256_portable \
      $(BUILD)/test_addr32 $(BUILD)/test_nodus_profile \
      $(BUILD)/test_solc_exec $(BUILD)/test_example_token $(BUILD)/test_trie
	./$(BUILD)/test_u256
	./$(BUILD)/test_u256_portable
	./$(BUILD)/test_addr32
	./$(BUILD)/test_nodus_profile
	./$(BUILD)/test_solc_exec
	./$(BUILD)/test_example_token
	./$(BUILD)/test_trie

vectors: $(BUILD)/u256_vectors.h

# Official Prague state tests (execution-spec-tests v5.4.0 fixtures_stable).
# FIXTURES must point at the extracted fixtures/state_tests directory.
statetest: $(BUILD)/libevm.a $(BUILD)/libevm_deps.a $(GMP_LIB)
	$(MAKE) -C tests -f Makefile.statetest statetest test_rlp_mpt test_precompile

conformance: statetest
	./$(BUILD)/statetest/test_rlp_mpt
	./$(BUILD)/statetest/statetest --fork Prague $(FIXTURES)

# Differential 20/32 run (Kurultay #9 item 4): every eligible Prague case
# through the engine at addr_bytes 20 and 32, normalized results compared.
# Nodus-derived / self-consistent — NOT an official result (README
# "Conformance"). Same FIXTURES as conformance.
differential: statetest
	./$(BUILD)/statetest/statetest --differential --fork Prague $(FIXTURES)

clean:
	rm -rf $(BUILD)
