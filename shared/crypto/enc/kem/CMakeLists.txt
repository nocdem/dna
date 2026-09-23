# pq-crystals/kyber `standard` @ d5b791c0c601b543233daccbae2845c6197a9e77,
# ML-KEM-1024 (KYBER_K=4, see params.h), FIPS 203 input-output conformant
# (KAT: messenger/tests/fixtures/mlkem/PIN.md — NIST ACVP-Server @975de31,
# FIPS 203 final, PIN.md §1; + CCTV@4448f20, draft-era: encaps/decaps/
# modulus/strcmp only, PIN.md §2).
# NOT a FIPS 140-3 validated module — (d, z) seeds come from a BIP39 master
# seed via SHAKE256, not an approved RBG (docs/plans/2026-09-23-mlkem-fips203-
# migration-design.md §3).
#
# Two deviations from the upstream `ref/` tree, no others (2026-09-23 port,
# docs/plans/decisions/2026-09-23-kem-mlkem-migration.md):
#   1. params.h:5 `#define KYBER_K 3` -> `#define KYBER_K 4` — upstream's own
#      "change this for different security strengths" knob; K=4 = ML-KEM-1024.
#   2. randombytes.h: upstream's `void randombytes(uint8_t*, size_t);`
#      declaration replaced with the same shim
#      shared/crypto/sign/dsa/randombytes.h uses:
#      `#include "crypto/utils/qgp_random.h"` + `#define randombytes
#      qgp_randombytes` — so upstream kem.c's unmodified `randombytes(...)`
#      calls resolve to qgp_randombytes. kem.c itself is byte-identical to
#      upstream.
#
# The legacy round-3 wrapper (pre-FIPS-203 KDF/keygen-domain, kept for
# backward-compatible decaps + Faz 1-2 encaps to old peers) lives OUTSIDE this
# directory: ../kyber_r3_legacy.{c,h}. It calls back into this library's
# exported gen_matrix/poly_getnoise_eta1/indcpa_enc/indcpa_dec/verify/cmov —
# no poly/ntt/indcpa code is duplicated.
# SDK Independence: Removed dap_core/dap_crypto dependencies

cmake_minimum_required(VERSION 3.10)

project(kem C)
set(CMAKE_C_STANDARD 11)

# Platform-specific definitions
if(NOT MSVC)
    add_definitions("-D_GNU_SOURCE")
    # GCC-specific warning suppressions (not supported by Clang)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-stringop-overflow")
        if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 12.2)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Warray-parameter=0")
        endif()
    endif()
endif()

# ML-KEM-1024 source files (pq-crystals/kyber `standard` ref/ names)
set(MLKEM_SOURCES
    kem.c
    indcpa.c
    poly.c
    polyvec.c
    ntt.c
    cbd.c
    reduce.c
    verify.c
    symmetric-shake.c
    fips202.c
)

# ML-KEM-1024 headers
set(MLKEM_HEADERS
    kem.h
    indcpa.h
    params.h
    poly.h
    polyvec.h
    ntt.h
    cbd.h
    reduce.h
    verify.h
    symmetric.h
    fips202.h
    randombytes.h
    fips202_kyber.h   # shim only — see fips202_kyber.h; kept for seed_derivation.c
)

# Create the ML-KEM-1024 static library (target name "kem" unchanged)
add_library(${PROJECT_NAME} STATIC ${MLKEM_SOURCES} ${MLKEM_HEADERS})

# Include directory for Kyber headers
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../..   # shared/crypto/ root (for crypto/utils/*.h includes)
    ${CMAKE_CURRENT_SOURCE_DIR}/../../..  # shared/ root
)

# No external dependencies - uses qgp_randombytes via the randombytes.h shim
# (deviation #2 above); upstream kem.c/indcpa.c are otherwise unmodified.
