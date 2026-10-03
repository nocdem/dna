# Component split S3 — LINK GATE for the nodus-witness binary.
#
# Decision docs/plans/decisions/2026-10-01-nodus-component-split.md: the
# witness runs as its own process (items 5, 22) and only core owns the
# server, cluster, storage and presence roles. A source-level test cannot
# show what the LINKED binary contains: one stray call from a witness-side
# file into nodus_server.c (or nodus_cluster.c, nodus_storage.c, ...) makes
# the static library pull that whole object into nodus-witness, and the
# witness process would then carry — and could start — core's code. This
# inspects the linked artefact with `nm`.
#
# Symbols are matched as GLOBAL TEXT (" T <name>" at a line end), never as a
# bare substring: `nm --defined-only` also lists static (" t ") symbols, and
# a helper in nodus-witness.c named like one of these must neither trip a
# FORBIDDEN match nor fake a REQUIRED one.
#
# Invoked by ctest as:
#   cmake -DNODUS_WITNESS=<path to nodus-witness> -P this
cmake_minimum_required(VERSION 3.10)

# Core-only entry points — none may be in the witness binary.
set(_FORBIDDEN
    nodus_server_init
    nodus_cluster_init
    nodus_storage_open
    nodus_presence_tick)

# The witness's own — present, so a pass cannot come from an empty symbol
# table, the wrong file, or an `nm` that silently failed.
# nodus_witness_v2_gen_derive_v3: --derive-v2-genesis is served by this
# binary too (tools/nodus_node_config.c).
set(_REQUIRED
    nodus_witness_init
    nodus_witness_p2p_new
    nodus_witness_v2_gen_derive_v3)

find_program(NM_EXE NAMES nm)
if(NOT NM_EXE)
    message(FATAL_ERROR
        "split_linked: `nm` not found — what nodus-witness links CANNOT BE "
        "VERIFIED. Failing closed: an unverifiable claim is not a verified "
        "one.")
endif()

if(NOT DEFINED NODUS_WITNESS OR NODUS_WITNESS STREQUAL "")
    message(FATAL_ERROR
        "split_linked: NODUS_WITNESS was not supplied — add "
        "-DNODUS_WITNESS=$<TARGET_FILE:nodus-witness> to this test's "
        "add_test() COMMAND in nodus/CMakeLists.txt.")
endif()
if(NOT EXISTS "${NODUS_WITNESS}")
    message(FATAL_ERROR "split_linked: nodus-witness not found at ${NODUS_WITNESS}")
endif()

execute_process(COMMAND "${NM_EXE}" --defined-only "${NODUS_WITNESS}"
                OUTPUT_VARIABLE _syms
                ERROR_VARIABLE  _err
                RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR
        "split_linked: nm failed on nodus-witness (rc=${_rc}): ${_err}")
endif()

foreach(_sym IN LISTS _FORBIDDEN)
    if(_syms MATCHES " T ${_sym}\n")
        message(FATAL_ERROR
            "split_linked: core-only symbol `${_sym}` IS LINKED INTO "
            "nodus-witness (${NODUS_WITNESS}). A witness-side file calls "
            "into a core object; the witness process must not carry core's "
            "code (decision 2026-10-01-nodus-component-split).")
    endif()
endforeach()

foreach(_sym IN LISTS _REQUIRED)
    if(NOT _syms MATCHES " T ${_sym}\n")
        message(FATAL_ERROR
            "split_linked: expected witness symbol `${_sym}` is MISSING "
            "from nodus-witness — this gate is inspecting the wrong "
            "artefact, or the module was dropped. Either way its absence "
            "proof is worthless.")
    endif()
endforeach()

message(STATUS "split_linked: PASS — nodus-witness links no core entry point")
