# Component split S6 — LINK GATE for the nodus-core binary.
#
# Decision docs/plans/decisions/2026-10-01-nodus-component-split.md: core is
# its own process (item 2) holding UDP 4000, client sessions, the 4002
# listener, cluster, presence and circuits (items 3, 4, 6); the DHT /
# storage half is nodus-storage and consensus is nodus-witness (items 5,
# 12). A source-level test cannot show what the LINKED binary contains: one
# reference from a core-side file to an in-process constructor
# (nodus_dht_backend_inproc_new, nodus_chain_backend_inproc_open, ...) makes
# the static library pull nodus_dht_server.c / nodus_witness.c into
# nodus-core, and the core process would then carry — and could start — a
# second DHT or witness. This inspects the linked artefact with `nm`.
#
# Symbols are matched as GLOBAL TEXT (" T <name>" at a line end), never as a
# bare substring: `nm --defined-only` also lists static (" t ") symbols, and
# a helper named like one of these must neither trip a FORBIDDEN match nor
# fake a REQUIRED one.
#
# Invoked by ctest as:
#   cmake -DNODUS_CORE=<path to nodus-core> -P this
cmake_minimum_required(VERSION 3.10)

# In-process DHT / storage / witness entry points — none may be in core.
set(_FORBIDDEN
    nodus_storage_open
    nodus_routing_try_insert
    nodus_witness_init
    nodus_dht_backend_inproc_new
    nodus_chain_backend_inproc_open)

# Core's own and the two IPC doors — present, so a pass cannot come from an
# empty symbol table, the wrong file, or an `nm` that silently failed.
set(_REQUIRED
    nodus_auth_handle_auth
    nodus_presence_tick
    nodus_cluster_tick
    nodus_inter_circuit_table_init
    nodus_dht_backend_ipc_open
    nodus_chain_backend_ipc_open)

find_program(NM_EXE NAMES nm)
if(NOT NM_EXE)
    message(FATAL_ERROR
        "core_linked: `nm` not found — what nodus-core links CANNOT BE "
        "VERIFIED. Failing closed: an unverifiable claim is not a verified "
        "one.")
endif()

if(NOT DEFINED NODUS_CORE OR NODUS_CORE STREQUAL "")
    message(FATAL_ERROR
        "core_linked: NODUS_CORE was not supplied — add "
        "-DNODUS_CORE=$<TARGET_FILE:nodus-core> to this test's "
        "add_test() COMMAND in nodus/CMakeLists.txt.")
endif()
if(NOT EXISTS "${NODUS_CORE}")
    message(FATAL_ERROR "core_linked: nodus-core not found at ${NODUS_CORE}")
endif()

execute_process(COMMAND "${NM_EXE}" --defined-only "${NODUS_CORE}"
                OUTPUT_VARIABLE _syms
                ERROR_VARIABLE  _err
                RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR
        "core_linked: nm failed on nodus-core (rc=${_rc}): ${_err}")
endif()

foreach(_sym IN LISTS _FORBIDDEN)
    if(_syms MATCHES " T ${_sym}\n")
        message(FATAL_ERROR
            "core_linked: in-process symbol `${_sym}` IS LINKED INTO "
            "nodus-core (${NODUS_CORE}). A core-side file references an "
            "in-process DHT / storage / witness object; the core process "
            "must reach those halves over IPC only (decision "
            "2026-10-01-nodus-component-split).")
    endif()
endforeach()

foreach(_sym IN LISTS _REQUIRED)
    if(NOT _syms MATCHES " T ${_sym}\n")
        message(FATAL_ERROR
            "core_linked: expected core symbol `${_sym}` is MISSING from "
            "nodus-core — this gate is inspecting the wrong artefact, or "
            "the module was dropped. Either way its absence proof is "
            "worthless.")
    endif()
endforeach()

message(STATUS "core_linked: PASS — nodus-core links no in-process DHT, "
               "storage or witness entry point")
