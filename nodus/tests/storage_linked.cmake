# Component split S5b — LINK GATE for the nodus-storage binary.
#
# Decision docs/plans/decisions/2026-10-01-nodus-component-split.md: the DHT /
# storage half runs as its own process (items 7, 16, 19) and only core owns
# the server, client auth, cluster and presence roles; the witness is its own
# component (items 5, 12). A source-level test cannot show what the LINKED
# binary contains: one stray call from a storage-side file into
# nodus_server.c (or nodus_auth.c, nodus_cluster.c, nodus_presence.c, a
# witness object) makes the static library pull that whole object into
# nodus-storage, and the storage process would then carry — and could start
# — another component's code. This inspects the linked artefact with `nm`.
#
# Symbols are matched as GLOBAL TEXT (" T <name>" at a line end), never as a
# bare substring: `nm --defined-only` also lists static (" t ") symbols, and
# a helper in nodus-storage.c named like one of these must neither trip a
# FORBIDDEN match nor fake a REQUIRED one.
#
# Invoked by ctest as:
#   cmake -DNODUS_STORAGE=<path to nodus-storage> -P this
cmake_minimum_required(VERSION 3.10)

# Other components' entry points — none may be in the storage binary
# (Fable S5 review (f)1).
#   nodus_server_init — the server object (sessions, 4001 / 4002 listeners);
#   nodus_auth_handle_auth — the client-port auth handshake;
#   nodus_cluster_init / nodus_cluster_tick — cluster heartbeat (core);
#   nodus_presence_tick — presence (core);
#   nodus_witness_init / nodus_witness_p2p_new — the witness and its 4004
#     host;
#   nodus_dht_backend_inproc_new — core's in-process door to the DHT.
set(_FORBIDDEN
    nodus_server_init
    nodus_auth_handle_auth
    nodus_cluster_init
    nodus_cluster_tick
    nodus_presence_tick
    nodus_witness_init
    nodus_witness_p2p_new
    nodus_dht_backend_inproc_new)

# The storage process's own — present, so a pass cannot come from an empty
# symbol table, the wrong file, or an `nm` that silently failed.
#   nodus_dht_init / nodus_storage_open / nodus_routing_try_insert /
#     handle_t2_media_put — the DHT, its stores, its routing table and the
#     media TU;
#   nodus_dht_ipc_new — the storage-side IPC runtime;
#   nodus_inter_dial_on_frame — the SHARED 4002 dialer (decision item 28):
#     the process dials with core's handshake code, not a copy.
set(_REQUIRED
    nodus_dht_init
    nodus_storage_open
    nodus_routing_try_insert
    handle_t2_media_put
    nodus_dht_ipc_new
    nodus_inter_dial_on_frame)

find_program(NM_EXE NAMES nm)
if(NOT NM_EXE)
    message(FATAL_ERROR
        "storage_linked: `nm` not found — what nodus-storage links CANNOT BE "
        "VERIFIED. Failing closed: an unverifiable claim is not a verified "
        "one.")
endif()

if(NOT DEFINED NODUS_STORAGE OR NODUS_STORAGE STREQUAL "")
    message(FATAL_ERROR
        "storage_linked: NODUS_STORAGE was not supplied — add "
        "-DNODUS_STORAGE=$<TARGET_FILE:nodus-storage> to this test's "
        "add_test() COMMAND in nodus/CMakeLists.txt.")
endif()
if(NOT EXISTS "${NODUS_STORAGE}")
    message(FATAL_ERROR "storage_linked: nodus-storage not found at ${NODUS_STORAGE}")
endif()

execute_process(COMMAND "${NM_EXE}" --defined-only "${NODUS_STORAGE}"
                OUTPUT_VARIABLE _syms
                ERROR_VARIABLE  _err
                RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR
        "storage_linked: nm failed on nodus-storage (rc=${_rc}): ${_err}")
endif()

foreach(_sym IN LISTS _FORBIDDEN)
    if(_syms MATCHES " T ${_sym}\n")
        message(FATAL_ERROR
            "storage_linked: another component's symbol `${_sym}` IS LINKED "
            "INTO nodus-storage (${NODUS_STORAGE}). A storage-side file calls "
            "into a core or witness object; the storage process must not "
            "carry that code (decision 2026-10-01-nodus-component-split).")
    endif()
endforeach()

foreach(_sym IN LISTS _REQUIRED)
    if(NOT _syms MATCHES " T ${_sym}\n")
        message(FATAL_ERROR
            "storage_linked: expected storage symbol `${_sym}` is MISSING "
            "from nodus-storage — this gate is inspecting the wrong "
            "artefact, or the module was dropped. Either way its absence "
            "proof is worthless.")
    endif()
endforeach()

message(STATUS "storage_linked: PASS — nodus-storage links no core or witness entry point")
