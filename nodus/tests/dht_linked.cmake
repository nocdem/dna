# Component split S4 — LINK GATE for the DHT / storage half.
#
# Decision docs/plans/decisions/2026-10-01-nodus-component-split.md: S4
# separates the DHT half (dht/nodus_dht_server.c, dht/nodus_dht_media.c)
# from core inside the combined binary, every crossing behind the seam
# (server/nodus_dht_backend.h one way, nodus_dht_host_t the other) so S5 can
# put the DHT into its own process. A source-level check cannot show what
# the DHT objects actually call: one stray direct call into nodus_server.c,
# nodus_auth.c, nodus_presence.c or nodus_cluster.c makes the static
# library pull that whole object in, and the S5 storage process would carry
# — and could start — core's code.
#
# dht_link_probe references every core -> DHT entry point and nothing else,
# so its linked symbol table is exactly the closure of the DHT objects.
# This inspects it with `nm`. The probe is never run.
#
# Symbols are matched as GLOBAL TEXT (" T <name>" at a line end), never as a
# bare substring: `nm --defined-only` also lists static (" t ") symbols, so
# a DHT-side static helper named like one of these neither trips a
# FORBIDDEN match nor fakes a REQUIRED one.
#
# Invoked by ctest as:
#   cmake -DDHT_PROBE=<path to dht_link_probe> -P this
cmake_minimum_required(VERSION 3.10)

# Core-only entry points — none may be reachable from the DHT objects.
#   nodus_server_init / nodus_server_dht_host — the server object (session
#     table, inter-node pool, the host side of the seam);
#   nodus_auth_handle_auth — the client-port auth handshake;
#   nodus_presence_tick — presence;
#   nodus_cluster_init / nodus_cluster_tick — cluster heartbeat;
#   nodus_dht_backend_inproc_new — core's door to the DHT (the DHT must not
#     call back through its own wrapper).
set(_FORBIDDEN
    nodus_server_init
    nodus_server_dht_host
    nodus_auth_handle_auth
    nodus_presence_tick
    nodus_cluster_init
    nodus_cluster_tick
    nodus_dht_backend_inproc_new)

# The DHT's own — present, so a pass cannot come from an empty symbol table,
# the wrong file, or an `nm` that silently failed. handle_t2_media_put proves
# the media TU is in the closure; nodus_storage_open and
# nodus_routing_try_insert that the storage / routing objects it owns are.
set(_REQUIRED
    nodus_dht_init
    nodus_dht_client_request
    nodus_dht_tick
    handle_t2_media_put
    nodus_storage_open
    nodus_routing_try_insert)

find_program(NM_EXE NAMES nm)
if(NOT NM_EXE)
    message(FATAL_ERROR
        "dht_linked: `nm` not found — what the DHT objects link CANNOT BE "
        "VERIFIED. Failing closed: an unverifiable claim is not a verified "
        "one.")
endif()

if(NOT DEFINED DHT_PROBE OR DHT_PROBE STREQUAL "")
    message(FATAL_ERROR
        "dht_linked: DHT_PROBE was not supplied — add "
        "-DDHT_PROBE=$<TARGET_FILE:dht_link_probe> to this test's "
        "add_test() COMMAND in nodus/CMakeLists.txt.")
endif()
if(NOT EXISTS "${DHT_PROBE}")
    message(FATAL_ERROR "dht_linked: dht_link_probe not found at ${DHT_PROBE}")
endif()

execute_process(COMMAND "${NM_EXE}" --defined-only "${DHT_PROBE}"
                OUTPUT_VARIABLE _syms
                ERROR_VARIABLE  _err
                RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR
        "dht_linked: nm failed on dht_link_probe (rc=${_rc}): ${_err}")
endif()

foreach(_sym IN LISTS _FORBIDDEN)
    if(_syms MATCHES " T ${_sym}\n")
        message(FATAL_ERROR
            "dht_linked: core-only symbol `${_sym}` IS REACHABLE from the "
            "DHT objects (${DHT_PROBE}). A DHT-side file calls into a core "
            "object instead of going through its host; the S5 storage "
            "process must not carry core's code (decision "
            "2026-10-01-nodus-component-split).")
    endif()
endforeach()

foreach(_sym IN LISTS _REQUIRED)
    if(NOT _syms MATCHES " T ${_sym}\n")
        message(FATAL_ERROR
            "dht_linked: expected DHT symbol `${_sym}` is MISSING from "
            "dht_link_probe — this gate is inspecting the wrong artefact, "
            "or the module was dropped. Either way its absence proof is "
            "worthless.")
    endif()
endforeach()

message(STATUS "dht_linked: PASS — the DHT objects reach no core entry point")
