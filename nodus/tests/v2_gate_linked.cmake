# Ledger V2 O15B — LINK GATE for the test-only activation-authority fixture.
#
# WHY A LINK GATE AND NOT A C TEST
# A C test proves things about the binary it is compiled into, and this
# season's gate test deliberately compiles the fixture IN (it is the only
# way to exercise the armed ingress and sync paths at all). So that binary's
# symbol table says nothing whatsoever about what production ships.
#
# The claim that matters — "no shipped binary contains a way to grant
# activation authority" — can only be checked against the LINKED artefacts,
# which is what this does.
#
# WHAT WOULD BREAK WITHOUT IT
# `NODUS_V2_TEST_AUTHORITY` is added ONLY to test targets that deliberately
# compile the gate TU in (today: test_v2_gate, test_v2_sync_claims), and to
# NO library or server target. Moving it to a directory-scope
# `add_definitions()`, or adding it to the `nodus` library while chasing a
# build error, would silently compile an authority override into the shipped
# server. Review catches that only if someone is looking; this fails.
#
# ── O15J Faz 3: THE THIRD BINARY ───────────────────────────────────────
# The activation ceremony is gone, and authority is now DERIVED from the
# chain's own committed genesis manifest. `test_v2_gate_pure` is the test
# that proves a pure-V2 chain opens the gate in an ordinary build — a claim
# that is only worth anything while that binary carries NO synthetic
# authority. If someone ever adds NODUS_V2_TEST_AUTHORITY to that target to
# turn a red test green, the test would still pass and would have stopped
# meaning anything. So its symbol table is checked here too, by the same
# `nm` that polices the shipped artefacts.
#
# Invoked by ctest as:
#   cmake -DNODUS_LIB=... -DNODUS_SERVER=... -DGATE_PURE=... -P this
cmake_minimum_required(VERSION 3.10)

set(_FORBIDDEN
    nodus_witness_v2_gate_test_arm
    nodus_witness_v2_gate_test_clear)

# Present in production — so a pass cannot come from inspecting the wrong
# file, an empty symbol table, or an `nm` that silently failed.
set(_REQUIRED
    nodus_witness_v2_gate_state
    nodus_witness_v2_activation_permitted
    nodus_witness_v2_ingress_arm)

find_program(NM_EXE NAMES nm)
if(NOT NM_EXE)
    message(FATAL_ERROR
        "v2_gate_linked: `nm` not found — the absence of the test-only "
        "authority fixture from the shipped binaries CANNOT BE VERIFIED. "
        "Failing closed: an unverifiable claim is not a verified one.")
endif()

function(_check_binary _path _label)
    if(NOT EXISTS "${_path}")
        message(FATAL_ERROR "v2_gate_linked: ${_label} not found at ${_path}")
    endif()

    execute_process(COMMAND "${NM_EXE}" -C --defined-only "${_path}"
                    OUTPUT_VARIABLE _syms
                    ERROR_VARIABLE  _err
                    RESULT_VARIABLE _rc)
    if(NOT _rc EQUAL 0)
        # A stripped or unreadable binary means we could not check. That is
        # not a pass.
        message(FATAL_ERROR
            "v2_gate_linked: nm failed on ${_label} (rc=${_rc}): ${_err}")
    endif()

    foreach(_sym IN LISTS _FORBIDDEN)
        if(_syms MATCHES "${_sym}")
            message(FATAL_ERROR
                "v2_gate_linked: TEST-ONLY AUTHORITY FIXTURE `${_sym}` IS "
                "PRESENT IN ${_label} (${_path}). A shipped binary must "
                "contain no way to grant Ledger V2 activation authority. "
                "Check that NODUS_V2_TEST_AUTHORITY is defined on test "
                "targets ONLY.")
        endif()
    endforeach()

    foreach(_sym IN LISTS _REQUIRED)
        if(NOT _syms MATCHES "${_sym}")
            message(FATAL_ERROR
                "v2_gate_linked: expected production symbol `${_sym}` is "
                "MISSING from ${_label} — this gate is inspecting the wrong "
                "artefact, or the gate module was dropped from the build. "
                "Either way its absence proof is worthless.")
        endif()
    endforeach()

    message(STATUS "v2_gate_linked: ${_label} OK — fixture absent, gate present")
endfunction()

_check_binary("${NODUS_LIB}"    "libnodus")
_check_binary("${NODUS_SERVER}" "nodus-server")

# The pure-gate test must be checkable, and "the argument was not passed"
# is NOT a pass — the same fail-closed rule this file applies to a missing
# `nm`. An unverifiable claim is not a verified one.
if(NOT DEFINED GATE_PURE OR GATE_PURE STREQUAL "")
    message(FATAL_ERROR
        "v2_gate_linked: GATE_PURE was not supplied, so it CANNOT BE "
        "VERIFIED that test_v2_gate_pure carries no synthetic activation "
        "authority — the property that makes that test mean anything. "
        "Add -DGATE_PURE=$<TARGET_FILE:test_v2_gate_pure> to this test's "
        "add_test() COMMAND in nodus/CMakeLists.txt.")
endif()
_check_binary("${GATE_PURE}" "test_v2_gate_pure")

message(STATUS "v2_gate_linked: PASS")
