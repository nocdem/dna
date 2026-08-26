# Ledger V2 O15J — LINK GATE for the test-only conservation bypass.
#
# WHAT THIS DEFENDS
# Red-team finding L2-F1 (CRITICAL, found independently by two lenses):
# an ABSENT supply_tracking row made nodus_rt_core_invariant return 0 —
# the CORE conservation equation SKIPPED, not satisfied, for the entire
# life of the chain, with the manifest cross-check reading the same
# absent row as 0 and passing too. A chain born without that row would
# have minted the treasury with nothing behind it and reported green.
#
# That hole is now a hard refusal. But TWO engine-level tests
# (test_v2_apply, test_v2_exec) drive SYNTHETIC envelopes that create
# value from nothing to cover the apply engine's effect plumbing, and no
# genesis seeding can balance conjured value — that is exactly what the
# equation forbids. They were relying on the hole. They now use an
# explicit bypass instead, and the whole point of this gate is that the
# replacement CANNOT EXIST IN PRODUCTION where the original could.
#
# (Review R2-F5 corrected the count: test_v2_claims was given the macro
# too, but it never calls v2x_genesis_min and so never arms the bypass —
# all nine of its supply assertions run live. It was dropped back to a
# plain register_witness_test.)
#
# WHY A LINK GATE AND NOT A C TEST
# A C test proves things about the binary it is compiled into, and those
# two targets deliberately compile the bypass IN. Their symbol tables
# therefore say nothing about what production ships. The claim that
# matters — "no shipped binary can suspend supply conservation" — is only
# checkable against the LINKED artefacts.
#
# WHAT WOULD BREAK WITHOUT IT
# `NODUS_V2_TEST_SUPPLY` is added by exactly one CMake function
# (register_witness_test_supply_bypass) to exactly two targets. Moving
# it to a directory-scope add_definitions(), or adding it to the `nodus`
# library while chasing a build error, would silently compile a
# conservation off-switch into the shipped server. Review catches that
# only if someone is looking; this fails.
#
# Invoked by ctest as: cmake -DNODUS_LIB=... -DNODUS_SERVER=... -P this
cmake_minimum_required(VERSION 3.10)

set(_FORBIDDEN
    nodus_witness_v2_supply_test_bypass)

# Present in production — so a pass cannot come from inspecting the wrong
# file, an empty symbol table, or an `nm` that silently failed.
set(_REQUIRED
    nodus_rt_core_invariant
    nodus_witness_v2_supply_check)

find_program(NM_EXE NAMES nm)
if(NOT NM_EXE)
    message(FATAL_ERROR
        "v2_supply_linked: `nm` not found — the absence of the test-only "
        "conservation bypass from the shipped binaries CANNOT BE VERIFIED. "
        "Failing closed: an unverifiable claim is not a verified one.")
endif()

function(_check_binary _path _label)
    if(NOT EXISTS "${_path}")
        message(FATAL_ERROR "v2_supply_linked: ${_label} not found at ${_path}")
    endif()

    execute_process(COMMAND "${NM_EXE}" -C --defined-only "${_path}"
                    OUTPUT_VARIABLE _syms
                    ERROR_VARIABLE  _err
                    RESULT_VARIABLE _rc)
    if(NOT _rc EQUAL 0)
        # A stripped or unreadable binary means we could not check. That is
        # not a pass.
        message(FATAL_ERROR
            "v2_supply_linked: nm failed on ${_label} (rc=${_rc}): ${_err}")
    endif()

    foreach(_sym IN LISTS _FORBIDDEN)
        if(_syms MATCHES "${_sym}")
            message(FATAL_ERROR
                "v2_supply_linked: TEST-ONLY CONSERVATION BYPASS `${_sym}` "
                "IS PRESENT IN ${_label} (${_path}). A shipped binary must "
                "contain no way to suspend the CORE supply invariant — that "
                "is the L2-F1 hole this season closed. Check that "
                "NODUS_V2_TEST_SUPPLY is defined on test targets ONLY "
                "(register_witness_test_supply_bypass).")
        endif()
    endforeach()

    foreach(_sym IN LISTS _REQUIRED)
        if(NOT _syms MATCHES "${_sym}")
            message(FATAL_ERROR
                "v2_supply_linked: expected production symbol `${_sym}` is "
                "MISSING from ${_label} — this gate is inspecting the wrong "
                "artefact, or the claims module was dropped from the build. "
                "Either way its absence proof is worthless.")
        endif()
    endforeach()

    message(STATUS
        "v2_supply_linked: ${_label} OK — bypass absent, invariant present")
endfunction()

_check_binary("${NODUS_LIB}"    "libnodus")
_check_binary("${NODUS_SERVER}" "nodus-server")

message(STATUS "v2_supply_linked: PASS")
