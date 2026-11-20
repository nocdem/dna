# B-01: the build system must re-run configure when nodus_types.h changes.
#
# CMT_SOFTWARE_VERSION is read out of nodus_types.h with file(STRINGS) at
# configure time (nodus/CMakeLists.txt); file(STRINGS) does not register the
# header as a configure dependency by itself, so an incremental build after a
# version bump kept the old version compiled in.
#
# Proves: the generated build system lists nodus_types.h among the files whose
#   change triggers a re-configure (CMakeFiles/Makefile.cmake for the Makefile
#   generator, build.ninja for Ninja).
# Run as: cmake -DBUILD_DIR=<build dir> -P check_version_reconfigure.cmake
# Flags/env: none. Leaves behind: nothing (read only).
# How it can falsely pass: it checks that the dependency is recorded, not that
#   a rebuild actually re-runs configure; and any other, unrelated mention of
#   the header in those generated files would satisfy it. Before the fix the
#   header is absent from both files and the check fails.

if(NOT BUILD_DIR)
    message(FATAL_ERROR "BUILD_DIR not set")
endif()

set(_candidates "${BUILD_DIR}/CMakeFiles/Makefile.cmake" "${BUILD_DIR}/build.ninja")
set(_checked FALSE)
foreach(_f IN LISTS _candidates)
    if(EXISTS "${_f}")
        set(_checked TRUE)
        file(READ "${_f}" _text)
        if(NOT _text MATCHES "include/nodus/nodus_types\\.h")
            message(FATAL_ERROR
                "${_f} does not list nodus_types.h as a configure dependency")
        endif()
    endif()
endforeach()
if(NOT _checked)
    message(FATAL_ERROR "no Makefile.cmake or build.ninja in ${BUILD_DIR}")
endif()
message(STATUS "nodus_types.h is a configure dependency")
