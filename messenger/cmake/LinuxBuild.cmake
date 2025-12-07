# LinuxBuild.cmake - Linux/Unix Build Configuration
#
# Sets: PLATFORM_SOURCES, PLATFORM_LIBS, platform-specific flags

if(UNIX AND NOT ANDROID AND NOT APPLE)
    message(STATUS "=== Linux/Unix Build Configuration ===")

    # Platform sources
    set(PLATFORM_SOURCES crypto/utils/qgp_platform_linux.c)

    # No extra platform libs needed on Linux (pthread linked separately)
    set(PLATFORM_LIBS)

    # Linux-specific compiler flags (if needed)
    # Currently none required

    message(STATUS "Linux build configured successfully")
    message(STATUS "======================================")
endif()
