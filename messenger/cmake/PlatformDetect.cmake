# PlatformDetect.cmake - Platform Detection and Configuration
#
# Detects the target platform and includes the appropriate platform-specific
# configuration file. Sets common variables used across all platforms.
#
# Sets: PLATFORM_SOURCES, PLATFORM_LIBS (via included platform files)

# Platform detection and configuration
if(ANDROID)
    message(STATUS "Platform: Android")
    include(${CMAKE_SOURCE_DIR}/cmake/AndroidBuild.cmake)
elseif(WIN32)
    message(STATUS "Platform: Windows")
    include(${CMAKE_SOURCE_DIR}/cmake/WindowsBuild.cmake)
elseif(APPLE)
    message(STATUS "Platform: macOS/iOS")
    # Future: include(${CMAKE_SOURCE_DIR}/cmake/AppleBuild.cmake)
    # For now, treat as Unix-like
    set(PLATFORM_SOURCES crypto/utils/qgp_platform_linux.c)
    set(PLATFORM_LIBS)
else()
    message(STATUS "Platform: Linux/Unix")
    include(${CMAKE_SOURCE_DIR}/cmake/LinuxBuild.cmake)
endif()

# Verify platform sources are set
if(NOT DEFINED PLATFORM_SOURCES)
    message(FATAL_ERROR "PLATFORM_SOURCES not defined after platform detection!")
endif()
