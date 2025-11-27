# AndroidBuild.cmake - Android NDK Build Configuration
#
# Usage:
#   mkdir build-android && cd build-android
#   cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a \
#         -DANDROID_PLATFORM=android-24 \
#         -DBUILD_GUI=OFF \
#         ..
#
# Supported ABIs:
#   - arm64-v8a (recommended, 64-bit ARM)
#   - armeabi-v7a (32-bit ARM, legacy)
#   - x86_64 (emulator)
#   - x86 (emulator, legacy)
#
# Minimum API Level: 24 (Android 7.0) - required for getrandom()
#

if(ANDROID)
    message(STATUS "=== Android NDK Build Configuration ===")
    message(STATUS "Android ABI: ${ANDROID_ABI}")
    message(STATUS "Android Platform: ${ANDROID_PLATFORM}")
    message(STATUS "Android NDK: ${ANDROID_NDK}")

    # Enforce minimum API level (24 for getrandom())
    if(ANDROID_NATIVE_API_LEVEL LESS 24)
        message(WARNING "Android API level ${ANDROID_NATIVE_API_LEVEL} is below recommended 24")
        message(WARNING "getrandom() may not be available, falling back to /dev/urandom")
    endif()

    # Define Android platform
    add_definitions(-D__ANDROID__)
    add_definitions(-DANDROID)

    # Disable GUI on Android (always)
    set(BUILD_GUI OFF CACHE BOOL "Disable GUI on Android" FORCE)

    # Use static STL
    set(ANDROID_STL c++_static)

    # Platform-specific sources
    set(PLATFORM_SOURCES
        crypto/utils/qgp_platform_android.c
    )

    # No extra platform libs needed on Android
    # (pthread is part of bionic libc)
    set(PLATFORM_LIBS)

    # Android-specific compiler flags
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

    # Disable features not available/needed on Android
    set(BUILD_DNA_SEND OFF CACHE BOOL "Disable dna-send on Android" FORCE)

    # OpenDHT-PQ configuration for Android
    set(OPENDHT_TOOLS OFF CACHE BOOL "Disable OpenDHT tools on Android" FORCE)

    message(STATUS "Android build configured successfully")
    message(STATUS "========================================")
endif()
