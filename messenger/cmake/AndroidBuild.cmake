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
# Sets: PLATFORM_SOURCES, PLATFORM_LIBS, ANDROID_DEPS_DIR, ANDROID_GNUTLS_LIBS

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
    set(PLATFORM_SOURCES crypto/utils/qgp_platform_android.c)

    # Android platform libs
    # - log: Android logging (__android_log_print for logcat)
    set(PLATFORM_LIBS log)

    # Android-specific compiler flags
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

    # NOTE: Static C++ runtime linkage is handled via target_link_options() on dna_lib
    # in CMakeLists.txt. Using CMAKE_SHARED_LINKER_FLAGS doesn't work because the
    # Android NDK toolchain overrides it. See CMakeLists.txt for the actual implementation.

    # Android cross-compiled dependencies paths
    # These are built by the Android NDK build process
    set(ANDROID_DEPS_DIR "$ENV{HOME}/android-deps" CACHE PATH "Android dependencies directory")
    if(EXISTS "${ANDROID_DEPS_DIR}")
        message(STATUS "Android deps dir: ${ANDROID_DEPS_DIR}")

        # Add all dependency include paths globally
        include_directories(
            ${ANDROID_DEPS_DIR}/openssl-arm64/include
            ${ANDROID_DEPS_DIR}/sqlite-arm64/include
            ${ANDROID_DEPS_DIR}/asio-1.30.2/include
            ${ANDROID_DEPS_DIR}/fmt-arm64/include
            ${ANDROID_DEPS_DIR}/gnutls-arm64/include
            ${ANDROID_DEPS_DIR}/nettle-arm64/include
            ${ANDROID_DEPS_DIR}/gmp-arm64/include
            ${ANDROID_DEPS_DIR}/libtasn1-arm64/include
            ${ANDROID_DEPS_DIR}/argon2-arm64/include
            ${ANDROID_DEPS_DIR}/jsonc-arm64/include
            ${ANDROID_DEPS_DIR}/msgpack-arm64/include
            ${ANDROID_DEPS_DIR}/zstd-arm64/include
            ${ANDROID_DEPS_DIR}/curl-arm64/include
        )

        # Link directories for static libraries
        link_directories(
            ${ANDROID_DEPS_DIR}/openssl-arm64/lib
            ${ANDROID_DEPS_DIR}/sqlite-arm64/lib
            ${ANDROID_DEPS_DIR}/fmt-arm64/lib
            ${ANDROID_DEPS_DIR}/gnutls-arm64/lib
            ${ANDROID_DEPS_DIR}/nettle-arm64/lib
            ${ANDROID_DEPS_DIR}/gmp-arm64/lib
            ${ANDROID_DEPS_DIR}/libtasn1-arm64/lib
            ${ANDROID_DEPS_DIR}/argon2-arm64/lib
            ${ANDROID_DEPS_DIR}/jsonc-arm64/lib
            ${ANDROID_DEPS_DIR}/zstd-arm64/lib
            ${ANDROID_DEPS_DIR}/curl-arm64/lib
        )

        # Set json-c variables for CMake find
        set(JSON-C_FOUND TRUE)
        set(JSON-C_INCLUDE_DIR "${ANDROID_DEPS_DIR}/jsonc-arm64/include")
        set(JSON-C_LIBRARY "${ANDROID_DEPS_DIR}/jsonc-arm64/lib/libjson-c.a")

        # Set CURL variables for CMake find
        set(CURL_FOUND TRUE)
        set(CURL_INCLUDE_DIRS "${ANDROID_DEPS_DIR}/curl-arm64/include")
        set(CURL_LIBRARIES "${ANDROID_DEPS_DIR}/curl-arm64/lib/libcurl.a")

        # Set OpenSSL variables for CMake find (bypass find_package)
        set(OPENSSL_FOUND TRUE)
        set(OPENSSL_VERSION "3.3.2")
        set(OPENSSL_INCLUDE_DIR "${ANDROID_DEPS_DIR}/openssl-arm64/include")
        set(OPENSSL_CRYPTO_LIBRARY "${ANDROID_DEPS_DIR}/openssl-arm64/lib/libcrypto.a")
        set(OPENSSL_SSL_LIBRARY "${ANDROID_DEPS_DIR}/openssl-arm64/lib/libssl.a")
        set(OPENSSL_LIBRARIES "${OPENSSL_SSL_LIBRARY};${OPENSSL_CRYPTO_LIBRARY}")

        # Create OpenSSL::Crypto imported target
        if(NOT TARGET OpenSSL::Crypto)
            add_library(OpenSSL::Crypto STATIC IMPORTED)
            set_target_properties(OpenSSL::Crypto PROPERTIES
                IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
            )
        endif()

        # Create OpenSSL::SSL imported target
        if(NOT TARGET OpenSSL::SSL)
            add_library(OpenSSL::SSL STATIC IMPORTED)
            set_target_properties(OpenSSL::SSL PROPERTIES
                IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
                INTERFACE_LINK_LIBRARIES "OpenSSL::Crypto"
            )
        endif()

        # Set SQLite3 variables for CMake find (bypass find_package)
        set(SQLite3_FOUND TRUE)
        set(SQLite3_VERSION "3.46.0")
        set(SQLite3_INCLUDE_DIRS "${ANDROID_DEPS_DIR}/sqlite-arm64/include")
        set(SQLite3_LIBRARIES "${ANDROID_DEPS_DIR}/sqlite-arm64/lib/libsqlite3.a")

        # GnuTLS and dependencies for dna_lib linking (used in CMakeLists.txt)
        # Order matters: libraries must come AFTER libraries that depend on them
        set(ANDROID_GNUTLS_LIBS
            ${ANDROID_DEPS_DIR}/gnutls-arm64/lib/libgnutls.a
            ${ANDROID_DEPS_DIR}/libtasn1-arm64/lib/libtasn1.a
            ${ANDROID_DEPS_DIR}/nettle-arm64/lib/libhogweed.a
            ${ANDROID_DEPS_DIR}/nettle-arm64/lib/libnettle.a
            ${ANDROID_DEPS_DIR}/gmp-arm64/lib/libgmp.a
            ${ANDROID_DEPS_DIR}/zstd-arm64/lib/libzstd.a
        )
    else()
        message(WARNING "Android deps directory not found: ${ANDROID_DEPS_DIR}")
        message(WARNING "Build dependencies with build-android-deps.sh first")
    endif()

    # Disable pkg-config for Android (would find host libraries)
    set(PKG_CONFIG_EXECUTABLE "" CACHE FILEPATH "Disable pkg-config for Android" FORCE)

    # Disable features not available/needed on Android
    set(BUILD_DNA_SEND OFF CACHE BOOL "Disable dna-send on Android" FORCE)

    # OpenDHT-PQ configuration for Android
    set(OPENDHT_TOOLS OFF CACHE BOOL "Disable OpenDHT tools on Android" FORCE)

    # Fix msgpack boost dependency
    add_definitions(-DMSGPACK_NO_BOOST)

    message(STATUS "Android build configured successfully")
    message(STATUS "========================================")
endif()
