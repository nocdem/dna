# JNI Bridge for Android
#
# Builds libdna_jni.so shared library for Android
# Links against static dna_lib and all dependencies

cmake_minimum_required(VERSION 3.10)
project(dna_jni C)

if(NOT ANDROID)
    message(FATAL_ERROR "JNI build is only for Android")
endif()

# JNI source
set(JNI_SOURCES
    dna_jni.c
)

# Create shared library for Android
add_library(dna_jni SHARED ${JNI_SOURCES})

# Include paths
target_include_directories(dna_jni PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}
    ${ANDROID_DEPS_DIR}/openssl-arm64/include
    ${ANDROID_DEPS_DIR}/sqlite-arm64/include
    ${ANDROID_DEPS_DIR}/jsonc-arm64/include
    ${ANDROID_DEPS_DIR}/curl-arm64/include
)

# Link against DNA libraries (order matters for static linking)
target_link_libraries(dna_jni
    dna_lib
    dht_lib
    p2p_transport
    opendht
    cellframe_minimal
    cellframe_dilithium
    kem
    dsa
    # libjuice is built as external project
    ${CMAKE_BINARY_DIR}/vendor/libjuice/install/lib/libjuice.a
    # Android dependencies (static)
    ${ANDROID_DEPS_DIR}/openssl-arm64/lib/libssl.a
    ${ANDROID_DEPS_DIR}/openssl-arm64/lib/libcrypto.a
    ${ANDROID_DEPS_DIR}/sqlite-arm64/lib/libsqlite3.a
    ${ANDROID_DEPS_DIR}/gnutls-arm64/lib/libgnutls.a
    ${ANDROID_DEPS_DIR}/nettle-arm64/lib/libhogweed.a
    ${ANDROID_DEPS_DIR}/nettle-arm64/lib/libnettle.a
    ${ANDROID_DEPS_DIR}/gmp-arm64/lib/libgmp.a
    ${ANDROID_DEPS_DIR}/libtasn1-arm64/lib/libtasn1.a
    ${ANDROID_DEPS_DIR}/argon2-arm64/lib/libargon2.a
    ${ANDROID_DEPS_DIR}/jsonc-arm64/lib/libjson-c.a
    ${ANDROID_DEPS_DIR}/zstd-arm64/lib/libzstd.a
    ${ANDROID_DEPS_DIR}/curl-arm64/lib/libcurl.a
    # Android system libraries
    log
    android
    z
)

# Ensure libjuice is built before dna_jni
add_dependencies(dna_jni libjuice_external)

# Strip in release mode
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET dna_jni POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:dna_jni>
        COMMENT "Stripping libdna_jni.so"
    )
endif()

message(STATUS "JNI library configured for Android")
