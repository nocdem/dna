# Secp256k1.cmake - Bitcoin's secp256k1 elliptic curve library
#
# Used for Ethereum wallet key generation (BIP-32/BIP-44)
#
# This integrates the vendored secp256k1 library from vendor/secp256k1/

message(STATUS "Configuring secp256k1...")

# Set options before adding subdirectory
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "Enable ECDSA pubkey recovery module" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDH ON CACHE BOOL "Enable ECDH module" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "Enable extrakeys module" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF CACHE BOOL "Disable schnorrsig (not needed)" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "Disable musig (not needed)" FORCE)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF CACHE BOOL "Disable ellswift (not needed)" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "Disable tests" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "Disable exhaustive tests" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "Disable benchmark" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "Disable examples" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "Disable installation" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static library" FORCE)

# Disable visibility attributes for static linking
set(SECP256K1_ENABLE_API_VISIBILITY_ATTRIBUTES OFF CACHE BOOL "Disable visibility" FORCE)

# Add secp256k1 as subdirectory
add_subdirectory(${CMAKE_SOURCE_DIR}/vendor/secp256k1 ${CMAKE_BINARY_DIR}/secp256k1 EXCLUDE_FROM_ALL)

# Create an alias target for consistent naming
if(NOT TARGET secp256k1::secp256k1)
    add_library(secp256k1::secp256k1 ALIAS secp256k1)
endif()

# Export include directory for use by other targets
set(SECP256K1_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/vendor/secp256k1/include CACHE PATH "secp256k1 include directory")

message(STATUS "secp256k1 configured - include: ${SECP256K1_INCLUDE_DIR}")
