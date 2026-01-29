# =============================================================================
# DNA Engine Library
# =============================================================================
#
# The DNA Engine is the async API layer that provides thread-safe access to
# all DNA Messenger functionality. It manages:
#   - Task queue with worker thread pool
#   - Event dispatch (DHT status, messages, contacts, etc.)
#   - Engine lifecycle (create, pause, resume, destroy)
#   - All handler functions for identity, contacts, messaging, groups, etc.
#
# CURRENT STATE: Unified module (single source file)
# FUTURE: Will be split into domain-specific modules:
#   - dna_engine_core.c, dna_engine_identity.c, dna_engine_contacts.c, etc.
#
# Dependencies:
#   - dna-crypto (cryptographic primitives)
#   - dna-dht (DHT operations)
#   - dna-transport (P2P connectivity)
#   - dna-messenger-core (messaging logic)
#   - dna-database (SQLite caching)
#   - dna-blockchain (wallet, optional)
#
# =============================================================================

cmake_minimum_required(VERSION 3.10)

# Get the root directory (dna-messenger)
get_filename_component(DNA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

# =============================================================================
# Engine Source Files
# =============================================================================

# Hybrid approach: unified module + extracted modules
# - dna_engine_unified.c includes dna_engine.c with guarded sections
# - Extracted modules compile the guarded-out sections
set(ENGINE_SOURCES
    ${DNA_ROOT}/src/api/engine/dna_engine_unified.c
    ${DNA_ROOT}/src/api/engine/dna_engine_feed.c
    ${DNA_ROOT}/src/api/engine/dna_engine_identity.c
    ${DNA_ROOT}/src/api/engine/dna_engine_contacts.c
    ${DNA_ROOT}/src/api/engine/dna_engine_messaging.c
    ${DNA_ROOT}/src/api/engine/dna_engine_groups.c
    ${DNA_ROOT}/src/api/engine/dna_engine_wallet.c
    ${DNA_ROOT}/src/api/engine/dna_engine_p2p.c
)

# Future modular structure (commented out until extraction complete):
# set(ENGINE_SOURCES
#     ${DNA_ROOT}/src/api/engine/dna_engine_core.c
#     ${DNA_ROOT}/src/api/engine/dna_engine_identity.c
#     ${DNA_ROOT}/src/api/engine/dna_engine_contacts.c
#     ${DNA_ROOT}/src/api/engine/dna_engine_messaging.c
#     ${DNA_ROOT}/src/api/engine/dna_engine_groups.c
#     ${DNA_ROOT}/src/api/engine/dna_engine_wallet.c
#     ${DNA_ROOT}/src/api/engine/dna_engine_p2p.c
#     ${DNA_ROOT}/src/api/engine/dna_engine_feed.c
#     ${DNA_ROOT}/src/api/engine/dna_engine_utils.c
# )

# =============================================================================
# Library Definition
# =============================================================================

# Note: dna-engine is part of the main build, not a standalone library
# The sources are compiled as part of dna_engine shared library in root CMakeLists.txt

# This CMakeLists.txt is primarily for documentation and future modularization
# The actual build is handled by the parent CMakeLists.txt

# Export source files for parent CMakeLists.txt to use
set(DNA_ENGINE_SOURCES ${ENGINE_SOURCES} PARENT_SCOPE)
