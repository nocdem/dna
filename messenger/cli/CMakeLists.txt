# =============================================================================
# DNA Connect CLI Tool
# =============================================================================
# Interactive REPL for testing DNA Connect without GUI.
# Designed for automated testing by Claude AI.

set(CLI_SOURCES
    main.c
    cli_commands.c
    cli_dna_chain.c
)

# DNA Chain: compile DNAC CLI commands directly (they are not part of libdnac)
set(DNAC_DIR "${CMAKE_SOURCE_DIR}/../dnac")
set(DNAC_BUILD_DIR "${DNAC_DIR}/build")
if(EXISTS "${DNAC_BUILD_DIR}/libdnac.a")
    list(APPEND CLI_SOURCES ${DNAC_DIR}/src/cli/commands.c)
endif()

add_executable(dna-connect-cli ${CLI_SOURCES})

target_include_directories(dna-connect-cli PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${SHARED_DIR}/crypto/key/bip39
    ${CMAKE_SOURCE_DIR}
    ${DNAC_DIR}/include
)

# Link libdnac (static) for DNA Chain commands
if(EXISTS "${DNAC_BUILD_DIR}/libdnac.a")
    target_link_libraries(dna-connect-cli
        dna
        ${DNAC_BUILD_DIR}/libdnac.a
    )
    target_compile_definitions(dna-connect-cli PRIVATE DNA_CHAIN_ENABLED=1)
    message(STATUS "DNA Chain (DNAC) integration: ENABLED")
else()
    target_link_libraries(dna-connect-cli
        dna
    )
    message(STATUS "DNA Chain (DNAC) integration: DISABLED (libdnac.a not found at ${DNAC_BUILD_DIR})")
endif()

# Install target
install(TARGETS dna-connect-cli
    RUNTIME DESTINATION bin
)
