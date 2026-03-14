# =============================================================================
# DNA Connect CLI Tool
# =============================================================================
# Interactive REPL for testing DNA Connect without GUI.
# Designed for automated testing by Claude AI.

add_executable(dna-connect-cli
    main.c
    cli_commands.c
)

target_include_directories(dna-connect-cli PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${SHARED_DIR}/crypto/key/bip39
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(dna-connect-cli
    dna
)

# Install target
install(TARGETS dna-connect-cli
    RUNTIME DESTINATION bin
)
