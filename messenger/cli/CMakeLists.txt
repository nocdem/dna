# =============================================================================
# DNA Connect CLI Tool
# =============================================================================
# Interactive REPL for testing DNA Connect without GUI.
# Designed for automated testing by Claude AI.

add_executable(dna-messenger-cli
    main.c
    cli_commands.c
)

target_include_directories(dna-messenger-cli PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${SHARED_DIR}/crypto/key/bip39
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(dna-messenger-cli
    dna
)

# Install target
install(TARGETS dna-messenger-cli
    RUNTIME DESTINATION bin
)
