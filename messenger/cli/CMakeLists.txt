# =============================================================================
# DNA Messenger CLI Tool
# =============================================================================
# Interactive REPL for testing DNA Messenger without GUI.
# Designed for automated testing by Claude AI.

add_executable(dna-messenger-cli
    main.c
    cli_commands.c
)

target_include_directories(dna-messenger-cli PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/crypto/bip39
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(dna-messenger-cli
    dna_lib
)

# Install target
install(TARGETS dna-messenger-cli
    RUNTIME DESTINATION bin
)
