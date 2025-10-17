# DNA Messenger - Utility Programs

cmake_minimum_required(VERSION 3.10)

# Export public key utility
add_executable(export_pubkey
    export_pubkey.c
)

target_link_libraries(export_pubkey
    dna_lib
)

target_include_directories(export_pubkey PRIVATE
    ${CMAKE_SOURCE_DIR}
)

# Sign JSON utility
add_executable(sign_json
    sign_json.c
)

target_link_libraries(sign_json
    dna_lib
)

target_include_directories(sign_json PRIVATE
    ${CMAKE_SOURCE_DIR}
)

# Verify JSON utility
add_executable(verify_json
    verify_json.c
)

target_link_libraries(verify_json
    dna_lib
)

target_include_directories(verify_json PRIVATE
    ${CMAKE_SOURCE_DIR}
)

# Install utilities
if(WIN32)
    install(TARGETS export_pubkey sign_json verify_json DESTINATION utils)
else()
    install(TARGETS export_pubkey sign_json verify_json DESTINATION bin)
endif()
