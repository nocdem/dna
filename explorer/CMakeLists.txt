# =============================================================================
# DNA Explorer daemon — read-only chain indexer + JSON API for scan.cpunk.io
# =============================================================================
set(EXPLORER_SOURCES
    src/main.c
)

set(DNAC_DIR "${CMAKE_SOURCE_DIR}/../dnac")
set(NODUS_DIR "${CMAKE_SOURCE_DIR}/../nodus")

add_executable(dna-explorerd ${EXPLORER_SOURCES})

target_include_directories(dna-explorerd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${SHARED_DIR}
    ${DNAC_DIR}/include
    ${NODUS_DIR}/include
    ${NODUS_DIR}/src          # nodus_identity.h (crypto/nodus_identity.h)
)

target_link_libraries(dna-explorerd dna sqlite3 pthread)
if(EXISTS "${DNAC_DIR}/build/libdnac.a")
    target_link_libraries(dna-explorerd ${DNAC_DIR}/build/libdnac.a)
endif()

# Unit tests
add_executable(test_explorer
    tests/test_explorer.c
)
target_include_directories(test_explorer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${SHARED_DIR}
    ${DNAC_DIR}/include
    ${NODUS_DIR}/include
    ${NODUS_DIR}/src
)
target_link_libraries(test_explorer dna sqlite3 pthread)
if(EXISTS "${DNAC_DIR}/build/libdnac.a")
    target_link_libraries(test_explorer ${DNAC_DIR}/build/libdnac.a)
endif()
