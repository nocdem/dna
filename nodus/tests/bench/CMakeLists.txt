# Nodus performance benchmark harness — Phase 1 micro-benchmarks.
#
# All targets are standalone C binaries linked against the nodus
# library (which re-exports shared/crypto primitives). They emit
# single-line JSON to stdout and carry the `bench` ctest label so
# `ctest -L bench` runs them as a group without pulling in the
# regular test suite.
#
# See nodus/docs/plans/2026-04-24-perf-harness-design.md for the
# full plan and phase roadmap.

set(BENCH_COMMON_SOURCES
    bench_common.c
)

# Helper — declare a bench binary with the common sources and the
# correct label. Matches the nodus/CMakeLists.txt idiom of
# `target_link_libraries(name nodus dsa nodus)` (the duplicate nodus
# is a deliberate linker-order workaround).
function(nodus_add_bench name)
    add_executable(${name} ${name}.c ${BENCH_COMMON_SOURCES})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${name} nodus dsa nodus)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES LABELS "bench")
endfunction()

nodus_add_bench(bench_dilithium_verify)
nodus_add_bench(bench_dilithium_sign)
nodus_add_bench(bench_sha3_512)
nodus_add_bench(bench_merkle_combine)
nodus_add_bench(bench_framework_smoke)
nodus_add_bench(bench_injection_smoke)

# Cluster TPS bench — uses pthreads + fork/exec. Not run via ctest
# (requires a running cluster); built for manual invocation by
# tests/bench_run.sh (Phase 5 orchestrator).
add_executable(bench_cluster_tps
    bench_cluster_tps.c
    ${BENCH_COMMON_SOURCES}
)
target_include_directories(bench_cluster_tps PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bench_cluster_tps nodus dsa nodus pthread)

# dna-bench — in-process libnodus client TPS bench.
#
# v3 (2026-04-28): bench links libdna.so to use nodus_client_dnac_spend +
# dnac_tx_* + qgp_dsa87_sign directly in-process. One nodus_client_t per
# wallet, parallel threads, no fork-exec per send. libdna.so is built
# with -fsanitize=address; bench must compile/link with ASan to avoid
# runtime mismatch SEGVs.
#
# Pool create / list / reset still fork-exec dna-connect-cli (one-time).
set(DNA_LIB_PATH "${CMAKE_SOURCE_DIR}/../messenger/build/libdna.so")
set(DNA_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../messenger/include")
set(DNAC_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../dnac/include")
set(DNA_SHARED_DIR "${CMAKE_SOURCE_DIR}/../shared")

if(NOT EXISTS "${DNA_LIB_PATH}")
    message(WARNING
        "libdna.so not found at ${DNA_LIB_PATH}; dna_bench skipped.\n"
        "Build messenger first: cd messenger/build && cmake .. && make -j$(nproc)")
else()
    add_executable(dna_bench
        dna_bench.c
        dna_bench_pool.c
        dna_bench_wallets.c
        dna_bench_run.c
        dna_bench_reconcile.c
        dna_bench_observe.c
        dna_bench_output.c
        dna_bench_native.c
    )
    target_include_directories(dna_bench PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${DNA_INCLUDE_DIR}
        ${DNAC_INCLUDE_DIR}
        ${DNA_SHARED_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    target_compile_options(dna_bench PRIVATE -fsanitize=address)
    target_link_libraries(dna_bench
        ${DNA_LIB_PATH}
        sqlite3
        pthread
        -fsanitize=address
    )
endif()
# Manual invocation only — not registered via add_test (requires prod cluster).

# SQLite bench has an extra dependency — link sqlite3 explicitly.
add_executable(bench_sqlite_commit
    bench_sqlite_commit.c
    ${BENCH_COMMON_SOURCES}
)
target_include_directories(bench_sqlite_commit PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bench_sqlite_commit nodus dsa nodus sqlite3)
add_test(NAME bench_sqlite_commit COMMAND bench_sqlite_commit)
set_tests_properties(bench_sqlite_commit PROPERTIES LABELS "bench")
