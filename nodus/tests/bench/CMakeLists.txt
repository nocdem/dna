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
