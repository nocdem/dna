# Perf Baselines

Committed baseline JSON files from the Nodus benchmark harness. The executable
workflow is defined by `nodus/tests/bench_run.sh`, `bench_diff.py` and the
benchmark CMake targets.

## Current inventory

This checkout contains `micro_v0.17.7.json` only. It does not contain a
cluster baseline, and the current Nodus header reports v0.18.22. Do not treat
the available file as a current-version performance claim; capture a new
host-specific baseline before running a release regression gate.

## File naming

- `micro_v<VERSION>.json` — aggregated output of the Phase 1 micro
  benchmarks (primitives only, no cluster).
- `cluster_v<VERSION>.json` — output of `bench_cluster_tps` against
  the Stage F cluster (real throughput under load).

Version in the filename is the nodus semver at capture time (e.g.
`micro_v0.17.7.json`).

## How to regenerate

### Micro baselines

```bash
cmake -S nodus -B nodus/build -DCMAKE_BUILD_TYPE=Release -DQGP_BENCH=ON
cmake --build nodus/build -j"$(nproc)"
ctest --test-dir nodus/build -L bench --output-on-failure

# Capture aggregated JSON from the 5 Phase 1 bench binaries:
{ ./nodus/build/tests/bench/bench_dilithium_verify
  ./nodus/build/tests/bench/bench_dilithium_sign
  ./nodus/build/tests/bench/bench_sha3_512
  ./nodus/build/tests/bench/bench_merkle_combine
  ./nodus/build/tests/bench/bench_sqlite_commit
} | jq -s '{ nodus_version: "X.Y.Z", results: . }' \
  > nodus/docs/perf_baselines/micro_vX.Y.Z.json
```

### Cluster baseline

```bash
cmake -S nodus -B nodus/build -DCMAKE_BUILD_TYPE=Release -DQGP_BENCH=ON
cmake --build nodus/build -j"$(nproc)"

bash nodus/tests/bench_run.sh \
    --concurrency 4 --duration 60 \
    --output /tmp/bench_run_$(date +%s)
```

Copy the produced `throughput.json` into this directory:

```bash
cp /tmp/bench_run_*/throughput.json \
   nodus/docs/perf_baselines/cluster_vX.Y.Z.json
```

## Threshold policy (bench_diff.py)

A new measurement is considered a regression when it falls OUTSIDE
these bands relative to baseline:

| Metric | Threshold | Action |
|--------|-----------|--------|
| `tps_commit` | -10% | FAIL (exit 1) |
| `submit_success_rate` | -5 percentage points | FAIL |
| `p95_us` | +25% | WARN (exit 0 + stderr) |

Tune per-run with `--tps-threshold`, `--success-pp`, `--p95-threshold`.

## Host dependency

Measurements are host-specific. The baseline filename **does not**
encode host, but each baseline file carries `"cpu"` and `"timestamp"`
fields captured at baseline time. When moving to a different host,
recapture the baseline — do NOT compare across hosts.

Recommended practice: keep one reference host for baselines (the
machine where the user runs `bench_run.sh` habitually), and name
baselines after the nodus version rather than the host.
