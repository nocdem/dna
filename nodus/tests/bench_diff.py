#!/usr/bin/env python3
"""
bench_diff.py — regression gate for perf baselines.

Compares two throughput.json outputs (baseline vs. current) and
applies the threshold policy from
nodus/docs/plans/2026-04-24-perf-harness-design.md section 5/Phase 5.

Threshold policy (exit codes):
  - TPS commit: regression > 10% -> FAIL (exit 1)
  - Submit success rate: regression > 5 percentage points -> FAIL
  - Commit latency p95: regression > 25% -> WARN (exit 0 + stderr note)

"Regression" always means: current is worse than baseline.
"""

import argparse
import json
import sys


def load(path):
    with open(path) as f:
        return json.load(f)


def extract(obj):
    """Accept either the single-line bench JSON or a {"throughput": ...}
    wrapper. Return a flat dict of the fields we care about."""
    if "tps_commit" in obj:
        src = obj
    elif "throughput" in obj and isinstance(obj["throughput"], dict):
        src = obj["throughput"]
    else:
        src = obj
    return {
        "tps_commit": float(src.get("tps_commit", 0.0)),
        "tps_submit": float(src.get("tps_submit", 0.0)),
        "submit_success_rate": float(src.get("submit_success_rate", 0.0)),
        "p50_us": float(src.get("p50_us", 0.0)),
        "p95_us": float(src.get("p95_us", 0.0)),
        "p99_us": float(src.get("p99_us", 0.0)),
        "tx_committed": int(src.get("tx_committed", 0)),
    }


def pct_change(baseline, current):
    """Return current / baseline - 1, guarded against zero."""
    if baseline == 0:
        return 0.0
    return (current - baseline) / baseline


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", required=True, help="baseline JSON path")
    ap.add_argument("--current",  required=True, help="current  JSON path")
    ap.add_argument("--tps-threshold", type=float, default=0.10,
                    help="TPS regression threshold (fraction, default 0.10)")
    ap.add_argument("--success-pp", type=float, default=0.05,
                    help="submit success rate regression threshold "
                         "(percentage points, default 0.05)")
    ap.add_argument("--p95-threshold", type=float, default=0.25,
                    help="p95 latency regression threshold "
                         "(fraction, default 0.25)")
    args = ap.parse_args()

    b = extract(load(args.baseline))
    c = extract(load(args.current))

    tps_change = pct_change(b["tps_commit"], c["tps_commit"])
    ss_delta   = c["submit_success_rate"] - b["submit_success_rate"]
    p95_change = pct_change(b["p95_us"], c["p95_us"])

    print(f"baseline: {args.baseline}")
    print(f"current : {args.current}")
    print(f"  tps_commit:    {b['tps_commit']:.3f} -> {c['tps_commit']:.3f}"
          f"  ({tps_change:+.1%})")
    print(f"  success_rate:  {b['submit_success_rate']:.4f} -> "
          f"{c['submit_success_rate']:.4f}  ({ss_delta:+.4f})")
    print(f"  p95_us:        {b['p95_us']:.1f} -> {c['p95_us']:.1f}"
          f"  ({p95_change:+.1%})")

    fails = []
    warns = []

    if tps_change < -args.tps_threshold:
        fails.append(
            f"TPS regression: {tps_change:+.1%} (threshold "
            f"-{args.tps_threshold:.0%})")
    if ss_delta < -args.success_pp:
        fails.append(
            f"success-rate regression: {ss_delta:+.4f} "
            f"(threshold -{args.success_pp:.2f})")
    if p95_change > args.p95_threshold:
        warns.append(
            f"p95 latency worse by {p95_change:+.1%} (threshold "
            f"+{args.p95_threshold:.0%})")

    for w in warns:
        print(f"  WARN: {w}", file=sys.stderr)
    for f in fails:
        print(f"  FAIL: {f}", file=sys.stderr)

    if fails:
        return 1
    print("  OK: no regression beyond thresholds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
