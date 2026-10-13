#!/usr/bin/env python3
r"""
Independent oracle for HF-6 slice 5a: the water-fill power cap.

INDEPENDENCE DISCIPLINE
-----------------------
Written from the WRITTEN rule only, before and without reading any C
implementation of it:

  * design   docs/plans/2026-10-03-hf5-validator-owner-stake-design.md
             rev 6 §5 "Güç tavanı — tek fonksiyon (K1, K2, K5)";
  * decision docs/plans/decisions/2026-10-08-kurultay-14-hf6-summary.md
             item 1 (formula), K1 (cap = share of COUNTED power),
             K5 (ratio range [500, 3000] bps).

Python integers are unbounded here: this oracle does no overflow checking
of its own; it computes the exact mathematical value. The C side must
produce the same numbers with checked u64 arithmetic.

RULE (§5)
---------
  Input: p_1..p_n (p_i = total_stake_i / DNAC_DECIMAL_UNIT, each >= 1),
  each with a 64-byte validator_id; ratio_bps in [500, 3000].
  Order p DESC, ties validator_id ASC (bytewise).
  r' = max(ratio_bps, ceil(10000 / n)).
  For k = 0, 1, ...:
      S_k = sum_{i > k} p_i
      c_k = floor(r' * S_k / (10000 - r' * k))
  stop at the first k with p_{k+1} <= c_k;  counted_i = min(p_i, c_k).

INDEX CONVENTION (derived here, the three §5 examples are the test)
--------------------------------------------------------------------
  The indices in §5 are 1-BASED over the sorted order p_1 >= p_2 >= ... >= p_n:
  k = the number of leading entries already capped; S_k = p_{k+1} + ... + p_n
  (the uncapped tail, which INCLUDES p_{k+1}); the stop test is on p_{k+1},
  the largest uncapped entry. In 0-based terms (q_0 = p_1):
      S_k = q_k + q_{k+1} + ... + q_{n-1};  stop when q_k <= c_k.
  Reason (water-fill fixed point): the k capped entries sit at c, so the
  counted total is k*c + S_k and "share of c <= r'" is
  c * 10000 <= r' * (k*c + S_k)  <=>  c * (10000 - r'*k) <= r' * S_k.

  Check against §5:
    [88,2x6], 3000: r'=3000. k=0: S=100, c=30, 88>30. k=1: S=12,
                    c=floor(36000/7000)=5, p_2=2<=5 stop -> [5,2x6]  (matches)
    [45,45,10], 3000: n=3, r'=3334. k=0: S=100, c=33, 45>33. k=1: S=55,
                    c=floor(183370/6666)=27, 45>27. k=2: S=10,
                    c=floor(33340/3332)=10, 10<=10 stop -> [10,10,10] (matches)
    [10x7], 3000: r'=max(3000,1429)=3000. k=0: S=70, c=21, 10<=21
                    stop -> unchanged                                 (matches)
  The other reading (0-based, S_k EXCLUDING q_k) fails the first two
  examples: [88,2x6] gives k=0 S=12 c=3; k=1 S=10 c=floor(30000/7000)=4
  -> [4,2x6] (not [5,2x6]); [45,45,10] reaches k=2 with S=0, c=0 < 10
  and never stops. ([10x7] does not separate the readings: the alt
  reading gives S=60, c=18 >= 10, also unchanged.) derive_alt() below
  demonstrates this and the script asserts it.

VECTORS AND THEIR INPUTS
------------------------
  validator_id rule (all vectors except "tie_rev"): entry at INPUT
  position i gets 64 bytes all equal to (i*37 + 11) & 0xFF (37 is odd,
  so the 128 values for i < 128 are distinct).
  "tie_rev": ids 64 x byte(n - i) (descending in input order) so the
  tie-break visibly reorders equal entries. Equal p always yield equal
  counted (counted_i = min(p_i, c)), so the tie-break fixes the walk
  order only; it can never change an output.
  "rand32_*": rng = random.Random(1); for i in 0..31:
      v = rng.randint(1, 10**12); s = rng.randint(0, 40);
      p_i = max(1, v >> s)
  (skewed on purpose so the cap binds.)

Output: one block per vector: name, n, ratio, r', stop k, cap c,
input p (input order), counted (input order), and the share check
max_i counted_i*10000 <= r' * sum(counted). Written to stdout; the
committed copy is shared/dnac/tests/power_cap_oracle_out.txt.
"""

import random
import sys

UINT64_MAX = (1 << 64) - 1
DECIMAL_UNIT = 10 ** 8


def vid(i):
    return bytes([(i * 37 + 11) & 0xFF]) * 64


def r_prime(ratio, n):
    ceil_avg = -(-10000 // n)
    return max(ratio, ceil_avg)


def water_fill(p, ids, ratio):
    n = len(p)
    assert n >= 1 and all(x >= 1 for x in p) and 500 <= ratio <= 3000
    # 1-based sorted view: position j (1..n) -> input index order[j-1]
    order = sorted(range(n), key=lambda i: (-p[i], ids[i]))
    srt = [None] + [p[i] for i in order]          # srt[1..n]
    rp = r_prime(ratio, n)
    k = 0
    while True:
        assert k < n, "walk ran past n"
        s_k = sum(srt[k + 1:n + 1])               # sum_{i>k} p_i, 1-based
        den = 10000 - rp * k
        assert den > 0, "denominator <= 0"
        c_k = (rp * s_k) // den
        if srt[k + 1] <= c_k:
            break
        k += 1
    counted = [min(x, c_k) for x in p]
    return rp, k, c_k, counted


def derive_alt(p, ratio):
    """The rejected reading: 0-based, S_k excludes q_k. Returns counted."""
    n = len(p)
    q = sorted(p, reverse=True)
    rp = r_prime(ratio, n)
    for k in range(n):
        s_k = sum(q[k + 1:])
        den = 10000 - rp * k
        if den <= 0:
            return None
        c_k = (rp * s_k) // den
        if q[k] <= c_k:
            return [min(x, c_k) for x in p]
    return None


def emit(name, p, ratio, ids=None):
    n = len(p)
    if ids is None:
        ids = [vid(i) for i in range(n)]
    rp, k, c, counted = water_fill(p, ids, ratio)
    tot = sum(counted)
    assert all(x >= 1 for x in counted)
    assert all(x * 10000 <= rp * tot for x in counted), name
    worst = max(counted)
    print(f"vector {name}")
    print(f"  n={n} ratio_bps={ratio} r_prime={rp} stop_k={k} cap={c}")
    print(f"  p       = [{', '.join(str(x) for x in p)}]")
    print(f"  counted = [{', '.join(str(x) for x in counted)}]")
    print(f"  sum_counted={tot} max_counted={worst} "
          f"share_ok={worst * 10000 <= rp * tot}")
    return counted


def main():
    # §5 worked examples.
    c1 = emit("ex_88_2x6", [88, 2, 2, 2, 2, 2, 2], 3000)
    assert c1 == [5, 2, 2, 2, 2, 2, 2]
    c2 = emit("ex_45_45_10", [45, 45, 10], 3000)
    assert c2 == [10, 10, 10]
    c3 = emit("ex_10x7", [10] * 7, 3000)
    assert c3 == [10] * 7
    # The rejected index reading must fail the examples it can separate.
    assert derive_alt([88, 2, 2, 2, 2, 2, 2], 3000) == [4, 2, 2, 2, 2, 2, 2]
    assert derive_alt([45, 45, 10], 3000) is None
    assert derive_alt([10] * 7, 3000) == [10] * 7

    # Small sets: r' = ceil(10000/n) dominates.
    emit("n1", [5], 3000)                          # r' = 10000 -> unchanged
    emit("n2_equal", [7, 7], 3000)
    emit("n2_unequal", [9, 1], 3000)
    emit("n3_equal", [4, 4, 4], 3000)
    emit("n3_unequal", [50, 30, 20], 3000)
    emit("n3_unequal_order", [20, 50, 30], 3000)   # caller order kept
    # ratio 500, 7 equal: r' = 1429 (> 500) -> each stays at 1/7.
    emit("r500_7equal", [100] * 7, 500)
    emit("r500_7skew", [1000, 100, 90, 80, 70, 60, 50], 500)
    # Ties broken by validator_id (ids descending in input order).
    tie = [30, 5, 30, 5, 30, 5, 30, 5]
    emit("tie_rev", tie, 3000,
         ids=[bytes([len(tie) - i]) * 64 for i in range(len(tie))])

    # 32-entry pseudo-random set, seed 1 (rule in the docstring).
    rng = random.Random(1)
    rand32 = []
    for _ in range(32):
        v = rng.randint(1, 10 ** 12)
        s = rng.randint(0, 40)
        rand32.append(max(1, v >> s))
    emit("rand32_r3000", rand32, 3000)
    emit("rand32_r500", rand32, 500)

    # Maximum: 128 entries at UINT64_MAX / 10^8 (§5 overflow note).
    pmax = UINT64_MAX // DECIMAL_UNIT
    emit("max128_equal_r3000", [pmax] * 128, 3000)
    emit("max128_equal_r500", [pmax] * 128, 500)
    emit("max128_skew_r3000", [pmax] + [1] * 127, 3000)
    emit("max128_skew_r500", [pmax] + [1] * 127, 500)
    return 0


if __name__ == "__main__":
    sys.exit(main())
