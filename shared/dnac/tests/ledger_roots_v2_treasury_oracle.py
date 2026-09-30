#!/usr/bin/env python3
"""
Independent vector oracle for the TREASURY leg of the SYSTEM state root
(decision 2026-09-28-treasury-pools-and-exact-self-stake.md, item 12,
operator "1 ok", 2026-09-29): the per-pool treasury leaf
("NDS.TRLEAF.v1"), the treasury Merkle tree (inner "NDS.TRNODE.v1",
empty "NDS.E.TREAS.v1"), and the two SYSTEM compositions that gain the
treasury_root as their LAST leg: system_state_root ("NDS.SYS.v4", 8 legs)
and system_payload_root ("NDS.SYSPAYL.v3", 5 legs).

── PROVENANCE — HONEST LABEL ────────────────────────────────────────────
This is a SELF-CONSISTENCY oracle, not an external audit: the format is
this project's own invention (there is no pinned external reference for
"a treasury-pool leg of a tagged Merkle state root"). It re-derives the
byte layout from the written contract only — decision item 12 for the
new tags / leaf layout, and shared/dnac/ledger_roots_v2.h's "TAG TABLE" /
"Composition preimages" / "Merkle construction" comments for the tag
padding, the existing SYSTEM leg order and the Merkle rule. The C
implementation of this leg is written by a DIFFERENT agent (decision
item 12: author != auditor) and was NOT read while writing this script;
but both sides derive from the same contract text on the same day.
Agreement proves the C and this script implement the SAME documented
format; it does NOT prove the format sound or the only reasonable one.
Call it "self-consistent", never "independently audited". Same status as
ledger_roots_v2_accrual_oracle.py (P2) and
ledger_roots_v2_attendance_oracle.py (P1).

── WHAT IS PINNED ────────────────────────────────────────────────────────
  treasury leaf  = SHA3-512("NDS.TRLEAF.v1" (16B zero-padded) ||
                            pool_id(4 BE) || balance(8 BE))
  treasury inner = SHA3-512("NDS.TRNODE.v1" || left[64] || right[64])
  treasury empty = SHA3-512("NDS.E.TREAS.v1")   (the 16-byte padded tag
                   alone — the same rule as every other tagged empty root)
  system_state_root   = SHA3-512("NDS.SYS.v4" || 8 legs of 64 bytes:
                        validator, delegation, chain_config,
                        validator_set, domain_registry, manifest,
                        attendance, treasury)
  system_payload_root = SHA3-512("NDS.SYSPAYL.v3" || 5 legs of 64 bytes:
                        validator, delegation, chain_config,
                        validator_set, treasury)
The Merkle rule is the header's own: leaves in STRICTLY ascending pool_id
(duplicates reject), an unpaired node PROMOTED (never duplicated),
n == 1 -> the leaf, n == 0 -> the tagged empty root.

── HOW THIS CAN LIE ──────────────────────────────────────────────────────
 1. Same contract, same day: see PROVENANCE above.
 2. `fill(seed)` is test_roots_v2.c's own fixture convention, reproduced
    byte-for-byte; a bug shared between the C fixture and this generator
    would agree with itself.
 3. The two control legs (the LIVE "NDS.SYS.v3" 7-leg and
    "NDS.SYSPAYL.v2" 4-leg vectors pinned in nodus/tests/test_roots_v2.c
    before this change) are run FIRST; if either fails, nothing this
    script prints below them may be used. No treasury vector existed
    before, so the leaf / tree / empty root have NO control of their own
    — they rest on the same tag + Merkle method the controls prove.
 4. The contract is silent on whether a zero-balance pool stays in the
    tree and on the valid pool_id range; this script accepts any u32
    pool_id (including 0) and any u64 balance (including 0). If the C
    rejects or omits such rows, vectors built from them are not a
    disagreement about THIS layout.

Read-only: opens nothing, writes nothing, prints to stdout.
"""
import hashlib
import struct

TAG_LEN = 16


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def tag(name: str) -> bytes:
    b = name.encode("ascii")
    assert len(b) <= TAG_LEN, f"tag {name!r} too long for a 16-byte slot"
    return b + b"\x00" * (TAG_LEN - len(b))


def fill(seed: int, n: int = 64) -> bytes:
    """test_roots_v2.c's own fixture convention: dst[i] = seed + i*7 (mod 256)."""
    return bytes([(seed + i * 7) & 0xFF for i in range(n)])


def be32(v: int) -> bytes:
    return struct.pack(">I", v)   # raises struct.error outside u32


def be64(v: int) -> bytes:
    return struct.pack(">Q", v)   # raises struct.error outside u64


# Live (pre-change) composition tags — control legs only.
TAG_SYS_V3 = tag("NDS.SYS.v3")
TAG_SYSPAYL_V2 = tag("NDS.SYSPAYL.v2")
# New tags (decision item 12).
TAG_SYS_V4 = tag("NDS.SYS.v4")
TAG_SYSPAYL_V3 = tag("NDS.SYSPAYL.v3")
TAG_TRLEAF = tag("NDS.TRLEAF.v1")
TAG_TRNODE = tag("NDS.TRNODE.v1")
TAG_E_TREAS = tag("NDS.E.TREAS.v1")


def treasury_leaf(pool_id: int, balance: int) -> bytes:
    pre = TAG_TRLEAF + be32(pool_id) + be64(balance)
    assert len(pre) == TAG_LEN + 4 + 8
    return sha3_512(pre)


def tagged_merkle(node_tag: bytes, leaves):
    level = list(leaves)
    assert len(level) >= 1
    while len(level) > 1:
        nxt = []
        i = 0
        n = len(level)
        while i + 1 < n:
            nxt.append(sha3_512(node_tag + level[i] + level[i + 1]))
            i += 2
        if i < n:
            nxt.append(level[i])  # odd node PROMOTED, never duplicated
        level = nxt
    return level[0]


def treasury_root(rows):
    """rows: list of (pool_id, balance), STRICTLY ascending pool_id
    (asserted here — non-ascending and duplicate ids are refused)."""
    for a, b in zip(rows, rows[1:]):
        assert a[0] < b[0], "rows must be strictly ascending by pool_id"
    if len(rows) == 0:
        return sha3_512(TAG_E_TREAS)
    return tagged_merkle(TAG_TRNODE, [treasury_leaf(p, v) for p, v in rows])


def system_root_v3(legs7):
    assert len(legs7) == 7 and all(len(x) == 64 for x in legs7)
    return sha3_512(TAG_SYS_V3 + b"".join(legs7))


def system_payload_root_v2(legs4):
    assert len(legs4) == 4 and all(len(x) == 64 for x in legs4)
    return sha3_512(TAG_SYSPAYL_V2 + b"".join(legs4))


def system_root_v4(legs7, treasury):
    """legs7 in the header's order: validator, delegation, chain_config,
    validator_set, domain_registry, manifest, attendance; treasury LAST."""
    assert len(legs7) == 7 and all(len(x) == 64 for x in legs7)
    assert len(treasury) == 64
    pre = TAG_SYS_V4 + b"".join(legs7) + treasury
    assert len(pre) == TAG_LEN + 8 * 64
    return sha3_512(pre)


def system_payload_root_v3(legs4, treasury):
    """legs4 in the header's order: validator, delegation, chain_config,
    validator_set; treasury LAST."""
    assert len(legs4) == 4 and all(len(x) == 64 for x in legs4)
    assert len(treasury) == 64
    pre = TAG_SYSPAYL_V3 + b"".join(legs4) + treasury
    assert len(pre) == TAG_LEN + 5 * 64
    return sha3_512(pre)


def dummy_leg(i: int) -> bytes:
    """Composition fixture requested by the dispatch: SHA3-512(b"leg" || i)."""
    return sha3_512(b"leg" + bytes([i]))


# The 9-pool genesis-SHAPED set: pool ids 1..9 (decision item 11 numbering),
# balances chosen DISTINCT (the real §1 amounts repeat — 100M/100M, 50M x4 —
# so they would not catch a swapped-leaf bug). Raw units, printed below.
POOLS_9 = [
    (1, 10000000000000001),
    (2, 10000000000000002),
    (3, 5000000000000003),
    (4, 5000000000000004),
    (5, 5000000000000005),
    (6, 15000000000000006),
    (7, 10000000000000007),
    (8, 3000000000000008),
    (9, 5000000000000009),
]

POOLS_3 = [
    (1, 111),
    (5, 555),
    (9, 999),
]


def refused(rows) -> bool:
    try:
        treasury_root(rows)
    except AssertionError:
        return True
    return False


def main():
    for t in (TAG_SYS_V3, TAG_SYSPAYL_V2, TAG_SYS_V4, TAG_SYSPAYL_V3,
              TAG_TRLEAF, TAG_TRNODE, TAG_E_TREAS):
        assert len(t) == TAG_LEN

    # Control legs: the LIVE vectors pinned in nodus/tests/test_roots_v2.c
    # (KAT_SYSTEM_7LEG_V3 legs fill(0x90..0x96); KAT_SYSPAYL_V2 legs
    # fill(0xA0..0xA3)). The method must reproduce them before anything
    # new is trusted.
    # Re-pinned 2026-09-30 (tag prefix rebrand "DNA" → "NDS", decision
    # 2026-09-30-tag-rebrand-nds.md): the old-prefix values 841abb1a…56fd and
    # 0bf7a1b8…dd4b were reproduced first; these are the NDS-prefix values
    # emitted by ledger_roots_v2_attendance_oracle.py.
    KAT_SYSTEM_7LEG_V3 = (
        "da7eafdcbb49176f7260cb05387e7bda1f7f2c483b18327b73f9f6f796b3a603"
        "7709d4e6e90e7d962aff0f1070e431acbb2a1009081b942afafd6b39379b1f97"
    )
    KAT_SYSPAYL_V2 = (
        "2690da56226ae1995c2128a7e651857f6c96fa5f9562edea1783a7c3e5cff5db"
        "4bd674d85cd615b4886fc37f3c9cd90b5f522c42d7a9934fadae32310a105f19"
    )
    assert system_root_v3([fill(0x90 + i) for i in range(7)]).hex() == \
        KAT_SYSTEM_7LEG_V3, "live 7-leg NDS.SYS.v3 vector not reproduced"
    assert system_payload_root_v2([fill(0xA0 + i) for i in range(4)]).hex() == \
        KAT_SYSPAYL_V2, "live 4-leg NDS.SYSPAYL.v2 vector not reproduced"
    print("[self-check] live NDS.SYS.v3 (7-leg) and NDS.SYSPAYL.v2 (4-leg) "
          "vectors reproduced")
    print()

    # Refusals — demonstrated, not just declared.
    assert refused([(2, 1), (1, 1)]), "non-ascending pool ids accepted"
    assert refused([(1, 1), (3, 1), (3, 2)]), "duplicate pool id accepted"
    print("[refuse] non-ascending pool ids [(2,1),(1,1)]      -> REFUSED")
    print("[refuse] duplicate pool id [(1,1),(3,1),(3,2)]     -> REFUSED")
    print()

    empty = treasury_root([])
    print("EMPTY_TREASURY    =", empty.hex(), "  (SHA3-512 of 'NDS.E.TREAS.v1' padded to 16 B)")

    leaf_8_0 = treasury_leaf(8, 0)
    assert treasury_root([(8, 0)]) == leaf_8_0, "n==1 root must be the leaf"
    print("KAT_TR_LEAF_8_0   =", leaf_8_0.hex(), "  (pool 8, balance 0; = root of that 1-pool set)")

    leaf_1_1 = treasury_leaf(1, 1)
    assert treasury_root([(1, 1)]) == leaf_1_1, "n==1 root must be the leaf"
    print("KAT_TR_LEAF_1_1   =", leaf_1_1.hex(), "  (pool 1, balance 1; = root of that 1-pool set)")

    # 3-pool set: node(node(l1, l5), l9) — l9 promoted at level 0.
    r3 = treasury_root(POOLS_3)
    l = [treasury_leaf(p, v) for p, v in POOLS_3]
    assert r3 == sha3_512(TAG_TRNODE + sha3_512(TAG_TRNODE + l[0] + l[1]) + l[2]), \
        "3-pool promotion shape"
    print("KAT_TR_ROOT_3     =", r3.hex(),
          "  (pools (1,111),(5,555),(9,999) — pool 9's leaf promoted)")

    # 9-pool genesis-shaped set: 9 -> 5 -> 3 -> 2 -> 1, promotion at
    # three levels.
    r9 = treasury_root(POOLS_9)
    print("KAT_TR_ROOT_9     =", r9.hex())
    print("  9-pool balances (pool_id, balance raw):")
    for p, v in POOLS_9:
        print(f"    ({p}, {v})")
    print()

    # Compositions — dummy legs SHA3-512(b"leg" || i), treasury = KAT_TR_ROOT_9.
    sys_legs = [dummy_leg(i) for i in range(7)]
    pay_legs = [dummy_leg(i) for i in range(4)]
    print("  dummy legs SHA3-512(b'leg' || i):")
    for i, x in enumerate(sys_legs):
        print(f"    leg[{i}] =", x.hex())
    sys4 = system_root_v4(sys_legs, r9)
    pay3 = system_payload_root_v3(pay_legs, r9)
    assert sys4 != system_root_v3(sys_legs), "treasury leg must change SYS"
    print("KAT_SYS_V4_8LEG   =", sys4.hex(),
          "  (NDS.SYS.v4, legs leg[0..6] = validator..attendance, treasury = KAT_TR_ROOT_9)")
    print("KAT_SYSPAYL_V3    =", pay3.hex(),
          "  (NDS.SYSPAYL.v3, legs leg[0..3] = validator..vset, treasury = KAT_TR_ROOT_9)")

    # Same compositions over test_roots_v2.c's own fill() fixture, for a
    # C test that keeps its existing leg convention.
    sys4_f = system_root_v4([fill(0x90 + i) for i in range(7)], fill(0x97))
    pay3_f = system_payload_root_v3([fill(0xA0 + i) for i in range(4)], fill(0xA4))
    print("KAT_SYS_V4_FILL   =", sys4_f.hex(),
          "  (NDS.SYS.v4, legs fill(0x90..0x96), treasury fill(0x97))")
    print("KAT_SYSPAYL_V3_FILL =", pay3_f.hex(),
          "  (NDS.SYSPAYL.v3, legs fill(0xA0..0xA3), treasury fill(0xA4))")


if __name__ == "__main__":
    main()
