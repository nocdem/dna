#!/usr/bin/env python3
r"""
Independent oracle for the HF-4 (rule-set upgrade at a height + on-chain
names) pinned values: the generation-2 SYSTEM meter-policy digest, the
SYSTEM v7 and DNA_CORE v5 ruleset hashes, the param-9 vote literal D2,
and the name_root KAT vectors.

INDEPENDENCE DISCIPLINE
-----------------------
Written WITHOUT reading any HF-4 C code (none existed when this file was
written). Every value is computed here from the WRITTEN specification:

  * design   docs/plans/2026-10-02-onchain-names-design.md (rev 4,
             APPROVED): §1.1 (generation table: gen 2 = SYSTEM v7, policy
             shape v2 unchanged with op 8 weighted 1, CORE v5 rules
             {1..8}, descriptor names unchanged), §1.2 (D2 preimage,
             SWITCH_SPEC_VERSION = 1, top bit cleared), §2 "State" and
             "name_root" (leaf / node preimages, BINARY order, odd node
             promoted, empty -> NDS.E.NAMES.v1).
  * decision docs/plans/decisions/2026-10-02-onchain-names.md items 12
             (2 MiB field KEPT, policy shape v2, only op 8 added) and 18
             (tags NDS.RSGEN.v1 / NDS.NMLEAF.v1 / NDS.NMNODE.v1, 16-byte
             zero-padded ASCII).
  * decision docs/plans/decisions/2026-09-30-tag-rebrand-nds.md (NDS.
             prefix, 16-byte zero-padded tags, layouts unchanged).

The ALREADY-SHIPPED formats are reused from the existing independent
oracle shared/dnac/tests/ruleset_desc_oracle.py (imported, not modified):
  meter_policy_identity  — res_meter.h dna_meter_policy_digest comment
                           (NDS.METPOLID.v1, 2164-byte preimage)
  ruleset_hash           — domain_wire.h RulesetDescriptor v2
                           (dna_ruleset_desc_hash comment)
and the tagged-Merkle level rule of shared/dnac/ledger_roots_v2.h
("Merkle construction"): inner = SHA3-512(node_tag ‖ L ‖ R), pairs taken
left to right, an unpaired last node PROMOTED unchanged (never
duplicated), n == 1 -> the leaf itself.

Stages, fail-closed:
  CONTROL (must reproduce the shipped literals byte-exactly, else exit 1
  and emit nothing):
    C1 SYSTEM meter-policy digest (ops 1..7)  runtime.c SYS_METER_POLICY_DIGEST
    C2 SYSTEM v6 ruleset hash                 runtime.c SYS_RULESET_HASH
    C3 DNA_CORE v4 ruleset hash               runtime.c CORE_RULESET_HASH
    C4 empty name_root NDS.E.NAMES.v1         nodus/tests/test_roots_v2.c EMPTY_KAT
  EMIT (gen 2):
    G1 SYSTEM meter-policy digest, ops 1..8
    G2 SYSTEM v7 ruleset hash
    G3 DNA_CORE v5 ruleset hash (rules {1..8}, types unchanged)
    G4 D2 (param 9 RULESET_GEN2 literal)
    G5 name_root vectors

Run:  python3 shared/dnac/tests/hf4_oracle.py

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ruleset_desc_oracle import (  # noqa: E402
    CORE_RULES, CORE_TYPES, DOMAIN_CORE, DOMAIN_SYSTEM, ENV_MAX_TOTAL_LEN,
    METER_POLICY_VERSION, RUNTIME_ABI_V1, SYS_RULES, SYS_TYPES, be32, be64,
    meter_policy_identity, ruleset_hash, tag16)

# ── shipped literals (control expectations) ───────────────────────────
#
# nodus/src/witness/nodus_witness_runtime.c:96-115  SYS_METER_POLICY_DIGEST
# nodus/src/witness/nodus_witness_runtime.c:150-209 SYS_RULESET_HASH (v6)
# nodus/src/witness/nodus_witness_runtime.c:210-250 CORE_RULESET_HASH (v4)
# nodus/tests/test_roots_v2.c:81                    EMPTY_KAT NAMES
SHIPPED_METPOL_SYSTEM = (
    "8f1f9cb2a532bb287fc0d5a1d63da2cab5c4861a53e391c3f5b4b7dbdd36498b"
    "d8ca8b14501d6954fd5ac06a5e3c12bdf4af0571f331d4f5299daf2668746f32")
SHIPPED_RS_SYSTEM_V6 = (
    "ca05b4d957d90bab1b7be1f4b9ac8144c5dfa87d4c88948b46adc711d6de6c39"
    "003b3365fa01ac28ef95ce36f377e112d1bdd35b6a0be6e5720832921cdbefa3")
SHIPPED_RS_CORE_V4 = (
    "b87aabb8324dc05fd0544690180cece13b6e286078db99739caa65f006d0b1d1"
    "4154ed74eab78cf48b7fc418dedcad8684a485779aacf2a0a6ae40e00d818852")
SHIPPED_EMPTY_NAMES = (
    "f80feab8c3c32d66cf24129b45f356d55e1a324ff736ffddb26a45c24a34629b"
    "a3533cd9317dd87f526228bcb1f677e541d64c99ef995a11902c485cba2b7267")

# ── generation constants (design §1.1, §1.2) ──────────────────────────

SYS_RULESET_VERSION_GEN1 = 6
CORE_RULESET_VERSION_GEN1 = 4
SYS_RULESET_VERSION_GEN2 = 7          # design §1.1 "gen 2 = SYSTEM v7"
CORE_RULESET_VERSION_GEN2 = 5         # design §1.1 "CORE v5 with rules {1..8}"
CORE_RULES_GEN2 = CORE_RULES + [8]    # NAME_REGISTER = CORE rule 8 (§2)
CORE_TYPES_GEN2 = CORE_TYPES          # unchanged (rule 7 SYSFUND precedent)
SYS_RULES_GEN2 = SYS_RULES            # unchanged
SYS_TYPES_GEN2 = SYS_TYPES            # unchanged
GEN2 = 2
SWITCH_SPEC_VERSION = 1               # design §1.2

ROOT_LEN = 64


def sha3(b: bytes) -> bytes:
    return hashlib.sha3_512(b).digest()


# ── meter policy (shape v2, all scalars 1, 2 MiB, ops 1..last weight 1) ─


def system_policy(last_op: int) -> bytes:
    w_op = [0] * 256
    for op in range(1, last_op + 1):
        w_op[op] = 1
    return meter_policy_identity(METER_POLICY_VERSION, 1, 1, 1, 1, 1, 1, 1,
                                 2 * ENV_MAX_TOTAL_LEN, w_op,
                                 range(1, last_op + 1))


def system_rs(version: int, policy: bytes) -> bytes:
    return ruleset_hash(DOMAIN_SYSTEM, "SYSTEM", RUNTIME_ABI_V1, version,
                        SYS_RULES_GEN2, SYS_TYPES_GEN2, policy)


def core_rs(version: int, rules) -> bytes:
    return ruleset_hash(DOMAIN_CORE, "DNA_CORE", RUNTIME_ABI_V1, version,
                        rules, CORE_TYPES_GEN2, b"\x00" * 64)


# ── D2 (design §1.2) ──────────────────────────────────────────────────


def d2_preimage(sys_hash: bytes, core_hash: bytes) -> bytes:
    pre = (tag16("NDS.RSGEN.v1") + be32(GEN2) + sys_hash + core_hash
           + be32(SWITCH_SPEC_VERSION))
    if len(pre) != 16 + 4 + 64 + 64 + 4:
        raise AssertionError("D2 preimage length %d != 152" % len(pre))
    return pre


# ── name_root (design §2) ─────────────────────────────────────────────

TAG_NMLEAF = tag16("NDS.NMLEAF.v1")
TAG_NMNODE = tag16("NDS.NMNODE.v1")
TAG_E_NAMES = tag16("NDS.E.NAMES.v1")


def name_leaf_preimage(name: bytes, owner: bytes, height: int) -> bytes:
    if not (3 <= len(name) <= 36):
        raise ValueError("name length %d outside 3..36" % len(name))
    if len(owner) != 64:
        raise ValueError("owner must be 64 bytes")
    if not (1 <= height <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("registered_height must be >= 1 and fit u64")
    pre = TAG_NMLEAF + bytes([len(name)]) + name + owner + be64(height)
    if len(pre) != 16 + 1 + len(name) + 64 + 8:
        raise AssertionError("leaf preimage length")
    return pre


def name_leaf(name: bytes, owner: bytes, height: int) -> bytes:
    return sha3(name_leaf_preimage(name, owner, height))


def name_node(left: bytes, right: bytes) -> bytes:
    return sha3(TAG_NMNODE + left + right)


def tagged_merkle(level):
    """ledger_roots_v2.h Merkle rule: pairs left to right, unpaired last
    node promoted unchanged, n == 1 -> that node."""
    level = list(level)
    while len(level) > 1:
        nxt = [name_node(level[i], level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) & 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def name_root(rows):
    """rows: iterable of (name bytes, owner 64 B, registered_height), any
    order. Sorted by name in BINARY (memcmp, shorter-prefix-first) order —
    Python bytes ordering is exactly that. Duplicate names / owners
    refused (PRIMARY KEY / UNIQUE in the design §2 DDL)."""
    rows = sorted(rows, key=lambda r: r[0])
    for i in range(1, len(rows)):
        if rows[i - 1][0] >= rows[i][0]:
            raise ValueError("duplicate name")
    if len({r[1] for r in rows}) != len(rows):
        raise ValueError("duplicate owner")
    if not rows:
        return sha3(TAG_E_NAMES), rows
    return tagged_merkle(name_leaf(*r) for r in rows), rows


# ── output helpers ────────────────────────────────────────────────────


def print_c_bytes(var: str, len_macro: str, data: bytes) -> None:
    print("  static const uint8_t %s[%s] = {" % (var, len_macro))
    for i in range(0, len(data), 8):
        row = ", ".join("0x%02x" % b for b in data[i:i + 8])
        end = "," if i + 8 < len(data) else ""
        print("      %s%s" % (row, end))
    print("  };")


def owner_of(byte: int) -> bytes:
    return bytes([byte]) * 64


# ── stages ────────────────────────────────────────────────────────────


def control() -> bool:
    print("── CONTROL (shipped literals) " + "─" * 36)
    checks = [
        ("C1 SYSTEM meter policy (ops 1..7)", system_policy(7),
         SHIPPED_METPOL_SYSTEM),
        ("C2 SYSTEM ruleset v6",
         system_rs(SYS_RULESET_VERSION_GEN1, system_policy(7)),
         SHIPPED_RS_SYSTEM_V6),
        ("C3 DNA_CORE ruleset v4",
         core_rs(CORE_RULESET_VERSION_GEN1, CORE_RULES),
         SHIPPED_RS_CORE_V4),
        ("C4 empty name_root (NDS.E.NAMES.v1)", name_root([])[0],
         SHIPPED_EMPTY_NAMES),
    ]
    ok = True
    for label, got, want in checks:
        good = got.hex() == want
        ok = ok and good
        print("  [%s] %s" % ("PASS" if good else "FAIL", label))
        print("         got    %s" % got.hex())
        if not good:
            print("         pinned %s" % want)
    return ok


def emit() -> None:
    print()
    print("── G1 gen-2 SYSTEM meter-policy digest " + "─" * 27)
    print("  policy v2, scalars 1, max_block_env_bytes = %d, ops 1..8 w=1"
          % (2 * ENV_MAX_TOTAL_LEN))
    g1 = system_policy(8)
    print("  G1 = %s" % g1.hex())
    print_c_bytes("SYS_METER_POLICY_DIGEST_GEN2", "DNA_DOM_HASH_LEN", g1)

    print()
    print("── G2 SYSTEM ruleset v7 " + "─" * 42)
    print("  rules %s types %s policy G1" % (SYS_RULES_GEN2, SYS_TYPES_GEN2))
    g2 = system_rs(SYS_RULESET_VERSION_GEN2, g1)
    print("  G2 = %s" % g2.hex())
    print_c_bytes("SYS_RULESET_HASH_GEN2", "DNA_DOM_HASH_LEN", g2)

    print()
    print("── G3 DNA_CORE ruleset v5 " + "─" * 40)
    print("  rules %s types %s policy all-zero"
          % (CORE_RULES_GEN2, CORE_TYPES_GEN2))
    g3 = core_rs(CORE_RULESET_VERSION_GEN2, CORE_RULES_GEN2)
    print("  G3 = %s" % g3.hex())
    print_c_bytes("CORE_RULESET_HASH_GEN2", "DNA_DOM_HASH_LEN", g3)

    print()
    print("── G4 D2 (param 9 RULESET_GEN2) " + "─" * 34)
    pre = d2_preimage(g2, g3)
    dig = sha3(pre)
    raw = int.from_bytes(dig[:8], "big")
    d2 = raw & 0x7FFFFFFFFFFFFFFF
    print("  preimage (%d B) = %s" % (len(pre), pre.hex()))
    print("  SHA3-512        = %s" % dig.hex())
    print("  first 8 BE      = 0x%016x" % raw)
    print("  top bit was     = %s" % ("SET (cleared)" if raw >> 63 else
                                      "clear (unchanged)"))
    print("  D2              = 0x%016xULL" % d2)
    print("  D2 (decimal)    = %d" % d2)

    print()
    print("── G5 name_root vectors (design §2) " + "─" * 30)
    print("  owners: owner_X = 64 bytes of 0xXX")
    print("  empty root = C4 above")

    print()
    print("  (a) one leaf: name \"bios\", owner 0x11*64, height 1")
    lp = name_leaf_preimage(b"bios", owner_of(0x11), 1)
    la = sha3(lp)
    print("      preimage = %s" % lp.hex())
    print("      leaf     = %s" % la.hex())

    print()
    print("  (b) one node: L = leaf(\"bios\",0x11,1), "
          "R = leaf(\"punk\",0x22,2)")
    lb = name_leaf(b"punk", owner_of(0x22), 2)
    nb = name_node(la, lb)
    print("      R leaf   = %s" % lb.hex())
    print("      node     = %s" % nb.hex())
    print("      (equals the 2-row root of (c))")

    rows3 = [(b"bios", owner_of(0x11), 1),
             (b"punk", owner_of(0x22), 2),
             (b"nodus", owner_of(0x33), 3)]
    print()
    print("  (c) roots; rows (name, owner, height):")
    for n in (1, 2, 3):
        r, s = name_root(rows3[:n])
        print("      n=%d rows %s" % (n, [(x[0].decode(), "0x%02x" % x[1][0],
                                          x[2]) for x in rows3[:n]]))
        print("          sorted %s" % [x[0].decode() for x in s])
        print("          root = %s" % r.hex())
    r1, _ = name_root(rows3[:1])
    r2, _ = name_root(rows3[:2])
    r3, s3 = name_root(rows3)
    assert r1 == la, "n=1 root must equal the leaf"
    assert r2 == nb, "n=2 root must equal node (b)"
    # n=3 sorted: bios < nodus < punk; shape H(N ‖ H(N ‖ L0 ‖ L1) ‖ L2)
    l0, l1, l2 = (name_leaf(*x) for x in s3)
    assert r3 == name_node(name_node(l0, l1), l2)
    print("      n=3 shape: root = NODE(NODE(leaf_bios, leaf_nodus), "
          "leaf_punk)  [punk promoted]")
    print("      leaf_nodus = %s" % name_leaf(b"nodus", owner_of(0x33),
                                               3).hex())

    print()
    print("  (d) order vector, inserted as abd, abc, abcd")
    rows_d = [(b"abd", owner_of(0x33), 30),
              (b"abc", owner_of(0x11), 10),
              (b"abcd", owner_of(0x22), 20)]
    rd, sd = name_root(rows_d)
    rd_sorted, _ = name_root(sorted(rows_d, key=lambda r: r[0]))
    assert rd == rd_sorted
    assert [x[0] for x in sd] == [b"abc", b"abcd", b"abd"]
    print("      rows: abc/0x11/10, abcd/0x22/20, abd/0x33/30")
    print("      sorted %s" % [x[0].decode() for x in sd])
    for x in sd:
        print("      leaf %-5s = %s" % (x[0].decode(), name_leaf(*x).hex()))
    print("      root = %s" % rd.hex())
    print("      shape: NODE(NODE(leaf_abc, leaf_abcd), leaf_abd)")

    print()
    h = (1 << 32) + 5
    print("  (e) one row, height 2^32+5 = %d: name \"chip\", owner 0x44*64"
          % h)
    lp = name_leaf_preimage(b"chip", owner_of(0x44), h)
    le = sha3(lp)
    print("      preimage = %s" % lp.hex())
    print("      leaf = root = %s" % le.hex())
    assert name_root([(b"chip", owner_of(0x44), h)])[0] == le


def main() -> int:
    if not control():
        print()
        print("CONTROL FAILED — refusing to emit gen-2 values.")
        return 1
    emit()
    print()
    print("control green — gen-2 values above derived from the written "
          "spec, not from C.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
