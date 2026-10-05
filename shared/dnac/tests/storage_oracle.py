#!/usr/bin/env python3
r"""
Independent oracle for the storage reward v1 rule-set generation
(GEN_STORAGE) pinned values: the SYSTEM meter-policy digest with ops
1..9, the SYSTEM v8 and DNA_CORE v6 ruleset hashes, and the param-14
RULESET_GEN_STORAGE vote literal.

INDEPENDENCE DISCIPLINE (honest label)
--------------------------------------
Every value is computed HERE, by Python's hashlib, from the written
layouts — never by calling or porting this tree's C encoders
(res_meter.c, domain_wire.c). The formats themselves are reused from the
two existing independent oracles, imported and NOT modified:

  ruleset_desc_oracle.py  meter_policy_identity ("NDS.METPOLID.v1",
                          2164-byte preimage) and ruleset_hash
                          (RulesetDescriptor v2, "NDS.RULESET.v1")
  hf4_oracle.py           the generation-1 shipped literals and the D2
                          construction (design 2026-10-02-onchain-names
                          rev 4 §1.2: TAG16("NDS.RSGEN.v1") ‖ u32 BE gen
                          ‖ SYSTEM hash ‖ CORE hash ‖ u32 BE
                          SWITCH_SPEC_VERSION, first 8 bytes BE, top bit
                          cleared)

The DESCRIPTOR CONTENTS of the storage generation were taken from the
preimage list the package-B1 builder wrote at nodus_witness_runtime.c
(comment above SYS_RULESET_HASH_G3) and then CHECKED against the design
records, not trusted (the author of this file read that comment, so it is
not "written without reading the C"):

  * docs/plans/2026-10-04-storage-reward-v1-design.md rev 2.2 §1 (three
    new SYSTEM ops STORAGE_REGISTER / STORAGE_EXIT / STORAGE_REPORT §4;
    CORE: "rtn_sysfund_shape and the CORE decode/flow tables are extended
    to pair with the new op ids" — no new CORE op) and §6 ("SYSTEM ops
    … CORE funding pairing; meter-policy rows for each", "voted like
    RULESET_GEN2 (param 9 mechanism)").
  * docs/plans/2026-10-05-archive-reward-design.md rev 4 §6: activation
    = rev 2.2 §6 unchanged; rev 4 adds NO op (report = rev 2.2 §4).
  * docs/plans/decisions/2026-10-02-onchain-names.md item 12 (policy
    shape v2 kept, 2 MiB field kept) — the gen-2 policy shape this file
    extends by one op row.

PROVISIONAL (decision 2026-10-04-storage-reward-approved.md: "Generation
number, op ids, param ids and tag versions … are assigned in main merge
order (no pin before merge)"; design rev 2.2 §6 ⚠): the generation number
3, the SYSTEM op ids 7/8/9, SYSTEM ruleset_version 8 and CORE
ruleset_version 6 are the values of THIS branch's merge position. If
HF-5 or QEVM merges first, every value below is recomputed.

NOT GROUNDED IN A RECORD (stated, not hidden):
  * CORE ruleset_version 6 — no record names a CORE bump; it is the B1
    builder's argument from the W-C / general-multisig precedent (a
    hook-side semantics change — SYSFUND now pairs with the storage
    ops — advances the version).
  * SYSTEM tx_types unchanged {4,5,6,7,9,10} — inferred: no record
    assigns the storage ops a legacy tx type.
  * weight 1 for ops 7..9 — the placeholder-economics class of every
    other weight; no record states a value.
  * w_op is keyed by runtime_op (= rule id) across domains
    (shared/dnac/res_meter.h:67, :311), so the policy's op set is the
    UNION of SYSTEM {1..9} and CORE {1..8} = 1..9. The package-B2a
    "adapter ops" 10-12 (RTN_SYS_OP_STSET / SNAPSEAT / STREP,
    nodus_witness_rt_native.c:3589-3595, table RTN_SYS_OPS) are
    nodus_adapter_op_t effect ids — a separate namespace — not rule ids
    and not meter rows.

Stages, fail-closed:
  CONTROL (must reproduce the shipped literals byte-exactly, else exit 1
  and emit nothing):
    C1 gen-1 SYSTEM meter policy (ops 1..7)   runtime.c SYS_METER_POLICY_DIGEST
    C2 gen-1 SYSTEM v6 ruleset hash           runtime.c SYS_RULESET_HASH
    C3 gen-1 DNA_CORE v4 ruleset hash         runtime.c CORE_RULESET_HASH
    C4 gen-2 SYSTEM meter policy (ops 1..8)   runtime.c SYS_METER_POLICY_DIGEST_G2
    C5 gen-2 SYSTEM v7 ruleset hash           runtime.c SYS_RULESET_HASH_G2
    C6 gen-2 DNA_CORE v5 ruleset hash         runtime.c CORE_RULESET_HASH_G2
    C7 gen-2 vote literal D2 (gen_digest with gen = 2 — the control that
       grounds this file's generalised gen_digest)   dnac.h DNAC_CFG_RULESET_GEN2_D2
  EMIT (GEN_STORAGE):
    S1 SYSTEM meter-policy digest, ops 1..9
    S2 SYSTEM v8 ruleset hash (rules {1..9}, types {4,5,6,7,9,10}, policy S1)
    S3 DNA_CORE v6 ruleset hash (rules {1..8}, types {1,2,3,11,12,13}, zero)
    S4 vote literal = gen_digest(3, S2, S3), switch spec version 1

Run:  python3 shared/dnac/tests/storage_oracle.py

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ruleset_desc_oracle import (  # noqa: E402
    CORE_RULES, CORE_TYPES, DOMAIN_CORE, DOMAIN_SYSTEM, ENV_MAX_TOTAL_LEN,
    RUNTIME_ABI_V1, SYS_RULES, SYS_TYPES, be32, ruleset_hash, tag16)
from hf4_oracle import (  # noqa: E402
    CORE_RULES_GEN2, CORE_RULESET_VERSION_GEN1, CORE_RULESET_VERSION_GEN2,
    SHIPPED_METPOL_SYSTEM, SHIPPED_RS_CORE_V4, SHIPPED_RS_SYSTEM_V6,
    SWITCH_SPEC_VERSION, SYS_RULESET_VERSION_GEN1, SYS_RULESET_VERSION_GEN2,
    core_rs, print_c_bytes, system_policy, system_rs)

# ── shipped generation-2 literals (control expectations) ──────────────
#
# nodus/src/witness/nodus_witness_runtime.c:189-196  SYS_METER_POLICY_DIGEST_G2
# nodus/src/witness/nodus_witness_runtime.c:397-404  SYS_RULESET_HASH_G2 (v7)
# nodus/src/witness/nodus_witness_runtime.c:408-415  CORE_RULESET_HASH_G2 (v5)
# dnac/include/dnac/dnac.h:926                       DNAC_CFG_RULESET_GEN2_D2
# (line numbers at base commit 00698960; the values are hf4_oracle.py's
#  own G1-G4 outputs, filled in 89f9da09)
SHIPPED_METPOL_SYSTEM_G2 = (
    "0c251ca2920d77882bcab294311052a0681362c55b06f417f6aada46feb755b3"
    "ab304776ed33537ae07e73f79a10da3d3f4b788bd56e4c06a7172a6f19ceec87")
SHIPPED_RS_SYSTEM_V7 = (
    "8780a3a9129041e16db275fca2e2bfb8d21aae33371c0b4cafdbcb623159eacb"
    "74854107fad3503ee2e018ec2578377a63001e5156a07d386a7c7b55311d14b4")
SHIPPED_RS_CORE_V5 = (
    "20c7235b13db0f029a8c3be096e24403fd3a3e393e9ff723e0672a6027601a35"
    "0586db18985e7a6ac73365be6cfe65f0fb9ad53357db2d539a1c69d93d81cae5")
SHIPPED_D2 = 0x44dfbe7ad3c75adf

# ── storage generation constants (PROVISIONAL — main merge order) ─────

GEN2 = 2
GEN_STORAGE = 3                        # next free generation (design §6)
SYS_RULESET_VERSION_STORAGE = 8        # SYSTEM v7 -> v8 (rule list grew)
CORE_RULESET_VERSION_STORAGE = 6       # CORE v5 -> v6 (SYSFUND pairing;
                                       # B1 precedent argument, no record)
# design rev 2.2 §1/§4: STORAGE_REGISTER, STORAGE_EXIT, STORAGE_REPORT,
# appended after SYSTEM's six ops (ids provisional)
SYS_RULES_STORAGE = SYS_RULES + [7, 8, 9]
SYS_TYPES_STORAGE = SYS_TYPES          # no legacy tx type for storage ops
CORE_RULES_STORAGE = CORE_RULES_GEN2   # {1..8}: no new CORE op (§1)
CORE_TYPES_STORAGE = CORE_TYPES
# policy op set = union of the generation's rule ids = 1..9
POLICY_MAX_OP_STORAGE = max(SYS_RULES_STORAGE + CORE_RULES_STORAGE)


def sha3(b: bytes) -> bytes:
    return hashlib.sha3_512(b).digest()


def system_rs_rules(version: int, rules, policy: bytes) -> bytes:
    """hf4_oracle.system_rs() is hard-wired to rules {1..6}; the storage
    SYSTEM descriptor owns {1..9}, so the descriptor is hashed directly."""
    return ruleset_hash(DOMAIN_SYSTEM, "SYSTEM", RUNTIME_ABI_V1, version,
                        rules, SYS_TYPES_STORAGE, policy)


def gen_preimage(gen: int, sys_hash: bytes, core_hash: bytes) -> bytes:
    """hf4_oracle.d2_preimage() with the generation number a parameter
    (that function is hard-wired to gen 2). Control C7 proves the two
    agree at gen 2."""
    pre = (tag16("NDS.RSGEN.v1") + be32(gen) + sys_hash + core_hash
           + be32(SWITCH_SPEC_VERSION))
    if len(pre) != 16 + 4 + 64 + 64 + 4:
        raise AssertionError("gen preimage length %d != 152" % len(pre))
    return pre


def gen_digest(gen: int, sys_hash: bytes, core_hash: bytes):
    pre = gen_preimage(gen, sys_hash, core_hash)
    dig = sha3(pre)
    raw = int.from_bytes(dig[:8], "big")
    return raw & 0x7FFFFFFFFFFFFFFF, raw, dig, pre


# ── stages ────────────────────────────────────────────────────────────


def control() -> bool:
    print("── CONTROL (shipped gen-1 and gen-2 literals) " + "─" * 20)
    g1_pol = system_policy(7)
    g2_pol = system_policy(8)
    g2_sys = system_rs(SYS_RULESET_VERSION_GEN2, g2_pol)
    g2_core = core_rs(CORE_RULESET_VERSION_GEN2, CORE_RULES_GEN2)
    d2, _, _, _ = gen_digest(GEN2, g2_sys, g2_core)
    checks = [
        ("C1 gen-1 SYSTEM meter policy (ops 1..7)", g1_pol.hex(),
         SHIPPED_METPOL_SYSTEM),
        ("C2 gen-1 SYSTEM ruleset v6",
         system_rs(SYS_RULESET_VERSION_GEN1, g1_pol).hex(),
         SHIPPED_RS_SYSTEM_V6),
        ("C3 gen-1 DNA_CORE ruleset v4",
         core_rs(CORE_RULESET_VERSION_GEN1, CORE_RULES).hex(),
         SHIPPED_RS_CORE_V4),
        ("C4 gen-2 SYSTEM meter policy (ops 1..8)", g2_pol.hex(),
         SHIPPED_METPOL_SYSTEM_G2),
        ("C5 gen-2 SYSTEM ruleset v7", g2_sys.hex(), SHIPPED_RS_SYSTEM_V7),
        ("C6 gen-2 DNA_CORE ruleset v5", g2_core.hex(), SHIPPED_RS_CORE_V5),
        ("C7 gen-2 vote literal D2", "0x%016x" % d2, "0x%016x" % SHIPPED_D2),
    ]
    ok = True
    for label, got, want in checks:
        good = got == want
        ok = ok and good
        print("  [%s] %s" % ("PASS" if good else "FAIL", label))
        print("         got    %s" % got)
        if not good:
            print("         pinned %s" % want)
    # the generalised builders agree with hf4_oracle's gen-2 ones
    if system_rs_rules(SYS_RULESET_VERSION_GEN2, SYS_RULES, g2_pol) != g2_sys:
        print("  [FAIL] system_rs_rules != hf4_oracle.system_rs at gen 2")
        ok = False
    return ok


def emit() -> None:
    print()
    print("── S1 GEN_STORAGE SYSTEM meter-policy digest " + "─" * 21)
    print("  policy v2, scalars 1, max_block_env_bytes = %d, ops 1..%d w=1"
          % (2 * ENV_MAX_TOTAL_LEN, POLICY_MAX_OP_STORAGE))
    s1 = system_policy(POLICY_MAX_OP_STORAGE)
    print("  S1 = %s" % s1.hex())
    print_c_bytes("SYS_METER_POLICY_DIGEST_G3", "DNA_DOM_HASH_LEN", s1)

    print()
    print("── S2 SYSTEM ruleset v%d " % SYS_RULESET_VERSION_STORAGE
          + "─" * 42)
    print("  domain %d \"SYSTEM\" abi %d rules %s types %s policy S1"
          % (DOMAIN_SYSTEM, RUNTIME_ABI_V1, SYS_RULES_STORAGE,
             SYS_TYPES_STORAGE))
    s2 = system_rs_rules(SYS_RULESET_VERSION_STORAGE, SYS_RULES_STORAGE, s1)
    print("  S2 = %s" % s2.hex())
    print_c_bytes("SYS_RULESET_HASH_G3", "DNA_DOM_HASH_LEN", s2)

    print()
    print("── S3 DNA_CORE ruleset v%d " % CORE_RULESET_VERSION_STORAGE
          + "─" * 40)
    print("  domain %d \"DNA_CORE\" abi %d rules %s types %s policy all-zero"
          % (DOMAIN_CORE, RUNTIME_ABI_V1, CORE_RULES_STORAGE,
             CORE_TYPES_STORAGE))
    s3 = ruleset_hash(DOMAIN_CORE, "DNA_CORE", RUNTIME_ABI_V1,
                      CORE_RULESET_VERSION_STORAGE, CORE_RULES_STORAGE,
                      CORE_TYPES_STORAGE, b"\x00" * 64)
    print("  S3 = %s" % s3.hex())
    print_c_bytes("CORE_RULESET_HASH_G3", "DNA_DOM_HASH_LEN", s3)

    print()
    print("── S4 param-14 RULESET_GEN_STORAGE vote literal " + "─" * 18)
    lit, raw, dig, pre = gen_digest(GEN_STORAGE, s2, s3)
    print("  generation      = %d, switch spec version = %d"
          % (GEN_STORAGE, SWITCH_SPEC_VERSION))
    print("  preimage (%d B) = %s" % (len(pre), pre.hex()))
    print("  SHA3-512        = %s" % dig.hex())
    print("  first 8 BE      = 0x%016x" % raw)
    print("  top bit was     = %s" % ("SET (cleared)" if raw >> 63 else
                                      "clear (unchanged)"))
    print("  S4              = 0x%016xULL" % lit)
    print("  S4 (decimal)    = %d" % lit)

    print()
    print("  sanity: S1 != gen-2 policy: %s"
          % (s1 != system_policy(8)))
    print("  sanity: S3 != CORE v5 (version field only): %s"
          % (s3.hex() != SHIPPED_RS_CORE_V5))
    print("  sanity: S4 != D2: %s" % (lit != SHIPPED_D2))
    assert s1 != system_policy(8)
    assert s3.hex() != SHIPPED_RS_CORE_V5
    assert lit != SHIPPED_D2


def main() -> int:
    if not control():
        print()
        print("CONTROL FAILED — refusing to emit GEN_STORAGE values.")
        return 1
    emit()
    print()
    print("control green — GEN_STORAGE values above derived from the written "
          "layouts by hashlib, not by the C encoders (descriptor contents: "
          "B1's stated preimages, checked against the design records; "
          "generation / op ids / versions PROVISIONAL, main merge order).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
