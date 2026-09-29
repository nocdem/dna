#!/usr/bin/env python3
r"""
Independent oracle for the NATIVE_BUILTIN ruleset digests — the SYSTEM and
DNA_CORE `ruleset_hash` values pinned in
nodus/src/witness/nodus_witness_runtime.c (SYS_RULESET_HASH /
CORE_RULESET_HASH) and again in nodus/tests/test_domain_runtime.c
(KAT_RS_SYSTEM / KAT_RS_CORE / KAT_METPOL_SYSTEM).

INDEPENDENCE DISCIPLINE
-----------------------
Written from the WRITTEN CONTRACTS only, not from the C encoders:

  ruleset_hash  — shared/dnac/domain_wire.h, RulesetDescriptor v2
                  (dna_ruleset_desc_hash doc comment):
      SHA3-512( "DNA.RULESET.v1"(16, zero-padded)
                ‖ descriptor_version u32 BE (= 2)
                ‖ domain_id u32 BE ‖ name[32] (ASCII, zero-padded)
                ‖ runtime_abi u32 BE ‖ ruleset_version u32 BE
                ‖ rule_count u16 BE ‖ rule_ids[] u32 BE (strictly asc)
                ‖ tx_type_count u16 BE ‖ tx_types[] u8 (strictly asc)
                ‖ meter_policy_digest[64] (ALL-ZERO = none declared) )

  meter_policy_digest — shared/dnac/res_meter.h, dna_meter_policy_digest:
      SHA3-512( "DNA.METPOLID.v1"(16, zero-padded)
                ‖ policy_version u32 BE
                ‖ w_base ‖ w_callbyte ‖ w_authbyte ‖ w_effect
                ‖ w_effectbyte ‖ w_read ‖ w_write
                ‖ max_block_env_bytes          (u64 BE each)
                ‖ w_op[0..255]                 (u64 BE each)
                ‖ op_present[0..3]             (u64 BE each) )
      = 2164-byte preimage.

The descriptor CONTENTS (domain ids, names, ABI, rule/type lists, the
SYSTEM policy's weights) are the compiled data in
nodus_witness_runtime.c on main (BUILTIN[], SYS_RULES, SYS_TYPES,
CORE_RULES, CORE_TYPES, sys_policy_build) and the constants it names:
  DNA_DOMAIN_SYSTEM = 0, DNA_DOMAIN_CORE = 1      shared/dnac/ledger_ids.h:52-53
  NODUS_DOMAIN_RUNTIME_ABI_V1 = 1                 nodus_witness_runtime.h:72
  DNA_SYSRULE_* 1..6, DNA_CORERULE_* 1..7         nodus_witness_runtime.h:77-102
                                                  + runtime.c (5, 6 local)
  DNA_METER_POLICY_VERSION = 2                    shared/dnac/res_meter.h:205
  DNA_ENV_MAX_TOTAL_LEN = 1048576                 shared/dnac/env_wire.h:239

Three stages, fail-closed:

  stage 1 CONTROL — re-derive, and ASSERT byte-equal to the pins:
      * the SYSTEM meter-policy identity digest   (KAT_METPOL_SYSTEM)
      * SYSTEM ruleset_version 4 (RETIRED)        (RETIRED_RS_SYSTEM_V4)
      * SYSTEM ruleset_version 5 (RETIRED by v6)  (was KAT_RS_SYSTEM)
      * DNA_CORE ruleset_version 3 (RETIRED by v4) (was KAT_RS_CORE)
    The v4 → v5 pair is the proof that "the preimage differs ONLY in the
    ruleset_version field" is how the previous bump was pinned — the same
    shape this file then extends to v6.
  stage 2 EMIT    — SYSTEM ruleset_version 6: the v5 descriptor with ONLY
    ruleset_version changed (final-wipe package W-A, design doc §7 F3:
    "SYSTEM kural seti 5→6"). v6 is DERIVED here, not asserted: this
    file pins no C value for it (paste the C's SYS v6 pin in as a control
    once the ORCHESTRATOR has compared the two).
  stage 3 EMIT    — DNA_CORE ruleset_version 4: the v3 descriptor with
    ONLY ruleset_version changed (W-C + general multisig, ONE bump:
    docs/plans/decisions/2026-09-29-general-multisig.md "CORE 3→4 tek
    artış"; design 2026-09-29-general-multisig-design.md §7 rev 2).

  ⚠ The v6 value is right ONLY IF the SYSTEM descriptor's rule list
    {1..6}, type list {4,5,6,7,9,10} and meter policy are unchanged by the
    package. The treasury exit op is PARKED
    (docs/plans/decisions/2026-09-28-treasury-pools-and-exact-self-stake.md,
    "PARK"), so no rule id is added — but if the implementation appends a
    rule, a type or re-prices an op, this value is WRONG by construction.

  ⚠ The CORE v4 value is right ONLY IF CORE_RULES {1..7}, CORE_TYPES
    {1,2,3,11,12,13} and CORE's all-zero meter_policy_digest are unchanged.
    The CORE auth-kind allow mask ({1} → {1,3}, general multisig) is NOT a
    descriptor field: RulesetDescriptor v2 is exactly
      descriptor_version ‖ domain_id ‖ name ‖ runtime_abi ‖ ruleset_version
      ‖ rule_count ‖ rule_ids ‖ tx_type_count ‖ tx_types ‖ meter_policy_digest
    (shared/dnac/domain_wire.h:285-298 struct, :300-307 hash comment — no
    auth-kind member; the wipe-pkg copy of the header is byte-identical).
    The token-create fee becoming param 6 changes the TOKEN_CREATE rule's
    threshold source, not its rule id. If the implementation adds a rule
    id, a tx type or a CORE policy, this value is WRONG by construction.

Run:  python3 shared/dnac/tests/ruleset_desc_oracle.py

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import hashlib
import struct
import sys

# ── primitives ────────────────────────────────────────────────────────


def be16(x: int) -> bytes:
    return struct.pack(">H", x)


def be32(x: int) -> bytes:
    return struct.pack(">I", x)


def be64(x: int) -> bytes:
    return struct.pack(">Q", x)


def tag16(s: str) -> bytes:
    raw = s.encode("ascii")
    if len(raw) > 16:
        raise ValueError("tag longer than 16 bytes: %r" % s)
    return raw + b"\x00" * (16 - len(raw))


def name32(s: str) -> bytes:
    """name[32]: ASCII 0x21..0x7E, zero-padded, first byte non-zero
    (domain_wire.h:63 — the canonical-name rule)."""
    raw = s.encode("ascii")
    if not raw or len(raw) > 32 or any(b < 0x21 or b > 0x7E for b in raw):
        raise ValueError("non-canonical name: %r" % s)
    return raw + b"\x00" * (32 - len(raw))


# ── the metering-policy identity digest (res_meter.h) ─────────────────

METER_POLICY_VERSION = 2          # res_meter.h:205
ENV_MAX_TOTAL_LEN = 1048576       # env_wire.h:239


def meter_policy_identity(version, w_base, w_callbyte, w_authbyte,
                          w_effect, w_effectbyte, w_read, w_write,
                          max_block_env_bytes, w_op, present_ops) -> bytes:
    present = [0, 0, 0, 0]
    for op in present_ops:
        present[op // 64] |= 1 << (op % 64)
    pre = tag16("DNA.METPOLID.v1") + be32(version)
    for w in (w_base, w_callbyte, w_authbyte, w_effect, w_effectbyte,
              w_read, w_write, max_block_env_bytes):
        pre += be64(w)
    for w in w_op:
        pre += be64(w)
    for m in present:
        pre += be64(m)
    if len(pre) != 2164:
        raise AssertionError("policy preimage length %d != 2164" % len(pre))
    return hashlib.sha3_512(pre).digest()


def system_policy_digest() -> bytes:
    """The compiled SYSTEM policy (sys_policy_build on main): version 2,
    all seven scalar weights 1, max_block_env_bytes = 2 * 1 MiB, runtime
    ops 1..7 authoritative with weight 1."""
    w_op = [0] * 256
    for op in range(1, 8):
        w_op[op] = 1
    return meter_policy_identity(METER_POLICY_VERSION, 1, 1, 1, 1, 1, 1, 1,
                                 2 * ENV_MAX_TOTAL_LEN, w_op, range(1, 8))


# ── the ruleset descriptor digest (domain_wire.h, RulesetDescriptor v2) ─

RULESET_DESC_VERSION = 2          # domain_wire.h:283
DOMAIN_SYSTEM = 0                 # ledger_ids.h:52
DOMAIN_CORE = 1                   # ledger_ids.h:53
RUNTIME_ABI_V1 = 1                # nodus_witness_runtime.h:72


def ruleset_hash(domain_id, name, runtime_abi, ruleset_version,
                 rule_ids, tx_types, policy_digest) -> bytes:
    for i in range(1, len(rule_ids)):
        if rule_ids[i - 1] >= rule_ids[i]:
            raise ValueError("rule_ids not strictly ascending")
    for i in range(1, len(tx_types)):
        if tx_types[i - 1] >= tx_types[i]:
            raise ValueError("tx_types not strictly ascending")
    if len(policy_digest) != 64:
        raise ValueError("policy digest must be 64 bytes")
    pre = tag16("DNA.RULESET.v1")
    pre += be32(RULESET_DESC_VERSION)
    pre += be32(domain_id)
    pre += name32(name)
    pre += be32(runtime_abi)
    pre += be32(ruleset_version)
    pre += be16(len(rule_ids))
    for r in rule_ids:
        pre += be32(r)
    pre += be16(len(tx_types))
    pre += bytes(tx_types)
    pre += policy_digest
    want = (16 + 4 + 4 + 32 + 4 + 4 + 2 + 4 * len(rule_ids)
            + 2 + len(tx_types) + 64)
    if len(pre) != want:
        raise AssertionError("descriptor preimage %d != %d" % (len(pre), want))
    return hashlib.sha3_512(pre).digest()


SYS_RULES = [1, 2, 3, 4, 5, 6]            # runtime.c SYS_RULES
SYS_TYPES = [4, 5, 6, 7, 9, 10]           # runtime.c SYS_TYPES
CORE_RULES = [1, 2, 3, 4, 5, 6, 7]        # runtime.c CORE_RULES
CORE_TYPES = [1, 2, 3, 11, 12, 13]        # runtime.c CORE_TYPES


def system_hash(version: int) -> bytes:
    return ruleset_hash(DOMAIN_SYSTEM, "SYSTEM", RUNTIME_ABI_V1, version,
                        SYS_RULES, SYS_TYPES, system_policy_digest())


def core_hash(version: int) -> bytes:
    return ruleset_hash(DOMAIN_CORE, "DNA_CORE", RUNTIME_ABI_V1, version,
                        CORE_RULES, CORE_TYPES, b"\x00" * 64)


# ── stage 1: CONTROL — the pins on main ───────────────────────────────
#
# nodus/tests/test_domain_runtime.c:100-109  KAT_METPOL_SYSTEM
#   (= nodus_witness_runtime.c:96-115 SYS_METER_POLICY_DIGEST)
# nodus/tests/test_domain_runtime.c:116-125  RETIRED_RS_SYSTEM_V4
# nodus/tests/test_domain_runtime.c:57-79    KAT_RS_SYSTEM
#   (= nodus_witness_runtime.c:150-176 SYS_RULESET_HASH, version 5)
# nodus/tests/test_domain_runtime.c:80-93    KAT_RS_CORE
#   (= nodus_witness_runtime.c:177-195 CORE_RULESET_HASH, version 3)

PIN_METPOL_SYSTEM = (
    "8d038f1ec608be547bf98afe2df0532b4a94a7a042a9d9d86b7a0fb1ab51edaf"
    "bc4364dc3891c36bfbc443322f2a3b0b44c82316bd7842fd7ffbec2d19f1f5cc")
PIN_RS_SYSTEM_V4 = (
    "4fe76fed43ef372594713e97f6fff4684dba3d378ca23201fed6314b8147e1ce"
    "571a4fecd8170bfad55cb686162ebb1df462a4f244bcf9c23887eb7d147a7736")
PIN_RS_SYSTEM_V5 = (
    "0efc48bf13b8dad53f41b4e7623cabed262d94b3bdae2a1a07f7e0c9394c9f6c"
    "f4c5096f9853d9f2b7ae8d0845eaacdbf6d859df34c5b3dad1896c16b3f9f350")
PIN_RS_CORE_V3 = (
    "ed4b1bcdf0e8f78f0b64985e42d41d5181edd5d48594bceb73bf5efb6ada0838"
    "8d6fb6ba0492f8bdca212a5dda8779e74513c5210bc4baa2f70bf38cb2634437")


def control_leg() -> bool:
    print("── stage 1: CONTROL (the digests pinned on main) " + "─" * 16)
    checks = [
        ("SYSTEM meter-policy identity", system_policy_digest().hex(),
         PIN_METPOL_SYSTEM),
        ("SYSTEM ruleset v4 (retired)", system_hash(4).hex(),
         PIN_RS_SYSTEM_V4),
        ("SYSTEM ruleset v5 (retired)", system_hash(5).hex(),
         PIN_RS_SYSTEM_V5),
        ("DNA_CORE ruleset v3 (retired)", core_hash(3).hex(),
         PIN_RS_CORE_V3),
    ]
    ok = True
    for label, got, want in checks:
        good = (got == want)
        ok = ok and good
        print("  [%s] %-30s %s" % ("OK " if good else "FAIL", label, got))
        if not good:
            print("        pinned                          %s" % want)
    return ok


# ── stage 2: EMIT ─────────────────────────────────────────────────────


def print_c_bytes(name: str, digest: bytes) -> None:
    print("  static const uint8_t %s[DNA_DOM_HASH_LEN] = {" % name)
    for i in range(0, len(digest), 8):
        row = ", ".join("0x%02x" % b for b in digest[i:i + 8])
        end = "," if i + 8 < len(digest) else ""
        print("      %s%s" % (row, end))
    print("  };")


def emit() -> None:
    v6 = system_hash(6)
    print()
    print("── stage 2: SYSTEM ruleset_version 6 " + "─" * 28)
    print("  (v5 descriptor, ONLY ruleset_version 5 -> 6)")
    print("  SYSTEM v6 = %s" % v6.hex())
    print_c_bytes("SYS_RULESET_HASH_V6", v6)
    print()
    print("  sanity: v6 != v5: %s" % (v6 != system_hash(5)))
    print("  (DERIVED, not asserted — no C pin for SYSTEM v6 in this file)")

    core4 = core_hash(4)
    print()
    print("── stage 3: DNA_CORE ruleset_version 4 " + "─" * 26)
    print("  (v3 descriptor, ONLY ruleset_version 3 -> 4; the auth-kind")
    print("   mask {1,3} is not a descriptor field — domain_wire.h:285-307)")
    print("  CORE v4 = %s" % core4.hex())
    print_c_bytes("CORE_RULESET_HASH_V4", core4)
    print()
    print("  sanity: CORE v4 != CORE v3: %s" % (core4 != core_hash(3)))
    print("  sanity: CORE v4 != SYSTEM v4: %s" % (core4 != system_hash(4)))


def main() -> int:
    if not control_leg():
        print()
        print("CONTROL LEG FAILED — refusing to emit the SYSTEM v6 and "
              "CORE v4 digests.")
        return 1
    emit()
    print()
    print("control leg green — the SYSTEM v6 and CORE v4 digests above are")
    print("derived from the written layout, not from the C.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
