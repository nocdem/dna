#!/usr/bin/env python3
r"""
Independent oracle for the storage reward v1 rule-set generation
(GEN_STORAGE = generation 4, built on the EVM generation 3) pinned values:
the GEN_STORAGE SYSTEM meter-policy digest, the SYSTEM v9 and DNA_CORE v7
ruleset hashes, and the param-16 RULESET_GEN_STORAGE vote literal.

This file REPLACES the generation-3 / param-14 version (written before
Nodus EVM merged first and took generation 3 and params 14-15). Its old
outputs (S4 0x14bb86ad…) are dead.

INDEPENDENCE DISCIPLINE (honest label)
--------------------------------------
Every value is computed HERE, by Python's hashlib, from the written
layouts — never by calling or porting this tree's C encoders
(res_meter.c, domain_wire.c). The formats themselves are reused from the
two existing INDEPENDENT oracles, imported and NOT modified:

  ruleset_desc_oracle.py  meter_policy_identity ("NDS.METPOLID.v1",
                          2164-byte preimage) and ruleset_hash
                          (RulesetDescriptor v2, "NDS.RULESET.v1")
  hf4_oracle.py           the generation-1 shipped literals, the policy
                          builder system_policy(last_op) and the D2
                          construction (design 2026-10-02-onchain-names
                          rev 4 §1.2: TAG16("NDS.RSGEN.v1") ‖ u32 BE gen
                          ‖ SYSTEM hash ‖ CORE hash ‖ u32 BE
                          SWITCH_SPEC_VERSION, first 8 bytes BE, top bit
                          cleared)

NOT imported: shared/dnac/tests/nodus_evm_activation_oracle.py. It is
SELF-DERIVED (written by the agent that wrote the EVM C — its own header
says so). The EVM-generation controls below therefore re-implement the
EVM activation digest, the DomainManifest hash and the empty EVM root here
from the written contracts:

  * shared/dnac/domain_wire.h, "DomainManifest v1 canonical layout"
    comment (manifest_hash = SHA3-512("NDS.DOMMAN.v1" ‖ canonical bytes))
    and the dna_evm_activation_digest comment ("NDS.EVMACT.v1" ‖ gen ‖
    base ‖ SYSTEM ‖ CORE ‖ EVM ‖ manifest ‖ spec ‖ n ‖ n × u64 BE, first 8
    bytes BE, top bit cleared);
  * design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md
    rev 3 §6 (empty trie root = SHA3-512(RLP(b"")) = SHA3-512(0x80);
    META = wei_live ‖ wei_tickets ‖ wei_lost, 32 B BE each, digest under
    "NDS.EVMMETA.v1"; EVM root = SHA3-512("NDS.EVMROOT.v1" ‖ account
    trie root ‖ tickets root ‖ meta_digest)), §3 (EVM runtime_abi = 2),
    §9 (6c starts the domain with META zero, empty trie).
The author of this file HAS read the self-derived oracle and the EVM C
(nodus_witness_runtime.c, nodus_witness_rt_evm.c) — so the EVM-generation
legs are "re-derived from the written layout with C-only inputs read from
C", NOT "written without reading the C". Their job is CONTROL only: they
must reproduce the shipped EVM pins before generation 4 is emitted.

INPUTS THAT EXIST ONLY IN C (readings, stated — no written record names
them):
  * EVM generation descriptor contents: SYSTEM v8 rules {1..6} types
    {4,5,6,7,9,10}; CORE v6 rules {1..9} types {1,2,3,11,12,13}; EVM v2 =
    domain 2, "EVM", abi 2, rules {1..5}, no types, no policy
    (NODUS_RT_EVM_RULESET_VERSION_GEVM 2u, nodus_witness_runtime.h; v1 was
    never voted). The activation constants end with
    NODUS_RT_EVM_ADDR_BYTES (nodus_witness_rt_evm.h, 32u).
    Read at nodus_witness_runtime.c (comment above SYS_RULESET_HASH_GEVM,
    table entries) and nodus_witness_rt_evm.c NODUS_RT_EVM_RULES /
    nodus_rt_evm_runtime_build. Design §9 grounds "SYSTEM new version,
    CORE new version (op 9), EVM v1" qualitatively, without numbers.
  * the EVM activation constants and their order (EVM_ACT_CONSTS in
    nodus_witness_runtime.c and the #defines it names in
    nodus_witness_rt_evm.h, nodus_witness_runtime.h, shared/dnac/
    res_meter.h, dnac/include/dnac/dnac.h);
  * the EVM manifest's quota_tx_per_block 0, quota_verify_cost 0,
    activation_epoch 0, fee_policy 1, upgrade_authority 1,
    readiness_policy 1 (nodus_runtime_manifest_init);
  * NODUS_RT_GEN_EVM = 3, NODUS_RT_GEN_EVM_BASE = 2,
    DNAC_EVM_ACTIVATION_SPEC_VERSION = 1.

GENERATION 4 INPUTS (decision docs/plans/decisions/2026-10-05-storage-
reward-is-for-archive.md item K10, operator 2026-10-06 "ok"):
  "storage = rule-set generation 4 built on GEN_EVM (3); param
   DNAC_CFG_RULESET_GEN_STORAGE = 16; SYSTEM rules 7/8/9, SYSTEM
   ruleset_version 9, CORE ruleset_version 7 (EVM's rules {1..9} + SYSFUND
   widened to the storage ops), EVM v1 unchanged; meter policy = the EVM
   policy (ops 1..9 weight 1)."
  Switch procedure = the HF-4 one; spec version 1 (dnac.h comment above
  DNAC_CFG_RULESET_GEN_STORAGE_D; DNAC_RULESET_SWITCH_SPEC_VERSION).

NOT GROUNDED IN A RECORD (stated, not hidden):
  * SYSTEM tx_types unchanged {4,5,6,7,9,10} and CORE tx_types unchanged
    {1,2,3,11,12,13} for generation 4 — inferred: no record assigns the
    storage ops a legacy tx type, and K10 names only rule lists and
    versions.
  * the policy's scalar fields (version 2, seven scalars 1, 2 MiB) — K10
    says "the EVM policy"; their values are the gen-2 shape (decision
    2026-10-02-onchain-names.md item 12) carried through generation 3,
    whose own record is C-only (above).

Stages, fail-closed:
  CONTROL (must reproduce the shipped literals byte-exactly, else exit 1
  and emit nothing):
    C1  gen-1 SYSTEM meter policy (ops 1..7)  runtime.c SYS_METER_POLICY_DIGEST
    C2  gen-1 SYSTEM v6 ruleset hash          runtime.c SYS_RULESET_HASH
    C3  gen-1 DNA_CORE v4 ruleset hash        runtime.c CORE_RULESET_HASH
    C4  gen-2 SYSTEM meter policy (ops 1..8)  runtime.c SYS_METER_POLICY_DIGEST_G2
    C5  gen-2 SYSTEM v7 ruleset hash          runtime.c SYS_RULESET_HASH_G2
    C6  gen-2 DNA_CORE v5 ruleset hash        runtime.c CORE_RULESET_HASH_G2
    C7  gen-2 vote literal D2 (generalised gen_digest at gen 2)
                                              dnac.h DNAC_CFG_RULESET_GEN2_D2
    C8  gen-3 (EVM) SYSTEM meter policy (ops 1..9)
                                              runtime.c SYS_METER_POLICY_DIGEST_GEVM
    C9  gen-3 SYSTEM v8 ruleset hash          runtime.c SYS_RULESET_HASH_GEVM
    C10 gen-3 DNA_CORE v6 ruleset hash        runtime.c CORE_RULESET_HASH_GEVM
    C11 gen-3 EVM v2 ruleset hash             runtime.h NODUS_RT_EVM_RULESET_HASH_GEVM_INIT
    C12 gen-3 param-14 EVM_ACTIVE literal D (through the empty EVM root
        and the EVM manifest hash, computed here)
                                              dnac.h DNAC_CFG_EVM_ACTIVE_D
  EMIT (GEN_STORAGE, generation 4):
    S1 SYSTEM meter-policy digest, ops 1..9 (then compared with C8)
    S2 SYSTEM v9 ruleset hash (rules {1..9}, types {4,5,6,7,9,10}, policy S1)
    S3 DNA_CORE v7 ruleset hash (rules {1..9}, types {1,2,3,11,12,13}, zero)
    S4 param-16 vote literal = gen_digest(4, S2, S3), switch spec 1

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
    RUNTIME_ABI_V1, SYS_RULES, SYS_TYPES, be16, be32, be64, name32,
    ruleset_hash, tag16)
from hf4_oracle import (  # noqa: E402
    CORE_RULES_GEN2, CORE_RULESET_VERSION_GEN1, CORE_RULESET_VERSION_GEN2,
    SHIPPED_METPOL_SYSTEM, SHIPPED_RS_CORE_V4, SHIPPED_RS_SYSTEM_V6,
    SWITCH_SPEC_VERSION, SYS_RULESET_VERSION_GEN1, SYS_RULESET_VERSION_GEN2,
    core_rs, print_c_bytes, system_policy, system_rs)

# ── shipped generation-2 literals (control expectations) ──────────────
#
# nodus/src/witness/nodus_witness_runtime.c SYS_METER_POLICY_DIGEST_G2,
# SYS_RULESET_HASH_G2 (v7), CORE_RULESET_HASH_G2 (v5);
# dnac/include/dnac/dnac.h DNAC_CFG_RULESET_GEN2_D2 — hf4_oracle.py's own
# G1-G4 outputs, filled in 89f9da09.
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

# ── shipped generation-3 (EVM) literals on main (control expectations) ─
#
# nodus/src/witness/nodus_witness_runtime.c SYS_METER_POLICY_DIGEST_GEVM,
# SYS_RULESET_HASH_GEVM (v8), CORE_RULESET_HASH_GEVM (v6);
# nodus/src/witness/nodus_witness_runtime.h NODUS_RT_EVM_RULESET_HASH_GEVM_INIT;
# dnac/include/dnac/dnac.h DNAC_CFG_EVM_ACTIVE_D (param 14) — all
# SELF-DERIVED on main (nodus_evm_activation_oracle.py E1-E4, E7).
SHIPPED_METPOL_GEVM = (
    "0aa4c690a05af8827a322912a402d87b2642c99edc1db83f2871af64da18c3f8"
    "b74a6e5c870edc3450ae0474a3c8d7279efb884df8b285c8848beffb25922766")
SHIPPED_RS_SYSTEM_V8 = (
    "fe4ac585fba570280b87ec10cea8195acafbe1624c38e1efe476afc97c886457"
    "45567d291796cbdb12a805ede476efc3378d3c22d1c7334b1823200ac740516b")
SHIPPED_RS_CORE_V6 = (
    "ddde5acbd811aad624cddbf6d6d0d3d4c1452e02ce83507b5edce94e6a43f9ef"
    "e6d79b7b35c00a34f5889160b5a0992af67c699cd609bbe21864476ccf6d1fc8")
# EVM ruleset v2 (main f7aa7984: the bridge refuses a sender with code; the
# address width is the last EVM activation constant). v1 was
# 415e6f97…f11ae / D 0x5a10af78d85302e6, never voted.
SHIPPED_RS_EVM_V2 = (
    "6af8346d10c9ce5ced25b68e1ddd201be205e0d7d465e90412f78962206e775b"
    "f85f6c1d71d4cf3833148893977dc8126dfa01fcae2c83ca6a06d74c1bf4465f")
SHIPPED_EVM_ACTIVE_D = 0x029f47596864d407

# ── the EVM generation (C-only readings — see the docstring) ──────────

GEN2 = 2
GEN_EVM = 3                            # NODUS_RT_GEN_EVM
GEN_EVM_BASE = 2                       # NODUS_RT_GEN_EVM_BASE
SYS_RULESET_VERSION_GEVM = 8
CORE_RULESET_VERSION_GEVM = 6
CORE_RULES_GEVM = CORE_RULES_GEN2 + [9]   # + DNA_CORERULE_EVMFUND
POLICY_MAX_OP_GEVM = 9
DOMAIN_EVM = 2                         # shared/dnac/ledger_ids.h DNA_DOMAIN_EVM
RUNTIME_ABI_V2 = 2                     # design §3
EVM_RULESET_VERSION = 2                # NODUS_RT_EVM_RULESET_VERSION_GEVM
EVM_RULES = [1, 2, 3, 4, 5]            # CALL CREATE DEPOSIT WITHDRAW REDEEM
EVM_TYPES = []
EVM_ACTIVATION_SPEC_VERSION = 1        # dnac.h DNAC_EVM_ACTIVATION_SPEC_VERSION

# nodus_witness_runtime.c EVM_ACT_CONSTS, in that order; the values are the
# #defines it names (read from the headers, evaluated here by hand).
EVM_TX_GAS_CAP = 30000000
EVM_ACT_CONSTS = [
    10000000000,                       # NODUS_RT_EVM_Q
    25000,                             # NODUS_RT_EVM_TICKET_GAS
    EVM_TX_GAS_CAP,                    # NODUS_RT_EVM_TX_GAS_CAP
    (EVM_TX_GAS_CAP + 2099) // 2100 + 2048,   # NODUS_RT_EVM_READS_BASE
    32 * 1024 * 1024,                  # NODUS_RT_EVM_MAX_READ_BYTES
    1,                                 # DNA_METER_EVM_W_GAS
    4096,                              # DNA_METER_EVM_FAIL_RESERVE
    1,                                 # DNA_METER_EVM_FAIL_EFFECTS
    287,                               # DNA_METER_EVM_FAIL_BYTES
    16384,                             # DNA_METER_STREAM_MAX_EFFECTS
    4 * 1024 * 1024,                   # DNA_METER_STREAM_MAX_EFFECT_BYTES
    21000,                             # NODUS_RT_EVM_BRIDGE_GAS
    30000000,                          # DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT
    1000000,                           # DNAC_CFG_MIN_EVM_BLOCK_GAS
    1000000000,                        # DNAC_CFG_MAX_EVM_BLOCK_GAS
    32,                                # NODUS_RT_EVM_ADDR_BYTES (EVM v2)
]

# DomainManifest v1 field values (domain_wire.h layout comment: the only
# legal value of each enum; quotas / activation_epoch from
# nodus_runtime_manifest_init)
DOMMAN_VERSION = 1
RUNTIME_KIND_NATIVE_BUILTIN = 1
FEE_POLICY_GLOBAL_BURN = 1
QUOTA_TX_PER_BLOCK = 0
QUOTA_VERIFY_COST = 0
UPGRADE_AUTHORITY_CHAIN_CONFIG = 1
ACTIVATION_EPOCH = 0
READINESS_POLICY_STAGED_V1 = 1

# ── the storage generation (decision K10) ─────────────────────────────

GEN_STORAGE = 4                        # K10: "generation 4"
GEN_STORAGE_BASE = GEN_EVM             # K10: "built on GEN_EVM (3)"
SYS_RULESET_VERSION_STORAGE = 9        # K10: "SYSTEM ruleset_version 9"
CORE_RULESET_VERSION_STORAGE = 7       # K10: "CORE ruleset_version 7"
SYS_RULES_STORAGE = SYS_RULES + [7, 8, 9]   # K10: "SYSTEM rules 7/8/9"
SYS_TYPES_STORAGE = SYS_TYPES          # unchanged (no record — see above)
CORE_RULES_STORAGE = CORE_RULES_GEVM   # K10: "EVM's rules {1..9}"
CORE_TYPES_STORAGE = CORE_TYPES        # unchanged (no record — see above)
POLICY_MAX_OP_STORAGE = 9              # K10: "ops 1..9 weight 1"


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


# ── EVM generation helpers (design §6 / domain_wire.h layouts) ────────


def evm_empty_root() -> bytes:
    """design §6: both tries empty -> SHA3-512(RLP(b"")) = SHA3-512(0x80);
    META = three zero 32-byte BE words (§9: 6c starts META at zero)."""
    empty_trie = sha3(b"\x80")
    meta = b"\x00" * 32 * 3
    meta_digest = sha3(tag16("NDS.EVMMETA.v1") + meta)
    return sha3(tag16("NDS.EVMROOT.v1") + empty_trie + empty_trie
                + meta_digest)


def domain_manifest_hash(domain_id, name, abi, ruleset_version, rs_hash,
                         genesis_root, tx_types) -> bytes:
    """domain_wire.h "DomainManifest v1 canonical layout" (199 + count)."""
    enc = be32(DOMMAN_VERSION)                    # off   0
    enc += be32(domain_id)                        # off   4
    enc += name32(name)                           # off   8
    enc += bytes([RUNTIME_KIND_NATIVE_BUILTIN])   # off  40
    enc += be32(abi)                              # off  41
    enc += be32(ruleset_version)                  # off  45
    enc += rs_hash                                # off  49
    enc += genesis_root                           # off 113
    enc += be16(len(tx_types))                    # off 177
    enc += bytes(tx_types)                        # off 179
    enc += bytes([FEE_POLICY_GLOBAL_BURN])
    enc += be16(QUOTA_TX_PER_BLOCK)
    enc += be32(QUOTA_VERIFY_COST)
    enc += bytes([UPGRADE_AUTHORITY_CHAIN_CONFIG])
    enc += be64(ACTIVATION_EPOCH)
    enc += be32(READINESS_POLICY_STAGED_V1)
    if len(enc) != 199 + len(tx_types):
        raise AssertionError("manifest length %d != %d"
                             % (len(enc), 199 + len(tx_types)))
    return sha3(tag16("NDS.DOMMAN.v1") + enc)


def evm_activation_d(sys_h, core_h, evm_h, man_h) -> int:
    """domain_wire.h dna_evm_activation_digest comment."""
    pre = (tag16("NDS.EVMACT.v1") + be32(GEN_EVM) + be32(GEN_EVM_BASE)
           + sys_h + core_h + evm_h + man_h
           + be32(EVM_ACTIVATION_SPEC_VERSION) + be32(len(EVM_ACT_CONSTS)))
    for c in EVM_ACT_CONSTS:
        pre += be64(c)
    want = 16 + 4 + 4 + 4 * 64 + 4 + 4 + 8 * len(EVM_ACT_CONSTS)
    if len(pre) != want:
        raise AssertionError("EVMACT preimage %d != %d" % (len(pre), want))
    return int.from_bytes(sha3(pre)[:8], "big") & 0x7FFFFFFFFFFFFFFF


# ── stages ────────────────────────────────────────────────────────────


def evm_generation():
    """The EVM generation's four tuples, the empty root, the manifest
    hash and D — every one computed here."""
    pol = system_policy(POLICY_MAX_OP_GEVM)
    sys_h = system_rs(SYS_RULESET_VERSION_GEVM, pol)
    core_h = ruleset_hash(DOMAIN_CORE, "DNA_CORE", RUNTIME_ABI_V1,
                          CORE_RULESET_VERSION_GEVM, CORE_RULES_GEVM,
                          CORE_TYPES, b"\x00" * 64)
    evm_h = ruleset_hash(DOMAIN_EVM, "EVM", RUNTIME_ABI_V2,
                         EVM_RULESET_VERSION, EVM_RULES, EVM_TYPES,
                         b"\x00" * 64)
    root = evm_empty_root()
    man = domain_manifest_hash(DOMAIN_EVM, "EVM", RUNTIME_ABI_V2,
                               EVM_RULESET_VERSION, evm_h, root, EVM_TYPES)
    d = evm_activation_d(sys_h, core_h, evm_h, man)
    return pol, sys_h, core_h, evm_h, root, man, d


def control() -> bool:
    print("── CONTROL (shipped gen-1, gen-2 and gen-3 (EVM) literals) "
          + "─" * 7)
    g1_pol = system_policy(7)
    g2_pol = system_policy(8)
    g2_sys = system_rs(SYS_RULESET_VERSION_GEN2, g2_pol)
    g2_core = core_rs(CORE_RULESET_VERSION_GEN2, CORE_RULES_GEN2)
    d2, _, _, _ = gen_digest(GEN2, g2_sys, g2_core)
    e_pol, e_sys, e_core, e_evm, e_root, e_man, e_d = evm_generation()
    checks = [
        ("C1  gen-1 SYSTEM meter policy (ops 1..7)", g1_pol.hex(),
         SHIPPED_METPOL_SYSTEM),
        ("C2  gen-1 SYSTEM ruleset v6",
         system_rs(SYS_RULESET_VERSION_GEN1, g1_pol).hex(),
         SHIPPED_RS_SYSTEM_V6),
        ("C3  gen-1 DNA_CORE ruleset v4",
         core_rs(CORE_RULESET_VERSION_GEN1, CORE_RULES).hex(),
         SHIPPED_RS_CORE_V4),
        ("C4  gen-2 SYSTEM meter policy (ops 1..8)", g2_pol.hex(),
         SHIPPED_METPOL_SYSTEM_G2),
        ("C5  gen-2 SYSTEM ruleset v7", g2_sys.hex(), SHIPPED_RS_SYSTEM_V7),
        ("C6  gen-2 DNA_CORE ruleset v5", g2_core.hex(), SHIPPED_RS_CORE_V5),
        ("C7  gen-2 vote literal D2 (param 9)", "0x%016x" % d2,
         "0x%016x" % SHIPPED_D2),
        ("C8  gen-3 SYSTEM meter policy (ops 1..9)", e_pol.hex(),
         SHIPPED_METPOL_GEVM),
        ("C9  gen-3 SYSTEM ruleset v8", e_sys.hex(), SHIPPED_RS_SYSTEM_V8),
        ("C10 gen-3 DNA_CORE ruleset v6", e_core.hex(), SHIPPED_RS_CORE_V6),
        ("C11 gen-3 EVM ruleset v2", e_evm.hex(), SHIPPED_RS_EVM_V2),
        ("C12 gen-3 EVM_ACTIVE literal D (param 14)", "0x%016x" % e_d,
         "0x%016x" % SHIPPED_EVM_ACTIVE_D),
    ]
    ok = True
    for label, got, want in checks:
        good = got == want
        ok = ok and good
        print("  [%s] %s" % ("PASS" if good else "FAIL", label))
        print("         got    %s" % got)
        if not good:
            print("         pinned %s" % want)
    print("  (C12 inputs computed here: empty EVM root %s…, EVM manifest "
          "hash %s…)" % (e_root.hex()[:16], e_man.hex()[:16]))
    # the generalised builders agree with hf4_oracle's gen-2 ones
    if system_rs_rules(SYS_RULESET_VERSION_GEN2, SYS_RULES, g2_pol) != g2_sys:
        print("  [FAIL] system_rs_rules != hf4_oracle.system_rs at gen 2")
        ok = False
    return ok


def emit() -> None:
    e_pol = system_policy(POLICY_MAX_OP_GEVM)

    print()
    print("── S1 GEN_STORAGE SYSTEM meter-policy digest " + "─" * 21)
    print("  policy v2, scalars 1, max_block_env_bytes = %d, ops 1..%d w=1"
          % (2 * ENV_MAX_TOTAL_LEN, POLICY_MAX_OP_STORAGE))
    s1 = system_policy(POLICY_MAX_OP_STORAGE)
    print("  S1 = %s" % s1.hex())
    print("  S1 == the EVM generation's policy (C8, %s…): %s"
          % (SHIPPED_METPOL_GEVM[:16],
             "CONFIRMED" if s1 == e_pol else "REFUTED"))
    print_c_bytes("SYS_METER_POLICY_DIGEST_GST", "DNA_DOM_HASH_LEN", s1)

    print()
    print("── S2 SYSTEM ruleset v%d " % SYS_RULESET_VERSION_STORAGE
          + "─" * 42)
    print("  domain %d \"SYSTEM\" abi %d rules %s types %s policy S1"
          % (DOMAIN_SYSTEM, RUNTIME_ABI_V1, SYS_RULES_STORAGE,
             SYS_TYPES_STORAGE))
    s2 = system_rs_rules(SYS_RULESET_VERSION_STORAGE, SYS_RULES_STORAGE, s1)
    print("  S2 = %s" % s2.hex())
    print_c_bytes("SYS_RULESET_HASH_GST", "DNA_DOM_HASH_LEN", s2)

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
    print_c_bytes("CORE_RULESET_HASH_GST", "DNA_DOM_HASH_LEN", s3)

    print()
    print("── S4 param-16 RULESET_GEN_STORAGE vote literal " + "─" * 18)
    lit, raw, dig, pre = gen_digest(GEN_STORAGE, s2, s3)
    print("  generation      = %d (base %d), switch spec version = %d"
          % (GEN_STORAGE, GEN_STORAGE_BASE, SWITCH_SPEC_VERSION))
    print("  preimage (%d B) = %s" % (len(pre), pre.hex()))
    print("  SHA3-512        = %s" % dig.hex())
    print("  first 8 BE      = 0x%016x" % raw)
    print("  top bit was     = %s" % ("SET (cleared)" if raw >> 63 else
                                      "clear (unchanged)"))
    print("  S4              = 0x%016xULL" % lit)
    print("  S4 (decimal)    = %d" % lit)

    print()
    print("  sanity: S2 != SYSTEM v8 (EVM): %s"
          % (s2.hex() != SHIPPED_RS_SYSTEM_V8))
    print("  sanity: S3 != CORE v6 (EVM, version field only): %s"
          % (s3.hex() != SHIPPED_RS_CORE_V6))
    print("  sanity: S4 != D2, S4 != EVM_ACTIVE D: %s"
          % (lit != SHIPPED_D2 and lit != SHIPPED_EVM_ACTIVE_D))
    assert s2.hex() != SHIPPED_RS_SYSTEM_V8
    assert s3.hex() != SHIPPED_RS_CORE_V6
    assert lit != SHIPPED_D2 and lit != SHIPPED_EVM_ACTIVE_D
    # CORE v7 differs from CORE v6 ONLY in the ruleset_version field
    assert ruleset_hash(DOMAIN_CORE, "DNA_CORE", RUNTIME_ABI_V1,
                        CORE_RULESET_VERSION_GEVM, CORE_RULES_STORAGE,
                        CORE_TYPES_STORAGE, b"\x00" * 64).hex() \
        == SHIPPED_RS_CORE_V6


def main() -> int:
    if not control():
        print()
        print("CONTROL FAILED — refusing to emit GEN_STORAGE values.")
        return 1
    emit()
    print()
    print("control green — GEN_STORAGE (generation 4) values above derived "
          "from the written layouts by hashlib, not by the C encoders "
          "(generation-4 inputs: decision K10; C-only inputs listed in the "
          "docstring).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
