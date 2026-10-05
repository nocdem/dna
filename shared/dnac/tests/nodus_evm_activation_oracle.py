#!/usr/bin/env python3
r"""
Oracle for the Nodus EVM activation package's pinned values: the EVM
generation's SYSTEM meter-policy digest, the SYSTEM v8 / DNA_CORE v6 / EVM
v1 ruleset hashes, the empty EVM domain root, the EVM registry manifest
hash and the EVM_ACTIVE vote literal D.

⚠ PROVENANCE — SELF-DERIVED, NOT INDEPENDENT
--------------------------------------------
Written by the SAME agent that wrote the activation package's C (Nodus EVM
activation package, 2026-10-04). It therefore proves only that the C
encoders and THIS file agree on the layout the agent wrote down — it is
"self-consistent", NOT an independent pin (the CLAUDE.md "KAFADAN" rule:
the same author writing code and audit is circular). Before any EVM_ACTIVE
vote, an agent that has NOT read the activation package's C must re-derive
every value below from the written specification:

  * design   docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3
             §5 (supply), §6 (empty MPT root SHA3-512(0x80), META digest,
             EVM root composition), §9 (activation digest contents);
  * the C contracts it relies on: shared/dnac/domain_wire.h
             (dna_evm_activation_digest, DomainManifest encoding,
             dna_domman_hash), shared/dnac/res_meter.h (policy identity).

What IS reused unmodified: the shipped helpers of the existing independent
oracles shared/dnac/tests/ruleset_desc_oracle.py and hf4_oracle.py (policy
identity, ruleset hash, D2), whose CONTROL legs must reproduce the shipped
literals first.

Stages, fail-closed:
  CONTROL (byte-exact against the shipped literals, else exit 1):
    C1 SYSTEM meter policy ops 1..7   8f1f9cb2…
    C2 SYSTEM v6, C3 DNA_CORE v4       (runtime.c generation 1)
    C4 SYSTEM meter policy ops 1..8, C5 SYSTEM v7, C6 DNA_CORE v5,
    C7 D2 0x44dfbe7ad3c75adf           (runtime.c / dnac.h generation 2)
  EMIT (the EVM generation, NODUS_RT_GEN_EVM = 3, base = 2):
    E1 SYSTEM meter-policy digest, ops 1..9 weight 1
    E2 SYSTEM v8 ruleset hash
    E3 DNA_CORE v6 ruleset hash (rules {1..9})
    E4 EVM v1 ruleset hash (domain 2, "EVM", ABI 2, rules {1..5}, no types)
    E5 empty EVM root
    E6 EVM manifest hash (genesis_state_root = E5)
    E7 D (EVM_ACTIVE literal)

Run:  python3 shared/dnac/tests/nodus_evm_activation_oracle.py

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ruleset_desc_oracle import (  # noqa: E402
    CORE_RULES, CORE_TYPES, DOMAIN_CORE, DOMAIN_SYSTEM, SYS_RULES,
    SYS_TYPES, be16, be32, be64, name32, ruleset_hash, tag16)
from hf4_oracle import (  # noqa: E402
    SHIPPED_METPOL_SYSTEM, SHIPPED_RS_CORE_V4, SHIPPED_RS_SYSTEM_V6,
    core_rs, d2_preimage, system_policy, system_rs)

# ── shipped generation-2 literals (control) ───────────────────────────
# nodus/src/witness/nodus_witness_runtime.c SYS_METER_POLICY_DIGEST_G2,
# SYS_RULESET_HASH_G2, CORE_RULESET_HASH_G2; dnac/include/dnac/dnac.h
# DNAC_CFG_RULESET_GEN2_D2.
SHIPPED_METPOL_G2 = (
    "0c251ca2920d77882bcab294311052a0681362c55b06f417f6aada46feb755b3"
    "ab304776ed33537ae07e73f79a10da3d3f4b788bd56e4c06a7172a6f19ceec87")
SHIPPED_RS_SYSTEM_V7 = (
    "8780a3a9129041e16db275fca2e2bfb8d21aae33371c0b4cafdbcb623159eacb"
    "74854107fad3503ee2e018ec2578377a63001e5156a07d386a7c7b55311d14b4")
SHIPPED_RS_CORE_V5 = (
    "20c7235b13db0f029a8c3be096e24403fd3a3e393e9ff723e0672a6027601a35"
    "0586db18985e7a6ac73365be6cfe65f0fb9ad53357db2d539a1c69d93d81cae5")
SHIPPED_D2 = 0x44dfbe7ad3c75adf

# ── the EVM generation (nodus_witness_runtime.c / runtime.h) ───────────
GEN_EVM = 3                    # NODUS_RT_GEN_EVM
GEN_EVM_BASE = 2               # NODUS_RT_GEN_EVM_BASE
SYS_VERSION_GEVM = 8
CORE_VERSION_GEVM = 6
CORE_RULES_GEVM = CORE_RULES + [8, 9]   # + NAME_REGISTER, EVMFUND
DOMAIN_EVM = 2                 # shared/dnac/ledger_ids.h DNA_DOMAIN_EVM
RUNTIME_ABI_V2 = 2
EVM_VERSION = 1
EVM_RULES = [1, 2, 3, 4, 5]
EVM_ACTIVATION_SPEC_VERSION = 1   # dnac.h DNAC_EVM_ACTIVATION_SPEC_VERSION

# evm_act_consts, in the order nodus_witness_runtime.c lists them
EVM_CONSTS = [
    10000000000,     # NODUS_RT_EVM_Q
    25000,           # NODUS_RT_EVM_TICKET_GAS
    30000000,        # NODUS_RT_EVM_TX_GAS_CAP
    (30000000 + 2099) // 2100 + 2048,   # NODUS_RT_EVM_READS_BASE
    32 * 1024 * 1024,                   # NODUS_RT_EVM_MAX_READ_BYTES
    1,               # DNA_METER_EVM_W_GAS
    4096,            # DNA_METER_EVM_FAIL_RESERVE
    1,               # DNA_METER_EVM_FAIL_EFFECTS
    287,             # DNA_METER_EVM_FAIL_BYTES
    16384,           # DNA_METER_STREAM_MAX_EFFECTS
    4 * 1024 * 1024,                    # DNA_METER_STREAM_MAX_EFFECT_BYTES
    21000,           # NODUS_RT_EVM_BRIDGE_GAS
    30000000,        # DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT
    1000000,         # DNAC_CFG_MIN_EVM_BLOCK_GAS
    1000000000,      # DNAC_CFG_MAX_EVM_BLOCK_GAS
]

# DomainManifest constants (shared/dnac/domain_wire.h)
DOMMAN_VERSION = 1
RUNTIME_NATIVE_BUILTIN = 1
FEEPOL_GLOBAL_BURN = 1
UPGAUTH_CHAIN_CONFIG = 1
RDYPOL_STAGED_V1 = 1


def sha3(b: bytes) -> bytes:
    return hashlib.sha3_512(b).digest()


def evm_empty_root() -> bytes:
    """design §6: empty trie root = SHA3-512(RLP(b"")) = SHA3-512(0x80);
    meta_digest = SHA3-512("NDS.EVMMETA.v1" ‖ 96 zero bytes); root =
    SHA3-512("NDS.EVMROOT.v1" ‖ acct_root ‖ tickets_root ‖ meta_digest)."""
    empty_trie = sha3(b"\x80")
    meta = sha3(tag16("NDS.EVMMETA.v1") + b"\x00" * 96)
    return sha3(tag16("NDS.EVMROOT.v1") + empty_trie + empty_trie + meta)


def manifest_hash(domain_id, name, abi, version, rs_hash, genesis_root,
                  tx_types) -> bytes:
    enc = (be32(DOMMAN_VERSION) + be32(domain_id) + name32(name)
           + bytes([RUNTIME_NATIVE_BUILTIN]) + be32(abi) + be32(version)
           + rs_hash + genesis_root + be16(len(tx_types)) + bytes(tx_types)
           + bytes([FEEPOL_GLOBAL_BURN]) + be16(0) + be32(0)
           + bytes([UPGAUTH_CHAIN_CONFIG]) + be64(0)
           + be32(RDYPOL_STAGED_V1))
    return sha3(tag16("NDS.DOMMAN.v1") + enc)


def d_of(sys_h, core_h, evm_h, man_h) -> int:
    pre = (tag16("NDS.EVMACT.v1") + be32(GEN_EVM) + be32(GEN_EVM_BASE)
           + sys_h + core_h + evm_h + man_h
           + be32(EVM_ACTIVATION_SPEC_VERSION) + be32(len(EVM_CONSTS)))
    for c in EVM_CONSTS:
        pre += be64(c)
    want = 16 + 4 + 4 + 4 * 64 + 4 + 4 + 8 * len(EVM_CONSTS)
    if len(pre) != want:
        raise AssertionError("D preimage %d != %d" % (len(pre), want))
    return int.from_bytes(sha3(pre)[:8], "big") & 0x7FFFFFFFFFFFFFFF


def c_bytes(name: str, data: bytes) -> None:
    print("static const uint8_t %s[DNA_DOM_HASH_LEN] = {" % name)
    for i in range(0, len(data), 8):
        row = ", ".join("0x%02x" % b for b in data[i:i + 8])
        print("    %s%s" % (row, "," if i + 8 < len(data) else ""))
    print("};")


def main() -> int:
    ok = True
    p7 = system_policy(7)
    p8 = system_policy(8)
    s7 = system_rs(7, p8)
    c5 = core_rs(5, CORE_RULES + [8])
    raw2 = sha3(d2_preimage(s7, c5))
    d2 = int.from_bytes(raw2[:8], "big") & 0x7FFFFFFFFFFFFFFF
    controls = [
        ("C1 policy ops 1..7", p7.hex(), SHIPPED_METPOL_SYSTEM),
        ("C2 SYSTEM v6", system_rs(6, p7).hex(), SHIPPED_RS_SYSTEM_V6),
        ("C3 DNA_CORE v4", core_rs(4, CORE_RULES).hex(), SHIPPED_RS_CORE_V4),
        ("C4 policy ops 1..8", p8.hex(), SHIPPED_METPOL_G2),
        ("C5 SYSTEM v7", s7.hex(), SHIPPED_RS_SYSTEM_V7),
        ("C6 DNA_CORE v5", c5.hex(), SHIPPED_RS_CORE_V5),
        ("C7 D2", "%016x" % d2, "%016x" % SHIPPED_D2),
    ]
    for label, got, want in controls:
        good = got == want
        ok = ok and good
        print("[%s] %s" % ("PASS" if good else "FAIL", label))
        if not good:
            print("   got    %s\n   pinned %s" % (got, want))
    if not ok:
        print("CONTROL FAILED — emitting nothing")
        return 1

    e1 = system_policy(9)
    e2 = ruleset_hash(DOMAIN_SYSTEM, "SYSTEM", 1, SYS_VERSION_GEVM,
                      SYS_RULES, SYS_TYPES, e1)
    e3 = ruleset_hash(DOMAIN_CORE, "DNA_CORE", 1, CORE_VERSION_GEVM,
                      CORE_RULES_GEVM, CORE_TYPES, b"\x00" * 64)
    e4 = ruleset_hash(DOMAIN_EVM, "EVM", RUNTIME_ABI_V2, EVM_VERSION,
                      EVM_RULES, [], b"\x00" * 64)
    e5 = evm_empty_root()
    e6 = manifest_hash(DOMAIN_EVM, "EVM", RUNTIME_ABI_V2, EVM_VERSION, e4,
                       e5, [])
    e7 = d_of(e2, e3, e4, e6)
    print()
    print("E1 policy ops 1..9      %s" % e1.hex())
    print("E2 SYSTEM v8            %s" % e2.hex())
    print("E3 DNA_CORE v6          %s" % e3.hex())
    print("E4 EVM v1               %s" % e4.hex())
    print("E5 empty EVM root       %s" % e5.hex())
    print("E6 EVM manifest hash    %s" % e6.hex())
    print("E7 D                    0x%016x (%d)" % (e7, e7))
    print()
    c_bytes("SYS_METER_POLICY_DIGEST_GEVM", e1)
    c_bytes("SYS_RULESET_HASH_GEVM", e2)
    c_bytes("CORE_RULESET_HASH_GEVM", e3)
    c_bytes("EVM_RULESET_HASH_GEVM", e4)
    print("#define DNAC_CFG_EVM_ACTIVE_D 0x%016xULL" % e7)
    print()
    print("control green — EVM-generation values above are SELF-DERIVED "
          "(see PROVENANCE)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
