#!/usr/bin/env python3
r"""
Independent oracle for the HF-7 generation-5 (ROOTS) vote value D5
(chain_config param 22, proposed name RULESET_GEN_ROOTS) and the two
generation-5 ruleset hashes it binds.

WHAT IT PROVES
--------------
Given the written specs below, it derives:
  R1  the generation-5 SYSTEM ruleset hash (SYSTEM ruleset_version 11)
  R2  the generation-5 CORE   ruleset hash (CORE   ruleset_version 10)
  D5  = dna_rolegen_vote_digest(5, 4, R1, R2, HF7_SWITCH_SPEC_VERSION 1,
        the HF-6 Foundation owner, HF7_VOTE_CONSTS = [720])
and, BEFORE it prints any of them, it re-derives through the SAME code
path four already-pinned generation-3/4 values plus the shipped HF-6 vote
literal D4 and refuses (exit 1) unless every one is byte-equal:
  C1  gen-3/gen-4 SYSTEM meter-policy identity digest (ops 1..9)
                                    nodus_ruleset_pins.h G3/G4 POLICY_DIGEST
  C2  gen-3 SYSTEM v8  ruleset hash nodus_ruleset_pins.h G3_SYS_RULESET_HASH
  C3  gen-3 CORE   v6  ruleset hash nodus_ruleset_pins.h G3_CORE_RULESET_HASH
  C4  gen-4 SYSTEM v10 ruleset hash nodus_ruleset_pins.h G4_SYS_RULESET_HASH
  C5  gen-4 CORE   v9  ruleset hash nodus_ruleset_pins.h G4_CORE_RULESET_HASH
  C6  HF-6 D4 (generation 4, base 3, spec 1, owner K8, the nine
      GEN4_VOTE_CONSTS)             dnac.h DNAC_CFG_RULESET_GEN_ROLES_D
                                    = 0x642af9b4bf735409
Each control is checked against BOTH the hex literal written in this file
AND the value parsed at run time from the tree's header (a text read of
the data, not a call into C).
When the pins header carries NODUS_PIN_G5_* (HF-7 P1d), the C's pinned
generation-5 SYSTEM / CORE version + hash are printed against R1 / R2 as
OK / MISMATCH (a report line for the reviewer; until then "not pinned").

SPECIFICATIONS (the text this file was written from)
----------------------------------------------------
* D5 inputs — docs/plans/2026-09-11-nodus-ledger-snapshot-design.md
  §10.2 item 1 (D5 = dna_rolegen_vote_digest(5, 4, SYS-gen5 ruleset hash,
  CORE-gen5 ruleset hash, HF7_SWITCH_SPEC_VERSION 1, the HF-6 Foundation
  owner unchanged, HF7_VOTE_CONSTS)), §10.9 ("generation 5 must bump both"
  the SYSTEM and CORE ruleset version), §10.11 khan decision C
  ("HF7_VOTE_CONSTS = {720} only" — the mempool 100 is NOT bound);
  decision docs/plans/decisions/2026-10-20-kurultay-27-hf7-p1-summary.md
  "Agreed" item 1 and khan answer C.
* Digest layout — shared/dnac/domain_wire.h dna_rolegen_vote_digest
  comment (:373-407 at 30cb1ece6; tag :402, declaration :408):
      off 0  16  DNA_ROLEGEN_TAG "NDS.ROLEGEN.v1", zero-padded to 16
         16   4  generation u32 BE
         20   4  base_generation u32 BE
         24  64  sys_ruleset_hash
         88  64  core_ruleset_hash
        152   4  spec_version u32 BE
        156  64  foundation_owner (raw 64 bytes)
        220   4  n_consts u32 BE
        224 8·n  n_consts × u64 BE (the caller's order)
      *out = first 8 digest bytes read big-endian, top bit cleared.
  For n = 1 the preimage is 232 bytes (DNA_ROLEGEN_PREIMAGE_LEN(1)).
* RulesetDescriptor v2 hash — shared/dnac/domain_wire.h :303-312
  (struct :288-301):
      SHA3-512("NDS.RULESET.v1"(16) ‖ descriptor_version u32 BE (= 2,
      DNA_RULESET_DESC_VERSION :286) ‖ domain_id u32 BE ‖ name[32]
      ‖ runtime_abi u32 BE ‖ ruleset_version u32 BE ‖ rule_count u16 BE
      ‖ rule_ids[] u32 BE ‖ tx_type_count u16 BE ‖ tx_types[] u8
      ‖ meter_policy_digest[64] (all-zero = none declared))
  name[32] ASCII, zero-padded (domain_wire.h DomainManifest name rule
  :66-67); 16-byte tags zero-padded (TAG TABLE :50).
* Meter-policy identity digest — shared/dnac/res_meter.h :283-308:
      SHA3-512("NDS.METPOLID.v1"(16) ‖ policy_version u32 BE ‖ w_base
      ‖ w_callbyte ‖ w_authbyte ‖ w_effect ‖ w_effectbyte ‖ w_read
      ‖ w_write ‖ max_block_env_bytes ‖ w_op[0..255] ‖ op_present[0..3]
      (u64 BE each))  = 2164-byte preimage.
  op_present: 4 u64 words; bit (op mod 64) of word (op div 64) — the
  presence mask of res_meter.h DNA_METER_OP_MASK_WORDS; the bit order is
  confirmed only by control C1 reproducing the pinned digest.

DESCRIPTOR CONTENTS AND INPUT SOURCES (tree at 30cb1ece6)
---------------------------------------------------------
  DNA_DOMAIN_SYSTEM 0, DNA_DOMAIN_CORE 1     shared/dnac/ledger_ids.h:52-53
  names "SYSTEM", "DNA_CORE"                 nodus_witness_runtime.c:1056,1113
  NODUS_DOMAIN_RUNTIME_ABI_V1 = 1            nodus_witness_runtime.h:73
  SYSTEM rules gen 4: {1..9}                 runtime.c:169-174 SYS_RULES_GST,
                                             runtime.h:88-93,105-109
  SYSTEM rules gen 3: {1..6}                 runtime.c:93-97 SYS_RULES (C2)
  SYSTEM tx_types {4,5,6,7,9,10}             runtime.c:98 SYS_TYPES
  CORE rules gen 3/4: {1..9}                 runtime.c:138-143 CORE_RULES_GEVM,
                                             runtime.h:127-164, runtime.c:108-109
  CORE tx_types {1,2,3,11,12,13}             runtime.c:179 CORE_TYPES
  CORE meter_policy_digest all-zero          (no CORE policy; runtime.c:1135
                                             .meter_policy = NULL; ruleset_desc_
                                             oracle.py and storage_oracle.py S3)
  SYSTEM policy: version 2, seven scalar weights 1, max_block_env_bytes
    2 × DNA_ENV_MAX_TOTAL_LEN (1048576) = 2097152, ops 1..9 weight 1
                                             runtime.c:303 SYS_POLICY_MAX_OP_GST,
                                             :329-342 sys_policy_build,
                                             env_wire.h:249, res_meter.h:206,
                                             nodus_ruleset_pins.h:230-252
  gen-4 versions SYSTEM 10 / CORE 9          runtime.c:1050,1107;
                                             nodus_ruleset_pins.h:202,216
  gen-3 versions SYSTEM 8 / CORE 6           runtime.c:923,956
  generation 5 = NODUS_RT_GEN_ROOTS          runtime.h:290
  base 4 = NODUS_RT_GEN_ROOTS_BASE = GEN_STORAGE  runtime.h:292
  HF7_SWITCH_SPEC_VERSION = 1                design §10.2 item 1 (no C
                                             symbol exists yet at 30cb1ece6)
  foundation owner = DNAC_HF6_FOUNDATION_OWNER    dnac/include/dnac/dnac.h:
                                             1185-1193; the value HF-6's D4
                                             took (runtime.c:1857-1864
                                             nodus_runtime_gen4_vote_digest;
                                             hf6_vote_oracle.py K8_OWNER_HEX)
  HF7_VOTE_CONSTS = [720]                    design §10.11 C; the value is
                                             NODUS_V2_EXPIRY_WINDOW_BLOCKS
                                             nodus_witness_v2_apply.h:1583
  D4 control inputs: gen 4, base 3, spec 1   runtime.c:1860-1863;
    (DNAC_HF6_SWITCH_SPEC_VERSION 1          dnac.h:1267), nine consts in
    GEN4_VOTE_CONSTS order                   runtime.c:1836-1846 /
                                             hf6_vote_oracle.py CONSTS

GENERATION-5 DESCRIPTORS (the rule this file applies)
-----------------------------------------------------
Generation 5 = the generation-4 SYSTEM and CORE descriptors with ONLY the
ruleset_version field changed: SYSTEM 10 -> 11, CORE 9 -> 10.
  * Why only the version: HF-7 adds no rule id, no tx type and no op (no
    item of §10.2 / the Kurultay #27 summary names one; §10.2 item 3:
    "CORE unchanged in content"); the SYSTEM change ("§8.9 S4
    composition" — the state root "NDS.SYS.v6") is not a descriptor field
    (domain_wire.h:285-298 lists every member: version, domain, name,
    abi, ruleset_version, rules, types, policy digest — nothing about root
    composition; the gen-4 comment runtime.c:1042-1043 records that a
    root-composition change rides on the version number). The SYSTEM
    policy is unchanged because no op is added.
  * Why 11 and 10: the registry selfcheck requires each domain's version
    to STRICTLY exceed the previous generation's (runtime.c:1619-1634);
    the smallest such values are 11 (> SYSTEM 10) and 10 (> CORE 9).
    Neither is used by any compiled descriptor (runtime.c ruleset_version
    lines: SYSTEM 6/7/8/10, CORE 4/5/6/9, EVM via its own macro) nor by
    any retired pin this tree records (SYSTEM 4/5/9, CORE 3/7/8 —
    ruleset_desc_oracle.py, storage_oracle.py). design §8.7 says the
    numbers are "computed by the registry code, not chosen by hand": if
    the C table picks any other value, R1/R2/D5 here are WRONG for it.

HOW IT CAN LIE
--------------
* SELF-CONSISTENT with the written spec, not grounded in an external
  standard: the layout's reference is the tree's own convention. SHA3-512
  itself is FIPS 202 (Python hashlib).
* Independent of the C encoder only as far as this file did not copy it:
  no C function was called; dna_rolegen_vote_digest / dna_ruleset_desc_hash
  / dna_meter_policy_digest bodies were NOT read — only their header
  comments. The descriptor CONTENTS (rule lists, types, policy fields,
  versions) are read from the C table and the generated pins header: if
  those data are wrong, the controls prove nothing about them beyond
  "they match what is pinned".
* The generation-5 rule ("only the version moves", 11 / 10) is this
  file's reading of the design text above; a later design change that
  adds a rule, a type, an op or re-prices the policy makes R1/R2/D5 wrong
  by construction.
* The owner is the DEFAULT compiled owner (K8); a test build that compiles
  another owner (dnac.h:1169-1182) has a different D5 — use --owner.

Run:  python3 shared/dnac/tests/hf7_vote_oracle.py [--owner <128 hex>]
      (writes to stdout; the checked-in output is hf7_vote_oracle_out.txt)

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import argparse
import hashlib
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
PINS_H = os.path.join(REPO, "nodus", "include", "nodus",
                      "nodus_ruleset_pins.h")
DNAC_H = os.path.join(REPO, "dnac", "include", "dnac", "dnac.h")

# ── primitives (written here, from the spec text) ─────────────────────


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
    raw = s.encode("ascii")
    if not raw or len(raw) > 32 or any(b < 0x21 or b > 0x7E for b in raw):
        raise ValueError("non-canonical name: %r" % s)
    return raw + b"\x00" * (32 - len(raw))


def strictly_ascending(xs) -> bool:
    return all(a < b for a, b in zip(xs, xs[1:]))


# ── constants (sources in the docstring) ──────────────────────────────

RAW = 100000000                       # 1 NODUS = 10^8 raw

DOMAIN_SYSTEM = 0
DOMAIN_CORE = 1
RUNTIME_ABI_V1 = 1
RULESET_DESC_VERSION = 2

METER_POLICY_VERSION = 2
ENV_MAX_TOTAL_LEN = 1048576
MAX_BLOCK_ENV_BYTES = 2 * ENV_MAX_TOTAL_LEN
OP_SPACE = 256
OP_MASK_WORDS = OP_SPACE // 64

SYS_RULES_G3 = [1, 2, 3, 4, 5, 6]
SYS_RULES_G4 = [1, 2, 3, 4, 5, 6, 7, 8, 9]
SYS_TYPES = [4, 5, 6, 7, 9, 10]
CORE_RULES_G34 = [1, 2, 3, 4, 5, 6, 7, 8, 9]
CORE_TYPES = [1, 2, 3, 11, 12, 13]
SYS_POLICY_MAX_OP = 9                 # gen 3 and gen 4: ops 1..9 weight 1

SYS_V_G3, CORE_V_G3 = 8, 6
SYS_V_G4, CORE_V_G4 = 10, 9
SYS_V_G5, CORE_V_G5 = 11, 10          # the generation-5 bump (docstring)

ROLEGEN_TAG = "NDS.ROLEGEN.v1"
OWNER_LEN = 64

# HF-6 D4 (control)
GEN4, GEN4_BASE, HF6_SPEC = 4, 3, 1
GEN4_VOTE_CONSTS = [
    2000000 * RAW,                    # STAKE_MIN default
    100000 * RAW,                     # STAKE_MIN lower bound
    3000,                             # POWER_CAP_BPS default
    500,                              # POWER_CAP_BPS min
    3000,                             # POWER_CAP_BPS max
    1000000 * RAW,                    # STORAGE_BOND default
    100000 * RAW,                     # STORAGE_BOND min
    1000000 * RAW,                    # STORAGE_BOND max
    720,                              # consent window (blocks)
]
SHIPPED_D4 = 0x642af9b4bf735409       # dnac.h:1325 DNAC_CFG_RULESET_GEN_ROLES_D

# HF-7 D5
GEN5, GEN5_BASE, HF7_SPEC = 5, 4, 1
HF7_VOTE_CONSTS = [
    ("expiry window (blocks)", 720),  # §10.11 C; NODUS_V2_EXPIRY_WINDOW_BLOCKS
]

# K8 — decision 2026-10-08-kurultay-14-hf6-summary.md; dnac.h:1185-1193
K8_OWNER_HEX = (
    "8eff7f418ab7a4432118ff99e21f2c3d1baf186200c148a3bba7d274499386ac"
    "970e267a9c9b3bbc05bfff1c62a72d63f72a555db780feeaaad4fb49ba9f7b89")

# Pinned hex (nodus_ruleset_pins.h at 30cb1ece6; also storage_oracle.py
# S1/S2/S3 and its SHIPPED_* gen-3 constants)
PIN_POLICY_G34 = (
    "0aa4c690a05af8827a322912a402d87b2642c99edc1db83f2871af64da18c3f8"
    "b74a6e5c870edc3450ae0474a3c8d7279efb884df8b285c8848beffb25922766")
PIN_SYS_V8 = (
    "fe4ac585fba570280b87ec10cea8195acafbe1624c38e1efe476afc97c886457"
    "45567d291796cbdb12a805ede476efc3378d3c22d1c7334b1823200ac740516b")
PIN_CORE_V6 = (
    "ddde5acbd811aad624cddbf6d6d0d3d4c1452e02ce83507b5edce94e6a43f9ef"
    "e6d79b7b35c00a34f5889160b5a0992af67c699cd609bbe21864476ccf6d1fc8")
PIN_SYS_V10 = (
    "a012cc08bbf96524fa2dace331921f9d39107aa52643fc99392c14146ef09159"
    "a54d11502d538d424f1e5bde9a493e2abab2738bf20c3e261fe5627c09bb662a")
PIN_CORE_V9 = (
    "964f300629cdbea0a543c52aa815034a61df8377f333ddbbd4f6f7a0c349763b"
    "e1b08e70215dda924402fd199ccad697a3bfb6cc68ef7f102d8c1fad4cb0aac0")

# Vote literals D5 must not collide with (dnac.h; hf6_vote_oracle.py)
OTHER_LITERALS = [
    ("D2 (param 9)", 0x44dfbe7ad3c75adf),
    ("EVM_ACTIVE D (param 14)", 0x029f47596864d407),
    ("slice-6a gen 4 (param 16, dev)", 0x329b0ea92c8b8c58),
    ("D4 (param 18)", SHIPPED_D4),
]

# ── the three encoders ────────────────────────────────────────────────


def meter_policy_identity(max_op: int) -> bytes:
    """res_meter.h :283-308 — ops 1..max_op present, weight 1; the seven
    scalar weights 1; version 2; max_block_env_bytes 2 MiB."""
    w_op = [0] * OP_SPACE
    present = [0] * OP_MASK_WORDS
    for op in range(1, max_op + 1):
        w_op[op] = 1
        present[op // 64] |= 1 << (op % 64)
    pre = tag16("NDS.METPOLID.v1") + be32(METER_POLICY_VERSION)
    for w in (1, 1, 1, 1, 1, 1, 1, MAX_BLOCK_ENV_BYTES):
        pre += be64(w)
    for w in w_op:
        pre += be64(w)
    for word in present:
        pre += be64(word)
    if len(pre) != 2164:
        raise AssertionError("policy preimage %d != 2164" % len(pre))
    return hashlib.sha3_512(pre).digest()


def ruleset_preimage(domain_id: int, name: str, abi: int, version: int,
                     rules, types, policy: bytes) -> bytes:
    """domain_wire.h :300-311 — RulesetDescriptor v2."""
    if not strictly_ascending(rules) or not strictly_ascending(types):
        raise ValueError("rule / type list not strictly ascending")
    if len(policy) != 64:
        raise ValueError("policy digest must be 64 bytes")
    pre = tag16("NDS.RULESET.v1")
    pre += be32(RULESET_DESC_VERSION) + be32(domain_id) + name32(name)
    pre += be32(abi) + be32(version)
    pre += be16(len(rules)) + b"".join(be32(r) for r in rules)
    pre += be16(len(types)) + bytes(types)
    pre += policy
    return pre


def ruleset_hash(*args) -> bytes:
    return hashlib.sha3_512(ruleset_preimage(*args)).digest()


def rolegen_fields(gen: int, base: int, sys_h: bytes, core_h: bytes,
                   spec: int, owner: bytes, consts):
    """domain_wire.h dna_rolegen_vote_digest comment — returns the named
    fields in preimage order. consts = list of (name, value)."""
    if len(sys_h) != 64 or len(core_h) != 64 or len(owner) != OWNER_LEN:
        raise ValueError("bad hash / owner length")
    if len(consts) > 64:
        raise ValueError("n_consts > DNA_ROLEGEN_MAX_CONSTS")
    f = [
        ('TAG16("%s")' % ROLEGEN_TAG, tag16(ROLEGEN_TAG)),
        ("generation u32 BE = %d" % gen, be32(gen)),
        ("base_generation u32 BE = %d" % base, be32(base)),
        ("sys_ruleset_hash", sys_h),
        ("core_ruleset_hash", core_h),
        ("spec_version u32 BE = %d" % spec, be32(spec)),
        ("foundation_owner", owner),
        ("n_consts u32 BE = %d" % len(consts), be32(len(consts))),
    ]
    for i, (nm, v) in enumerate(consts):
        f.append(("const[%d] %s = %d" % (i, nm, v), be64(v)))
    return f


def rolegen_digest(fields):
    pre = b"".join(b for _, b in fields)
    n = (len(pre) - (16 + 4 + 4 + 64 + 64 + 4 + 64 + 4)) // 8
    if len(pre) != 16 + 4 + 4 + 2 * 64 + 4 + OWNER_LEN + 4 + 8 * n:
        raise AssertionError("rolegen preimage length")
    dig = hashlib.sha3_512(pre).digest()
    raw = int.from_bytes(dig[:8], "big")
    return pre, dig, raw, raw & 0x7FFFFFFFFFFFFFFF


# ── run-time reads of the tree's DATA (text parse, no C called) ──────


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def pins_bytes(text: str, macro: str) -> str:
    m = re.search(r"#define\s+%s\s*\{\s*\\?(.*?)\}" % re.escape(macro),
                  text, re.S)
    if not m:
        raise SystemExit("pins header: %s not found" % macro)
    vals = re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))
    if len(vals) != 64:
        raise SystemExit("pins header: %s has %d bytes" % (macro, len(vals)))
    return "".join(vals).lower()


def pins_has(text: str, macro: str) -> bool:
    return re.search(r"#define\s+%s\b" % re.escape(macro), text) is not None


def pins_u32(text: str, macro: str) -> int:
    m = re.search(r"#define\s+%s\s+(\d+)u" % re.escape(macro), text)
    if not m:
        raise SystemExit("pins header: %s not found" % macro)
    return int(m.group(1))


def dnac_owner(text: str) -> str:
    m = re.search(r"#define\s+DNAC_HF6_FOUNDATION_OWNER\s*\{(.*?)\}",
                  text, re.S)
    if not m:
        raise SystemExit("dnac.h: DNAC_HF6_FOUNDATION_OWNER not found")
    vals = re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))
    if len(vals) != 64:
        raise SystemExit("dnac.h: owner has %d bytes" % len(vals))
    return "".join(vals).lower()


def dnac_d4(text: str) -> int:
    m = re.search(r"#define\s+DNAC_CFG_RULESET_GEN_ROLES_D\s+"
                  r"0x([0-9a-fA-F]+)ULL", text)
    if not m:
        raise SystemExit("dnac.h: DNAC_CFG_RULESET_GEN_ROLES_D not found")
    return int(m.group(1), 16)


# ── controls ──────────────────────────────────────────────────────────


def controls(owner_k8: bytes):
    pins = _read(PINS_H)
    dnac = _read(DNAC_H)
    ok = True
    lines = []

    def chk(label, got_hex, pin_hex, tree_hex):
        nonlocal ok
        good = got_hex == pin_hex == tree_hex
        ok = ok and good
        lines.append("  %-4s %s  %s" % (label, "OK  " if good else "FAIL",
                                         got_hex[:16] + "…"))
        if not good:
            lines.append("       got  %s\n       pin  %s\n       tree %s"
                         % (got_hex, pin_hex, tree_hex))

    pol = meter_policy_identity(SYS_POLICY_MAX_OP)
    chk("C1", pol.hex(), PIN_POLICY_G34,
        pins_bytes(pins, "NODUS_PIN_G4_SYS_METER_POLICY_DIGEST_INIT"))
    if pins_bytes(pins, "NODUS_PIN_G3_SYS_METER_POLICY_DIGEST_INIT") \
            != PIN_POLICY_G34:
        ok = False
        lines.append("  C1   FAIL  G3 policy pin differs from G4")

    zero = b"\x00" * 64
    s3 = ruleset_hash(DOMAIN_SYSTEM, "SYSTEM", RUNTIME_ABI_V1, SYS_V_G3,
                      SYS_RULES_G3, SYS_TYPES, pol)
    c3 = ruleset_hash(DOMAIN_CORE, "DNA_CORE", RUNTIME_ABI_V1, CORE_V_G3,
                      CORE_RULES_G34, CORE_TYPES, zero)
    s4 = ruleset_hash(DOMAIN_SYSTEM, "SYSTEM", RUNTIME_ABI_V1, SYS_V_G4,
                      SYS_RULES_G4, SYS_TYPES, pol)
    c4 = ruleset_hash(DOMAIN_CORE, "DNA_CORE", RUNTIME_ABI_V1, CORE_V_G4,
                      CORE_RULES_G34, CORE_TYPES, zero)
    chk("C2", s3.hex(), PIN_SYS_V8,
        pins_bytes(pins, "NODUS_PIN_G3_SYS_RULESET_HASH_INIT"))
    chk("C3", c3.hex(), PIN_CORE_V6,
        pins_bytes(pins, "NODUS_PIN_G3_CORE_RULESET_HASH_INIT"))
    chk("C4", s4.hex(), PIN_SYS_V10,
        pins_bytes(pins, "NODUS_PIN_G4_SYS_RULESET_HASH_INIT"))
    chk("C5", c4.hex(), PIN_CORE_V9,
        pins_bytes(pins, "NODUS_PIN_G4_CORE_RULESET_HASH_INIT"))

    vers = (pins_u32(pins, "NODUS_PIN_G3_SYS_RULESET_VERSION"),
            pins_u32(pins, "NODUS_PIN_G3_CORE_RULESET_VERSION"),
            pins_u32(pins, "NODUS_PIN_G4_SYS_RULESET_VERSION"),
            pins_u32(pins, "NODUS_PIN_G4_CORE_RULESET_VERSION"))
    if vers != (SYS_V_G3, CORE_V_G3, SYS_V_G4, CORE_V_G4):
        ok = False
        lines.append("  VER  FAIL  pinned versions %r" % (vers,))
    if pins_u32(pins, "NODUS_PIN_GEN_COUNT") < 4:
        ok = False
        lines.append("  GEN  FAIL  NODUS_PIN_GEN_COUNT < 4")

    tree_owner = dnac_owner(dnac)
    if tree_owner != K8_OWNER_HEX or owner_k8.hex() != K8_OWNER_HEX:
        ok = False
        lines.append("  OWN  FAIL  dnac.h owner %s" % tree_owner)
    tree_d4 = dnac_d4(dnac)
    f4 = rolegen_fields(GEN4, GEN4_BASE, s4, c4, HF6_SPEC, owner_k8,
                        [("", v) for v in GEN4_VOTE_CONSTS])
    pre4, _, _, d4 = rolegen_digest(f4)
    good = (d4 == SHIPPED_D4 == tree_d4) and len(pre4) == 296
    ok = ok and good
    lines.append("  C6   %s  D4 = 0x%016x (shipped 0x%016x, dnac.h "
                 "0x%016x, preimage %d B)"
                 % ("OK  " if good else "FAIL", d4, SHIPPED_D4, tree_d4,
                    len(pre4)))
    return ok, lines, pol, s4, c4, d4


# ── main ──────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--owner", default=K8_OWNER_HEX,
                    help="foundation owner, 128 hex chars (default: K8)")
    args = ap.parse_args()
    owner_hex = args.owner.strip().lower()
    if len(owner_hex) != 128:
        print("--owner must be exactly 128 hex chars (64 bytes)")
        return 2
    owner = bytes.fromhex(owner_hex)
    k8 = bytes.fromhex(K8_OWNER_HEX)

    ok, clines, pol, s4, c4, d4 = controls(k8)
    print("── CONTROL (must all be OK, else nothing is emitted) " + "─" * 14)
    for ln in clines:
        print(ln)
    if not ok:
        print("CONTROL FAILED — refusing to emit generation-5 values")
        return 1
    print()

    # generation-5 descriptors: gen-4 with ONLY ruleset_version bumped
    assert SYS_V_G5 > SYS_V_G4 and CORE_V_G5 > CORE_V_G4
    zero = b"\x00" * 64
    sys4_pre = ruleset_preimage(DOMAIN_SYSTEM, "SYSTEM", RUNTIME_ABI_V1,
                                SYS_V_G4, SYS_RULES_G4, SYS_TYPES, pol)
    sys5_pre = ruleset_preimage(DOMAIN_SYSTEM, "SYSTEM", RUNTIME_ABI_V1,
                                SYS_V_G5, SYS_RULES_G4, SYS_TYPES, pol)
    core4_pre = ruleset_preimage(DOMAIN_CORE, "DNA_CORE", RUNTIME_ABI_V1,
                                 CORE_V_G4, CORE_RULES_G34, CORE_TYPES, zero)
    core5_pre = ruleset_preimage(DOMAIN_CORE, "DNA_CORE", RUNTIME_ABI_V1,
                                 CORE_V_G5, CORE_RULES_G34, CORE_TYPES, zero)
    # the version field sits at offset 16+4+4+32+4 = 60..63
    for a, b in ((sys4_pre, sys5_pre), (core4_pre, core5_pre)):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        assert len(a) == len(b) and diff and min(diff) >= 60 \
            and max(diff) <= 63, "gen-5 differs outside ruleset_version"
    r1 = hashlib.sha3_512(sys5_pre).digest()
    r2 = hashlib.sha3_512(core5_pre).digest()
    assert r1 != s4 and r2 != c4

    # Once the C table pins generation 5 (P1d regenerates the pins
    # header), compare its values with R1 / R2 — a report line, not a
    # gate: the C value is the thing this oracle checks.
    pins = _read(PINS_H)
    print("── G5 PINS in nodus_ruleset_pins.h (compared, not trusted) " + "─" * 7)
    if pins_has(pins, "NODUS_PIN_G5_SYS_RULESET_HASH_INIT") or \
            pins_has(pins, "NODUS_PIN_G5_CORE_RULESET_HASH_INIT"):
        for label, mac_h, mac_v, want_h, want_v in (
                ("SYSTEM", "NODUS_PIN_G5_SYS_RULESET_HASH_INIT",
                 "NODUS_PIN_G5_SYS_RULESET_VERSION", r1, SYS_V_G5),
                ("CORE", "NODUS_PIN_G5_CORE_RULESET_HASH_INIT",
                 "NODUS_PIN_G5_CORE_RULESET_VERSION", r2, CORE_V_G5)):
            got_h = pins_bytes(pins, mac_h) if pins_has(pins, mac_h) else ""
            got_v = pins_u32(pins, mac_v) if pins_has(pins, mac_v) else -1
            same = got_h == want_h.hex() and got_v == want_v
            print("  %-6s %s  pinned v%d %s… / oracle v%d %s…"
                  % (label, "OK      " if same else "MISMATCH", got_v,
                     got_h[:16], want_v, want_h.hex()[:16]))
    else:
        print("  generation 5 not pinned yet (NODUS_PIN_G5_* absent)")
    print()

    print("── R1 SYSTEM ruleset v%d (generation 5) " % SYS_V_G5 + "─" * 27)
    print("  domain 0, \"SYSTEM\", abi 1, rules %s, types %s,"
          % (SYS_RULES_G4, SYS_TYPES))
    print("  meter_policy_digest = C1 (ops 1..9 weight 1) %s" % pol.hex())
    print("  descriptor preimage (%d B) = %s" % (len(sys5_pre),
                                                 sys5_pre.hex()))
    print("  R1 = %s" % r1.hex())
    print("  (gen-4 SYSTEM v%d = %s)" % (SYS_V_G4, s4.hex()))
    print()
    print("── R2 DNA_CORE ruleset v%d (generation 5) " % CORE_V_G5 + "─" * 25)
    print("  domain 1, \"DNA_CORE\", abi 1, rules %s, types %s, policy zero"
          % (CORE_RULES_G34, CORE_TYPES))
    print("  descriptor preimage (%d B) = %s" % (len(core5_pre),
                                                 core5_pre.hex()))
    print("  R2 = %s" % r2.hex())
    print("  (gen-4 CORE v%d = %s)" % (CORE_V_G4, c4.hex()))
    print()

    f5 = rolegen_fields(GEN5, GEN5_BASE, r1, r2, HF7_SPEC, owner,
                        HF7_VOTE_CONSTS)
    pre5, dig5, raw5, d5 = rolegen_digest(f5)
    assert len(pre5) == 232

    print("── D5 HF-7 generation-5 vote value (param 22) " + "─" * 20)
    print("  spec: snapshot design §10.2 item 1, §10.9, §10.11 C; layout "
          "domain_wire.h dna_rolegen_vote_digest")
    print("  owner: %s" % ("K8 (default, DNAC_HF6_FOUNDATION_OWNER)"
                           if owner_hex == K8_OWNER_HEX
                           else "OVERRIDE (--owner)"))
    print()
    print("  preimage breakdown (offset, length, field, hex):")
    off = 0
    for nm, b in f5:
        print("  [%3d +%2d] %s" % (off, len(b), nm))
        print("            %s" % b.hex())
        off += len(b)
    print()
    print("  preimage (%d B) = %s" % (len(pre5), pre5.hex()))
    print("  SHA3-512        = %s" % dig5.hex())
    print("  first 8 BE      = 0x%016x" % raw5)
    print("  top bit was     = %s" % ("SET (cleared)" if raw5 >> 63 else
                                      "clear (unchanged)"))
    print("  D5              = 0x%016xULL" % d5)
    print("  D5 (decimal)    = %d" % d5)
    print()
    print("  C: _Static_assert(<D5 macro> == 0x%016xULL, "
          "\"D5 = hf7_vote_oracle.py\");" % d5)
    print()
    distinct = all(d5 != v for _, v in OTHER_LITERALS)
    print("  sanity: D5 differs from %s: %s"
          % (", ".join("%s 0x%016x" % (n, v) for n, v in OTHER_LITERALS),
             distinct))
    assert distinct
    return 0


if __name__ == "__main__":
    sys.exit(main())
