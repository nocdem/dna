#!/usr/bin/env python3
r"""Independent oracle for the HF-9 generation-6 vote value D6 (chain_config
param 24, RULESET_GEN_TRIE) and the two generation-6 ruleset hashes it binds.

Plan: docs/plans/approved/2026-11-04-hf9.md section 7.1 (D6 =
dna_rolegen_vote_digest(6, 5, SYS-gen6 ruleset hash, CORE-gen6 ruleset hash,
spec_version 1, the HF-6 Foundation owner unchanged, HF9_VOTE_CONSTS =
[1024, 4, 4, 16])), section 15 AD-7 (layout approved by the operator, D24
"3, evet."), section 15a A8 / A9 / F-15 / F-17 ("re-derives D4 and D5 as
controls before printing D6"). Precedent (format): hf7_vote_oracle.py.

WHAT IT DOES
  BEFORE it prints D6 it re-derives, through the SAME code path, the pinned
  generation-4 and generation-5 values and refuses (exit 1) unless every one
  is byte-equal:
    C1  gen-5 SYSTEM meter-policy identity digest (ops 1..9)
                       nodus_ruleset_pins.h NODUS_PIN_G5_SYS_METER_POLICY_
                       DIGEST_INIT
    C2  gen-4 SYSTEM v10 / CORE v9 ruleset hashes     NODUS_PIN_G4_*
    C3  gen-5 SYSTEM v11 / CORE v10 ruleset hashes    NODUS_PIN_G5_*
    C4  D4 (generation 4, base 3, spec 1, owner K8, nine constants)
        dnac.h DNAC_CFG_RULESET_GEN_ROLES_D
    C5  D5 (generation 5, base 4, spec 1, owner K8, [720])
        dnac.h DNAC_CFG_RULESET_GEN_ROOTS_D
  Each pinned value is a TEXT read of the data in the tree (no C called).
  Generation 6 = the generation-5 descriptors with ONLY ruleset_version
  bumped (SYSTEM 11 -> 12, CORE 10 -> 11), plan 7.1; the oracle asserts the
  descriptor preimages differ only in bytes 60..63.

PROVENANCE (what was read; nothing else)
  Author != the author of the HF-9 C code. No HF-9 C file was opened.
  Written from
    * the approved plan, sections 7.1, 15 (AD-7), 15a (A8, A9, F-15, F-17);
    * shared/dnac/domain_wire.c :290-349 (dna_rolegen_vote_digest: tag
      "NDS.ROLEGEN.v1" zero-padded to 16, generation u32 BE, base u32 BE,
      SYSTEM ruleset hash 64, CORE ruleset hash 64, spec_version u32 BE,
      foundation owner 64, n_consts u32 BE, n_consts x u64 BE; the digest's
      first 8 bytes read big-endian, top bit cleared);
    * shared/dnac/tests/hf7_vote_oracle.py (read: the RulesetDescriptor v2
      layout, the meter-policy identity layout, the descriptor contents of
      generations 4 / 5 and the nine HF-6 constants are taken from it and
      re-written here; they are confirmed only by the controls above);
    * data parsed at run time: nodus/include/nodus/nodus_ruleset_pins.h
      (NODUS_PIN_G4_* / G5_*), dnac/include/dnac/dnac.h
      (DNAC_HF6_FOUNDATION_OWNER, DNAC_CFG_RULESET_GEN_ROLES_D,
      DNAC_CFG_RULESET_GEN_ROOTS_D); shared/dnac/ledger_ids.h :52-53 for the
      domain ids (0 SYSTEM, 1 CORE).

HONEST LABEL
  SELF-CONSISTENT. The controls prove this file reproduces the already
  pinned D4, D5 and generation-4 / -5 hashes from the same layouts, so the
  layout code is the shipped one; the generation-6 values rest on the plan's
  rule ("only ruleset_version bumped", 12 / 11) and the approved constants.
  A later change that adds a rule, a type or an op, or a different version
  number chosen by the registry code, makes the printed values wrong for it.
  D6 is a fixed activation identifier and drift check, not a security
  commitment (plan AD-7). The owner is the compiled default (K8); a build
  with another owner has a different D6.

Run:  python3 -I -B shared/dnac/tests/hf9_vote_oracle.py
      (importable by path: derive(check) returns the data that
      nodus/tests/vectors/hf9_kat_oracle.py puts in hf9_kat.json)

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import sys

sys.dont_write_bytecode = True

import hashlib  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import struct  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
PINS_H = os.path.join(REPO, "nodus", "include", "nodus",
                      "nodus_ruleset_pins.h")
DNAC_H = os.path.join(REPO, "dnac", "include", "dnac", "dnac.h")

DOMAIN_SYSTEM = 0
DOMAIN_CORE = 1
RULESET_DESC_VERSION = 2
METER_POLICY_VERSION = 2
MAX_BLOCK_ENV_BYTES = 2 * 1048576
OP_SPACE = 256
SYS_RULES = [1, 2, 3, 4, 5, 6, 7, 8, 9]
SYS_TYPES = [4, 5, 6, 7, 9, 10]
CORE_RULES = [1, 2, 3, 4, 5, 6, 7, 8, 9]
CORE_TYPES = [1, 2, 3, 11, 12, 13]
GEN4_VOTE_CONSTS = [2000000 * 10 ** 8, 100000 * 10 ** 8, 3000, 500, 3000,
                    1000000 * 10 ** 8, 100000 * 10 ** 8, 1000000 * 10 ** 8,
                    720]
HF9_VOTE_CONSTS = [1024, 4, 4, 16]       # cap, copies default, min, max
SYS_RV_G6, CORE_RV_G6 = 12, 11           # plan 7.1


def sha3(b):
    return hashlib.sha3_512(bytes(b)).digest()


def be2(x):
    return struct.pack(">H", x)


def be4(x):
    return struct.pack(">I", x)


def be8(x):
    return struct.pack(">Q", x)


def tag16(s):
    raw = s.encode("ascii")
    assert len(raw) <= 16
    return raw + b"\x00" * (16 - len(raw))


def X(b):
    return bytes(b).hex()


def D(n):
    return str(int(n))


def name32(s):
    raw = s.encode("ascii")
    return raw + b"\x00" * (32 - len(raw))


def meter_policy_identity(max_op):
    w_op = [0] * OP_SPACE
    present = [0] * (OP_SPACE // 64)
    for op in range(1, max_op + 1):
        w_op[op] = 1
        present[op // 64] |= 1 << (op % 64)
    pre = tag16("NDS.METPOLID.v1") + be4(METER_POLICY_VERSION)
    for w in (1, 1, 1, 1, 1, 1, 1, MAX_BLOCK_ENV_BYTES):
        pre += be8(w)
    for w in w_op:
        pre += be8(w)
    for w in present:
        pre += be8(w)
    assert len(pre) == 2164
    return sha3(pre)


def ruleset_preimage(domain_id, name, version, rules, types, policy):
    pre = tag16("NDS.RULESET.v1") + be4(RULESET_DESC_VERSION) + \
        be4(domain_id) + name32(name) + be4(1) + be4(version) + \
        be2(len(rules)) + b"".join(be4(r) for r in rules) + \
        be2(len(types)) + bytes(types) + policy
    assert len(policy) == 64
    return pre


def rolegen_preimage(gen, base, sys_h, core_h, spec, owner, consts):
    assert len(sys_h) == 64 and len(core_h) == 64 and len(owner) == 64
    pre = (tag16("NDS.ROLEGEN.v1") + be4(gen) + be4(base) + sys_h + core_h +
           be4(spec) + owner + be4(len(consts)) +
           b"".join(be8(c) for c in consts))
    assert len(pre) == 16 + 4 + 4 + 128 + 4 + 64 + 4 + 8 * len(consts)
    dig = sha3(pre)
    raw = int.from_bytes(dig[:8], "big")
    return pre, dig, raw, raw & 0x7FFFFFFFFFFFFFFF


def pins_bytes(text, macro):
    m = re.search(r"#define\s+%s\s*\{\s*\\?(.*?)\}" % re.escape(macro), text,
                  re.S)
    vals = re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))
    assert len(vals) == 64, macro
    return bytes.fromhex("".join(vals))


def derive(check):
    """check(name, ok, detail='') must abort on failure. Returns the dict
    stored under vectors.votes in hf9_kat.json."""
    pins = open(PINS_H, "r", encoding="utf-8").read()
    dnac = open(DNAC_H, "r", encoding="utf-8").read()
    m = re.search(r"#define\s+DNAC_HF6_FOUNDATION_OWNER\s*\{(.*?)\}", dnac,
                  re.S)
    owner = bytes.fromhex("".join(re.findall(r"0x([0-9a-fA-F]{2})",
                                             m.group(1))))
    assert len(owner) == 64
    d4_lit = int(re.search(r"#define\s+DNAC_CFG_RULESET_GEN_ROLES_D\s+"
                           r"0x([0-9a-fA-F]+)ULL", dnac).group(1), 16)
    d5_lit = int(re.search(r"#define\s+DNAC_CFG_RULESET_GEN_ROOTS_D\s+"
                           r"0x([0-9a-fA-F]+)ULL", dnac).group(1), 16)
    zero = b"\x00" * 64
    pol = meter_policy_identity(9)
    check("meter policy digest (ops 1..9) == NODUS_PIN_G5_SYS_METER_POLICY_"
          "DIGEST_INIT",
          pol == pins_bytes(pins, "NODUS_PIN_G5_SYS_METER_POLICY_DIGEST_"
                            "INIT"))

    def sysh(v):
        return sha3(ruleset_preimage(DOMAIN_SYSTEM, "SYSTEM", v, SYS_RULES,
                                     SYS_TYPES, pol))

    def coreh(v):
        return sha3(ruleset_preimage(DOMAIN_CORE, "DNA_CORE", v, CORE_RULES,
                                     CORE_TYPES, zero))
    check("SYSTEM v10 ruleset hash == NODUS_PIN_G4_SYS_RULESET_HASH_INIT",
          sysh(10) == pins_bytes(pins, "NODUS_PIN_G4_SYS_RULESET_HASH_INIT"))
    check("CORE v9 ruleset hash == NODUS_PIN_G4_CORE_RULESET_HASH_INIT",
          coreh(9) == pins_bytes(pins, "NODUS_PIN_G4_CORE_RULESET_HASH_INIT"))
    check("SYSTEM v11 ruleset hash == NODUS_PIN_G5_SYS_RULESET_HASH_INIT",
          sysh(11) == pins_bytes(pins, "NODUS_PIN_G5_SYS_RULESET_HASH_INIT"))
    check("CORE v10 ruleset hash == NODUS_PIN_G5_CORE_RULESET_HASH_INIT",
          coreh(10) == pins_bytes(pins, "NODUS_PIN_G5_CORE_RULESET_HASH_INIT"))
    pre4, _, _, d4 = rolegen_preimage(4, 3, sysh(10), coreh(9), 1, owner,
                                      GEN4_VOTE_CONSTS)
    check("D4 re-derived == dnac.h DNAC_CFG_RULESET_GEN_ROLES_D "
          "0x%016x (preimage %d B)" % (d4_lit, len(pre4)),
          d4 == d4_lit and len(pre4) == 296)
    pre5, _, _, d5 = rolegen_preimage(5, 4, sysh(11), coreh(10), 1, owner,
                                      [720])
    check("D5 re-derived == dnac.h DNAC_CFG_RULESET_GEN_ROOTS_D "
          "0x%016x (preimage %d B)" % (d5_lit, len(pre5)),
          d5 == d5_lit and len(pre5) == 232)
    # D6: generation 6, base 5, gen-5 descriptors with ruleset_version only
    # bumped (SYSTEM 12 / CORE 11, plan 7.1)
    s6, c6 = sysh(SYS_RV_G6), coreh(CORE_RV_G6)
    a = ruleset_preimage(DOMAIN_SYSTEM, "SYSTEM", 11, SYS_RULES, SYS_TYPES,
                         pol)
    b = ruleset_preimage(DOMAIN_SYSTEM, "SYSTEM", SYS_RV_G6, SYS_RULES,
                         SYS_TYPES, pol)
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    check("gen-6 SYSTEM descriptor differs from gen-5 only in ruleset_version "
          "bytes 60..63", len(a) == len(b) and diff and min(diff) >= 60 and
          max(diff) <= 63)
    pre6, dig6, raw6, d6 = rolegen_preimage(6, 5, s6, c6, 1, owner,
                                            HF9_VOTE_CONSTS)
    check("D6 preimage is 256 bytes (n = 4)", len(pre6) == 256)
    others = {"D2 (param 9)": 0x44dfbe7ad3c75adf,
              "EVM_ACTIVE (param 14)": 0x029f47596864d407,
              "slice-6a gen 4 (param 16, dev)": 0x329b0ea92c8b8c58,
              "D4": d4_lit, "D5": d5_lit}
    check("D6 differs from D2, D4, D5 and the other shipped literals",
          all(d6 != x for x in others.values()))
    return {
        "controls": {
            "D4": {"derived": "0x%016x" % d4, "dnac_h_literal":
                   "0x%016x" % d4_lit, "preimage_len": len(pre4),
                   "consts": [D(c) for c in GEN4_VOTE_CONSTS]},
            "D5": {"derived": "0x%016x" % d5, "dnac_h_literal":
                   "0x%016x" % d5_lit, "preimage_len": len(pre5),
                   "consts": [D(720)]},
            "gen4_sys_ruleset_hash": X(sysh(10)),
            "gen4_core_ruleset_hash": X(coreh(9)),
            "gen5_sys_ruleset_hash": X(sysh(11)),
            "gen5_core_ruleset_hash": X(coreh(10)),
            "meter_policy_digest_ops_1_9": X(pol)},
        "D6": {
            "generation": 6, "base_generation": 5, "spec_version": 1,
            "foundation_owner": X(owner),
            "consts": [D(c) for c in HF9_VOTE_CONSTS],
            "consts_meaning": "cap, copies default, copies min, copies max",
            "sys_gen6_ruleset_version": SYS_RV_G6,
            "core_gen6_ruleset_version": CORE_RV_G6,
            "sys_gen6_ruleset_hash": X(s6), "core_gen6_ruleset_hash": X(c6),
            "preimage": X(pre6), "preimage_len": len(pre6),
            "sha3_512": X(dig6), "first_8_bytes_be": "0x%016x" % raw6,
            "top_bit_cleared": bool(raw6 >> 63),
            "value": "0x%016x" % d6, "value_decimal": D(d6)}}


def main():
    def check(name, ok, detail=""):
        print("  %-4s %s%s" % ("OK" if ok else "FAIL", name,
                               (" -- " + detail) if detail else ""))
        if not ok:
            print("CONTROL FAILED -- refusing to print D6")
            sys.exit(1)

    print("-- CONTROLS: D4 and D5 re-derived before D6 (all must be OK)")
    v = derive(check)
    d6 = v["D6"]
    print()
    print("-- D6 HF-9 generation-6 vote value (param 24)")
    print("  SYSTEM v%d ruleset hash = %s" % (d6["sys_gen6_ruleset_version"],
                                              d6["sys_gen6_ruleset_hash"]))
    print("  CORE   v%d ruleset hash = %s" % (d6["core_gen6_ruleset_version"],
                                              d6["core_gen6_ruleset_hash"]))
    print("  constants %s (%s)" % (d6["consts"], d6["consts_meaning"]))
    print("  preimage (%d B) = %s" % (d6["preimage_len"], d6["preimage"]))
    print("  SHA3-512        = %s" % d6["sha3_512"])
    print("  first 8 BE      = %s" % d6["first_8_bytes_be"])
    print("  D6              = %sULL" % d6["value"])
    print("  D6 (decimal)    = %s" % d6["value_decimal"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
