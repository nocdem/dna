#!/usr/bin/env python3
r"""
Independent oracle for the HF-6 generation-4 vote value D4 (chain_config
param 18 RULESET_GEN_ROLES).

SPECIFICATION (approved by the operator 2026-10-09, "approved"; the
296-byte sum fixed by the khan 2026-10-13, "önerilerle"):
docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6 §8.1 —

  D4 = first 8 bytes, big-endian, top bit cleared, of SHA3-512(
         TAG16("NDS.ROLEGEN.v1")                 16
       ‖ generation u32 BE = 4                     4
       ‖ base_generation u32 BE = 3 (GEN_EVM)      4
       ‖ gen-4 SYSTEM ruleset_hash[64]            64
       ‖ gen-4 CORE ruleset_hash[64]              64
       ‖ spec_version u32 BE = 1                   4
       ‖ foundation_owner[64]                     64
       ‖ n_consts u32 BE = 9                       4
       ‖ n_consts × u64 BE                        72 )   = 296 bytes

TAG16 = the NDS.* convention: ASCII, right-padded with 0x00 to 16 bytes
(design §8.1 "etiket biçimi NDS.* 16 B sağdan 0x00 dolgulu"; the same
padding as ruleset_desc_oracle.tag16 and effect_wire_oracle's
b"NDS.EFFRES.v1".ljust(16, b"\0")).

CONSTANTS, in the §8.1 order (1 NODUS = 10^8 raw, dnac.h
DNAC_DEFAULT_TOTAL_SUPPLY comment "8 decimals"):
  1 STAKE_MIN default        2M NODUS   design §8 param 19 "vars. 2M";
                                        decision 2026-10-08-kurultay-14 K9;
                                        2026-10-03-role-stake-amounts
                                        "varsayılan 2M"
  2 STAKE_MIN lower bound  100k NODUS   K9 "alt sınır 100.000 NODUS";
                                        role-stake-amounts "alt sınır 100k"
  3 POWER_CAP_BPS default       3000    design §8 param 20 "vars. 3000";
                                        kurultay-16 item 7
  4 POWER_CAP_BPS min            500    K5 "[500, 3000] bps"
  5 POWER_CAP_BPS max           3000    K5
  6 STORAGE_BOND default     1M NODUS   kurultay-16 khan decision 3
                                        ("100k 1m"): default 1M
  7 STORAGE_BOND min       100k NODUS   kurultay-16 khan decision 3
  8 STORAGE_BOND max         1M NODUS   kurultay-16 khan decision 3 (the
                                        earlier INT64_MAX proposal in its
                                        items 7 / "Hana giden" 3 was
                                        withdrawn by that decision); design
                                        §8 param 21 "[100k NODUS, 1M NODUS]"
  9 consent window        720 blocks    design §6.1 "expiry − h ≤ 720"
                                        (a fixed literal, not E)

INPUTS FROM OTHER ORACLES (not from C):
  * gen-4 SYSTEM / CORE ruleset hashes = storage_oracle.py S2 / S3. They
    are recomputed here through storage_oracle's own builders (after its
    CONTROL leg passes), cross-checked against storage_oracle.py run as a
    separate process, and against the hex pinned below.
  * foundation_owner default = K8 (decision 2026-10-08-kurultay-14 K8,
    verified 2026-10-08 as the 2-of-3 nocdem/bios/one multisig address);
    the same 64 bytes are in dnac.h DNAC_HF6_FOUNDATION_OWNER.
    --owner <128 hex> overrides it (test builds compile their own owner).

INDEPENDENCE: no C encoder for D4 was read or exists; the digest is built
here by hashlib.sha3_512 (FIPS 202) from the §8.1 text.

Run:  python3 shared/dnac/tests/hf6_vote_oracle.py [--owner <128 hex>]

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import argparse
import contextlib
import hashlib
import io
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import storage_oracle as so  # noqa: E402
from ruleset_desc_oracle import tag16 as rd_tag16  # noqa: E402

RAW = 100000000  # 1 NODUS = 10^8 raw

TAG = "NDS.ROLEGEN.v1"
GENERATION = 4
BASE_GENERATION = 3
SPEC_VERSION = 1

CONSTS = [
    ("STAKE_MIN default",        2000000 * RAW),
    ("STAKE_MIN lower bound",     100000 * RAW),
    ("POWER_CAP_BPS default",       3000),
    ("POWER_CAP_BPS min",            500),
    ("POWER_CAP_BPS max",           3000),
    ("STORAGE_BOND default",     1000000 * RAW),
    ("STORAGE_BOND min",          100000 * RAW),
    ("STORAGE_BOND max",         1000000 * RAW),
    ("consent window (blocks)",      720),
]

# decision 2026-10-08-kurultay-14-hf6-summary.md K8
K8_OWNER_HEX = (
    "8eff7f418ab7a4432118ff99e21f2c3d1baf186200c148a3bba7d274499386ac"
    "970e267a9c9b3bbc05bfff1c62a72d63f72a555db780feeaaad4fb49ba9f7b89")

# storage_oracle.py S2 / S3 as emitted at 3ef75a40 (checked, not trusted:
# the run below must reproduce them)
PIN_S2 = (
    "c347ddd7b30730b17fe62583a663356a303c548dd2fc0dab7fa8dfdfea63140b"
    "25c1f496590a66c8373c3e50d23cbaa5f5730097ee041eca50ed377a1f924b00")
PIN_S3 = (
    "fb25e5c41d600f0ed4e8979fb434d735b62ffe9aca0332770f95a94b338d1073"
    "ec3ec3b5aa59303467cc83fddca2b8baf1002dcab2c6c304974c06381437f060")

# vote literals D4 must not collide with
D2_LITERAL = 0x44dfbe7ad3c75adf        # generation 2, param 9
EVM_D_LITERAL = 0x029f47596864d407     # EVM_ACTIVE, param 14
SLICE6A_LITERAL = 0x329b0ea92c8b8c58   # storage-only gen 4 (param 16), dev

PREIMAGE_LEN = 16 + 4 + 4 + 64 + 64 + 4 + 64 + 4 + 8 * 9
assert PREIMAGE_LEN == 296


def tag16(s: str) -> bytes:
    raw = s.encode("ascii")
    if len(raw) > 16:
        raise ValueError("tag longer than 16 bytes: %r" % s)
    return raw.ljust(16, b"\x00")


def be32(x: int) -> bytes:
    return struct.pack(">I", x)


def be64(x: int) -> bytes:
    return struct.pack(">Q", x)


def gen4_hashes():
    """S2 / S3 through storage_oracle's builders, after its control."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = so.control()
    if not ok:
        sys.stdout.write(buf.getvalue())
        raise SystemExit("storage_oracle CONTROL failed — refusing")
    s1 = so.system_policy(so.POLICY_MAX_OP_STORAGE)
    s2 = so.system_rs_rules(so.SYS_RULESET_VERSION_STORAGE,
                            so.SYS_RULES_STORAGE, s1)
    s3 = so.ruleset_hash(so.DOMAIN_CORE, "DNA_CORE", so.RUNTIME_ABI_V1,
                         so.CORE_RULESET_VERSION_STORAGE,
                         so.CORE_RULES_STORAGE, so.CORE_TYPES_STORAGE,
                         b"\x00" * 64)
    return s2, s3


def storage_oracle_subprocess():
    """S2 / S3 as printed by storage_oracle.py run on its own."""
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "storage_oracle.py")],
        check=True, capture_output=True, text=True).stdout
    vals = {}
    for line in out.splitlines():
        line = line.strip()
        for key in ("S2", "S3"):
            if line.startswith(key + " = "):
                vals[key] = line[len(key) + 3:]
    return vals["S2"], vals["S3"]


def build_preimage(s2: bytes, s3: bytes, owner: bytes):
    fields = [
        ("TAG16(\"%s\")" % TAG, tag16(TAG)),
        ("generation u32 BE = %d" % GENERATION, be32(GENERATION)),
        ("base_generation u32 BE = %d" % BASE_GENERATION,
         be32(BASE_GENERATION)),
        ("gen-4 SYSTEM ruleset_hash (S2)", s2),
        ("gen-4 CORE ruleset_hash (S3)", s3),
        ("spec_version u32 BE = %d" % SPEC_VERSION, be32(SPEC_VERSION)),
        ("foundation_owner", owner),
        ("n_consts u32 BE = %d" % len(CONSTS), be32(len(CONSTS))),
    ]
    for i, (name, v) in enumerate(CONSTS):
        fields.append(("const[%d] %s = %d" % (i, name, v), be64(v)))
    pre = b"".join(f[1] for f in fields)
    if len(pre) != PREIMAGE_LEN:
        raise AssertionError("preimage length %d != 296" % len(pre))
    return pre, fields


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

    assert tag16(TAG) == rd_tag16(TAG)
    assert len(tag16(TAG)) == 16

    s2, s3 = gen4_hashes()
    p_s2, p_s3 = storage_oracle_subprocess()
    assert s2.hex() == p_s2 == PIN_S2, "S2 mismatch"
    assert s3.hex() == p_s3 == PIN_S3, "S3 mismatch"

    pre, fields = build_preimage(s2, s3, owner)
    dig = hashlib.sha3_512(pre).digest()
    raw = int.from_bytes(dig[:8], "big")
    top = raw >> 63
    d4 = raw & 0x7FFFFFFFFFFFFFFF

    print("── HF-6 generation-4 vote value D4 (param 18) " + "─" * 20)
    print("  spec: design 2026-10-03-hf5-validator-owner-stake rev 6 §8.1")
    print("  storage_oracle CONTROL: green; S2/S3 equal in-process, "
          "subprocess and pinned hex")
    print("  owner: %s" % ("K8 (default)" if owner_hex == K8_OWNER_HEX
                           else "OVERRIDE (--owner)"))
    print()
    print("  preimage breakdown (offset, length, field, hex):")
    off = 0
    for name, b in fields:
        print("  [%3d +%2d] %s" % (off, len(b), name))
        print("            %s" % b.hex())
        off += len(b)
    print()
    print("  preimage (%d B) = %s" % (len(pre), pre.hex()))
    print("  SHA3-512        = %s" % dig.hex())
    print("  first 8 BE      = 0x%016x" % raw)
    print("  top bit was     = %s" % ("SET (cleared)" if top else
                                      "clear (unchanged)"))
    print("  D4              = 0x%016xULL" % d4)
    print("  D4 (decimal)    = %d" % d4)
    print()
    print("  C: _Static_assert(<D4 macro> == 0x%016xULL, "
          "\"D4 = hf6_vote_oracle.py\");" % d4)
    print()
    distinct = (d4 != D2_LITERAL and d4 != EVM_D_LITERAL
                and d4 != SLICE6A_LITERAL)
    print("  sanity: D4 != D2 0x%016x, != EVM D 0x%016x, != slice-6a "
          "0x%016x: %s" % (D2_LITERAL, EVM_D_LITERAL, SLICE6A_LITERAL,
                           distinct))
    assert distinct
    return 0


if __name__ == "__main__":
    sys.exit(main())
