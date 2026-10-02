#!/usr/bin/env python3
r"""
Independent oracle for the HF-4 registry switch KATs (design
docs/plans/2026-10-02-onchain-names-design.md §1.4; decision
docs/plans/decisions/2026-10-02-onchain-names.md).

Computes, for the SYSTEM / DNA_CORE fixture defined by the test author:
  K1  DOMMAN hash of the post-switch SYSTEM manifest (generation 2)
  K2  DOMMAN hash of the post-switch DNA_CORE manifest (generation 2)
  K3  domain_registry_root over the two post-switch records
and, for reference, the same three values before the switch (gen 1).

INDEPENDENCE DISCIPLINE
-----------------------
Written from the SHIPPED written contracts, not from any C switch code:

  DomainManifest v1 — shared/dnac/domain_wire.h:60-79
      off   0 manifest_version u32 BE (= 1)          domain_wire.h:61
      off   4 domain_id u32 BE                       domain_wire.h:62
      off   8 name[32] ASCII zero-padded             domain_wire.h:63-64
      off  40 runtime_kind u8                        domain_wire.h:65
      off  41 runtime_abi u32 BE                     domain_wire.h:66
      off  45 ruleset_version u32 BE                 domain_wire.h:67
      off  49 ruleset_hash[64]                       domain_wire.h:68
      off 113 genesis_state_root[64]                 domain_wire.h:69
      off 177 tx_type_count u16 BE                   domain_wire.h:70
      off 179 tx_types[count] u8 strictly ascending  domain_wire.h:71
      then fee_policy u8, quota_tx_per_block u16 BE, quota_verify_cost
           u32 BE, upgrade_authority u8, activation_epoch u64 BE,
           readiness_policy u32 BE                   domain_wire.h:72-78
      length 199 + count                             domain_wire.h:60,206-209
      manifest_hash = SHA3-512("NDS.DOMMAN.v1" ‖ bytes)  domain_wire.h:79
  DomainRegistryRecord v1 (223 bytes) — domain_wire.h:88-100
      record_version u32 ‖ domain_id u32 ‖ status u8
      ‖ current_manifest_hash[64] ‖ pending_present u8
      ‖ pending_manifest_hash[64] ‖ proposal_present u8
      ‖ proposal_digest[64] ‖ scheduled_activation_epoch u64
      ‖ readiness_deadline_epoch u64 ‖ postpone_count u32   (all BE)
      leaf = SHA3-512("NDS.DRLEAF.v1" ‖ 223 bytes)   domain_wire.h:100
  Registry root — domain_wire.h:144-152
      leaves strictly ascending domain_id, first MUST be SYSTEM (0);
      inner = SHA3-512("NDS.DRNODE.v1" ‖ L ‖ R); odd node PROMOTED;
      n == 1 → the leaf; n == 0 → SHA3-512("NDS.E.DOMREG.v1")
      (ledger_roots_v2.c:69 tag, :89-92 construction).
  Shipped ordering: nodus/src/witness/nodus_witness_domreg.c:251-286
      (nodus_witness_domreg_root) — SELECT ... ORDER BY domain_id ASC,
      then dna_domreg_root over that array.
  Tags: 16 bytes, zero-padded ASCII (domain_wire.h:36,50-58).
  Enum values: NATIVE_BUILTIN 1 (domain_wire.h:181), GLOBAL_BURN 1 (:184),
      CHAIN_CONFIG 1 (:187), STAGED_V1 1 (:190), ACTIVE 3 (:196).
  DNA_DOMAIN_SYSTEM 0, DNA_DOMAIN_CORE 1 — shared/dnac/ledger_ids.h:52-53.

CONTROL LEG (fail-closed): the shipped KATs in
nodus/tests/test_domain_wire.c:62-90 (manifest A/B, leaf SYS/CORE, root
n=2, root n=3 with odd promotion, empty registry root) over the fixtures
at test_domain_wire.c:97-137 and :286-350 are re-derived here byte-exactly
before anything is emitted.

Run:  python3 shared/dnac/tests/hf4_switch_oracle.py
"""

import hashlib
import os
import struct
import sys

# ── primitives ─────────────────────────────────────────────────────────


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
    """domain_wire.h:63-64 — ASCII 0x21..0x7E, zero-padded, first byte
    non-NUL."""
    raw = s.encode("ascii")
    if not raw or len(raw) > 32 or any(b < 0x21 or b > 0x7E for b in raw):
        raise ValueError("non-canonical name: %r" % s)
    return raw + b"\x00" * (32 - len(raw))


def sha3_512(b: bytes) -> bytes:
    return hashlib.sha3_512(b).digest()


# ── enums (domain_wire.h:180-199) ──────────────────────────────────────

RUNTIME_NATIVE_BUILTIN = 1
FEEPOL_GLOBAL_BURN = 1
UPGAUTH_CHAIN_CONFIG = 1
RDYPOL_STAGED_V1 = 1
DOMST_REGISTERED = 1
DOMST_ACTIVE = 3

DOMAIN_SYSTEM = 0   # ledger_ids.h:52
DOMAIN_CORE = 1     # ledger_ids.h:53

# ── DomainManifest v1 ──────────────────────────────────────────────────


def manifest_bytes(*, domain_id, name, runtime_kind, runtime_abi,
                   ruleset_version, ruleset_hash, genesis_state_root,
                   tx_types, fee_policy, quota_tx_per_block,
                   quota_verify_cost, upgrade_authority, activation_epoch,
                   readiness_policy, manifest_version=1) -> bytes:
    if len(ruleset_hash) != 64 or len(genesis_state_root) != 64:
        raise ValueError("hash fields must be 64 bytes")
    if len(tx_types) > 256:
        raise ValueError("tx_type_count over cap")
    for i in range(1, len(tx_types)):
        if tx_types[i - 1] >= tx_types[i]:
            raise ValueError("tx_types not strictly ascending")
    out = be32(manifest_version)          # off 0
    out += be32(domain_id)                # off 4
    out += name32(name)                   # off 8
    out += bytes([runtime_kind])          # off 40
    out += be32(runtime_abi)              # off 41
    out += be32(ruleset_version)          # off 45
    out += ruleset_hash                   # off 49
    out += genesis_state_root             # off 113
    assert len(out) == 177
    out += be16(len(tx_types))            # off 177
    out += bytes(tx_types)                # off 179
    out += bytes([fee_policy])
    out += be16(quota_tx_per_block)
    out += be32(quota_verify_cost)
    out += bytes([upgrade_authority])
    out += be64(activation_epoch)
    out += be32(readiness_policy)
    if len(out) != 199 + len(tx_types):
        raise AssertionError("manifest length %d" % len(out))
    return out


def manifest_hash(**kw) -> bytes:
    return sha3_512(tag16("NDS.DOMMAN.v1") + manifest_bytes(**kw))


# ── DomainRegistryRecord v1 ────────────────────────────────────────────


def record_bytes(*, domain_id, status, current_manifest_hash,
                 pending_present=0, pending_manifest_hash=b"\x00" * 64,
                 proposal_present=0, proposal_digest=b"\x00" * 64,
                 scheduled_activation_epoch=0, readiness_deadline_epoch=0,
                 postpone_count=0, record_version=1) -> bytes:
    out = be32(record_version)                 # off 0
    out += be32(domain_id)                     # off 4
    out += bytes([status])                     # off 8
    out += current_manifest_hash               # off 9
    out += bytes([pending_present])            # off 73
    out += pending_manifest_hash               # off 74
    out += bytes([proposal_present])           # off 138
    out += proposal_digest                     # off 139
    out += be64(scheduled_activation_epoch)    # off 203
    out += be64(readiness_deadline_epoch)      # off 211
    out += be32(postpone_count)                # off 219
    if len(out) != 223:
        raise AssertionError("record length %d" % len(out))
    return out


def record_leaf(rec: dict) -> bytes:
    return sha3_512(tag16("NDS.DRLEAF.v1") + record_bytes(**rec))


def registry_root(records: list) -> bytes:
    if not records:
        return sha3_512(tag16("NDS.E.DOMREG.v1"))
    if records[0]["domain_id"] != DOMAIN_SYSTEM:
        raise ValueError("first record must be SYSTEM")
    for i in range(1, len(records)):
        if records[i - 1]["domain_id"] >= records[i]["domain_id"]:
            raise ValueError("records not strictly ascending by domain_id")
    level = [record_leaf(r) for r in records]
    node_tag = tag16("NDS.DRNODE.v1")
    while len(level) > 1:
        nxt = [sha3_512(node_tag + level[i] + level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) & 1:
            nxt.append(level[-1])          # odd node PROMOTED unchanged
        level = nxt
    return level[0]


# ── CONTROL LEG: shipped KATs (nodus/tests/test_domain_wire.c:62-90) ───

KAT_MAN_A = ("0084572db50700b49ac67e0a311fc1197fc20380518179078550f6d3cebb79da"
             "49caf708e7d348df9615260b0697a59bf7c4df319d088dea2eeb7e9c00f5553e")
KAT_MAN_B = ("6c863e3e52825c9d6b8e2dee3fec3e49f4c17d63be276782712cdfbd9b0188a6"
             "ec5aac26da29c0e7fd3559f5c0d84a60403bb21b99fa01b99e6152978d0002c1")
KAT_LEAF_SYS = ("f6359b1cade898493337c630ec98f30b83f65655f9e57b9de560ff3ae531da51"
                "e0ed13fd7b561db543f39d23892829de09a67120a94e096d6ae00cde44b38c6a")
KAT_LEAF_CORE = ("e43f925d1536f93f4a3414d0d92e9eefa2d296149500052be3a5fdc6945037a4"
                 "5ccdda9537b37a91098c7ede4b9b9752766ed7b42253f42e576af0cd630f2c37")
KAT_ROOT2 = ("1a46586ae86ce437d7f4cad975bec1f6062a10bb0ae21eecfb1937f6fa3061c2"
             "aafb8a6970ca2e7500b3245310e405a4754d52ea6c9da3d236d483b4087bbb94")
KAT_ROOT3 = ("a35660ab16bc8e9b6501032564e3444ac8bd16721160a4978e40785c3e55549d"
             "c46c27919ba87d3fa686eeca1e021b61621a0d3acb5b41ad03307b884b1925b3")
KAT_EMPTY_DOMREG = ("07b4b225f5c073f998fc7bca7c9071142cb9bebfa619af849a2d47e9a5f61bf2"
                    "b8633cfbd3b83a51daf6940548a8e66bbedb86aa94b0a1001ac378523761ecaf")


def control_leg() -> bool:
    # fixture_manifest_a — test_domain_wire.c:97-117
    man_a = dict(domain_id=0, name="SYSTEM",
                 runtime_kind=RUNTIME_NATIVE_BUILTIN, runtime_abi=1,
                 ruleset_version=1,
                 ruleset_hash=bytes(i + 1 for i in range(64)),
                 genesis_state_root=bytes(i + 65 for i in range(64)),
                 tx_types=[4, 5, 6, 7, 9, 10],
                 fee_policy=FEEPOL_GLOBAL_BURN, quota_tx_per_block=0,
                 quota_verify_cost=0, upgrade_authority=UPGAUTH_CHAIN_CONFIG,
                 activation_epoch=0, readiness_policy=RDYPOL_STAGED_V1)
    # fixture_manifest_b — test_domain_wire.c:119-137
    man_b = dict(domain_id=1, name="DNA_CORE",
                 runtime_kind=RUNTIME_NATIVE_BUILTIN, runtime_abi=1,
                 ruleset_version=2,
                 ruleset_hash=b"\xaa" * 64, genesis_state_root=b"\xbb" * 64,
                 tx_types=[1, 2, 3, 11],
                 fee_policy=FEEPOL_GLOBAL_BURN, quota_tx_per_block=10,
                 quota_verify_cost=1000,
                 upgrade_authority=UPGAUTH_CHAIN_CONFIG,
                 activation_epoch=720, readiness_policy=RDYPOL_STAGED_V1)
    ok = True

    def chk(label, got: bytes, want_hex: str):
        nonlocal ok
        good = got.hex() == want_hex
        print("control %-14s %s" % (label, "MATCH" if good else "MISMATCH"))
        if not good:
            print("   pinned %s\n   got    %s" % (want_hex, got.hex()))
            ok = False

    # lengths pinned at test_domain_wire.c:146-147
    if len(manifest_bytes(**man_a)) != 205 or len(manifest_bytes(**man_b)) != 203:
        print("control manifest lengths MISMATCH")
        ok = False
    ha = manifest_hash(**man_a)
    hb = manifest_hash(**man_b)
    chk("manifest A", ha, KAT_MAN_A)
    chk("manifest B", hb, KAT_MAN_B)
    # fixture_record — test_domain_wire.c:286-294, records :303-304
    rs = dict(domain_id=0, status=DOMST_ACTIVE, current_manifest_hash=ha)
    rc = dict(domain_id=1, status=DOMST_ACTIVE, current_manifest_hash=hb)
    chk("leaf SYS", record_leaf(rs), KAT_LEAF_SYS)
    chk("leaf CORE", record_leaf(rc), KAT_LEAF_CORE)
    chk("root n=1", registry_root([rs]), KAT_LEAF_SYS)
    chk("root n=2", registry_root([rs, rc]), KAT_ROOT2)
    # third record — test_domain_wire.c:333-348
    r3 = dict(domain_id=7, status=DOMST_REGISTERED,
              current_manifest_hash=sha3_512(b"manifest-c"),
              proposal_present=1,
              proposal_digest=sha3_512(b"proposal-fixture"))
    chk("root n=3", registry_root([rs, rc, r3]), KAT_ROOT3)
    chk("empty root", registry_root([]), KAT_EMPTY_DOMREG)
    return ok


# ── optional cross-check of the gen-1 ruleset hashes ───────────────────


def gen1_crosscheck(sys_v6: bytes, core_v4: bytes) -> None:
    """Re-derive the gen-1 ruleset hashes with ruleset_desc_oracle.py (an
    independent oracle already in the tree). Informational only — the gen-1
    and gen-2 hashes are INPUTS here (test author's spec)."""
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    try:
        import ruleset_desc_oracle as rdo
    except Exception as e:  # pragma: no cover
        print("gen-1 cross-check: ruleset_desc_oracle import failed (%s)" % e)
        return
    s = rdo.system_hash(6)
    c = rdo.core_hash(4)
    print("gen-1 cross-check SYSTEM v6 ruleset_hash: %s"
          % ("MATCH" if s == sys_v6 else "MISMATCH " + s.hex()))
    print("gen-1 cross-check CORE   v4 ruleset_hash: %s"
          % ("MATCH" if c == core_v4 else "MISMATCH " + c.hex()))


# ── the HF-4 switch fixture (test author's spec) ───────────────────────

SYS_RS_GEN1 = bytes.fromhex(
    "ca05b4d957d90bab1b7be1f4b9ac8144c5dfa87d4c88948b46adc711d6de6c39"
    "003b3365fa01ac28ef95ce36f377e112d1bdd35b6a0be6e5720832921cdbefa3")
CORE_RS_GEN1 = bytes.fromhex(
    "b87aabb8324dc05fd0544690180cece13b6e286078db99739caa65f006d0b1d1"
    "4154ed74eab78cf48b7fc418dedcad8684a485779aacf2a0a6ae40e00d818852")
SYS_RS_GEN2 = bytes.fromhex(
    "8780a3a9129041e16db275fca2e2bfb8d21aae33371c0b4cafdbcb623159eacb"
    "74854107fad3503ee2e018ec2578377a63001e5156a07d386a7c7b55311d14b4")
CORE_RS_GEN2 = bytes.fromhex(
    "20c7235b13db0f029a8c3be096e24403fd3a3e393e9ff723e0672a6027601a35"
    "0586db18985e7a6ac73365be6cfe65f0fb9ad53357db2d539a1c69d93d81cae5")

COMMON = dict(runtime_kind=RUNTIME_NATIVE_BUILTIN, runtime_abi=1,
              fee_policy=FEEPOL_GLOBAL_BURN, quota_tx_per_block=0,
              quota_verify_cost=0, upgrade_authority=UPGAUTH_CHAIN_CONFIG,
              activation_epoch=0, readiness_policy=RDYPOL_STAGED_V1)


def sys_manifest(version, rs_hash, types):
    return dict(COMMON, domain_id=DOMAIN_SYSTEM, name="SYSTEM",
                ruleset_version=version, ruleset_hash=rs_hash,
                genesis_state_root=b"\x11" * 64, tx_types=types)


def core_manifest(version, rs_hash, types):
    return dict(COMMON, domain_id=DOMAIN_CORE, name="DNA_CORE",
                ruleset_version=version, ruleset_hash=rs_hash,
                genesis_state_root=b"\x22" * 64, tx_types=types)


def print_value(label: str, digest: bytes) -> None:
    print("%s\n  hex: %s" % (label, digest.hex()))
    print("  C:")
    for i in range(0, len(digest), 8):
        print("    " + ", ".join("0x%02x" % b for b in digest[i:i + 8]) + ",")


def main() -> int:
    if not control_leg():
        print("CONTROL LEG FAILED — refusing to emit")
        return 1
    print("CONTROL LEG: all shipped KATs reproduced byte-exactly\n")

    gen1_crosscheck(SYS_RS_GEN1, CORE_RS_GEN1)
    print()

    pre_sys = manifest_hash(**sys_manifest(6, SYS_RS_GEN1, [4, 5, 6, 7, 9, 10]))
    pre_core = manifest_hash(**core_manifest(4, CORE_RS_GEN1, [1, 2, 3, 11, 12, 13]))
    pre_root = registry_root([
        dict(domain_id=DOMAIN_SYSTEM, status=DOMST_ACTIVE,
             current_manifest_hash=pre_sys),
        dict(domain_id=DOMAIN_CORE, status=DOMST_ACTIVE,
             current_manifest_hash=pre_core)])

    k1 = manifest_hash(**sys_manifest(7, SYS_RS_GEN2, [4, 5, 6, 7, 9, 10]))
    k2 = manifest_hash(**core_manifest(5, CORE_RS_GEN2, [1, 2, 3, 11, 12, 13]))
    k3 = registry_root([
        dict(domain_id=DOMAIN_SYSTEM, status=DOMST_ACTIVE,
             current_manifest_hash=k1),
        dict(domain_id=DOMAIN_CORE, status=DOMST_ACTIVE,
             current_manifest_hash=k2)])

    print_value("REF pre SYSTEM manifest hash (gen 1, v6)", pre_sys)
    print_value("REF pre CORE manifest hash (gen 1, v4)", pre_core)
    print_value("REF pre registry root", pre_root)
    print()
    print_value("K1 post SYSTEM manifest hash (gen 2, v7)", k1)
    print_value("K2 post CORE manifest hash (gen 2, v5)", k2)
    print_value("K3 post registry root", k3)
    return 0


if __name__ == "__main__":
    sys.exit(main())
