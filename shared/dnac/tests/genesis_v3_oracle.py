#!/usr/bin/env python3
r"""
Independent oracle for the VERSION-3 genesis document (D-18 rev 4).

INDEPENDENCE DISCIPLINE
-----------------------
This file re-implements the canonical encoding from the SPEC — the byte
table in nodus/src/witness/nodus_witness_v2_gen.h, which is D-18 rev 4's
layout — and NOT by calling the C.  A vector produced only by the
implementation under test is not grounding, it is an echo.

Same two-stage shape as shared/dnac/tests/block_v3_oracle.py:

  stage 1 CONTROL — re-derive the SHIPPED version-2 canonical encoding of
                    the fixture test_v2_gen.c builds (cfg_make(salt=0,
                    n_alloc=1, reverse=0)) and compare it against the
                    constant pinned below.  Nothing is emitted unless it
                    matches.
  stage 2 EMIT    — the version-3 vectors, from the same code paths.

  ⚠ WHAT THE CONTROL LEG DOES AND DOES NOT PROVE, stated plainly because
    it differs from block_v3_oracle.py's.  That oracle's control compares
    against five KATs that were ALREADY pinned in the C test suite.  This
    tree pins NO version-2 genesis-config vector anywhere — verified by
    `grep -n '"[0-9a-f]\{32,\}"' nodus/tests/test_v2_gen.c
    nodus/tests/test_v2_econ_params.c`, which matches nothing — so the
    constant below was derived by THIS FILE from the layout.  It becomes
    a genuine cross-implementation control the moment test_v2_gen.c is
    run: §5 there asserts the SAME constant against the shipped C encoder
    (nodus_witness_v2_gen_config_encode).  Until that run, the honest
    statement is "the Python model of the version-2 layout is
    self-consistent", never "it matches the C".

Run:  python3 shared/dnac/tests/genesis_v3_oracle.py

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import hashlib
import sys

# ── primitives ────────────────────────────────────────────────────────


def sha3_512(b: bytes) -> bytes:
    return hashlib.sha3_512(b).digest()


def tag16(s: str) -> bytes:
    """16-byte zero-padded domain tag (the C form: char[16] = "...")."""
    raw = s.encode("ascii")
    if len(raw) > 16:
        raise ValueError("tag longer than 16 bytes: %r" % s)
    return raw + b"\x00" * (16 - len(raw))


def u(v: int, width: int) -> bytes:
    return v.to_bytes(width, "big")


def i64(v: int) -> bytes:
    """8-byte two's complement, big-endian — the C `put_be64((uint64_t)v)`."""
    return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")


TAG_GENCFG = tag16("DNA.GENCFG.v1")

# ── the compiled constants the fixture uses ───────────────────────────
# dnac/include/dnac/dnac.h:72, :107, :116, :137, :172, :187 and
# nodus/src/witness/nodus_witness_emission.h:34, :42.  All of
# DNAC_EPOCH_LENGTH / DNAC_BLOCKS_PER_YEAR / DNAC_DECIMAL_UNIT are
# `#ifndef`-guarded, so a -D build changes them AND changes every vector
# below; the C test compares them at run time and does not run the KAT
# section when they differ (it says so, loudly — a skip is not a pass).

PUBKEY_SIZE = 2592
FINGERPRINT_SIZE = 129
COMMITTEE_SIZE = 7
DEFAULT_TOTAL_SUPPLY = 100000000000000000
SELF_STAKE_AMOUNT = 10000000 * 100000000
EPOCH_LENGTH = 720
BLOCKS_PER_YEAR = 6307200
DECIMAL_UNIT = 100000000
SRCID_LEN = 64

TREASURY_RAW = 93000000000000000        # test_v2_gen.c:66
UINT64_MAX = 0xFFFFFFFFFFFFFFFF

# ── the fixture test_v2_gen.c builds (cfg_make, :202-262) ─────────────


def fill_pubkey(i: int, salt: int) -> bytes:
    """v->pubkey[bb] = 0x11 * (i + 1) + (bb & 0x3F) + salt   (test:230-232)"""
    return bytes(((0x11 * (i + 1) + (bb & 0x3F) + salt) & 0xFF)
                 for bb in range(PUBKEY_SIZE))


def fp_hex129(src: bytes) -> bytes:
    """hex_lower_fp (test:94-103): 128 lowercase hex chars + a NUL byte."""
    return sha3_512(src).hex().encode("ascii") + b"\x00"


def make_cfg(salt: int = 0, n_alloc: int = 1) -> dict:
    vals = []
    for i in range(COMMITTEE_SIZE):
        pk = fill_pubkey(i, salt)
        udp = bytes(b ^ 0x5A for b in pk)
        vals.append({
            "pubkey": pk,
            "unstake_destination_pubkey": udp,
            "unstake_destination_fp": fp_hex129(udp),
            "self_stake": SELF_STAKE_AMOUNT,
            "commission_bps": 100 * (i + 1),
        })

    allocs = []
    for i in range(n_alloc):
        sid = bytearray(SRCID_LEN)
        sid[0] = 0x30 + i
        sid[63] = i
        owner = bytes(((0xA0 + i + (bb & 0x1F)) & 0xFF)
                      for bb in range(PUBKEY_SIZE))
        allocs.append({
            "source_id": bytes(sid),
            "dest_binding": sha3_512(owner),
            "amount": TREASURY_RAW if n_alloc == 1 else TREASURY_RAW // 3,
        })

    return {
        "config_version": 2,
        "total_supply_raw": DEFAULT_TOTAL_SUPPLY,
        "epoch_length": EPOCH_LENGTH,
        "blocks_per_year": BLOCKS_PER_YEAR,
        "decimal_unit": DECIMAL_UNIT,
        # tokenomics-v3 P2 (P2-4): the mint is deleted and a nonzero
        # inflation_start_block is REFUSED (nodus_witness_v2_gen.c); the
        # C fixture (test_v2_gen.c cfg_make) moved to 0 in the same package.
        "inflation_start_block": 0,
        "claim_start_height": 0,
        "claim_end_height": UINT64_MAX,
        "validators": vals,
        "allocs": allocs,
    }


# ── the canonical body (nodus_witness_v2_gen.h's table) ───────────────


def encode_body(c: dict) -> bytes:
    """The version-2 body.  Version 3 carries it BYTE-IDENTICALLY with
    config_version reading 3 — which is why this one function writes
    both, exactly as gen_encode_planned does in the C."""
    out = TAG_GENCFG
    out += u(c["config_version"], 4)
    out += u(c["total_supply_raw"], 8)
    out += u(c["epoch_length"], 8)
    out += u(c["blocks_per_year"], 8)
    out += u(c["decimal_unit"], 8)
    out += u(c["inflation_start_block"], 8)
    out += u(c["claim_start_height"], 8)
    out += u(c["claim_end_height"], 8)

    # canonical validator order: pubkey bytes ASC (the C sorts an index
    # array; sorting the list by the same key is the same total order,
    # the keys being pairwise distinct).
    vals = sorted(c["validators"], key=lambda v: v["pubkey"])
    out += u(len(vals), 2)
    for v in vals:
        out += v["pubkey"]
        out += v["unstake_destination_pubkey"]
        out += v["unstake_destination_fp"]
        out += u(v["self_stake"], 8)
        out += u(v["commission_bps"], 2)

    # canonical allocation order: source_id ASC
    allocs = sorted(c["allocs"], key=lambda a: a["source_id"])
    out += u(len(allocs), 4)
    for a in allocs:
        out += u(SRCID_LEN, 2)
        out += a["source_id"]
        out += u(a["amount"], 8)
        out += a["dest_binding"]
    return out


# ── the version-3 tail ────────────────────────────────────────────────

DEFAULT_PARAMS = {
    # types/params.go:97-102, :105-111, :115-119, :121-125, :127-132
    "block_max_bytes": 22020096,
    "block_max_gas": -1,
    "ev_max_age_num_blocks": 100000,
    "ev_max_age_duration_ns": 48 * 3600 * 1000000000,
    "ev_max_bytes": 1048576,
    "pub_key_types": ["mldsa87"],
    "version_app": 0,
    "abci_vote_extensions_enable_height": 0,
}


def encode_tail(c: dict, zero_chain_id: bool, zero_app_hash: bool) -> bytes:
    p = c["params"]
    out = u(c["consensus_protocol"], 4)
    out += u(c["genesis_time_ms"], 8)
    out += u(c["initial_height"], 8)
    out += i64(p["block_max_bytes"])
    out += i64(p["block_max_gas"])
    out += i64(p["ev_max_age_num_blocks"])
    out += i64(p["ev_max_age_duration_ns"])
    out += i64(p["ev_max_bytes"])
    out += u(len(p["pub_key_types"]), 2)
    for t in p["pub_key_types"]:
        raw = t.encode("ascii")
        out += u(len(raw), 2) + raw
    out += u(p["version_app"], 8)
    out += i64(p["abci_vote_extensions_enable_height"])
    out += u(len(c["comet"]), 2)
    for r in c["comet"]:
        out += r["address"]
        out += r["pub_key"]
        out += i64(r["power"])
        name = r["name"].encode("ascii")
        out += bytes([len(name)]) + name
    out += (b"\x00" * 64) if zero_app_hash else c["app_hash"]
    out += (b"\x00" * 32) if zero_chain_id else c["chain_id"]
    out += u(c["reward_pool_initial"], 8)
    out += u(c["reward_divisor_log2"], 8)
    out += u(c["payout_interval_epochs"], 8)
    return out


def encode_v3(c: dict, zero_chain_id=False, zero_app_hash=False) -> bytes:
    return encode_body(c) + encode_tail(c, zero_chain_id, zero_app_hash)


def chain_id(c: dict) -> bytes:
    """SHA3-512(the whole encoding with chain_id blanked)[0..31]."""
    return sha3_512(encode_v3(c, zero_chain_id=True))[:32]


def source_commit_v3(c: dict) -> bytes:
    """SHA3-512(the whole encoding with chain_id AND app_hash blanked)."""
    return sha3_512(encode_v3(c, zero_chain_id=True, zero_app_hash=True))


def derive_rows(c: dict, names=None) -> list:
    """address = SHA3-512(pubkey)[0..31]; power = self_stake // decimal_unit.
    In the canonical validator order (pubkey ASC), which is the order the
    body writes the validators in."""
    rows = []
    for idx, v in enumerate(sorted(c["validators"], key=lambda x: x["pubkey"])):
        rows.append({
            "address": sha3_512(v["pubkey"])[:32],
            "pub_key": v["pubkey"],
            "power": v["self_stake"] // c["decimal_unit"],
            "name": (names[idx] if names and idx < len(names) else ""),
        })
    return rows


def make_v3(names=None, params=None, **over) -> dict:
    c = make_cfg()
    c["config_version"] = 3
    c["consensus_protocol"] = 1
    c["genesis_time_ms"] = 1767225600000     # 2026-01-01T00:00:00Z
    c["initial_height"] = 1
    c["params"] = dict(DEFAULT_PARAMS)
    if params:
        c["params"].update(params)
    c["app_hash"] = b"\x00" * 64
    c["chain_id"] = b"\x00" * 32
    c["reward_pool_initial"] = 200000000 * 100000000
    c["reward_divisor_log2"] = 16
    c["payout_interval_epochs"] = 24
    c.update(over)
    # tokenomics-v3 P2 (P2-1): Rule P.2 now counts the reward reserve —
    # Σ allocations + Σ self-stake + reward_pool_initial == total supply —
    # so the single treasury allocation shrinks by exactly the reserve,
    # as the C fixtures do (test_v2_gen.c cfg_make_v3 / cfg_make_v3_b).
    if len(c["allocs"]) == 1:
        c["allocs"][0]["amount"] = TREASURY_RAW - c["reward_pool_initial"]
    c["comet"] = derive_rows(c, names)
    return c


# ── stage 1: CONTROL ──────────────────────────────────────────────────
#
# The canonical version-2 encoding of cfg_make(0, 1, 0), as this file
# models it.  test_v2_gen.c §5 asserts the same constant against the
# SHIPPED C encoder — that assertion is what turns this leg into a
# cross-implementation control rather than a self-comparison.

# Re-pinned 2026-09-24 (tokenomics-v3 P2: inflation_start_block 1 → 0)
# AFTER test_v2_gen.c §5 was run against the C encoder with this value
# and agreed — the rule stated in control_leg() below.
CONTROL_V2_ENC_SHA = (
    "523e2c971f1c44f06ad63cf8d0b4b4eb56ae7b98b58f8dc7afa09b97b523893a"
    "5c408314a06f32e378b4f4f24764bb2763fe6fcdae8a1ccd63e279b09f4103bf"
)
# The encoding is 37481 bytes: 78 head (16 tag + 4 version + 7 × 8 + 2
# count) + 7 × 5323 validator + 4 + 1 × 138 allocation.  The C computes
# the same length from GEN_CFG_HEAD_LEN and GEN_VAL_ENC_LEN
# (nodus_witness_v2_gen.c:876-884) and asserts it wrote exactly that many
# bytes, so a length disagreement is itself a caught failure.
CONTROL_V2_ENC_LEN = 37481


def control_leg() -> bool:
    c = make_cfg()
    enc = encode_body(c)
    got = sha3_512(enc).hex()

    print("── stage 1: CONTROL (the version-2 body of cfg_make(0,1,0)) ───")
    print("  encoding length      = %d bytes" % len(enc))
    print("  SHA3-512(encoding)   = %s" % got)
    print("  source_commit        = %s" % got)
    ok = (got == CONTROL_V2_ENC_SHA and len(enc) == CONTROL_V2_ENC_LEN)
    print("  [%s] matches CONTROL_V2_ENC_SHA / _LEN"
          % ("OK " if ok else "FAIL"))
    if not ok:
        print()
        print("  The pinned constant in this file does not match what this")
        print("  file computes.  Update CONTROL_V2_ENC_SHA to the value")
        print("  above ONLY after test_v2_gen.c's §5 assertion has been run")
        print("  against the C encoder and agrees — otherwise the constant")
        print("  is an unverified number and the control proves nothing.")
    return ok


# ── stage 2: EMIT ─────────────────────────────────────────────────────


def print_hex_c(name: str, h: str) -> None:
    print('  static const char *%s =' % name)
    for i in range(0, len(h), 64):
        end = ';' if i + 64 >= len(h) else ''
        print('      "%s"%s' % (h[i:i + 64], end))


def emit(tag: str, c: dict) -> None:
    enc = encode_v3(c)
    print()
    print("── %s " % tag + "─" * max(0, 60 - len(tag)))
    print("  encoding length = %d bytes" % len(enc))
    print("  body length     = %d bytes" % len(encode_body(c)))
    print("  tail length     = %d bytes" % (len(enc) - len(encode_body(c))))
    print_hex_c("KAT_%s_ENC_SHA" % tag, sha3_512(enc).hex())
    print_hex_c("KAT_%s_CHAIN_ID" % tag, chain_id(c).hex())
    print_hex_c("KAT_%s_SRC_COMMIT" % tag, source_commit_v3(c).hex())


def emit_all() -> None:
    a = make_v3()
    emit("A", a)

    b = make_v3(
        params={
            "block_max_bytes": 1234567,
            "block_max_gas": 99,
            "ev_max_age_num_blocks": 7,
            "ev_max_age_duration_ns": 3600 * 1000000000,
            "ev_max_bytes": 4096,
            "pub_key_types": ["mldsa87", "testkey"],
            "version_app": 9,
            "abci_vote_extensions_enable_height": 5,
        },
        genesis_time_ms=1234567890123,
        initial_height=12345,
        app_hash=bytes(((0x77 + i * 7) & 0xFF) for i in range(64)),
        chain_id=bytes(((0x99 + i * 5) & 0xFF) for i in range(32)),
        reward_pool_initial=123456789,
        reward_divisor_log2=15,
        payout_interval_epochs=7,
    )
    emit("B", b)

    c = make_v3(names=["alpha", "bravo", ""])
    emit("C", c)

    # D — a COMPLETED document: app_hash present (as the genesis apply
    # leaves it) and chain_id holding its own value, which is the shape
    # the derivation stores under "genesisDoc".  The one vector where all
    # three numbers differ from each other AND the id is self-consistent.
    d = make_v3(app_hash=bytes(((0x20 + i * 3) & 0xFF) for i in range(64)))
    d["chain_id"] = chain_id(d)
    emit("D", d)
    print("  chain_id is self-consistent inside the document: %s"
          % (chain_id(d) == d["chain_id"]))

    print()
    print("── the two zeroing rules " + "─" * 44)
    # the chain id does not depend on the chain_id field
    a_set = make_v3()
    a_set["chain_id"] = chain_id(a_set)
    print("  chain_id(doc with its id set) == chain_id(doc with it zero): %s"
          % (chain_id(a_set) == chain_id(a)))
    # the source commit does not depend on app_hash
    a_app = make_v3(app_hash=bytes(((0x11 + i) & 0xFF) for i in range(64)))
    print("  source_commit ignores app_hash:                             %s"
          % (source_commit_v3(a_app) == source_commit_v3(a)))
    print("  chain_id DOES depend on app_hash:                           %s"
          % (chain_id(a_app) != chain_id(a)))
    print()
    print("  per-field sensitivity (each flipped ALONE, chain id changes):")
    base = chain_id(a)
    muts = {
        "inflation_start_block": lambda c: c.update(
            {"inflation_start_block": 2}),
        "consensus_protocol": lambda c: c.update({"consensus_protocol": 2}),
        "genesis_time_ms": lambda c: c.update(
            {"genesis_time_ms": 1767225600001}),
        "initial_height": lambda c: c.update({"initial_height": 2}),
        "block.max_bytes": lambda c: c["params"].update(
            {"block_max_bytes": 22020097}),
        "block.max_gas": lambda c: c["params"].update({"block_max_gas": -2}),
        "ev.max_age_num_blocks": lambda c: c["params"].update(
            {"ev_max_age_num_blocks": 100001}),
        "ev.max_age_duration": lambda c: c["params"].update(
            {"ev_max_age_duration_ns": 48 * 3600 * 1000000000 + 1}),
        "ev.max_bytes": lambda c: c["params"].update({"ev_max_bytes": 1048577}),
        "pub_key_types": lambda c: c["params"].update(
            {"pub_key_types": ["mldsa88"]}),
        "version.app": lambda c: c["params"].update({"version_app": 1}),
        "abci.enable_height": lambda c: c["params"].update(
            {"abci_vote_extensions_enable_height": 1}),
        "comet row power": lambda c: c["comet"][0].update({"power": 1}),
        "comet row address": lambda c: c["comet"][0].update(
            {"address": b"\x01" * 32}),
        "comet row name": lambda c: c["comet"][0].update({"name": "x"}),
        "app_hash": lambda c: c.update({"app_hash": b"\x01" * 64}),
        "reward_pool_initial": lambda c: c.update(
            {"reward_pool_initial": 1}),
        "reward_divisor_log2": lambda c: c.update({"reward_divisor_log2": 17}),
        "payout_interval_epochs": lambda c: c.update(
            {"payout_interval_epochs": 25}),
    }
    for name, mutate in muts.items():
        m = make_v3()
        mutate(m)
        print("    %-24s changes the chain id: %s"
              % (name, chain_id(m) != base))

    print()
    print("  the chain_id field alone must NOT change it:")
    z = make_v3()
    z["chain_id"] = b"\x42" * 32
    print("    chain_id field           changes the chain id: %s"
          % (chain_id(z) != base))


def main() -> int:
    if not control_leg():
        print()
        print("CONTROL LEG FAILED — refusing to emit version-3 vectors.")
        return 1
    emit_all()
    print()
    print("control leg green — the version-3 vectors above are derived from")
    print("the layout, not from the C.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
