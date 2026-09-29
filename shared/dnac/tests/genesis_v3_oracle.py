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

  stage 1 CONTROL — re-derive the version-2 canonical encoding (its C
                    encoder was deleted in P4; the body it modelled is the
                    version-3 body with config_version = 2) of
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
    a cross-implementation control through test_v2_gen.c §5.  Since P4
    (2026-09-24) the C version-2 encoder is DELETED; §5 re-checks the
    constant over the version-3 document's first 37 481 bytes with byte
    19 (config_version) patched to 2 — valid because the v2 body is
    byte-identical to the v3 body except that field (D-18 rev 4).  That
    is a self-consistency check of the shared body layout, not an
    independent run of a v2 encoder.

  ⚠ SINCE GENERAL MULTISIG (ONAY 2) §5 NO LONGER CHECKS THIS CONSTANT.
    The C fixture (test_v2_gen.c cfg_make :247-254) now zeroes every
    validator's unstake_destination_pubkey, and those 7 × 2592 bytes are
    inside the body §5 hashes.  CONTROL_V2_ENC_SHA below is kept as this
    file's own stage-1 control (the pubkey-XOR-0x5A body it has always
    modelled, previously agreed with the C); the constant §5 needs now is
    printed by stage 5 as KAT_V2_ENC_SHA and is NOT pinned here — per
    the rule in control_leg(), it is pinned only after §5 has been run
    against the C with it and agreed.

VERSION 4 (final-wipe package W-A, 2026-09-29)
----------------------------------------------
Governing records: docs/plans/decisions/
2026-09-28-treasury-pools-and-exact-self-stake.md (items 1, 11-13) and
docs/plans/2026-09-28-final-wipe-package-design.md (§1 W-A, §7 F8).
The version-4 document is the version-3 document with

  * config_version = 4 (the only value version 4 accepts), and
  * a treasury block APPENDED after payout_interval_epochs — exactly nine
    entries, NO count field, each  pool_id u32 BE ‖ balance u64 BE
    (12 bytes; 108 bytes in all), pool_id == index + 1 (1..9, the order
    of decision item 11: 1 Storage … 8 Foundation, 9 Community airdrop).

Everything else is byte-identical to version 3.  Read plainly, that
includes the two zeroing rules: the chain id is SHA3-512 of the WHOLE
version-4 encoding (treasury included) with chain_id blanked, taking the
first 32 bytes; the source commit is SHA3-512 of the whole encoding with
chain_id AND app_hash blanked.  That reading is this file's, not a
pinned C fact — the ORCHESTRATOR checks it against the C.

Stages, all fail-closed (nothing after a failed stage is printed):

  stage 1  CONTROL — the version-2 body (unchanged, see above).
  stage 1b CONTROL — the version-3 vectors A-D re-derived and asserted
                     against the values PINNED in nodus/tests/test_v2_gen.c
                     (KAT_A..D_ENC_LEN / _ENC_SHA / _CHAIN_ID / _SRC_COMMIT,
                     :1402-1439).  Proves the version-3 model this file
                     extends is the one the C tree agrees with today.
  stage 2  EMIT    — the version-3 vectors (unchanged output).
  stage 3  EMIT    — the version-4 vectors: A4-D4 are A-D with
                     config_version 4 and nine ZERO-balance pools (the
                     composition otherwise identical); E4 and F4 carry the
                     operator's pool balances (decision item 1: 100M,
                     100M, 50M, 50M, 50M, 150M, 100M, 30M, 50M NODUS).

  ⚠ FIXTURE COMPOSITION (same honesty label as the P2 re-pin in
    test_v2_gen.c:1381-1393).  Rule P.2 as the design doc words it
    (§1 W-A: Σ allocations + Σ self_stake + reward_pool_initial +
    Σ treasury == total_supply_raw) counts the pools, so where a fixture
    carries non-zero pools its single allocation shrinks by exactly
    Σ treasury — for E4/F4 that leaves 50M NODUS, the Founder allocation
    W-A keeps.  This is a composition choice made by this file; a C
    fixture that does not shrink its allocation the same way will not
    match E4/F4, and that is a fixture difference, not an encoding one.
    Whether the C version-4 CONTENT validator accepts zero-balance pools
    is not known to this file; A4-D4 are ENCODING vectors (like B's
    reward_divisor_log2 = 15, which only the content rule refuses).

VERSION 5 (W-C + general multisig, 2026-09-29)
----------------------------------------------
Governing records (docs/plans/decisions/):
  2026-09-25-gas-price.md, "Son wipe paketi" — genesis gas price 121
      raw/unit;
  2026-09-28-token-create-fee-governance.md, "Tamam yap" — token-create
      fee 10^11 raw (1 000 NODUS);
  2026-09-29-general-multisig.md, ONAY 2 — genesis outputs, and every
      genesis validator's unstake_destination_pubkey ALL ZERO.
Layout as dispatched to the implementer (and written in the wipe-pkg
nodus_witness_v2_gen.h layout table, :702-720):

  version-4 document (body ‖ tail ‖ treasury[9])  with config_version = 5
  ‖ gas_price_raw_per_unit  u64 BE
  ‖ token_create_fee_raw    u64 BE
  ‖ genesis_output_count    u32 BE
  ‖ count × (owner[64] ‖ amount u64 BE)   DOCUMENT ORDER, never sorted

chain_id and source_commit keep their zeroing rules over the WHOLE
version-5 encoding (outputs included).

  stage 4  EMIT    — A5-D5: A-D at config_version 5, nine zero pools
                     (B5: the operator's pool balances — see below), gas
                     121, fee 10^11, NO outputs, every unstake destination
                     pubkey zeroed.  E5: A5 plus two genesis outputs.

  ⚠ FIXTURE CHANGE vs A-D/A4-D4: those carried NON-ZERO destination
    pubkeys (pubkey XOR 0x5A).  Version 5 zeroes them (ONAY 2).  The
    destination FINGERPRINT is an address checked by shape only (header
    :360-369) and is NOT zeroed: by default this file keeps it at the
    A-D value hex(SHA3-512(pubkey XOR 0x5A)) ‖ NUL — a FIXTURE CHOICE, the
    one most likely to differ from a C fixture.  The alternative
    (hex(SHA3-512(2592 zero bytes)) ‖ NUL) is printed as one extra A5 line.
  ⚠ B5 carries the operator's nine pool balances (the dispatch said "as
    before"; in THIS file B4 had zero pools — only E4/F4 carried them).
    The zero-pool B5 digest is printed as one extra line.
  ⚠ Rule P.2 counts the genesis outputs (header :571, :629), so E5's
    single allocation shrinks by exactly Σ outputs — composition choice.
  ⚠ This file's version-4 stage models W-A only (108-byte block).  The
    wipe-pkg header says version 4 also carried W-C (124 bytes).  Version
    4 is RETIRED; stage 1c below uses it only as a control.

THE C FIXTURES, READ (2026-09-29) — the two fixture choices above settled
------------------------------------------------------------------------
From nodus/tests/test_v2_gen.c (test data only; the genesis
implementation .c was NOT read):
  * cfg_make :241-257 — unstake_destination_fp = hex(SHA3-512(pubkey XOR
    0x5A)) ‖ NUL computed FIRST (:247-251), THEN the pubkey memset to
    zero (:254).  That is this file's dest_fp = "keep".
  * cfg_make :223-227 — config_version 5, treasury pool_id = t + 1, every
    balance 0; no genesis outputs are ever set (calloc'd config; §5
    :1773-1778 asserts a zero output count).
  * cfg_make_v3 :1619-1636 (A) — allocation TREASURY_RAW −
    reward_pool_initial, genesis_time 1767225600000, height 1; gas 121 /
    fee 10^11 via nodus_witness_v2_gen_v3_defaults (header :758-761; §5
    :1783-1793 asserts the bytes).
  * cfg_make_v3_b :1639-1690 (B) — the operator's nine pools (:1677-1685)
    and allocation TREASURY_RAW − 123456789 − Σ pools (:1687).  So B4 and
    B5 carry the pools here too (B4 changed accordingly, 2026-09-29).
  * cfg_make_v3_c :1693-1704 (C) — names on comet rows 0, 1, 2 after the
    rows are filled in pubkey-ASC order; with salt 0 / reverse 0 index
    order IS pubkey-ASC order, which is what derive_rows assumes.
  * cfg_make_v3_d :1709-1720 (D) — app_hash then its own chain id.
  * §5 :1748-1827 — cfg_make_v3_ex (alloc TREASURY_RAW, untouched), the
    first 37 481 bytes, byte 19 := 2.

  stage 1c CONTROL — V4 A-D (W-A, B with the operator pools) asserted
                     against the RETIRED W-A literals written in the
                     test_v2_gen.c comment :1566-1581.  Those literals are
                     labelled there as this oracle's earlier output; whether
                     the C §6 ever ran green on them is NOT known to this
                     file.  They prove this file still reproduces them.
  stage 5  EMIT    — the placeholders under their C names: KAT_V2_ENC_SHA
                     (the §5 body, dest pubkeys zeroed) and KAT_A..D_* at
                     config_version 5 (= V5_A..D).  Derived from the layout;
                     NOT asserted against any C value.

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


# ── the version-4 treasury block ──────────────────────────────────────

TREASURY_POOLS = 9
TREASURY_ENTRY_LEN = 4 + 8
TREASURY_BLOCK_LEN = TREASURY_POOLS * TREASURY_ENTRY_LEN      # 108


def encode_treasury(pools: list) -> bytes:
    """Nine (pool_id u32 BE ‖ balance u64 BE) entries, no count field;
    pool_id must equal index + 1.  Refuses anything else — the encoder
    never writes a block the layout does not define."""
    if len(pools) != TREASURY_POOLS:
        raise ValueError("treasury must have exactly %d entries, got %d"
                         % (TREASURY_POOLS, len(pools)))
    out = b""
    for idx, (pool_id, balance) in enumerate(pools):
        if pool_id != idx + 1:
            raise ValueError("treasury entry %d carries pool_id %d, "
                             "expected %d" % (idx, pool_id, idx + 1))
        if not 0 <= balance <= UINT64_MAX:
            raise ValueError("treasury balance out of u64 range")
        out += u(pool_id, 4) + u(balance, 8)
    if len(out) != TREASURY_BLOCK_LEN:
        raise AssertionError("treasury block %d != %d"
                             % (len(out), TREASURY_BLOCK_LEN))
    return out


def encode_v4(c: dict, zero_chain_id=False, zero_app_hash=False) -> bytes:
    if c["config_version"] != 4:
        raise ValueError("encode_v4 needs config_version 4")
    return (encode_body(c) + encode_tail(c, zero_chain_id, zero_app_hash)
            + encode_treasury(c["treasury"]))


# ── the version-5 tail: W-C fee parameters + genesis outputs ──────────

INT64_MAX = 0x7FFFFFFFFFFFFFFF
GENESIS_GAS_PRICE = 121                  # decision 2026-09-25-gas-price.md
GENESIS_TOKEN_CREATE_FEE = 10 ** 11      # decision 2026-09-28-token-create-
                                         # fee-governance.md (1 000 NODUS)
MAX_GENOUTS = 64                         # release bound (wipe-pkg header)
GENOUT_OWNER_LEN = 64
GENOUT_ENTRY_LEN = GENOUT_OWNER_LEN + 8                         # 72
V5_EXTRA_LEN = 8 + 8 + 4                 # gas ‖ fee ‖ output count


def encode_genouts(outputs: list) -> bytes:
    """count u32 BE ‖ count × (owner[64] ‖ amount u64 BE), in the order
    given — NEVER sorted (the index is each coin's identity).  Refuses
    every list the layout / ONAY 2 does not define."""
    if len(outputs) > MAX_GENOUTS:
        raise ValueError("%d genesis outputs > %d" % (len(outputs),
                                                      MAX_GENOUTS))
    out = u(len(outputs), 4)
    for owner, amount in outputs:
        if len(owner) != GENOUT_OWNER_LEN:
            raise ValueError("genesis output owner is %d bytes, not 64"
                             % len(owner))
        if owner == b"\x00" * GENOUT_OWNER_LEN:
            raise ValueError("genesis output owner is all-zero")
        if not 1 <= amount <= INT64_MAX:
            raise ValueError("genesis output amount %d outside 1..INT64_MAX"
                             % amount)
        out += owner + u(amount, 8)
    if len(out) != 4 + GENOUT_ENTRY_LEN * len(outputs):
        raise AssertionError("genesis output section length")
    return out


def encode_v5(c: dict, zero_chain_id=False, zero_app_hash=False) -> bytes:
    if c["config_version"] != 5:
        raise ValueError("encode_v5 needs config_version 5")
    for name in ("gas_price_raw_per_unit", "token_create_fee_raw"):
        if not 0 <= c[name] <= UINT64_MAX:
            raise ValueError("%s out of u64 range" % name)
    return (encode_body(c) + encode_tail(c, zero_chain_id, zero_app_hash)
            + encode_treasury(c["treasury"])
            + u(c["gas_price_raw_per_unit"], 8)
            + u(c["token_create_fee_raw"], 8)
            + encode_genouts(c["genesis_outputs"]))


def encode_doc(c: dict, zero_chain_id=False, zero_app_hash=False) -> bytes:
    """The document in the version its config_version names (3, 4 or 5)."""
    if c["config_version"] == 3:
        return encode_v3(c, zero_chain_id, zero_app_hash)
    if c["config_version"] == 4:
        return encode_v4(c, zero_chain_id, zero_app_hash)
    if c["config_version"] == 5:
        return encode_v5(c, zero_chain_id, zero_app_hash)
    raise ValueError("no document encoding for config_version %d"
                     % c["config_version"])


def chain_id(c: dict) -> bytes:
    """SHA3-512(the whole encoding with chain_id blanked)[0..31]."""
    return sha3_512(encode_doc(c, zero_chain_id=True))[:32]


def source_commit_v3(c: dict) -> bytes:
    """SHA3-512(the whole encoding with chain_id AND app_hash blanked).
    For a version-4 or version-5 document "the whole encoding" includes
    the treasury block (and, for 5, the gas/fee fields and the genesis
    outputs) — see the module docstring; this file's reading."""
    return sha3_512(encode_doc(c, zero_chain_id=True, zero_app_hash=True))


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


# The operator's pool balances, decision
# 2026-09-28-treasury-pools-and-exact-self-stake.md item 1, in the pool
# order of item 11 (1 Storage, 2 Compute, 3 VPN/Bandwidth, 4 Future
# services, 5 Security/bug bounty, 6 Liquidity, 7 Ecosystem grants,
# 8 Foundation, 9 Community airdrop).  Whole NODUS; raw = × DECIMAL_UNIT.
OPERATOR_POOLS_NODUS = [100000000, 100000000, 50000000, 50000000, 50000000,
                        150000000, 100000000, 30000000, 50000000]
assert len(OPERATOR_POOLS_NODUS) == TREASURY_POOLS
# 680 000 000 NODUS.  ⚠ The decision text says "Toplam 730M" for the
# pools; the nine listed values sum to 680M (730M = 680M + the Founder's
# 50M allocation).  This file uses the listed values.
OPERATOR_POOLS_SUM_NODUS = 680000000
assert sum(OPERATOR_POOLS_NODUS) == OPERATOR_POOLS_SUM_NODUS


def operator_pools() -> list:
    return [(i + 1, n * DECIMAL_UNIT)
            for i, n in enumerate(OPERATOR_POOLS_NODUS)]


def zero_pools() -> list:
    return [(i + 1, 0) for i in range(TREASURY_POOLS)]


def make_v4(pools=None, names=None, params=None, **over) -> dict:
    """make_v3's document at config_version 4 with a treasury block.
    Rule P.2 (design doc §1 W-A) counts the pools, so a single allocation
    shrinks by exactly Σ treasury — a no-op for all-zero pools."""
    c = make_v3(names=names, params=params, **over)
    c["config_version"] = 4
    c["treasury"] = list(pools) if pools is not None else zero_pools()
    if len(c["allocs"]) == 1:
        c["allocs"][0]["amount"] -= sum(b for _, b in c["treasury"])
        if c["allocs"][0]["amount"] < 0:
            raise ValueError("treasury exceeds the allocation it is "
                             "carved from")
    # comet rows depend only on the validators, which did not move
    return c


ZERO_PUBKEY = b"\x00" * PUBKEY_SIZE

# How a version-5 fixture fills unstake_destination_fp once the pubkey is
# zero (a FIXTURE choice, see the module docstring):
#   "keep"        — unchanged: hex(SHA3-512(pubkey XOR 0x5A)) ‖ NUL
#   "zero_pk_fp"  — hex(SHA3-512(2592 zero bytes)) ‖ NUL
DEST_FP_MODES = ("keep", "zero_pk_fp")


def make_v5(pools=None, outputs=None, names=None, params=None,
            dest_fp="keep", gas=GENESIS_GAS_PRICE,
            fee=GENESIS_TOKEN_CREATE_FEE, **over) -> dict:
    """make_v4's document at config_version 5: every genesis validator's
    unstake_destination_pubkey zeroed (ONAY 2), the two W-C fee values,
    and the genesis outputs in the order given.  Rule P.2 counts the
    outputs, so a single allocation shrinks by exactly Σ outputs."""
    if dest_fp not in DEST_FP_MODES:
        raise ValueError("unknown dest_fp mode %r" % dest_fp)
    c = make_v4(pools=pools, names=names, params=params, **over)
    c["config_version"] = 5
    for v in c["validators"]:
        v["unstake_destination_pubkey"] = ZERO_PUBKEY
        if dest_fp == "zero_pk_fp":
            v["unstake_destination_fp"] = fp_hex129(ZERO_PUBKEY)
    c["gas_price_raw_per_unit"] = gas
    c["token_create_fee_raw"] = fee
    c["genesis_outputs"] = list(outputs) if outputs is not None else []
    if len(c["allocs"]) == 1:
        c["allocs"][0]["amount"] -= sum(a for _, a in c["genesis_outputs"])
        if c["allocs"][0]["amount"] < 0:
            raise ValueError("genesis outputs exceed the allocation they "
                             "are carved from")
    # comet rows depend only on the validators' pubkey and self_stake,
    # neither of which moved
    return c


# E5's two genesis outputs.  Owners are plain byte patterns (not a hash of
# anything this file uses elsewhere), chosen so the FIRST owner is
# byte-greater than the second: an encoder that sorts would write them in
# the other order and miss E5.  Amounts: 150 000 000 NODUS and 7 raw.
E5_OUTPUTS = [
    (bytes(((0xE1 + 3 * j) & 0xFF) for j in range(GENOUT_OWNER_LEN)),
     150000000 * DECIMAL_UNIT),
    (bytes(((0xC0 + j) & 0xFF) for j in range(GENOUT_OWNER_LEN)),
     7),
]
assert E5_OUTPUTS[0][0] > E5_OUTPUTS[1][0]


# ── stage 1: CONTROL ──────────────────────────────────────────────────
#
# The canonical version-2 encoding of cfg_make(0, 1, 0), as this file
# models it.  test_v2_gen.c §5 asserts the same constant against the C
# version-3 encoder's first 37 481 bytes with byte 19 (config_version)
# patched to 2 — the version-2 C encoder itself was deleted in P4.

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
    ok = (got == CONTROL_V2_ENC_SHA and len(enc) == CONTROL_V2_ENC_LEN)
    print("  [%s] matches CONTROL_V2_ENC_SHA / _LEN"
          % ("OK " if ok else "FAIL"))
    if not ok:
        print()
        print("  The pinned constant in this file does not match what this")
        print("  file computes.  Update CONTROL_V2_ENC_SHA to the value")
        print("  above ONLY after test_v2_gen.c's §5 assertion (the C v3")
        print("  body with config_version patched to 2) has been run and")
        print("  agrees — otherwise the constant proves nothing.")
    return ok


# ── stage 2: EMIT ─────────────────────────────────────────────────────


def print_hex_c(name: str, h: str) -> None:
    print('  static const char *%s =' % name)
    for i in range(0, len(h), 64):
        end = ';' if i + 64 >= len(h) else ''
        print('      "%s"%s' % (h[i:i + 64], end))


def emit(tag: str, c: dict) -> None:
    enc = encode_doc(c)
    print()
    print("── %s " % tag + "─" * max(0, 60 - len(tag)))
    print("  config_version  = %d" % c["config_version"])
    print("  encoding length = %d bytes" % len(enc))
    print("  body length     = %d bytes" % len(encode_body(c)))
    print("  tail length     = %d bytes" % (len(enc) - len(encode_body(c))))
    if c["config_version"] in (4, 5):
        print("    of which treasury block = %d bytes" % TREASURY_BLOCK_LEN)
    if c["config_version"] == 5:
        print("    gas_price_raw_per_unit  = %d" % c["gas_price_raw_per_unit"])
        print("    token_create_fee_raw    = %d" % c["token_create_fee_raw"])
        print("    genesis outputs         = %d (%d bytes incl. count)"
              % (len(c["genesis_outputs"]),
                 4 + GENOUT_ENTRY_LEN * len(c["genesis_outputs"])))
        print("    treasury Σ              = %d raw"
              % sum(b for _, b in c["treasury"]))
    print_hex_c("KAT_%s_ENC_SHA" % tag, sha3_512(enc).hex())
    print_hex_c("KAT_%s_CHAIN_ID" % tag, chain_id(c).hex())
    print_hex_c("KAT_%s_SRC_COMMIT" % tag, source_commit_v3(c).hex())


# The B fixture's overrides (test_v2_gen.c cfg_make_v3_b, :1466-1498) —
# shared by the version-3 and version-4 builders so B and B4 cannot drift.
B_PARAMS = {
    "block_max_bytes": 1234567,
    "block_max_gas": 99,
    "ev_max_age_num_blocks": 7,
    "ev_max_age_duration_ns": 3600 * 1000000000,
    "ev_max_bytes": 4096,
    "pub_key_types": ["mldsa87", "testkey"],
    "version_app": 9,
    "abci_vote_extensions_enable_height": 5,
}


def b_over() -> dict:
    return {
        "genesis_time_ms": 1234567890123,
        "initial_height": 12345,
        "app_hash": bytes(((0x77 + i * 7) & 0xFF) for i in range(64)),
        "chain_id": bytes(((0x99 + i * 5) & 0xFF) for i in range(32)),
        "reward_pool_initial": 123456789,
        "reward_divisor_log2": 15,
        "payout_interval_epochs": 7,
    }


C_NAMES = ["alpha", "bravo", ""]
D_APP_HASH = bytes(((0x20 + i * 3) & 0xFF) for i in range(64))


def v3_fixtures() -> dict:
    """A-D exactly as stage 2 has always built them."""
    a = make_v3()
    b = make_v3(params=B_PARAMS, **b_over())
    c = make_v3(names=C_NAMES)
    d = make_v3(app_hash=D_APP_HASH)
    d["chain_id"] = chain_id(d)
    return {"A": a, "B": b, "C": c, "D": d}


# ── stage 1b: the version-3 KATs PINNED in the C tree ─────────────────
# nodus/tests/test_v2_gen.c:1402-1405 (lengths) and :1411-1439 (digests).
# C and D pin no source commit (v3_vector(..., NULL), :1673-1674).

PINNED_V3 = {
    "A": {
        "len": 56121,
        "enc_sha":
            "e63e9ff5c6f9d2f13ef3276b8f678221d478211607dcbd66545c9d27f2b93fd6"
            "244a44c16ec82c9785701bcb392949e4882ea4510fa3560a17b9973e32c8be64",
        "chain_id":
            "e63e9ff5c6f9d2f13ef3276b8f678221d478211607dcbd66545c9d27f2b93fd6",
        "src_commit":
            "e63e9ff5c6f9d2f13ef3276b8f678221d478211607dcbd66545c9d27f2b93fd6"
            "244a44c16ec82c9785701bcb392949e4882ea4510fa3560a17b9973e32c8be64",
    },
    "B": {
        "len": 56130,
        "enc_sha":
            "c9ab02d3d443846aa435d27bb207d4f0c342f6f322833eb57a9455b7d4fa1cab"
            "95de99861f3d709f097f9a353f8455c37f18a48e36490b412e08614ecfe32b4b",
        "chain_id":
            "f2e3e45cc11822a931cc0bcd4e42a25ea92108f5021e47be70263bf6d03a8940",
        "src_commit":
            "efa32045899a99de4a846653811ae8316d4ea1e32e95f15059c53bf66853a70f"
            "bc4d1d68e4d1aad86880dcbc58615b3b5d2a7ec173f8a3c09c047d61d0e0ba8e",
    },
    "C": {
        "len": 56131,
        "enc_sha":
            "aacf24c34b20d9fb8bb02209075f6c13e64902d2fdbddebb9b742d7b741bacae"
            "2be6ab9caa58b40ff1fda9fbf5d81293479ae70361d3ee11dfafd565644d57eb",
        "chain_id":
            "aacf24c34b20d9fb8bb02209075f6c13e64902d2fdbddebb9b742d7b741bacae",
        "src_commit": None,
    },
    "D": {
        "len": 56121,
        "enc_sha":
            "7925db184e5883ed3b9563ca85d0b518b6ed6e2de00ccaea61def42a2dc5dc43"
            "8d9eb9675696a6b4ddfe173a0e435937baf228d02a273522a492e06f0d1ef2b2",
        "chain_id":
            "8f633f2022d6ae833817b604737a09cb881b3a130dd3cddd7540e723088b6040",
        "src_commit": None,
    },
}


def v3_kat_control() -> bool:
    print()
    print("── stage 1b: CONTROL (version-3 A-D vs test_v2_gen.c pins) "
          + "─" * 6)
    ok = True
    for tag, c in v3_fixtures().items():
        pin = PINNED_V3[tag]
        enc = encode_v3(c)
        rows = [
            ("length", str(len(enc)), str(pin["len"])),
            ("enc_sha", sha3_512(enc).hex(), pin["enc_sha"]),
            ("chain_id", chain_id(c).hex(), pin["chain_id"]),
        ]
        if pin["src_commit"] is not None:
            rows.append(("src_commit", source_commit_v3(c).hex(),
                         pin["src_commit"]))
        for what, got, want in rows:
            good = (got == want)
            ok = ok and good
            print("  [%s] %s %-10s %s" % ("OK " if good else "FAIL", tag,
                                          what, got[:32] +
                                          ("…" if len(got) > 32 else "")))
            if not good:
                print("        computed     %s" % got)
                print("        pinned       %s" % want)
    return ok


def emit_all() -> None:
    # A-D come from v3_fixtures(), the SAME builder stage 1b asserted
    # against the C pins — so what is printed here is what was checked.
    fx = v3_fixtures()
    a = fx["A"]
    emit("A", a)
    emit("B", fx["B"])
    emit("C", fx["C"])

    # D — a COMPLETED document: app_hash present (as the genesis apply
    # leaves it) and chain_id holding its own value, which is the shape
    # the derivation stores under "genesisDoc".  The one vector where all
    # three numbers differ from each other AND the id is self-consistent.
    d = fx["D"]
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


# ── stage 3: the version-4 vectors ────────────────────────────────────


def v4_fixtures() -> dict:
    """A4, C4, D4: A, C, D at config_version 4 with nine zero-balance
    pools; B4: B with the operator's pool balances (the C B fixture's).
    E4: A4 with the operator's pool balances.  F4: E4 COMPLETED — app_hash
    present and chain_id holding its own value (D's shape, with pools)."""
    a4 = make_v4()
    # B4 carries the operator's pools, as the C cfg_make_v3_b does
    # (test_v2_gen.c :1669-1688) — required for stage 1c's W-A control.
    b4 = make_v4(pools=operator_pools(), params=B_PARAMS, **b_over())
    c4 = make_v4(names=C_NAMES)
    d4 = make_v4(app_hash=D_APP_HASH)
    d4["chain_id"] = chain_id(d4)
    e4 = make_v4(pools=operator_pools())
    f4 = make_v4(pools=operator_pools(), app_hash=D_APP_HASH)
    f4["chain_id"] = chain_id(f4)
    return {"V4_A": a4, "V4_B": b4, "V4_C": c4, "V4_D": d4,
            "V4_E": e4, "V4_F": f4}


def v4_self_checks(fx: dict) -> bool:
    """Structural facts the version-4 vectors must satisfy, checked before
    they are printed (a failure here is this file's defect)."""
    ok = True

    def check(label: str, cond: bool) -> None:
        nonlocal ok
        ok = ok and cond
        print("  [%s] %s" % ("OK " if cond else "FAIL", label))

    v3 = v3_fixtures()
    for t in ("A", "B", "C", "D"):
        n4 = len(encode_v4(fx["V4_" + t]))
        check("V4_%s length = pinned v3 %s length + %d (= %d)"
              % (t, t, TREASURY_BLOCK_LEN, PINNED_V3[t]["len"]
                 + TREASURY_BLOCK_LEN),
              n4 == PINNED_V3[t]["len"] + TREASURY_BLOCK_LEN)
    for t in ("A", "C"):
        # zero pools + unchanged composition: v4 = v3 with byte 19 = 4,
        # followed by the 108-byte block
        e3 = bytearray(encode_v3(v3[t]))
        e3[19] = 4
        check("V4_%s = v3 %s with config_version 4 ‖ treasury block" % (t, t),
              encode_v4(fx["V4_" + t]) == bytes(e3)
              + encode_treasury(zero_pools()))
    e4 = fx["V4_E"]
    check("E4 treasury Σ = %d NODUS" % OPERATOR_POOLS_SUM_NODUS,
          sum(b for _, b in e4["treasury"])
          == OPERATOR_POOLS_SUM_NODUS * DECIMAL_UNIT)
    check("E4 allocation = 50 000 000 NODUS (the Founder, W-A)",
          e4["allocs"][0]["amount"] == 50000000 * DECIMAL_UNIT)
    supply = (sum(a["amount"] for a in e4["allocs"])
              + sum(v["self_stake"] for v in e4["validators"])
              + e4["reward_pool_initial"]
              + sum(b for _, b in e4["treasury"]))
    check("E4 Rule P.2: Σ alloc + Σ stake + reward_pool + Σ treasury "
          "== total supply", supply == e4["total_supply_raw"])
    check("F4 chain_id is self-consistent inside the document",
          chain_id(fx["V4_F"]) == fx["V4_F"]["chain_id"])
    check("F4 source commit == E4 source commit (differ only in the two "
          "blanked fields)",
          source_commit_v3(fx["V4_F"]) == source_commit_v3(e4))
    check("V4_A chain id != v3 A chain id (the version field moves it)",
          chain_id(fx["V4_A"]) != chain_id(v3["A"]))
    check("E4 chain id != V4_A chain id (the pools move it)",
          chain_id(e4) != chain_id(fx["V4_A"]))

    # the encoder refuses every block the layout does not define
    bad = {
        "eight entries": zero_pools()[:8],
        "ten entries": zero_pools() + [(10, 0)],
        "pool ids out of order": [(2, 0), (1, 0)] + zero_pools()[2:],
        "pool id 0": [(0, 0)] + zero_pools()[1:],
        "balance > u64": [(1, UINT64_MAX + 1)] + zero_pools()[1:],
    }
    for label, pools in bad.items():
        try:
            encode_treasury(pools)
            refused = False
        except ValueError:
            refused = True
        check("encoder refuses a treasury with %s" % label, refused)
    try:
        encode_v4(dict(fx["V4_A"], config_version=3))
        refused = False
    except ValueError:
        refused = True
    check("encode_v4 refuses config_version 3", refused)
    return ok


def emit_v4_all(fx: dict) -> None:
    for tag, c in fx.items():
        emit(tag, c)
    print("  (F4 chain_id is self-consistent: %s)"
          % (chain_id(fx["V4_F"]) == fx["V4_F"]["chain_id"]))

    print()
    print("── version-4 per-pool sensitivity " + "─" * 35)
    base = fx["V4_E"]
    base_id = chain_id(base)
    base_sc = source_commit_v3(base)
    for i in range(TREASURY_POOLS):
        m = make_v4(pools=operator_pools())
        pid, bal = m["treasury"][i]
        m["treasury"][i] = (pid, bal + 1)
        print("    pool %d balance +1 raw changes the chain id: %s   "
              "source commit: %s"
              % (pid, chain_id(m) != base_id, source_commit_v3(m) != base_sc))
    a_app = make_v4(pools=operator_pools(),
                    app_hash=bytes(((0x11 + i) & 0xFF) for i in range(64)))
    print("    source_commit ignores app_hash (v4):          %s"
          % (source_commit_v3(a_app) == base_sc))
    z = make_v4(pools=operator_pools())
    z["chain_id"] = b"\x42" * 32
    print("    chain_id field alone does NOT change the id:  %s"
          % (chain_id(z) == base_id))


# ── stage 4: the version-5 vectors ────────────────────────────────────

BODY_HEAD_LEN = 16 + 4 + 7 * 8 + 2                  # 78, see CONTROL_V2
VAL_ENC_LEN = PUBKEY_SIZE * 2 + FINGERPRINT_SIZE + 8 + 2     # 5323
UDP_OFFSET_IN_VAL = PUBKEY_SIZE                              # 2592


def v5_fixtures() -> dict:
    """A5-D5: A-D at config_version 5 (B5 with the operator's pools), no
    outputs.  E5: A5 plus E5_OUTPUTS."""
    a5 = make_v5()
    b5 = make_v5(pools=operator_pools(), params=B_PARAMS, **b_over())
    c5 = make_v5(names=C_NAMES)
    d5 = make_v5(app_hash=D_APP_HASH)
    d5["chain_id"] = chain_id(d5)
    e5 = make_v5(outputs=E5_OUTPUTS)
    return {"V5_A": a5, "V5_B": b5, "V5_C": c5, "V5_D": d5, "V5_E": e5}


def v5_self_checks(fx: dict) -> bool:
    """Structural facts the version-5 vectors must satisfy, checked before
    they are printed (a failure here is this file's defect)."""
    ok = True

    def check(label: str, cond: bool) -> None:
        nonlocal ok
        ok = ok and cond
        print("  [%s] %s" % ("OK " if cond else "FAIL", label))

    extra = TREASURY_BLOCK_LEN + V5_EXTRA_LEN                  # 128
    for t in ("A", "B", "C", "D"):
        n5 = len(encode_v5(fx["V5_" + t]))
        check("V5_%s length = pinned v3 %s length + %d (= %d)"
              % (t, t, extra, PINNED_V3[t]["len"] + extra),
              n5 == PINNED_V3[t]["len"] + extra)
    check("V5_E length = V5_A length + 2 × %d" % GENOUT_ENTRY_LEN,
          len(encode_v5(fx["V5_E"]))
          == len(encode_v5(fx["V5_A"])) + 2 * GENOUT_ENTRY_LEN)

    # exactly which bytes moved: v3 A/C with byte 19 = 5 and the seven
    # 2592-byte destination-pubkey slots zeroed, then treasury ‖ gas ‖ fee
    # ‖ u32(0).  (dest_fp "keep" leaves every other body byte as in v3.)
    v3 = v3_fixtures()
    for t in ("A", "C"):
        e3 = bytearray(encode_v3(v3[t]))
        e3[19] = 5
        for i in range(COMMITTEE_SIZE):
            off = BODY_HEAD_LEN + i * VAL_ENC_LEN + UDP_OFFSET_IN_VAL
            e3[off:off + PUBKEY_SIZE] = ZERO_PUBKEY
        want = (bytes(e3) + encode_treasury(zero_pools())
                + u(GENESIS_GAS_PRICE, 8) + u(GENESIS_TOKEN_CREATE_FEE, 8)
                + u(0, 4))
        check("V5_%s = v3 %s, version 5, dest pubkeys zeroed ‖ treasury ‖ "
              "gas ‖ fee ‖ count 0" % (t, t),
              encode_v5(fx["V5_" + t]) == want)

    for tag, c in fx.items():
        check("%s every validator unstake_destination_pubkey is all-zero"
              % tag,
              all(v["unstake_destination_pubkey"] == ZERO_PUBKEY
                  for v in c["validators"]))
        check("%s gas = 121, token-create fee = 10^11" % tag,
              c["gas_price_raw_per_unit"] == 121
              and c["token_create_fee_raw"] == 10 ** 11)

    for tag in ("V5_B", "V5_E"):
        c = fx[tag]
        supply = (sum(a["amount"] for a in c["allocs"])
                  + sum(v["self_stake"] for v in c["validators"])
                  + c["reward_pool_initial"]
                  + sum(b for _, b in c["treasury"])
                  + sum(a for _, a in c["genesis_outputs"]))
        check("%s Rule P.2: Σ alloc + Σ stake + reward_pool + Σ treasury "
              "+ Σ outputs == total supply" % tag,
              supply == c["total_supply_raw"])
    check("V5_B treasury Σ = %d NODUS" % OPERATOR_POOLS_SUM_NODUS,
          sum(b for _, b in fx["V5_B"]["treasury"])
          == OPERATOR_POOLS_SUM_NODUS * DECIMAL_UNIT)

    e5 = fx["V5_E"]
    enc = encode_v5(e5)
    tail = enc[-(4 + 2 * GENOUT_ENTRY_LEN):]
    check("V5_E output section = count 2 ‖ outputs in DOCUMENT order",
          tail == u(2, 4) + E5_OUTPUTS[0][0] + u(E5_OUTPUTS[0][1], 8)
          + E5_OUTPUTS[1][0] + u(E5_OUTPUTS[1][1], 8))
    swapped = make_v5(outputs=list(reversed(E5_OUTPUTS)))
    check("swapping E5's two outputs changes the chain id",
          chain_id(swapped) != chain_id(e5))
    check("swapping E5's two outputs changes the source commit",
          source_commit_v3(swapped) != source_commit_v3(e5))
    check("V5_D chain_id is self-consistent inside the document",
          chain_id(fx["V5_D"]) == fx["V5_D"]["chain_id"])
    check("V5_D source commit == V5_A source commit (differ only in the "
          "two blanked fields)",
          source_commit_v3(fx["V5_D"]) == source_commit_v3(fx["V5_A"]))
    check("V5_A chain id != V4_A chain id",
          chain_id(fx["V5_A"]) != chain_id(make_v4()))
    check("V5_E chain id != V5_A chain id (the outputs move it)",
          chain_id(e5) != chain_id(fx["V5_A"]))

    # the encoder refuses every section the layout does not define
    good_owner = E5_OUTPUTS[0][0]
    bad = {
        "65 outputs": [(good_owner, 1)] * (MAX_GENOUTS + 1),
        "an all-zero owner": [(b"\x00" * GENOUT_OWNER_LEN, 1)],
        "a 63-byte owner": [(good_owner[:63], 1)],
        "amount 0": [(good_owner, 0)],
        "amount INT64_MAX + 1": [(good_owner, INT64_MAX + 1)],
    }
    for label, outs in bad.items():
        try:
            encode_genouts(outs)
            refused = False
        except ValueError:
            refused = True
        check("encoder refuses genesis outputs with %s" % label, refused)
    try:
        encode_genouts([(good_owner, 1)] * MAX_GENOUTS)
        accepted = True
    except ValueError:
        accepted = False
    check("encoder accepts exactly %d outputs" % MAX_GENOUTS, accepted)
    try:
        encode_v5(dict(fx["V5_A"], config_version=4))
        refused = False
    except ValueError:
        refused = True
    check("encode_v5 refuses config_version 4", refused)
    return ok


def emit_v5_all(fx: dict) -> None:
    for tag, c in fx.items():
        emit(tag, c)
    print("  (V5_D chain_id is self-consistent: %s)"
          % (chain_id(fx["V5_D"]) == fx["V5_D"]["chain_id"]))

    print()
    print("── version-5 fixture ALTERNATIVES — NOT the C fixture (test_v2_gen.c")
    print("   :247-254 keeps the XOR-0x5A fp; :1669-1688 gives B the pools) ──")
    alt_a = make_v5(dest_fp="zero_pk_fp")
    print("  A5 with dest fp = hex(SHA3-512(zero pubkey)) — enc_sha:")
    print("      %s" % sha3_512(encode_v5(alt_a)).hex())
    alt_b = make_v5(params=B_PARAMS, **b_over())
    print("  B5 with ZERO pools (as B4 was built) — enc_sha:")
    print("      %s" % sha3_512(encode_v5(alt_b)).hex())

    print()
    print("── version-5 sensitivity (each flipped ALONE, vs V5_E) " + "─" * 13)
    base = fx["V5_E"]
    base_id = chain_id(base)
    base_sc = source_commit_v3(base)

    def line(label: str, m: dict) -> None:
        print("    %-32s chain id: %s   source commit: %s"
              % (label, chain_id(m) != base_id, source_commit_v3(m) != base_sc))

    line("gas price +1", make_v5(outputs=E5_OUTPUTS,
                                 gas=GENESIS_GAS_PRICE + 1))
    line("token-create fee +1", make_v5(outputs=E5_OUTPUTS,
                                        fee=GENESIS_TOKEN_CREATE_FEE + 1))
    m = make_v5(outputs=E5_OUTPUTS)
    m["genesis_outputs"][1] = (E5_OUTPUTS[1][0], E5_OUTPUTS[1][1] + 1)
    line("output 1 amount +1", m)
    m = make_v5(outputs=E5_OUTPUTS)
    flipped = bytearray(E5_OUTPUTS[0][0])
    flipped[63] ^= 0x01
    m["genesis_outputs"][0] = (bytes(flipped), E5_OUTPUTS[0][1])
    line("output 0 owner last bit", m)
    line("outputs swapped", make_v5(outputs=list(reversed(E5_OUTPUTS))))
    a_app = make_v5(outputs=E5_OUTPUTS,
                    app_hash=bytes(((0x11 + i) & 0xFF) for i in range(64)))
    print("    source_commit ignores app_hash (v5):          %s"
          % (source_commit_v3(a_app) == base_sc))
    z = make_v5(outputs=E5_OUTPUTS)
    z["chain_id"] = b"\x42" * 32
    print("    chain_id field alone does NOT change the id:  %s"
          % (chain_id(z) == base_id))


# ── stage 1c: the RETIRED W-A literals written in the C tree ──────────
# nodus/tests/test_v2_gen.c :1566-1581 (comment "RETIRED W-A (config_version
# 4 without the fee fields) values — the oracle's stage-1c control
# legs").  A and C: chain id / source commit coincide with the
# encoding digest (zero app_hash and chain_id).  B pins all three; D pins
# enc and id.  Provenance: this oracle's earlier output, per that comment —
# NOT known to have been run green against the C.

PINNED_V4_WA = {
    "V4_A": {
        "enc_sha":
            "cc867861cb75f5135e4bb88dda3350a1b712da38abf120855340b448a7380406"
            "fd445b197c745188c1282f7d34494588a2b8de89c7202e806007be4980925efa",
        "chain_id":
            "cc867861cb75f5135e4bb88dda3350a1b712da38abf120855340b448a7380406",
        "src_commit":
            "cc867861cb75f5135e4bb88dda3350a1b712da38abf120855340b448a7380406"
            "fd445b197c745188c1282f7d34494588a2b8de89c7202e806007be4980925efa",
    },
    "V4_B": {
        "enc_sha":
            "83d631380dd291a29d44441f1a661c506c3c279976318fc7cdf82da1d15f540a"
            "e06847ad941898cff304e440a70376941be05d4e4deb354661e0bb3af9d0b460",
        "chain_id":
            "dd4f448e4d0137ce78386cd639d31fbceca7b36e5ba2be22230351eb3dec3cae",
        "src_commit":
            "bcb91c4e5f4d258e591f23949f9af5e0bb0bd753fa3f83ad142e137bf730ab2a"
            "1c3be07e25047842337984a351548c323682dd66fd7aa792f286da3cb22e28a5",
    },
    "V4_C": {
        "enc_sha":
            "0ef525aa070ba5dd5e5a56e3d438fe510831b2beadf724cc2f92a55bf7bb968d"
            "0f743c0a91c3d0d105fd84a43d8b9700b63401b0019121282835a2e698837709",
        "chain_id":
            "0ef525aa070ba5dd5e5a56e3d438fe510831b2beadf724cc2f92a55bf7bb968d",
        "src_commit": None,
    },
    "V4_D": {
        "enc_sha":
            "f3ebeb9d675afbfced3eb41e93e49ea7201a613108155a9c373c015331790d27"
            "73b7b70c9d1435bc26648e7e167fd79c7dce21a452f07612150f1cc2652da202",
        "chain_id":
            "75d47725f9b9dd551d5e1702294ee34e74b152962ff145672cee4daf5d892582",
        "src_commit": None,
    },
}


def v4_wa_control() -> bool:
    print()
    print("── stage 1c: CONTROL (V4 A-D vs the retired W-A literals, "
          "test_v2_gen.c :1566-1581) ─")
    fx = v4_fixtures()
    ok = True
    for tag, pin in PINNED_V4_WA.items():
        c = fx[tag]
        rows = [("enc_sha", sha3_512(encode_v4(c)).hex(), pin["enc_sha"]),
                ("chain_id", chain_id(c).hex(), pin["chain_id"])]
        if pin["src_commit"] is not None:
            rows.append(("src_commit", source_commit_v3(c).hex(),
                         pin["src_commit"]))
        for what, got, want in rows:
            good = (got == want)
            ok = ok and good
            print("  [%s] %s %-10s %s…" % ("OK " if good else "FAIL", tag,
                                           what, got[:32]))
            if not good:
                print("        computed     %s" % got)
                print("        pinned       %s" % want)
    return ok


# ── stage 5: the test_v2_gen.c placeholders, under their C names ──────


def make_control_v5_body_cfg() -> dict:
    """The §5 fixture's BODY (test_v2_gen.c :1757 cfg_make_v3_ex(0, 1, 0)
    → cfg_make :206-279): make_cfg() with every unstake_destination_pubkey
    zeroed AFTER the fp was derived from pubkey XOR 0x5A (:247-254), the
    single allocation left at TREASURY_RAW (cfg_make_v3_ex :291-311 never
    touches it), and config_version rewritten to 2 (§5 :1815)."""
    c = make_cfg()
    for v in c["validators"]:
        v["unstake_destination_pubkey"] = ZERO_PUBKEY
    c["config_version"] = 2
    return c


# The C lengths, test_v2_gen.c :1509, :1528-1535 (version-3 length + 108
# treasury + 16 fee + 4 output count).
C_KAT_LEN = {"A": 56121 + 128, "B": 56130 + 128,
             "C": 56131 + 128, "D": 56121 + 128}


def c_placeholders() -> bool:
    print()
    print("══ STAGE 5: test_v2_gen.c placeholders (C names) " + "═" * 19)
    ok = True

    def check(label: str, cond: bool) -> None:
        nonlocal ok
        ok = ok and cond
        print("  [%s] %s" % ("OK " if cond else "FAIL", label))

    # §5 control body
    ctl = make_control_v5_body_cfg()
    body = encode_body(ctl)
    check("§5 body length == KAT_V2_ENC_LEN 37481", len(body) == 37481)
    old = bytearray(encode_body(make_cfg()))
    for i in range(COMMITTEE_SIZE):
        off = BODY_HEAD_LEN + i * VAL_ENC_LEN + UDP_OFFSET_IN_VAL
        old[off:off + PUBKEY_SIZE] = ZERO_PUBKEY
    check("§5 body == stage-1 body with exactly the seven destination-"
          "pubkey slots zeroed", bytes(old) == body)
    check("§5 body reads config_version 2 at byte 19", body[16:20]
          == u(2, 4))
    # the §5 body is the version-5 A-type body with byte 19 := 2 (the tail
    # does not reach it); cross-check against a v5 document built the
    # §5 way (reward 0, alloc TREASURY_RAW)
    v5 = make_v5(reward_pool_initial=0,
                 genesis_time_ms=1700000000000)
    v5_body = bytearray(encode_v5(v5)[:37481])
    v5_body[19] = 2
    check("§5 body == first 37481 bytes of a v5 document (§5 composition) "
          "with byte 19 := 2", bytes(v5_body) == body)

    fx = v5_fixtures()
    for t in ("A", "B", "C", "D"):
        n = len(encode_v5(fx["V5_" + t]))
        check("KAT_%s_ENC_LEN: %d == C arithmetic %d" % (t, n, C_KAT_LEN[t]),
              n == C_KAT_LEN[t])
    check("D chain_id self-consistent", chain_id(fx["V5_D"])
          == fx["V5_D"]["chain_id"])
    if not ok:
        return False

    print()
    print_hex_c("KAT_V2_ENC_SHA", sha3_512(body).hex())
    names = {"A": ("ENC_SHA", "CHAIN_ID", "SRC_COMMIT"),
             "B": ("ENC_SHA", "CHAIN_ID", "SRC_COMMIT"),
             "C": ("ENC_SHA", "CHAIN_ID"),        # :1903 pins no src commit
             "D": ("ENC_SHA", "CHAIN_ID")}        # :1904 pins no src commit
    for t, fields in names.items():
        c = fx["V5_" + t]
        vals = {"ENC_SHA": sha3_512(encode_v5(c)).hex(),
                "CHAIN_ID": chain_id(c).hex(),
                "SRC_COMMIT": source_commit_v3(c).hex()}
        print()
        for f in fields:
            print_hex_c("KAT_%s_%s" % (t, f), vals[f])
    return True


def main() -> int:
    if not control_leg():
        print()
        print("CONTROL LEG FAILED — refusing to emit version-3 vectors.")
        return 1
    if not v3_kat_control():
        print()
        print("VERSION-3 KAT CONTROL FAILED — this file's version-3 model")
        print("no longer reproduces test_v2_gen.c's pins; refusing to emit")
        print("anything, version 4 included.")
        return 1
    if not v4_wa_control():
        print()
        print("W-A CONTROL FAILED — this file no longer reproduces the retired")
        print("W-A literals in test_v2_gen.c; refusing to emit anything.")
        return 1
    emit_all()
    print()
    print("control leg green — the version-3 vectors above are derived from")
    print("the layout, not from the C.")

    print()
    print("══ VERSION 4 " + "═" * 55)
    fx = v4_fixtures()
    if not v4_self_checks(fx):
        print()
        print("VERSION-4 SELF-CHECK FAILED — refusing to emit version-4 "
              "vectors.")
        return 1
    emit_v4_all(fx)
    print()
    print("version-4 vectors above: the version-3 model (asserted against")
    print("the C pins in stage 1b) plus the 108-byte treasury block.")

    print()
    print("══ VERSION 5 " + "═" * 55)
    fx5 = v5_fixtures()
    if not v5_self_checks(fx5):
        print()
        print("VERSION-5 SELF-CHECK FAILED — refusing to emit version-5 "
              "vectors.")
        return 1
    emit_v5_all(fx5)
    print()
    print("version-5 vectors above: the version-4 model plus gas ‖ fee ‖")
    print("genesis outputs, destination pubkeys zeroed. Derived from the")
    print("written layout, NOT asserted against any C pin.")

    if not c_placeholders():
        print()
        print("STAGE 5 SELF-CHECK FAILED — refusing to print the placeholder "
              "values.")
        return 1
    print()
    print("stage 5 values: derived from the layout and the test_v2_gen.c")
    print("fixtures; NOT asserted against any C value. Pin KAT_V2_ENC_SHA")
    print("into CONTROL_V2_ENC_SHA only after §5 runs green with it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
