#!/usr/bin/env python3
"""
Independent oracle for BlockHeader v3 / BlockID v3 (Ledger V2 O13).

INDEPENDENCE DISCIPLINE
-----------------------
This file re-implements the canonical encoding from the SPEC (the byte
table in shared/dnac/block_v2.h), not by calling the C code.  A vector
generated only by the implementation under test is not grounding.

It runs in two stages and refuses to print v3 vectors unless stage 1
passes:

  stage 1 CONTROL — reproduce the five SHIPPED v2 KATs currently pinned
                    in nodus/tests/test_block_v2.c byte-identically.
                    If this fails, the oracle itself is wrong and every
                    v3 number it would print is worthless.
  stage 2 EMIT    — the v3 vectors, from the same code paths.

Run:  python3 shared/dnac/tests/block_v3_oracle.py

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import hashlib
import sys

# ── primitives ────────────────────────────────────────────────────────

def sha3_512(b: bytes) -> bytes:
    return hashlib.sha3_512(b).digest()


def tag16(s: str) -> bytes:
    """16-byte zero-padded domain tag (the C form: char[16] = "..."), the
    trailing NULs including the implicit string terminator."""
    raw = s.encode("ascii")
    if len(raw) > 16:
        raise ValueError("tag longer than 16 bytes: %r" % s)
    return raw + b"\x00" * (16 - len(raw))


def fill(n: int, seed: int) -> bytes:
    """Mirror of test_block_v2.c fill(): dst[i] = (seed + i*7) & 0xff."""
    return bytes(((seed + i * 7) & 0xFF) for i in range(n))


def be(v: int, width: int) -> bytes:
    return v.to_bytes(width, "big")


TAG_BLOCK_V2 = tag16("DNA.BLOCK.v2")
TAG_BLOCK_V3 = tag16("DNA.BLOCK.v3")

# ── canonical encoders (from the spec byte tables) ────────────────────

def encode_v2(h: dict) -> bytes:
    """349-byte v2 encoding; bound prefix is the first 341 bytes."""
    out = b""
    out += bytes([h["header_version"]])          # off   0
    out += h["chain_id"]                         # off   1  (32)
    out += be(h["block_height"], 8)              # off  33
    out += be(h["epoch"], 8)                     # off  41
    out += h["prev_block_id"]                    # off  49  (64)
    out += h["global_state_root"]                # off 113  (64)
    out += h["tx_root"]                          # off 177  (64)
    out += h["validator_set_hash"]               # off 241  (64)
    out += be(h["tx_count"], 4)                  # off 305
    out += h["proposer_id"]                      # off 309  (32)
    assert len(out) == 341, len(out)
    out += be(h["timestamp"], 8)                 # off 341
    assert len(out) == 349, len(out)
    return out


def encode_v3(h: dict) -> bytes:
    """413-byte v3 encoding; bound prefix is the first 405 bytes.

    Delta vs v2: domain_updates_root[64] inserted at offset 241, between
    tx_root (the transaction-body commitment) and validator_set_hash (the
    certification authority commitment).  Everything after it shifts by 64.
    """
    out = b""
    out += bytes([h["header_version"]])          # off   0
    out += h["chain_id"]                         # off   1  (32)
    out += be(h["block_height"], 8)              # off  33
    out += be(h["epoch"], 8)                     # off  41
    out += h["prev_block_id"]                    # off  49  (64)
    out += h["global_state_root"]                # off 113  (64)
    out += h["tx_root"]                          # off 177  (64)
    out += h["domain_updates_root"]              # off 241  (64)  <-- NEW
    out += h["validator_set_hash"]               # off 305  (64)
    out += be(h["tx_count"], 4)                  # off 369
    out += h["proposer_id"]                      # off 373  (32)
    assert len(out) == 405, len(out)
    out += be(h["timestamp"], 8)                 # off 405
    assert len(out) == 413, len(out)
    return out


def block_id_v2(h: dict) -> bytes:
    return sha3_512(TAG_BLOCK_V2 + encode_v2(h)[:341])


def block_id_v3(h: dict) -> bytes:
    return sha3_512(TAG_BLOCK_V3 + encode_v3(h)[:405])


def genesis_id_v2(h: dict, manifest: bytes) -> bytes:
    return sha3_512(TAG_BLOCK_V2 + encode_v2(h)[:341] + manifest)


def genesis_id_v3(h: dict, manifest: bytes) -> bytes:
    return sha3_512(TAG_BLOCK_V3 + encode_v3(h)[:405] + manifest)


# ── the empty domain_updates_root (domain_wire.h:436-440) ─────────────
# n == 0 yields SHA3-512 of the "DNA.E.DUPD.v1" tag ALONE.  A block that
# touches nothing must be distinguishable from a missing/malformed body,
# so this value is pinned too.
EMPTY_DUPD_ROOT = sha3_512(tag16("DNA.E.DUPD.v1"))

# ── fixtures (mirror of test_block_v2.c base_header/genesis block) ────

def base_v2() -> dict:
    return {
        "header_version": 2,
        "chain_id": fill(32, 0xA0),
        "block_height": 5,
        "epoch": 2,
        "prev_block_id": fill(64, 0xC0),
        "global_state_root": fill(64, 0xD0),
        "tx_root": fill(64, 0xE0),
        "validator_set_hash": fill(64, 0xF0),
        "tx_count": 3,
        "proposer_id": fill(32, 0x11),
        "timestamp": 0x0102030405060708,
    }


def base_v3() -> dict:
    h = base_v2()
    h["header_version"] = 3
    # New seed 0x55, distinct from every other fixture seed above, so a
    # field-swap mutant cannot accidentally produce the same bytes.
    h["domain_updates_root"] = fill(64, 0x55)
    return h


MANIFEST = b"DNA-TEST-MANIFEST-v1" + fill(44, 0x33)

# ── stage 1: CONTROL LEGS — the shipped v2 pins ───────────────────────

SHIPPED_V2 = {
    "KAT_ENC_SHA":
        "6b57e520049189934aea09aded30538f1d87f59a39a4e94ab3be2313d4985793"
        "14451a5bf3da3807764bb7dddefc09c14b41dceb710486992001f4b51ac9ef3b",
    "KAT_BLOCK_ID":
        "d7beb71ce44dc5b4676cf5f247e5210f2199a089cd10111303c20fe581c2f1da"
        "437997018d2936183900b82e85b71aa2d0ae013fb2fe953e0dbdc49ec98150be",
    "KAT_GENESIS_ID":
        "d4485cd6f0b044ad760742ca124f9633ae32c38aaf7257c8c860432c1f03ea38"
        "4bfec62599589bb593af1c2a1786f481637a3f79d5b627e87dae59a15ea17e47",
    "KAT_GENESIS_CHAIN":
        "d4485cd6f0b044ad760742ca124f9633ae32c38aaf7257c8c860432c1f03ea38",
    "KAT_GENESIS_ID_MUT":
        "e902ef055f75ecbf083b0bf0c1c143bbf252d09db203e650a824374df6c23da7"
        "1716fa1bd3c1e20fe83cae136955b47c69c6ace0dd488cfd0b1177a17000c6d5",
}


def genesis_header(base_fn, version_field_name="header_version"):
    g = base_fn()
    g["chain_id"] = b"\x00" * 32
    g["block_height"] = 0
    g["epoch"] = 0
    g["prev_block_id"] = b"\x00" * 64
    g["tx_count"] = 1
    return g


def control_legs() -> bool:
    ok = True
    h = base_v2()
    got = {
        "KAT_ENC_SHA": sha3_512(encode_v2(h)).hex(),
        "KAT_BLOCK_ID": block_id_v2(h).hex(),
    }

    g = genesis_header(base_v2)
    gid = genesis_id_v2(g, MANIFEST)
    got["KAT_GENESIS_ID"] = gid.hex()
    got["KAT_GENESIS_CHAIN"] = gid[:32].hex()

    mut = bytearray(MANIFEST)
    mut[0] ^= 1
    got["KAT_GENESIS_ID_MUT"] = genesis_id_v2(g, bytes(mut)).hex()

    print("── stage 1: CONTROL LEGS (shipped v2 pins) " + "─" * 26)
    for k, expect in SHIPPED_V2.items():
        actual = got[k]
        good = (actual == expect)
        ok = ok and good
        print("  [%s] %s" % ("OK " if good else "FAIL", k))
        if not good:
            print("        pinned: %s" % expect)
            print("        oracle: %s" % actual)
    return ok


# ── stage 2: EMIT v3 ──────────────────────────────────────────────────

def emit_v3() -> None:
    h = base_v3()
    enc = encode_v3(h)

    print()
    print("── stage 2: v3 VECTORS " + "─" * 46)
    print("  DNA_BH3_ENC_SIZE        = %d" % len(enc))
    print("  DNA_BH3_BOUND_SIZE      = 405")
    print("  BlockID preimage length = %d" % (16 + 405))
    print()
    print("  offset spot-checks (canonical table):")
    for name, off, val in [
        ("version",             0,   enc[0]),
        ("chain_id",            1,   enc[1]),
        ("block_height end",    40,  enc[40]),
        ("epoch end",           48,  enc[48]),
        ("prev_block_id",       49,  enc[49]),
        ("global_state_root",   113, enc[113]),
        ("tx_root",             177, enc[177]),
        ("domain_updates_root", 241, enc[241]),
        ("validator_set_hash",  305, enc[305]),
        ("tx_count end",        372, enc[372]),
        ("proposer_id",         373, enc[373]),
        ("timestamp first",     405, enc[405]),
        ("timestamp last",      412, enc[412]),
    ]:
        print("    %-22s @%-4d = 0x%02x" % (name, off, val))

    print()
    print('  static const char *KAT3_ENC_SHA =')
    print_hex_c(sha3_512(enc).hex())
    print('  static const char *KAT3_BLOCK_ID =')
    print_hex_c(block_id_v3(h).hex())

    g = genesis_header(base_v3)
    gid = genesis_id_v3(g, MANIFEST)
    print('  static const char *KAT3_GENESIS_ID =')
    print_hex_c(gid.hex())
    print('  static const char *KAT3_GENESIS_CHAIN =')
    print_hex_c(gid[:32].hex())

    mut = bytearray(MANIFEST)
    mut[0] ^= 1
    print('  static const char *KAT3_GENESIS_ID_MUT =')
    print_hex_c(genesis_id_v3(g, bytes(mut)).hex())

    print('  static const char *KAT3_EMPTY_DUPD_ROOT =')
    print_hex_c(EMPTY_DUPD_ROOT.hex())

    # Cross-version separation: the SAME semantic content under v2 vs v3
    # tags/layout must never collide.
    print()
    print("  cross-version separation:")
    print("    v3 id != v2 id (same fixture core): %s"
          % (block_id_v3(base_v3()) != block_id_v2(base_v2())))

    # Zero-envelope vs populated: the tagged empty root must produce a
    # DIFFERENT BlockID than any populated update root.
    z = base_v3()
    z["domain_updates_root"] = EMPTY_DUPD_ROOT
    print("    zero-envelope id != populated id:   %s"
          % (block_id_v3(z) != block_id_v3(base_v3())))
    print('  static const char *KAT3_BLOCK_ID_EMPTY_DUPD =')
    print_hex_c(block_id_v3(z).hex())


def print_hex_c(hexstr: str) -> None:
    """Emit a hex digest as the project's two-line C literal form."""
    if len(hexstr) == 128:
        print('      "%s"' % hexstr[:64])
        print('      "%s";' % hexstr[64:])
    else:
        print('      "%s";' % hexstr)


def main() -> int:
    if not control_legs():
        print()
        print("CONTROL LEGS FAILED — the oracle does not reproduce the "
              "shipped v2 pins.")
        print("Refusing to emit v3 vectors.")
        return 1
    emit_v3()
    print()
    print("control legs green — v3 vectors above are independently derived.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
