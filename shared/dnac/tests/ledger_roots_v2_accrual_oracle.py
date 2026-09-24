#!/usr/bin/env python3
"""
Independent vector oracle for tokenomics-v3 P2's changes to the CORE
state root (shared/dnac/ledger_roots_v2.{h,c}): the reward-pool field of
the supply leaf ("DNA.SUPPLY.v2"), the reward-accrual leg
(dna_v2_accrual_leaf_hash / dna_v2_accrual_root, empty tag
"DNA.E.ACCRU.v1") and the 7-leg core_state_root ("DNA.CORE.v2"); and,
since the root-layout round (K1, 2026-09-25), the 340-byte UTXO leaf
that feeds core_state_root's utxo_root leg.

── PROVENANCE — HONEST LABEL ────────────────────────────────────────────
This is a SELF-CONSISTENCY oracle, not an external audit: the format is
this project's own invention (there is no pinned external reference for
"a reward-accrual leg of a tagged Merkle state root"). It was written the
SAME DAY as the C it checks, by re-deriving the byte layout from
shared/dnac/ledger_roots_v2.h's written contract ("TAG TABLE" /
"Composition preimages") in an independent Python implementation.
Agreement proves the C and this script implement the SAME documented
format; it does NOT prove the format sound or the only reasonable one.
Call it "self-consistent", never "independently audited". Same status as
ledger_roots_v2_attendance_oracle.py (P1).

── WHAT IS PINNED ────────────────────────────────────────────────────────
  supply_root   = SHA3-512("DNA.SUPPLY.v2" (16B zero-padded) ||
                           genesis(8 BE) || minted(8 BE) ||
                           burned(8 BE) || reward_pool(8 BE))
  accrual leaf  = SHA3-512("DNA.ACLEAF.v1" || owner_fp[64] || amount(8 BE))
  accrual inner = SHA3-512("DNA.ACNODE.v1" || left[64] || right[64])
  accrual empty = SHA3-512("DNA.E.ACCRU.v1")
  core_root     = SHA3-512("DNA.CORE.v2" || 7 legs of 64 bytes, in order:
                  utxo, token, pools, claims, names, supply, accrual)
The Merkle rule is the file's own: leaves in strictly ascending key
order, an unpaired node PROMOTED (never duplicated), n == 1 -> the leaf.

  UTXO leaf (root-layout round K1, 2026-09-25 — the utxo_root leg of
  the same core_state_root; nodus_witness_merkle.c
  nodus_witness_merkle_leaf_hash + its client mirror
  dnac_utxo_compute_leaf_hash):
    digest = SHA3-512(nullifier[64] || owner[128, NUL-padded] ||
                      amount(8 LE) || token_id[64] || tx_hash[64] ||
                      output_index(4 LE) || unlock_block(8 LE))  — 340 B,
             NO tag (the pre-K1 leaf was the first 332 bytes)
    utxo_root is RFC 6962: leaf = SHA3-512(0x00 || digest), inner =
    SHA3-512(0x01 || L || R), split at the largest power of two < n;
    n == 1 -> SHA3-512(0x00 || digest).
  NO control leg exists for the UTXO leaf: no test at d2056c59 pinned a
  332-byte leaf or a non-empty utxo_root literal (grep of nodus/tests
  for 128-hex literals in the merkle tests: only all-zero token_id
  DEFAULTs). The C test reproduces the digest a SECOND way (hand-built
  340-byte buffer hashed directly), which is the independent path.

── HOW THIS CAN LIE ──────────────────────────────────────────────────────
 1. Same-author, same-day: see PROVENANCE above.
 2. `fill(seed)` is test_roots_v2.c's own fixture convention, reproduced
    byte-for-byte; a bug shared between the C fixture and this generator
    would agree with itself.
 3. The two self-checks (the RETIRED "DNA.SUPPLY.v1" and 6-leg
    "DNA.CORE.v1" vectors already pinned in test_roots_v2.c before P2)
    are run FIRST; if either fails, nothing this script prints below them
    may be used.

Read-only: opens nothing, writes nothing, prints to stdout.
"""
import hashlib
import struct

TAG_LEN = 16


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def tag(name: str) -> bytes:
    b = name.encode("ascii")
    assert len(b) <= TAG_LEN, f"tag {name!r} too long for a 16-byte slot"
    return b + b"\x00" * (TAG_LEN - len(b))


def fill(seed: int, n: int = 64) -> bytes:
    """test_roots_v2.c's own fixture convention: dst[i] = seed + i*7 (mod 256)."""
    return bytes([(seed + i * 7) & 0xFF for i in range(n)])


def be64(v: int) -> bytes:
    return struct.pack(">Q", v)


TAG_SUPPLY_V1 = tag("DNA.SUPPLY.v1")
TAG_SUPPLY_V2 = tag("DNA.SUPPLY.v2")
TAG_CORE_V1 = tag("DNA.CORE.v1")
TAG_CORE_V2 = tag("DNA.CORE.v2")
TAG_ACLEAF = tag("DNA.ACLEAF.v1")
TAG_ACNODE = tag("DNA.ACNODE.v1")
TAG_E_ACCRU = tag("DNA.E.ACCRU.v1")


def supply_root_v2(genesis: int, minted: int, burned: int, pool: int) -> bytes:
    return sha3_512(TAG_SUPPLY_V2 + be64(genesis) + be64(minted) +
                    be64(burned) + be64(pool))


def accrual_leaf(owner_fp: bytes, amount: int) -> bytes:
    assert len(owner_fp) == 64
    return sha3_512(TAG_ACLEAF + owner_fp + be64(amount))


def tagged_merkle(node_tag: bytes, leaves):
    level = list(leaves)
    assert len(level) >= 1
    while len(level) > 1:
        nxt = []
        i = 0
        n = len(level)
        while i + 1 < n:
            nxt.append(sha3_512(node_tag + level[i] + level[i + 1]))
            i += 2
        if i < n:
            nxt.append(level[i])  # odd node PROMOTED, never duplicated
        level = nxt
    return level[0]


def accrual_root(rows):
    """rows: list of (owner_fp[64], amount), STRICTLY ascending owner_fp
    (asserted here — the C rejects any other order)."""
    for a, b in zip(rows, rows[1:]):
        assert a[0] < b[0], "rows must be strictly ascending by owner_fp"
    if len(rows) == 0:
        return sha3_512(TAG_E_ACCRU)
    return tagged_merkle(TAG_ACNODE, [accrual_leaf(fp, a) for fp, a in rows])


def core_root_v2(legs7):
    assert len(legs7) == 7
    return sha3_512(TAG_CORE_V2 + b"".join(legs7))


def le64(v: int) -> bytes:
    return struct.pack("<Q", v)


def le32(v: int) -> bytes:
    return struct.pack("<I", v)


def utxo_leaf_digest(nullifier: bytes, owner: bytes, amount: int,
                     token_id: bytes, tx_hash: bytes, output_index: int,
                     unlock_block: int) -> bytes:
    """Root-layout round K1 — the 340-byte untagged preimage."""
    assert len(nullifier) == 64 and len(token_id) == 64 and len(tx_hash) == 64
    assert len(owner) <= 128
    pre = (nullifier + owner + b"\x00" * (128 - len(owner)) + le64(amount) +
           token_id + tx_hash + le32(output_index) + le64(unlock_block))
    assert len(pre) == 340
    return sha3_512(pre)


def utxo_root_1(digest: bytes) -> bytes:
    """RFC 6962, n == 1: the leaf-tagged digest."""
    return sha3_512(b"\x00" + digest)


# The UTXO KAT fixture — transcribed byte-for-byte in
# nodus/tests/test_merkle_utxo_root.c and dnac/tests/test_merkle_verify.c.
UTXO_NULLIFIER = fill(0x11)
UTXO_OWNER = b"ab" * 64                 # 128 ASCII bytes, no NUL padding needed
UTXO_AMOUNT = 0x0102030405060708
UTXO_TOKEN_ID = fill(0x22)
UTXO_TX_HASH = fill(0x33)
UTXO_OUTPUT_INDEX = 0x0A0B0C0D
UTXO_UNLOCK_BLOCK = 0x1122334455667788


def main():
    for t in (TAG_SUPPLY_V1, TAG_SUPPLY_V2, TAG_CORE_V1, TAG_CORE_V2,
              TAG_ACLEAF, TAG_ACNODE, TAG_E_ACCRU):
        assert len(t) == TAG_LEN

    # Self-checks against the values ALREADY pinned in test_roots_v2.c
    # before P2 (KAT_SUPPLY, KAT_CORE) — the method must reproduce the
    # retired vectors before anything new is trusted.
    old_supply = sha3_512(TAG_SUPPLY_V1 + be64(100000000000000000) +
                          be64(500) + be64(300))
    OLD_KAT_SUPPLY = (
        "ef949407440c0a7adab9f6b0a0999e06074e57a4b2b04f7b1532cf2effb597f2"
        "e656e3f396f663a1b3d5237d6709165393ec076ddc5f47f35abe0de3b26e91b7"
    )
    assert old_supply.hex() == OLD_KAT_SUPPLY, "retired supply vector not reproduced"
    old_core = sha3_512(TAG_CORE_V1 + b"".join(fill(0xB0 + i) for i in range(6)))
    OLD_KAT_CORE = (
        "ccaae1c6ced38cfd93a99f9a15f26c490c15fd343d18f9232116bab6d7ba1f7f"
        "c918b7a324b071cda8b6a556dbb89226da6082f9efc55aa2667659c2f4f8db3e"
    )
    assert old_core.hex() == OLD_KAT_CORE, "retired 6-leg core vector not reproduced"
    print("[self-check] retired DNA.SUPPLY.v1 and 6-leg DNA.CORE.v1 vectors reproduced")
    print()

    print("EMPTY_ACCRUAL     =", sha3_512(TAG_E_ACCRU).hex())
    print("KAT_SUPPLY_V2     =",
          supply_root_v2(100000000000000000, 500, 300, 400).hex(),
          "  (genesis 1e17, minted 500, burned 300, pool 400)")
    print("KAT_ACC_LEAF      =", accrual_leaf(fill(0x11), 12345).hex(),
          "  (owner fill(0x11), amount 12345)")
    root1 = accrual_root([(fill(0x11), 12345)])
    assert root1 == accrual_leaf(fill(0x11), 12345), "n==1 root must be the leaf"
    print("KAT_ACC_ROOT_2    =",
          accrual_root([(fill(0x11), 12345), (fill(0x22), 67890)]).hex(),
          "  (owners fill(0x11), fill(0x22); amounts 12345, 67890)")
    print("KAT_ACC_ROOT_3    =",
          accrual_root([(fill(0x11), 12345), (fill(0x22), 67890),
                        (fill(0x33), 1)]).hex(),
          "  (+ owner fill(0x33), amount 1 — the promoted odd node)")
    print("KAT_CORE_7LEG     =",
          core_root_v2([fill(0xB0 + i) for i in range(7)]).hex(),
          "  (DNA.CORE.v2, legs = fill(0xB0..0xB6))")

    # Root-layout round K1 — the UTXO leaf with unlock_block.
    print()
    d = utxo_leaf_digest(UTXO_NULLIFIER, UTXO_OWNER, UTXO_AMOUNT,
                         UTXO_TOKEN_ID, UTXO_TX_HASH, UTXO_OUTPUT_INDEX,
                         UTXO_UNLOCK_BLOCK)
    d0 = utxo_leaf_digest(UTXO_NULLIFIER, UTXO_OWNER, UTXO_AMOUNT,
                          UTXO_TOKEN_ID, UTXO_TX_HASH, UTXO_OUTPUT_INDEX, 0)
    assert d != d0, "unlock_block must reach the leaf"
    assert utxo_root_1(d) != utxo_root_1(d0), "unlock_block must reach the root"
    print("KAT_UTXO_LEAF_UB  =", d.hex(),
          "  (nullifier fill(0x11), owner 'ab'*64, amount 0x0102030405060708,"
          " token fill(0x22), tx fill(0x33), idx 0x0A0B0C0D,"
          " unlock_block 0x1122334455667788)")
    print("KAT_UTXO_LEAF_UB0 =", d0.hex(), "  (same row, unlock_block 0)")
    print("KAT_UTXO_ROOT_UB  =", utxo_root_1(d).hex(),
          "  (utxo_root over that single row = SHA3-512(0x00 || leaf))")


if __name__ == "__main__":
    main()
