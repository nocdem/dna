#!/usr/bin/env python3
"""
Independent vector oracle for tokenomics-v3 P1's attendance leg
(shared/dnac/ledger_roots_v2.{h,c}: dna_v2_attendance_digest,
dna_v2_attendance_leaf_hash, dna_v2_attendance_root, and the 8-leg
dna_v2_system_root).

── PROVENANCE — HONEST LABEL ────────────────────────────────────────────
This is a SELF-CONSISTENCY oracle, not an external audit: this format is
this project's own invention (there is no pinned external reference for
"an attendance leg of a tagged Merkle state root" the way cmt_vset_oracle.py
has cometbft's validator_set.go). It was written the SAME DAY as the C it
checks, by re-deriving the byte layout from shared/dnac/ledger_roots_v2.h's
own written contract ("TAG TABLE" / "Composition preimages" sections) in an
independent Python implementation, then comparing against the C's output.
Agreement proves the C and this script implement the SAME documented
format; it does NOT prove the format itself is sound, novel-attack-free,
or the only reasonable choice — there is nothing external to agree with.
Call it "self-consistent", never "independently audited".

── WHAT IS PINNED ────────────────────────────────────────────────────────
  attendance digest = SHA3-512("DNA.ATTEP.v1" (16B zero-padded) ||
      epoch_start(8 BE) || n(4 BE) ||
      sum_{rows ASC by voter_id} (voter_id[32] || signed_count(8 BE) ||
                                   last_signed_height(8 BE)))
  attendance leaf    = SHA3-512("DNA.ATLEAF.v1" || epoch_start(8 BE) ||
                                 digest[64])
  attendance inner   = SHA3-512("DNA.ATNODE.v1" || left[64] || right[64])
  attendance empty   = SHA3-512("DNA.E.ATTND.v1")
  system_state_root  = SHA3-512("DNA.SYS.v2" || 8 legs of 64 bytes, in
      order: validator_root, delegation_root, epoch_state_root_v2,
      chain_config_root, validator_set_root, domain_registry_root,
      manifest_root, attendance_root)

Every tag is a FIXED 16-byte zero-padded ASCII string (ledger_roots_v2.h
"TAG TABLE" convention) — this script pads exactly the same way the C
array initializers do (explicit NUL bytes filling out to 16), verified in
`_check_tag_padding` below before anything else runs.

── HOW THIS CAN LIE ──────────────────────────────────────────────────────
 1. Same-author, same-day: see PROVENANCE above.
 2. The `fill(seed)` fixture bytes are this test file's own convention
    (test_roots_v2.c), reproduced here byte-for-byte; a bug shared between
    the C fixture and this generator's `fill()` would agree with itself
    and prove nothing about the real hash.
 3. `KAT_SYSTEM_8LEG` (the sanity re-derivation of the OLD 7-leg
    "DNA.SYS.v1" vector) is checked against the value ALREADY pinned in
    test_roots_v2.c before this script's method is trusted for the NEW
    8-leg vector — if that check fails, nothing below it should be used.

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


def be32(v: int) -> bytes:
    return struct.pack(">I", v)


TAG_ATTEP = tag("DNA.ATTEP.v1")
TAG_ATLEAF = tag("DNA.ATLEAF.v1")
TAG_ATNODE = tag("DNA.ATNODE.v1")
TAG_E_ATTND = tag("DNA.E.ATTND.v1")
TAG_SYS_V2 = tag("DNA.SYS.v2")
TAG_SYS_V1 = tag("DNA.SYS.v1")


def _check_tag_padding():
    for name, t in (
        ("DNA.ATTEP.v1", TAG_ATTEP), ("DNA.ATLEAF.v1", TAG_ATLEAF),
        ("DNA.ATNODE.v1", TAG_ATNODE), ("DNA.E.ATTND.v1", TAG_E_ATTND),
        ("DNA.SYS.v2", TAG_SYS_V2), ("DNA.SYS.v1", TAG_SYS_V1),
    ):
        assert len(t) == TAG_LEN, (name, len(t))


def attendance_digest(epoch_start: int, rows) -> bytes:
    """rows: iterable of (voter_id: bytes[32], signed_count: int,
    last_signed_height: int), already in the caller's chosen order (the C
    contract requires ascending voter_id; this oracle does not re-sort —
    a caller that hands unsorted rows gets a digest matching a C caller
    that made the same mistake, not a validity check)."""
    pre = TAG_ATTEP + be64(epoch_start) + be32(len(rows))
    for voter_id, signed_count, last_signed_height in rows:
        assert len(voter_id) == 32
        pre += voter_id + be64(signed_count) + be64(last_signed_height)
    return sha3_512(pre)


def attendance_leaf(epoch_start: int, digest: bytes) -> bytes:
    assert len(digest) == 64
    return sha3_512(TAG_ATLEAF + be64(epoch_start) + digest)


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


def attendance_root(entries):
    """entries: list of (epoch_start, digest[64]), STRICTLY ascending by
    epoch_start (not enforced here — the C rejects a non-canonical order;
    this oracle assumes the caller already sorted, matching how the other
    *_root functions in this file are used)."""
    if len(entries) == 0:
        return sha3_512(TAG_E_ATTND)
    leaves = [attendance_leaf(es, dg) for es, dg in entries]
    return tagged_merkle(TAG_ATNODE, leaves)


def system_root_v2(legs8):
    assert len(legs8) == 8
    return sha3_512(TAG_SYS_V2 + b"".join(legs8))


def main():
    _check_tag_padding()

    # Self-check against the value ALREADY pinned in test_roots_v2.c
    # (KAT_SYSTEM, the retired 7-leg "DNA.SYS.v1" vector) before trusting
    # this script's method for anything new.
    legs7 = [fill(0x90 + i) for i in range(7)]
    old_sys = sha3_512(TAG_SYS_V1 + b"".join(legs7))
    OLD_KAT_SYSTEM = (
        "5de7c65076b43e882f7cf814971dce313ce35d39573c5bf73f78b420c561198"
        "6f5c9bcfe01b0841af5c9ef6ae469ea00b96067c3ddbf888b5d947e40572d6e57"
    )
    assert old_sys.hex() == OLD_KAT_SYSTEM, "method does not reproduce the pinned 7-leg vector"
    print("[self-check] 7-leg DNA.SYS.v1 vector reproduced:", old_sys.hex() == OLD_KAT_SYSTEM)

    print()
    print("EMPTY_ATTENDANCE  =", sha3_512(TAG_E_ATTND).hex())

    row0 = (fill(0x01, 32), 100, 5000)
    row1 = (fill(0x02, 32), 200, 6000)
    dg2 = attendance_digest(720, [row0, row1])
    print("ATT_DIGEST_2ROW   =", dg2.hex(), "  (epoch_start=720, 2 rows)")

    leaf1 = attendance_leaf(720, dg2)
    print("ATT_LEAF          =", leaf1.hex(), "  (epoch_start=720, digest=ATT_DIGEST_2ROW)")

    root1 = attendance_root([(720, dg2)])
    assert root1 == leaf1, "n==1 attendance_root must equal the single leaf"
    print("ATT_ROOT_1ENTRY   =", root1.hex(), "  (== ATT_LEAF, n==1 rule)")

    dg_b = fill(0x60, 64)
    root2 = attendance_root([(720, dg2), (1440, dg_b)])
    print("ATT_ROOT_2ENTRY   =", root2.hex(), "  (epochs 720 + 1440, second digest = fill(0x60))")

    legs8 = [fill(0x90 + i) for i in range(8)]
    sys8 = system_root_v2(legs8)
    print("KAT_SYSTEM_8LEG   =", sys8.hex(), "  (DNA.SYS.v2, legs = fill(0x90..0x97))")


if __name__ == "__main__":
    main()
