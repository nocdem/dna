#!/usr/bin/env python3
"""
Independent vector oracle for GENERAL MULTISIG (M-of-N address) and the
genesis-output UTXO identity — design rev 2, operator-APPROVED
2026-09-29:
  docs/plans/2026-09-29-general-multisig-design.md  §7 (rev 2)
  docs/plans/decisions/2026-09-29-general-multisig.md (ONAY section)
The genesis-output vector (section 4) follows the later "ONAY 2" item 1
of the same decision file (operator, 2026-09-29), which replaces the
design §7 chain_id input with source_commit; §7's chain_id form is
recorded there as INVALID.

── PROVENANCE — HONEST LABEL ────────────────────────────────────────────
This is a SELF-CONSISTENCY oracle, not an external audit. The layout is
this project's own adaptation of the Bitcoin P2SH / P2WSH pattern
(BIP-16 / BIP-141: address = hash(locking script), script revealed at
spend time in a witness field); there is NO pinned external reference for
these exact bytes (tag, M/N octets, key order, framing). It was written
from the design text ONLY, before the C implementation existed, by a
different agent than the one writing the C. Agreement between the C and
this script proves both implement the SAME written layout; it does NOT
prove the layout sound or the only reasonable one. Call it
"self-consistent, not externally audited".

── WHAT IS PINNED ────────────────────────────────────────────────────────
  descriptor = "NDS.MSIG.v1" (16 B zero-padded) || M u8 || N u8 ||
               N x pubkey[2592], strictly ascending (bytewise)
               2 <= N <= 7, 1 <= M <= N, no zero key (first 32 bytes zero)
  msig addr  = SHA3-512(descriptor)                       (64 B)
  plain addr = SHA3-512(pubkey)            (untagged, for contrast)

  auth_kind 3 blob =
      count u8 || count x (pubkey[2592] || sig[4627])     (the kind-1 body:
                                1 <= count <= 15, pubkeys strictly
                                ascending, no zero key)
   || dcount u8 || dcount x (dlen u16 BE || descriptor)
                                descriptors strictly ascending by ADDRESS,
                                sum of N over the descriptors <= 15

  genesis output UTXO (decision "ONAY 2" item 1):
      nullifier    = SHA3-512("NDS.GENOUT.v1" (16 B zero-padded) ||
                              source_commit[64] || index u32 BE)
      tx_hash      = nullifier
      output_index = 0
  source_commit is, per the decision text, the SHA3-512 of the genesis
  document with chain_id AND app_hash zeroed; it exists before genesis is
  applied, so there is no cycle (document -> source_commit -> outputs ->
  app_hash -> chain_id). This oracle does NOT derive source_commit from a
  document: it takes a fixed 64-byte input (64 x 0x22) and pins only the
  hash composition above. A second value (64 x 0x23) is printed to show
  the nullifier depends on source_commit.
  (The decision also fixes unlock 0 and domain CORE for these UTXOs; this
  oracle does not pin the resulting UTXO leaf — identity fields only.)

── ASSUMPTIONS (the design text does not state these; flagged) ──────────
 A1. dlen == len(descriptor) == 18 + N*2592 exactly; a dlen that does not
     match its own N is a framing error. Max dlen = 18 + 7*2592 = 18162,
     which fits u16.
 A2. dcount >= 1 (a kind-3 blob with zero descriptors would be a
     non-canonical spelling of kind 1). dcount upper bound follows from
     sum(N) <= 15 with N >= 2, i.e. dcount <= 7.
 A3. "Zero key" = first 32 bytes all zero — the kind-1 signer discipline
     at nodus_witness_rt_native.c:527-530 (comment cites verify.c:657).
     NOTE the identity check at rt_native.c:795-797 compares the FULL
     DNAC_PUBKEY_SIZE (2592, dnac.h:107) key against zero instead; the
     design (F1.5) does not say which one applies to descriptor keys.
 A4. Descriptor keys and signer keys are framed independently; whether
     the signers satisfy >= M of a descriptor, and the "unused descriptor
     rejected" rule, are EXEC checks (design §7, F1.2) — not pinned here.
 A5. The blob must be consumed EXACTLY (no trailing bytes), as kind 1 is
     (rt_native.c:519, exact == 1).
 A6. The genesis index is the 0-based position in the document's
     genesis-output list.

── HOW THIS CAN LIE ──────────────────────────────────────────────────────
 1. Same design text read by both implementers; a misreading shared by
    both agrees with itself.
 2. The pubkeys are FAKE (SHA3-512-expanded seeds), not ML-DSA-87 keys,
    and the signatures in the blob vector are fixed filler bytes: the
    blob vector pins FRAMING only, never signature validity.
 3. The refusal self-checks exercise THIS script's asserts (each matched
    by its own message substring); they say nothing about the C
    rejecting the same inputs.

Read-only: opens nothing, writes nothing, prints to stdout.
"""
import hashlib
import struct

TAG_LEN = 16
PUBKEY_LEN = 2592           # NODUS_CC_PUBKEY_SIZE (nodus_chain_config.h:276)
SIG_LEN = 4627              # NODUS_CC_SIG_SIZE    (nodus_chain_config.h:278)
SIGNER_LEN = PUBKEY_LEN + SIG_LEN
MAX_SIGNERS = 15            # NODUS_RT_AUTH_MAX_SIGNERS (nodus_witness_runtime.h:253)
MSIG_MIN_N = 2
MSIG_MAX_N = 7              # operator: "maksimum 7 anahtar" (design §7)
MAX_DESC_KEYS_PER_LEG = 15  # design §7 / F3.1
SOURCE_COMMIT_LEN = 64      # SHA3-512 digest; decision "ONAY 2" item 1
                            # (cites nodus_witness_v2_gen.h:261-266 — not
                            # re-read by this script's author)
DESC_HDR_LEN = TAG_LEN + 2  # tag || M || N

FAKE_PK_DOMAIN = b"MSIG.ORACLE.PK"


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def tag(name: str) -> bytes:
    b = name.encode("ascii")
    assert len(b) <= TAG_LEN, f"tag {name!r} too long for a 16-byte slot"
    return b + b"\x00" * (TAG_LEN - len(b))


TAG_MSIG = tag("NDS.MSIG.v1")
TAG_GENOUT = tag("NDS.GENOUT.v1")


def be16(v: int) -> bytes:
    return struct.pack(">H", v)


def be32(v: int) -> bytes:
    return struct.pack(">I", v)


def fake_pubkey(seed: int) -> bytes:
    """Deterministic 2592-byte stand-in: concatenate
    SHA3-512(FAKE_PK_DOMAIN || seed u32 BE || ctr u32 BE) for ctr = 0,1,...
    and truncate to 2592 bytes. NOT an ML-DSA-87 key."""
    out = b""
    ctr = 0
    while len(out) < PUBKEY_LEN:
        out += sha3_512(FAKE_PK_DOMAIN + be32(seed) + be32(ctr))
        ctr += 1
    pk = out[:PUBKEY_LEN]
    assert any(pk[:32]), "fake key must not look like a zero key"
    return pk


def is_zero_key(pk: bytes) -> bool:
    return not any(pk[:32])  # assumption A3


# ── 1. descriptor ─────────────────────────────────────────────────────────
def descriptor(m: int, pubkeys) -> bytes:
    """Encoder: REQUIRES strictly ascending input (it never sorts)."""
    n = len(pubkeys)
    assert MSIG_MIN_N <= n <= MSIG_MAX_N, f"N={n} outside [2,7]"
    assert 1 <= m <= n, f"M={m} outside [1,N]"
    for pk in pubkeys:
        assert len(pk) == PUBKEY_LEN, "pubkey must be 2592 bytes"
        assert not is_zero_key(pk), "zero key refused"
    for a, b in zip(pubkeys, pubkeys[1:]):
        assert a < b, "descriptor pubkeys must be strictly ascending"
    d = TAG_MSIG + bytes([m, n]) + b"".join(pubkeys)
    assert len(d) == DESC_HDR_LEN + n * PUBKEY_LEN
    return d


def msig_address(m: int, pubkeys) -> bytes:
    return sha3_512(descriptor(m, pubkeys))


def plain_address(pk: bytes) -> bytes:
    return sha3_512(pk)


def refuses(needle: str, fn, *args) -> bool:
    """True only if fn raises an AssertionError whose message contains
    `needle` — a refusal for the WRONG reason does not count."""
    try:
        fn(*args)
    except AssertionError as exc:
        return needle in str(exc)
    return False


# ── 3. auth_kind 3 blob ───────────────────────────────────────────────────
def desc_n(d: bytes) -> int:
    return d[TAG_LEN + 1]


def auth_kind3_blob(signers, descs) -> bytes:
    """signers: list of (pubkey, sig) strictly ascending by pubkey.
    descs: list of descriptor bytes, strictly ascending by ADDRESS."""
    count = len(signers)
    assert 1 <= count <= MAX_SIGNERS, f"signer count {count} outside [1,15]"
    for pk, sig in signers:
        assert len(pk) == PUBKEY_LEN and len(sig) == SIG_LEN, \
            "signer entry size"
        assert not is_zero_key(pk), "zero signer key refused"
    for a, b in zip(signers, signers[1:]):
        assert a[0] < b[0], "signer pubkeys must be strictly ascending"
    dcount = len(descs)
    assert dcount >= 1, "kind 3 needs >= 1 descriptor"
    assert dcount <= 255, "dcount does not fit u8"
    addrs = [sha3_512(d) for d in descs]
    for a, b in zip(addrs, addrs[1:]):
        assert a < b, "descriptors must be strictly ascending by address"
    total_keys = sum(desc_n(d) for d in descs)
    assert total_keys <= MAX_DESC_KEYS_PER_LEG, \
        f"descriptor key total {total_keys} > 15"
    out = bytes([count]) + b"".join(pk + sig for pk, sig in signers)
    out += bytes([dcount])
    for d in descs:
        assert len(d) == DESC_HDR_LEN + desc_n(d) * PUBKEY_LEN, "dlen/N"  # A1
        out += be16(len(d)) + d
    return out


def auth_kind3_len(count: int, desc_ns) -> int:
    """Closed-form length, independent of the builder above."""
    return (1 + count * SIGNER_LEN + 1 +
            sum(2 + DESC_HDR_LEN + n * PUBKEY_LEN for n in desc_ns))


FILLER_SIG = bytes([0xA5]) * SIG_LEN   # framing-only filler, NOT a signature


def sort_descs_by_address(descs):
    return sorted(descs, key=sha3_512)


# ── 4. genesis output ─────────────────────────────────────────────────────
def genout_nullifier(source_commit: bytes, index: int) -> bytes:
    assert len(source_commit) == SOURCE_COMMIT_LEN, \
        "source_commit must be 64 bytes"
    assert 0 <= index <= 0xFFFFFFFF
    return sha3_512(TAG_GENOUT + source_commit + be32(index))


def main():
    print("# multisig_oracle.py — self-consistent, not externally audited")
    print(f"TAG_MSIG   = {TAG_MSIG.hex()}")
    print(f"TAG_GENOUT = {TAG_GENOUT.hex()}")

    # 15 distinct keys (seeds 1..15), sorted ascending; 2 extra keys
    # (seeds 16, 17) used ONLY by the sum-N-over-15 refusal check.
    seeded = sorted((fake_pubkey(s), s) for s in range(1, 16))
    k = [pk for pk, _ in seeded]
    extra = sorted(fake_pubkey(s) for s in (16, 17))

    print("\n# fake pubkey recipe: pk(seed) = first 2592 bytes of")
    print("#   SHA3-512(\"MSIG.ORACLE.PK\" || seed u32 BE || ctr u32 BE)"
          " for ctr = 0,1,2,... concatenated")
    print("# key[i] = i-th smallest of pk(1..15) (bytewise); first 16 bytes:")
    for i, (pk, s) in enumerate(seeded):
        print(f"key[{i:2d}] seed={s:2d} head={pk[:16].hex()}")

    # ── refusal self-checks ──
    zero_key = bytes(32) + k[0][32:]
    checks = [
        ("N=1 refused", refuses("outside [2,7]", descriptor, 1, k[:1])),
        ("N=8 refused", refuses("outside [2,7]", descriptor, 1, k[:8])),
        ("M=0 refused", refuses("outside [1,N]", descriptor, 0, k[:3])),
        ("M=4>N=3 refused", refuses("outside [1,N]", descriptor, 4, k[:3])),
        ("descending keys refused",
         refuses("descriptor pubkeys must be strictly ascending",
                 descriptor, 2, [k[1], k[0], k[2]])),
        ("duplicate key refused",
         refuses("descriptor pubkeys must be strictly ascending",
                 descriptor, 2, [k[0], k[0], k[1]])),
        ("zero-prefix key refused",
         refuses("zero key refused", descriptor, 1,
                 sorted([zero_key, k[1]]))),
        ("short key refused",
         refuses("pubkey must be 2592 bytes", descriptor, 1,
                 [k[0][:-1], k[1]])),
    ]
    print("\n# refusal self-checks (THIS script's asserts)")
    for name, ok in checks:
        print(f"{name}: {'OK' if ok else 'FAIL'}")
        assert ok, name

    # ── 1. addresses ──
    print("\n# 1. descriptor / multisig address vectors")
    cases = [
        ("2-of-3", 2, k[0:3]),
        ("1-of-2", 1, k[0:2]),
        ("7-of-7", 7, k[0:7]),
        ("5-of-7", 5, k[0:7]),
    ]
    for label, m, pks in cases:
        d = descriptor(m, pks)
        print(f"{label}: keys=key[0..{len(pks) - 1}] "
              f"desc_len={len(d)} desc_sha3={sha3_512(d).hex()}")
        print(f"{label}: desc_head(18)={d[:DESC_HDR_LEN].hex()}")
        print(f"{label}: address={msig_address(m, pks).hex()}")

    a23 = msig_address(2, k[0:3])
    a13 = msig_address(1, k[0:3])
    a33 = msig_address(3, k[0:3])
    print("\n# M changes the address (same 3 keys)")
    print(f"1-of-3 address={a13.hex()}")
    print(f"2-of-3 address={a23.hex()}")
    print(f"3-of-3 address={a33.hex()}")
    assert len({a13, a23, a33}) == 3
    print("distinct: OK")

    shuffled = [k[2], k[0], k[1]]
    print("\n# input order: encoder REFUSES unsorted input; sorting first")
    print("# yields the same address as the canonical order")
    unsorted_refused = refuses("descriptor pubkeys must be strictly ascending",
                               descriptor, 2, shuffled)
    print(f"unsorted input refused: {unsorted_refused}")
    assert unsorted_refused
    a_sorted = msig_address(2, sorted(shuffled))
    print(f"2-of-3 address from sorted(shuffled)={a_sorted.hex()}")
    assert a_sorted == a23
    print("equal to canonical 2-of-3: OK")

    # ── 2. plain addresses ──
    print("\n# 2. plain single-key address SHA3-512(pubkey), same keys")
    for i in range(3):
        pa = plain_address(k[i])
        print(f"plain(key[{i}])={pa.hex()}")
        assert pa not in (a13, a23, a33)
    print("all differ from the 1/2/3-of-3 multisig addresses: OK")

    # ── 3. auth_kind 3 blobs ──
    print("\n# 3. auth_kind 3 framing (signatures are FILLER 0xA5 bytes)")
    print(f"per-signer entry = {SIGNER_LEN} B; descriptor header = "
          f"{DESC_HDR_LEN} B; dlen prefix = 2 B")

    d23 = descriptor(2, k[0:3])
    blob = auth_kind3_blob([(k[0], FILLER_SIG), (k[1], FILLER_SIG)], [d23])
    exp = auth_kind3_len(2, [3])
    print(f"2-of-3 spend (signers key[0],key[1]; 1 descriptor 2-of-3 "
          f"key[0..2]): len={len(blob)} (closed form {exp})")
    assert len(blob) == exp
    print(f"2-of-3 blob dcount+dlen bytes = "
          f"{blob[1 + 2 * SIGNER_LEN:1 + 2 * SIGNER_LEN + 3].hex()}")
    print(f"2-of-3 blob sha3_512={sha3_512(blob).hex()}")

    # Maximal legal blobs: 15 signers (key[0..14]) + descriptors whose key
    # total is 15. With sum(N) fixed at 15, length depends only on dcount
    # (each descriptor adds 2 + 18 bytes); dcount max = 7 (6 x N=2 + 1 x N=3).
    signers15 = [(pk, FILLER_SIG) for pk in k]
    # (a) the maximum-length shape: 6 x 2-of-2 + 1 x 2-of-3 over key[0..14]
    parts_a = [k[0:2], k[2:4], k[4:6], k[6:8], k[8:10], k[10:12], k[12:15]]
    descs_a = sort_descs_by_address([descriptor(2, p) for p in parts_a])
    blob_a = auth_kind3_blob(signers15, descs_a)
    exp_a = auth_kind3_len(15, [len(p) for p in parts_a])
    print(f"MAX blob (15 signers, 7 descriptors 2-of-2 x6 + 2-of-3, "
          f"sum N=15): len={len(blob_a)} (closed form {exp_a})")
    assert len(blob_a) == exp_a
    print(f"MAX blob sha3_512={sha3_512(blob_a).hex()}")
    # (b) a shape at the per-address cap: N = 7, 6, 2 (sum 15), each
    #     M = N//2 + 1 (4-of-7 key[0..6], 4-of-6 key[7..12], 2-of-2 key[13..14])
    parts_b = [k[0:7], k[7:13], k[13:15]]
    descs_b = sort_descs_by_address(
        [descriptor(len(p) // 2 + 1, p) for p in parts_b])
    blob_b = auth_kind3_blob(signers15, descs_b)
    exp_b = auth_kind3_len(15, [7, 6, 2])
    print(f"15 signers, 3 descriptors 4-of-7/4-of-6/2-of-2 (sum N=15): "
          f"len={len(blob_b)} (closed form {exp_b})")
    assert len(blob_b) == exp_b
    print(f"7/6/2 blob sha3_512={sha3_512(blob_b).hex()}")

    # framing refusals
    over = [descriptor(2, k[0:7]), descriptor(2, k[7:14]),
            descriptor(1, extra)]                     # 7 + 7 + 2 = 16, no reuse
    print("\n# framing refusal self-checks (THIS script's asserts)")
    fchecks = [
        ("sum N = 16 refused",
         refuses("descriptor key total 16 > 15", auth_kind3_blob,
                 signers15, sort_descs_by_address(over))),
        ("16 signers refused",
         refuses("signer count 16", auth_kind3_blob,
                 signers15 + [(b"\xff" * PUBKEY_LEN, FILLER_SIG)], [d23])),
        ("descriptors not ascending by address refused",
         refuses("ascending by address", auth_kind3_blob, signers15,
                 list(reversed(sort_descs_by_address(
                     [descriptor(2, k[0:3]), descriptor(2, k[3:6])]))))),
        ("duplicate descriptor refused",
         refuses("ascending by address", auth_kind3_blob,
                 signers15, [d23, d23])),
        ("zero descriptors refused",
         refuses("needs >= 1 descriptor", auth_kind3_blob, signers15, [])),
        ("unsorted signers refused",
         refuses("signer pubkeys must be strictly ascending", auth_kind3_blob,
                 [(k[1], FILLER_SIG), (k[0], FILLER_SIG)], [d23])),
    ]
    for name, ok in fchecks:
        print(f"{name}: {'OK' if ok else 'FAIL'}")
        assert ok, name

    # ── 4. genesis outputs ──
    print("\n# 4. genesis output UTXO identity, source_commit = 64 x 0x22")
    source_commit = bytes([0x22]) * SOURCE_COMMIT_LEN
    nfs = []
    for idx in range(3):
        nf = genout_nullifier(source_commit, idx)
        nfs.append(nf)
        print(f"genout[{idx}] nullifier={nf.hex()}")
        print(f"genout[{idx}] tx_hash={nf.hex()} output_index=0")
    assert len(set(nfs)) == 3

    print("\n# dependency: same indices, source_commit = 64 x 0x23")
    other_commit = bytes([0x23]) * SOURCE_COMMIT_LEN
    for idx in range(3):
        nf2 = genout_nullifier(other_commit, idx)
        print(f"genout'[{idx}] nullifier={nf2.hex()}")
        assert nf2 != nfs[idx]
    print("differs from source_commit 64 x 0x22 at every index: OK")


if __name__ == "__main__":
    main()
