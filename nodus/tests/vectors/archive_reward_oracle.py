#!/usr/bin/env python3
"""Independent oracle for the archive reward byte layouts.

PROVENANCE
  Written from docs/plans/2026-10-05-archive-reward-bytes.md (PROPOSAL,
  2026-10-05; APPROVED in docs/plans/decisions/
  2026-10-05-archive-reward-bytes-approved.md) ONLY: items 1-5 and the §6
  sample derivation (x_i, block index, part index). The §6 answer
  verification (cometbft header / part-set proofs) is NOT covered.
  Shape conventions read in shared/dnac/ledger_roots_v2.c (TAG_LEN 16
  zero-padded tags :21, tagged_merkle :116-138) and in the storage reward v1
  oracle nodus/tests/vectors/storage_reward_oracle.py (branch
  p1-storage-reward: status values 1/2/3, node_fp = SHA3-512(node_pk),
  empty tags NDS.E.STSET.v1 / NDS.E.STREP.v1).
  No C implementation of the new items was read (none exists; author !=
  oracle).

  K9 update (2026-10-05): item 4 leaf v2 gains grace_until(8, BE) after
  fail_streak, and the grace rule is covered as a pure function. Written
  from the K9 item of docs/plans/decisions/
  2026-10-05-storage-reward-is-for-archive.md and the K9 line at the end of
  docs/plans/2026-10-05-archive-reward-bytes.md ONLY; the C leaf
  implementation was not read.

  Honest label: SELF-CONSISTENT. This proves a second implementation of the
  same document agrees byte for byte; it does not prove the document sound.

Usage: python3 archive_reward_oracle.py [out.json]
  default output: archive_reward_kat.json next to this script.
Dependencies: Python 3 standard library only (hashlib.sha3_512).
"""

import hashlib
import json
import os
import sys

TAG_LEN = 16
FP_LEN = 64
HASH_LEN = 64
NODE_PK_LEN = 2592
NONCE_LEN = 32
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1

SEGMENT_BLOCKS = 17280          # K1: blocks per segment (count(4) constant)
HOLDERS_R = 3                   # K4: R = 3 holders per segment
FAIL_STREAK_LIMIT = 3           # K2: fail_streak >= 3 -> not eligible
SAMPLES = 3                     # K3: i = 0, 1, 2
EPOCH_LENGTHS = (720, 15)       # K9 grace vectors: production E, short E
GRACE_MID = (1 << 32) + 17280   # K9 leaf vectors: mid grace_until, both
                                # 32-bit halves non-zero

STATUS_ACTIVE = 1
STATUS_EXITING = 2
STATUS_RELEASED = 3

SYNTH_PREFIX = b"ARCHIVE-KAT-H"  # 13 raw bytes, NOT a padded tag


# ── primitives ────────────────────────────────────────────────────────────

def h(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def tag(s: str) -> bytes:
    b = s.encode("ascii")
    if len(b) > TAG_LEN:
        raise ValueError("tag longer than 16 bytes: " + s)
    return b + b"\x00" * (TAG_LEN - len(b))


def be32(v: int) -> bytes:
    if not 0 <= v <= U32_MAX:
        raise ValueError("u32 out of range")
    return v.to_bytes(4, "big")


def be64(v: int) -> bytes:
    if not 0 <= v <= U64_MAX:
        raise ValueError("u64 out of range")
    return v.to_bytes(8, "big")


def empty_root(empty_tag: str) -> bytes:
    """dna_v2_empty_root shape: SHA3-512(16-byte zero-padded tag)."""
    return h(tag(empty_tag))


def tagged_merkle(node_tag: str, leaves):
    """ledger_roots_v2.c tagged_merkle: pairwise SHA3-512(tag | L | R),
    odd node promoted (never duplicated), n == 1 -> the leaf itself."""
    if not leaves:
        raise ValueError("tagged_merkle needs n >= 1")
    t = tag(node_tag)
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(h(t + level[i] + level[i + 1]))
        if len(level) & 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def strictly_ascending(keys):
    return all(keys[i - 1] < keys[i] for i in range(1, len(keys)))


# ── tags ──────────────────────────────────────────────────────────────────

T_STSEG = "NDS.STSEG.v1"
T_STSGLEAF = "NDS.STSGLEAF.v1"
T_STSGNODE = "NDS.STSGNODE.v1"
T_E_STSEG = "NDS.E.STSEG.v1"
T_STASGN = "NDS.STASGN.v1"
T_STLEAF2 = "NDS.STLEAF.v2"
T_STRNODE = "NDS.STRNODE.v1"
T_E_STREG = "NDS.E.STREG.v1"
T_STOR2 = "NDS.STOR.v2"
T_STSAMP = "NDS.STSAMP.v1"
# unchanged legs of 2026-10-04 (names read in storage_reward_oracle.py)
T_E_STSET = "NDS.E.STSET.v1"
T_E_STREP = "NDS.E.STREP.v1"

ALL_TAGS = [T_STSEG, T_STSGLEAF, T_STSGNODE, T_E_STSEG, T_STASGN, T_STLEAF2,
            T_STRNODE, T_E_STREG, T_STOR2, T_STSAMP, T_E_STSET, T_E_STREP]


# ── synthetic block hashes ────────────────────────────────────────────────

def synth_hash(height: int) -> bytes:
    """hash[h] = SHA3-512(b"ARCHIVE-KAT-H" | h(8 BE))."""
    return h(SYNTH_PREFIX + be64(height))


def segment_heights(k: int):
    """Segment k = heights ((k-1)*17280, k*17280], k >= 1."""
    if k < 1:
        raise ValueError("segment index k must be >= 1")
    last = k * SEGMENT_BLOCKS
    if last > U64_MAX:
        raise ValueError("segment end height exceeds u64")
    return range((k - 1) * SEGMENT_BLOCKS + 1, last + 1)


# ── item 1: segment root ──────────────────────────────────────────────────

def segment_root_preimage(k: int, hashes):
    if len(hashes) != SEGMENT_BLOCKS:
        raise ValueError("segment must hold exactly 17280 hashes")
    for x in hashes:
        if len(x) != HASH_LEN:
            raise ValueError("block hash must be 64 bytes (fault)")
    return tag(T_STSEG) + be64(k) + be32(SEGMENT_BLOCKS) + b"".join(hashes)


def segment_root(k: int, hashes) -> bytes:
    return h(segment_root_preimage(k, hashes))


def synth_segment_hashes(k: int):
    return [synth_hash(x) for x in segment_heights(k)]


# ── item 2: segment list ──────────────────────────────────────────────────

def segment_leaf_preimage(k: int, root: bytes) -> bytes:
    assert len(root) == HASH_LEN
    if k < 1:
        raise ValueError("segment index k must be >= 1")
    return tag(T_STSGLEAF) + be64(k) + root


def segment_leaf(k, root):
    return h(segment_leaf_preimage(k, root))


def segments_root(entries):
    """entries: list of (k, Root(k)) strictly ascending by k."""
    if not entries:
        return empty_root(T_E_STSEG)
    if not strictly_ascending([e[0] for e in entries]):
        raise ValueError("segments not strictly ascending by k")
    return tagged_merkle(T_STSGNODE, [segment_leaf(k, r) for k, r in entries])


# ── item 3: assignment key and holders ────────────────────────────────────

def assignment_key(root: bytes) -> bytes:
    assert len(root) == HASH_LEN
    return h(tag(T_STASGN) + root)


def xor_distance(a: bytes, b: bytes) -> int:
    assert len(a) == HASH_LEN and len(b) == HASH_LEN
    return int.from_bytes(bytes(x ^ y for x, y in zip(a, b)), "big")


def holders(akey: bytes, members):
    """members: list of (node_pk, fail_streak). Returns the eligible members
    (fail_streak < 3) sorted by ascending XOR distance, truncated to 3;
    fewer than 3 eligible -> all eligible."""
    fps = [h(pk) for pk, _ in members]
    if len(set(fps)) != len(fps):
        raise ValueError("duplicate node hash (spec assumes distinct)")
    elig = [(xor_distance(akey, f), f) for f, (_, fs) in zip(fps, members)
            if fs < FAIL_STREAK_LIMIT]
    elig.sort()
    return elig[:HOLDERS_R]


# ── item 4: registry leaf v2 and registry root ────────────────────────────

def registry_leaf_v2_preimage(node_fp, payee_fp, bond, status, reg_h,
                              exit_h, fail_streak, grace_until):
    assert len(node_fp) == FP_LEN and len(payee_fp) == FP_LEN
    if status not in (STATUS_ACTIVE, STATUS_EXITING, STATUS_RELEASED):
        raise ValueError("status invalid")
    return (tag(T_STLEAF2) + node_fp + payee_fp + be64(bond) +
            bytes([status]) + be64(reg_h) + be64(exit_h) + be32(fail_streak) +
            be64(grace_until))


def registry_leaf_v2(*a):
    return h(registry_leaf_v2_preimage(*a))


def registry_root_v2(rows):
    """rows: list of leaf-v2 argument tuples, strictly ascending by node_fp."""
    if not rows:
        return empty_root(T_E_STREG)
    if not strictly_ascending([r[0] for r in rows]):
        raise ValueError("registry rows not strictly ascending by node_fp")
    return tagged_merkle(T_STRNODE, [registry_leaf_v2(*r) for r in rows])


# ── K9: grace rule (pure function) ────────────────────────────────────────

def grace_update(prev: int, H: int, n: int, E: int) -> int:
    """At boundary H, member gains n segments it did not hold at H-E:
    n > 0 -> max(prev, H + n*E); n == 0 -> prev. Overflow past u64 is
    undefined in the spec and refused."""
    if not (0 <= prev <= U64_MAX and 0 <= H <= U64_MAX):
        raise ValueError("u64 out of range")
    if n < 0 or E < 1:
        raise ValueError("n must be >= 0 and E >= 1")
    if n == 0:
        return prev
    cand = H + n * E
    if cand > U64_MAX:
        raise ValueError("H + n*E exceeds u64 (undefined in spec)")
    return max(prev, cand)


def probed(H: int, grace_until: int) -> bool:
    """Epoch starting at H is probed iff NOT (H < grace_until)."""
    return H >= grace_until


# ── item 5: storage leg v2 ────────────────────────────────────────────────

def storage_root_v2_preimage(reg_r, sets_r, reps_r, segs_r):
    for x in (reg_r, sets_r, reps_r, segs_r):
        assert len(x) == HASH_LEN
    return tag(T_STOR2) + reg_r + sets_r + reps_r + segs_r


def storage_root_v2(*a):
    return h(storage_root_v2_preimage(*a))


# ── §6: sample derivation (off-chain) ─────────────────────────────────────

def sample_x(nonce: bytes, target_fp: bytes, i: int) -> bytes:
    assert len(nonce) == NONCE_LEN and len(target_fp) == FP_LEN
    return h(tag(T_STSAMP) + nonce + target_fp + be32(i))


def block_index(x: bytes, B: int) -> int:
    if B < 1:
        raise ValueError("B must be >= 1 (no eligible block: no sample)")
    return int.from_bytes(x[0:8], "big") % B


def part_index(x: bytes, parts_total: int) -> int:
    if parts_total < 1:
        raise ValueError("parts_total must be >= 1")
    return int.from_bytes(x[8:12], "big") % parts_total


# ── deterministic test inputs ─────────────────────────────────────────────

def d(label: str) -> bytes:
    return h(("archive_reward_kat/" + label).encode("ascii"))


def fp(label):
    return d("fp/" + label)


def node_pk(label):
    out = b""
    j = 0
    while len(out) < NODE_PK_LEN:
        out += d("pk/%s/%d" % (label, j))
        j += 1
    return out[:NODE_PK_LEN]


def X(b):
    return b.hex()


READINGS = [
    "Synthetic block hashes: hash[h] = SHA3-512(b'ARCHIVE-KAT-H' | h) where "
    "'ARCHIVE-KAT-H' is the 13 raw ASCII bytes (NOT padded to 16) and h is "
    "the global height as u64 big-endian; the dispatch wrote exactly this "
    "derivation and it is a test input, not a spec item.",
    "Item 1: segment k covers global heights (k-1)*17280+1 .. k*17280 "
    "inclusive (the spec's half-open interval ((k-1)*17280, k*17280]); "
    "segment 1 starts at height 1, height 0 is never in a segment; k = 0 is "
    "rejected.",
    "Item 1: count(4) is the constant 17280 encoded u32 big-endian "
    "(0x00004380); preimage = 16-byte tag | k(8 BE) | count(4 BE) | 17280 x "
    "64-byte hashes in ascending height order, total 1,105,948 bytes; a "
    "plain SHA3-512 over that, no Merkle tree, as the spec states.",
    "Item 1: KAT entries do not list the 17280 hashes; they give the "
    "derivation, the first and last hash, the 28-byte preimage prefix, the "
    "preimage length, and hashes_sha3 = SHA3-512 over the bare concatenation "
    "of the 17280 hashes (untagged, a debug checksum only, not a spec item).",
    "Item 1 large k: k must satisfy k*17280 <= 2^64-1 so every height fits "
    "the u64 encoding of hash[h]; the large case uses k = 2^32+7 so the "
    "high 4 bytes of k(8) are non-zero.",
    "Tags are ASCII right-padded with 0x00 to exactly 16 bytes; empty roots "
    "are SHA3-512 over the 16-byte padded empty tag alone (dna_v2_empty_root "
    "shape).",
    "Item 2: Merkle inputs are the already-hashed 64-byte segment leaves; "
    "n == 1 root = that leaf hash (no node tag applied); odd node promoted; "
    "k must be strictly ascending (duplicates rejected, input not sorted by "
    "the oracle). Segment list vectors use k = 1..n with the synthetic "
    "Root(k); one extra sparse vector uses k = {1, 3, 5}.",
    "Item 3: SHA3-512(node_pk) is taken over the raw 2592-byte node public "
    "key with no prefix, which equals node_fp as the storage v1 oracle "
    "defines it; the XOR is A(k) XOR that 64-byte value, compared as a "
    "64-byte big-endian unsigned integer (equivalently memcmp order).",
    "Item 3: holders(k, H) is a SET in the spec; the oracle lists it in "
    "ascending distance order (rank 0 = smallest) and gives each eligible "
    "member's distance. H selects storage_set(H) and enters no bytes; the "
    "members list in a vector IS storage_set(H).",
    "Item 3: eligibility is fail_streak < 3 strictly (fail_streak 2 "
    "eligible, 3 excluded); excluded members never hold k even when fewer "
    "than 3 members are eligible; 0 eligible -> empty holder set.",
    "Item 3: the spec relies on distinct node hashes for no ties; the "
    "oracle refuses duplicate node_pk hashes rather than define a tie rule.",
    "Item 4: status(1) values ACTIVE=1, EXITING=2, RELEASED=3 are taken from "
    "the storage v1 oracle (the 2026-10-05 doc does not restate them); "
    "fail_streak(4) is u32 big-endian; bond, registered_height, exit_height "
    "are u64 big-endian.",
    "Item 4 (K9): grace_until(8) is u64 big-endian and is the LAST field, "
    "appended after fail_streak; leaf preimage = 16 + 64 + 64 + 8 + 1 + 8 + "
    "8 + 4 + 8 = 181 bytes. The tag stays NDS.STLEAF.v2 (never activated). "
    "The bytes doc's earlier Clarifications line 'fail_streak u32 BE, last "
    "field' is superseded by the K9 line of the same doc.",
    "Item 4 (K9): the oracle imposes no relation between grace_until and "
    "registered_height / exit_height / status; any u64 is encoded as given.",
    "K9 grace rule: n (segments the member holds at H that it did not hold "
    "at H-E) is an INPUT; the oracle does not derive it from holder sets. "
    "new grace_until = max(prev, H + n*E) when n > 0, else prev. H is not "
    "required to be a multiple of E (the vectors use multiples). H + n*E > "
    "2^64-1 is undefined in the spec; the oracle refuses it and emits no "
    "vector for it (prev = 2^64-1 with n > 0 is covered and yields prev).",
    "K9 probe rule: the decision says 'while the epoch start H < "
    "grace_until: m is not probed'. The oracle reads the grace_until in "
    "force for the epoch starting at H as the value AFTER the update at "
    "boundary H, so probed = H >= new_grace_until (any n > 0 therefore "
    "means not probed in epoch H, since new >= H + E > H). "
    "probed_vs_prev = H >= prev is emitted as well, for comparison only; "
    "the oracle's reading is 'probed'.",
    "K9: 'not probed' also means earns nothing and fail_streak unchanged "
    "for that epoch (decision text); those consequences are not separate "
    "vectors here, only the probed bit is.",
    "Item 4: registry_root v2 = tagged_merkle('NDS.STRNODE.v1') over leaf-v2 "
    "hashes strictly ascending by node_fp (unsigned bytewise order); empty "
    "= SHA3-512(padded 'NDS.E.STREG.v1').",
    "Item 5: sets_root and reports_root are the unchanged 2026-10-04 legs "
    "and are opaque 64-byte inputs here; the all-empty case uses the empty "
    "tags NDS.E.STSET.v1 / NDS.E.STREP.v1 as named in the storage v1 "
    "oracle. Leg order: registry, sets, reports, segments. SYS.v5 is not "
    "covered (unchanged composition, outside the dispatched items).",
    "§6: x_i = SHA3-512(padded 'NDS.STSAMP.v1' | nonce(32) | target_fp(64) "
    "| i(4 BE)) for i = 0, 1, 2; x_i[0..8] and x_i[8..12] are half-open "
    "byte ranges [0,8) and [8,12) read big-endian (u64 and u32).",
    "§6: block index is a 0-based position in the target's eligible blocks "
    "sorted by ascending height (not a height); part index is 0-based. B = 0 "
    "or parts_total = 0 is undefined in the spec and is not a vector (the "
    "oracle raises).",
]


def build():
    vec = {}
    count = 0

    vec["tags"] = {t: X(tag(t)) for t in ALL_TAGS}
    vec["empty_roots"] = {
        T_E_STSEG: X(empty_root(T_E_STSEG)),
        T_E_STREG: X(empty_root(T_E_STREG)),
        T_E_STSET: X(empty_root(T_E_STSET)),
        T_E_STREP: X(empty_root(T_E_STREP)),
    }
    count += 4

    # synthetic hash spot checks
    vec["synthetic_hash"] = [
        {"height": str(x), "preimage": X(SYNTH_PREFIX + be64(x)),
         "hash": X(synth_hash(x))}
        for x in (0, 1, 17280, 17281)
    ]
    count += 4

    # item 1 — segment roots
    roots = {}
    seg_vecs = []
    for k in (1, 2, 3, 4, 5, 1000, (1 << 32) + 7):
        hs = synth_segment_hashes(k)
        pre = segment_root_preimage(k, hs)
        r = h(pre)
        roots[k] = r
        hr = segment_heights(k)
        seg_vecs.append({
            "k": str(k),
            "first_height": str(hr[0]), "last_height": str(hr[-1]),
            "first_hash": X(hs[0]), "last_hash": X(hs[-1]),
            "hashes_sha3": X(h(b"".join(hs))),
            "preimage_prefix": X(pre[:TAG_LEN + 8 + 4]),
            "preimage_len": len(pre),
            "root": X(r),
        })
        count += 1
    vec["segment_root"] = seg_vecs

    # item 2 — segment leaf
    leafv = []
    for k in (1, 2, 1000, (1 << 32) + 7):
        pre = segment_leaf_preimage(k, roots[k])
        leafv.append({"k": str(k), "root": X(roots[k]), "preimage": X(pre),
                      "leaf": X(h(pre))})
        count += 1
    vec["segment_leaf"] = leafv

    # item 2 — segments root
    sroots = []
    cases = [("n0", []), ("n1", [1]), ("n2", [1, 2]), ("n3", [1, 2, 3]),
             ("n5", [1, 2, 3, 4, 5]), ("sparse_1_3_5", [1, 3, 5])]
    for name, ks in cases:
        entries = [(k, roots[k]) for k in ks]
        sroots.append({
            "name": name, "n": len(ks),
            "entries": [{"k": str(k), "root": X(r),
                         "leaf": X(segment_leaf(k, r))} for k, r in entries],
            "segments_root": X(segments_root(entries)),
        })
        count += 1
    vec["segments_root"] = sroots

    # item 3 — assignment key
    akv = []
    for k in (1, 2, 1000, (1 << 32) + 7):
        akv.append({"k": str(k), "root": X(roots[k]),
                    "preimage": X(tag(T_STASGN) + roots[k]),
                    "A": X(assignment_key(roots[k]))})
        count += 1
    vec["assignment_key"] = akv

    # item 3 — holders
    hold_cases = [
        ("set2_all_eligible", 1, [0, 0]),
        ("set3_all_eligible", 1, [0, 1, 2]),
        ("set4_all_eligible", 2, [0, 0, 0, 0]),
        ("set7_all_eligible", 1000, [0, 0, 1, 2, 0, 1, 2]),
        ("set7_excluded_3_4_u32max", 1000, [3, 0, 2, U32_MAX, 1, 4, 0]),
        ("set7_excluded_streak3_x3", (1 << 32) + 7, [0, 3, 3, 0, 3, 2, 0]),
        ("set4_two_eligible", 2, [3, 0, 5, 2]),
        ("set3_one_eligible", 1, [3, 1, U32_MAX]),
        ("set2_zero_eligible", 1, [3, U32_MAX]),
        ("set5_zero_eligible", 2, [3, 4, 5, 6, U32_MAX]),
    ]
    hv = []
    for name, k, streaks in hold_cases:
        akey = assignment_key(roots[k])
        members = [(node_pk("hold/%s/%d" % (name, i)), fs)
                   for i, fs in enumerate(streaks)]
        sel = holders(akey, members)
        mem_out = []
        for pk, fs in members:
            f = h(pk)
            mem_out.append({
                "node_pk": X(pk), "node_hash": X(f),
                "fail_streak": fs,
                "eligible": fs < FAIL_STREAK_LIMIT,
                "distance": "%0128x" % xor_distance(akey, f),
            })
        hv.append({
            "name": name, "k": str(k), "root": X(roots[k]), "A": X(akey),
            "members": mem_out,
            "eligible_count": sum(1 for _, fs in members
                                  if fs < FAIL_STREAK_LIMIT),
            "holders_by_rank": [X(f) for _, f in sel],
        })
        count += 1
    vec["holders"] = hv

    # item 4 — registry leaf v2
    leaf_cases = [
        ("streak0_active", 10 ** 15, STATUS_ACTIVE, 1440, 0, 0),
        ("streak1_active", 1, STATUS_ACTIVE, 720, 0, 1),
        ("streak3_exiting", 123456789, STATUS_EXITING, 4242, 99999, 3),
        ("streak_u32max_released", U64_MAX, STATUS_RELEASED,
         U64_MAX - 1, U64_MAX, U32_MAX),
        ("bond0_h0_streak2", 0, STATUS_ACTIVE, 0, 0, 2),
    ]
    grace_cases = [("0", 0), ("1", 1), ("mid", GRACE_MID), ("u64max", U64_MAX)]
    lv = []
    for name0, bond, st, rh, eh, fs in leaf_cases:
        for glabel, gu in grace_cases:
            name = "%s_grace%s" % (name0, glabel)
            nf = fp("leaf/node/" + name)
            pf = fp("leaf/payee/" + name)
            pre = registry_leaf_v2_preimage(nf, pf, bond, st, rh, eh, fs, gu)
            lv.append({"name": name, "node_fp": X(nf), "payee_fp": X(pf),
                       "bond": str(bond), "status": st,
                       "registered_height": str(rh), "exit_height": str(eh),
                       "fail_streak": str(fs), "grace_until": str(gu),
                       "preimage_len": len(pre), "preimage": X(pre),
                       "leaf": X(h(pre))})
            count += 1
    vec["registry_leaf_v2"] = lv

    # item 4 — registry root v2
    statuses = [STATUS_ACTIVE, STATUS_EXITING, STATUS_RELEASED]
    streaks = [0, 1, 3, U32_MAX, 2]
    graces = [0, 1, GRACE_MID, U64_MAX]
    rr = []
    reg_roots = {}
    for n in (0, 1, 2, 3, 5):
        rows = []
        for i in range(n):
            st = statuses[i % 3]
            rows.append((fp("reg/n%d/node/%d" % (n, i)),
                         fp("reg/n%d/payee/%d" % (n, i)),
                         [0, 1, 10 ** 15, U64_MAX][i % 4], st, i * 1000,
                         0 if st == STATUS_ACTIVE else i * 1000 + 720,
                         streaks[i % len(streaks)],
                         graces[(i + 1) % len(graces)]))
        rows.sort(key=lambda r: r[0])
        root = registry_root_v2(rows)
        reg_roots[n] = root
        rr.append({
            "n": n,
            "rows_sorted": [{
                "node_fp": X(r[0]), "payee_fp": X(r[1]), "bond": str(r[2]),
                "status": r[3], "registered_height": str(r[4]),
                "exit_height": str(r[5]), "fail_streak": str(r[6]),
                "grace_until": str(r[7]),
                "leaf": X(registry_leaf_v2(*r))} for r in rows],
            "registry_root": X(root),
        })
        count += 1
    vec["registry_root_v2"] = rr

    # K9 — grace rule (pure function), per epoch length E
    gr = []
    for E in EPOCH_LENGTHS:
        H = 100 * E
        Hbig = (1 << 40) * E
        cases = [
            ("n0_prev0", 0, H, 0),
            ("n0_prev_below_H", H - E, H, 0),
            ("n0_prev_eq_H", H, H, 0),
            ("n0_prev_above_H", H + 3 * E, H, 0),
            ("n0_prev_u64max", U64_MAX, H, 0),
            ("n1_prev0", 0, H, 1),
            ("n2_prev0", 0, H, 2),
            ("n3_prev_below_H", H - E, H, 3),
            ("n1_prev_eq_H", H, H, 1),
            ("n2_prev_eq_H_plus_2E", H + 2 * E, H, 2),
            ("n2_prev_above_H_plus_2E", H + 5 * E, H, 2),
            ("n5_prev_between", H + 2 * E, H, 5),
            ("n1_prev_u64max", U64_MAX, H, 1),
            ("n17280_prev0", 0, H, 17280),
            ("n1_H0_prev0", 0, 0, 1),
            ("n0_H0_prev0", 0, 0, 0),
            ("n4_Hbig_prev0", 0, Hbig, 4),
            ("n0_Hbig_prev_above", Hbig + E, Hbig, 0),
        ]
        out = []
        for name, prev, hh, n in cases:
            new = grace_update(prev, hh, n, E)
            out.append({"name": name, "prev_grace_until": str(prev),
                        "H": str(hh), "n": n, "E": E,
                        "new_grace_until": str(new),
                        "probed": probed(hh, new),
                        "probed_vs_prev": probed(hh, prev)})
            count += 1
        gr.append({"E": E, "cases": out})
    vec["grace_rule"] = gr

    # item 5 — storage root v2
    segs5 = segments_root([(k, roots[k]) for k in (1, 2, 3, 4, 5)])
    st_cases = [
        ("all_empty", empty_root(T_E_STREG), empty_root(T_E_STSET),
         empty_root(T_E_STREP), empty_root(T_E_STSEG)),
        ("reg5_opaque_sets_reports_segs5", reg_roots[5], d("opaque/sets"),
         d("opaque/reports"), segs5),
        ("reg_empty_segs5", empty_root(T_E_STREG), empty_root(T_E_STSET),
         empty_root(T_E_STREP), segs5),
    ]
    sv = []
    for name, a, b, c, e in st_cases:
        pre = storage_root_v2_preimage(a, b, c, e)
        sv.append({"name": name, "registry_root": X(a), "sets_root": X(b),
                   "reports_root": X(c), "segments_root": X(e),
                   "preimage": X(pre), "storage_root": X(h(pre))})
        count += 1
    vec["storage_root_v2"] = sv

    # §6 — sample derivation
    Bs = [1, 2, SEGMENT_BLOCKS, 3 * SEGMENT_BLOCKS]
    parts = [1, 2, 7]
    smp = []
    for name in ("probe_a", "probe_b"):
        nonce = d("nonce/" + name)[:NONCE_LEN]
        tf = fp("target/" + name)
        samples = []
        for i in range(SAMPLES):
            x = sample_x(nonce, tf, i)
            samples.append({
                "i": i,
                "preimage": X(tag(T_STSAMP) + nonce + tf + be32(i)),
                "x": X(x),
                "u64_x_0_8": str(int.from_bytes(x[0:8], "big")),
                "u32_x_8_12": str(int.from_bytes(x[8:12], "big")),
                "block_index": {str(B): str(block_index(x, B)) for B in Bs},
                "part_index": {str(p): str(part_index(x, p)) for p in parts},
            })
            count += 1
        smp.append({"name": name, "nonce": X(nonce), "target_fp": X(tf),
                    "samples": samples})
    vec["sample_derivation"] = smp

    return {
        "spec": "docs/plans/2026-10-05-archive-reward-bytes.md items 1-5 "
                "and the §6 sample derivation (APPROVED "
                "docs/plans/decisions/"
                "2026-10-05-archive-reward-bytes-approved.md); item 4 leaf "
                "and grace rule per K9 (docs/plans/decisions/"
                "2026-10-05-storage-reward-is-for-archive.md, K9 line of the "
                "bytes doc)",
        "oracle": "nodus/tests/vectors/archive_reward_oracle.py",
        "label": "SELF-CONSISTENT (independent re-implementation of the "
                 "same document; not an external reference)",
        "conventions": {
            "hash": "SHA3-512 (hashlib.sha3_512)",
            "tag": "16 bytes, ASCII, right-padded with 0x00",
            "integers": "big-endian; u64 values given as decimal strings",
            "hex": "lowercase, no prefix",
            "synthetic_block_hash": "hash[h] = SHA3-512(b'ARCHIVE-KAT-H' "
                                    "(13 raw bytes) | h as u64 BE)",
            "inputs": "fp = SHA3-512('archive_reward_kat/fp/' + label); "
                      "node_pk = concatenated SHA3-512('archive_reward_kat/"
                      "pk/<label>/<j>') truncated to 2592 bytes; nonce = "
                      "first 32 bytes of SHA3-512('archive_reward_kat/"
                      "nonce/<name>'); opaque legs = SHA3-512("
                      "'archive_reward_kat/opaque/<leg>')",
            "segment_blocks": SEGMENT_BLOCKS,
            "holders_R": HOLDERS_R,
            "fail_streak_limit": FAIL_STREAK_LIMIT,
            "grace_epoch_lengths": list(EPOCH_LENGTHS),
            "grace_until_mid": str(GRACE_MID),
        },
        "readings": READINGS,
        "vector_count": count,
        "vectors": vec,
    }


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "archive_reward_kat.json")
    doc = build()
    with open(out, "w", encoding="ascii") as f:
        json.dump(doc, f, indent=1, sort_keys=False)
        f.write("\n")
    sys.stdout.write("wrote %s (%d vectors)\n" % (out, doc["vector_count"]))


if __name__ == "__main__":
    main()
