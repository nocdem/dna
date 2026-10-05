#!/usr/bin/env python3
"""Independent oracle for storage reward v1 byte layouts.

PROVENANCE
  Written from docs/plans/2026-10-04-storage-reward-bytes.md (PROPOSAL,
  2026-10-04) ONLY, items 1-7, plus the tree's existing SHAPE helpers read in
  shared/dnac/ledger_roots_v2.c (TAG_LEN 16 zero-padded tags, put_be32 /
  put_be64, tagged_merkle :116-138, dna_v2_empty_root :93-96 = SHA3-512 over
  the 16-byte padded empty tag) and the EPGRAD derivation in
  nodus/src/witness/nodus_witness_v2_epoch.c:57-94 (tag(16) | chain_id(32) |
  domain(4 BE) | height(8 BE) | hash(64); nullifier = id | kind(1) |
  out_index(4 BE)). DNA_DOMAIN_CORE = 1 read from shared/dnac/ledger_ids.h:53.
  The C implementation of the storage code was NOT read (author != oracle).

  Honest label: SELF-CONSISTENT. This proves a second implementation of the
  same document agrees byte for byte; it does not prove the document sound.

Usage: python3 storage_reward_oracle.py [out.json]
  default output: storage_reward_kat.json next to this script.
Dependencies: Python 3 standard library only (hashlib.sha3_512).
"""

import hashlib
import json
import os
import sys

TAG_LEN = 16
FP_LEN = 64
NODE_PK_LEN = 2592
CHAIN_ID_LEN = 32
DNA_DOMAIN_CORE = 1
U64_MAX = (1 << 64) - 1

STATUS_ACTIVE = 1
STATUS_EXITING = 2
STATUS_RELEASED = 3

STEXIT_KIND = 0x11
STEXIT_OUT_IDX = 201


# ── primitives ────────────────────────────────────────────────────────────

def h(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def tag(s: str) -> bytes:
    b = s.encode("ascii")
    if len(b) > TAG_LEN:
        raise ValueError("tag longer than 16 bytes: " + s)
    return b + b"\x00" * (TAG_LEN - len(b))


def be16(v: int) -> bytes:
    if not 0 <= v <= 0xFFFF:
        raise ValueError("u16 out of range")
    return v.to_bytes(2, "big")


def be32(v: int) -> bytes:
    if not 0 <= v <= 0xFFFFFFFF:
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


# ── tags (spec items 1-7) ─────────────────────────────────────────────────

T_STLEAF = "NDS.STLEAF.v1"
T_STRNODE = "NDS.STRNODE.v1"
T_E_STREG = "NDS.E.STREG.v1"
T_STSET = "NDS.STSET.v1"
T_STSLEAF = "NDS.STSLEAF.v1"
T_STSNODE = "NDS.STSNODE.v1"
T_E_STSET = "NDS.E.STSET.v1"
T_STREP = "NDS.STREP.v1"
T_STRPNODE = "NDS.STRPNODE.v1"
T_E_STREP = "NDS.E.STREP.v1"
T_STOR = "NDS.STOR.v1"
T_SYS5 = "NDS.SYS.v5"
T_STEXIT = "NDS.STEXIT.v1"
T_STPROBE = "NDS.STPROBE.v1"

ALL_TAGS = [T_STLEAF, T_STRNODE, T_E_STREG, T_STSET, T_STSLEAF, T_STSNODE,
            T_E_STSET, T_STREP, T_STRPNODE, T_E_STREP, T_STOR, T_SYS5,
            T_STEXIT, T_STPROBE]


# ── item 1: registry ──────────────────────────────────────────────────────

def registry_leaf_preimage(node_fp, payee_fp, bond, status, reg_h, exit_h):
    assert len(node_fp) == FP_LEN and len(payee_fp) == FP_LEN
    if status not in (STATUS_ACTIVE, STATUS_EXITING, STATUS_RELEASED):
        raise ValueError("status invalid")
    return (tag(T_STLEAF) + node_fp + payee_fp + be64(bond) +
            bytes([status]) + be64(reg_h) + be64(exit_h))


def registry_leaf(*a):
    return h(registry_leaf_preimage(*a))


def registry_root(rows):
    """rows: list of (node_fp, payee_fp, bond, status, reg_h, exit_h),
    strictly ascending by node_fp."""
    if not rows:
        return empty_root(T_E_STREG)
    if not strictly_ascending([r[0] for r in rows]):
        raise ValueError("registry rows not strictly ascending by node_fp")
    return tagged_merkle(T_STRNODE, [registry_leaf(*r) for r in rows])


# ── item 2: frozen set and sets root ──────────────────────────────────────

def set_hash_preimage(epoch_start, fps):
    if not strictly_ascending(fps):
        raise ValueError("set members not strictly ascending")
    return tag(T_STSET) + be64(epoch_start) + be32(len(fps)) + b"".join(fps)


def set_hash(epoch_start, fps):
    return h(set_hash_preimage(epoch_start, fps))


def sets_leaf(epoch_start, s_h):
    return h(tag(T_STSLEAF) + be64(epoch_start) + s_h)


def sets_root(entries):
    """entries: list of (H, S(H)) strictly ascending by H."""
    if not entries:
        return empty_root(T_E_STSET)
    if not strictly_ascending([e[0] for e in entries]):
        raise ValueError("sets not strictly ascending by H")
    return tagged_merkle(T_STSNODE, [sets_leaf(H, s) for H, s in entries])


# ── item 3: report ────────────────────────────────────────────────────────

def bitmap_len_for(count):
    return (count + 7) // 8


def make_bitmap(count, members_present):
    """bit i (LSB-first within byte i//8) = member i present."""
    bm = bytearray(bitmap_len_for(count))
    for i in members_present:
        if not 0 <= i < count:
            raise ValueError("member index out of range")
        bm[i // 8] |= 1 << (i % 8)
    return bytes(bm)


def report_body(epoch_start, seat, s_h, bitmap):
    return be64(epoch_start) + be32(seat) + s_h + be16(len(bitmap)) + bitmap


def report_leaf_preimage(epoch_start, seat, s_h, bitmap):
    return tag(T_STREP) + report_body(epoch_start, seat, s_h, bitmap)


def report_leaf(*a):
    return h(report_leaf_preimage(*a))


def reports_root(reps):
    """reps: list of (epoch_start, seat, S(H), bitmap), strictly ascending
    by (epoch_start, seat)."""
    if not reps:
        return empty_root(T_E_STREP)
    if not strictly_ascending([(r[0], r[1]) for r in reps]):
        raise ValueError("reports not strictly ascending by (H, seat)")
    return tagged_merkle(T_STRPNODE, [report_leaf(*r) for r in reps])


# ── item 4: storage leg and SYSTEM v5 ─────────────────────────────────────

def storage_root(reg_root, sets_r, reps_root):
    return h(tag(T_STOR) + reg_root + sets_r + reps_root)


def system_v5(legs8, stor_root):
    if len(legs8) != 8:
        raise ValueError("need exactly 8 v4 legs")
    return h(tag(T_SYS5) + b"".join(legs8) + stor_root)


# ── item 5: register / exit bodies ────────────────────────────────────────

def node_fp_of(node_pk):
    assert len(node_pk) == NODE_PK_LEN
    return h(node_pk)


def register_body(node_pk, bond, payee_fp):
    assert len(node_pk) == NODE_PK_LEN and len(payee_fp) == FP_LEN
    return node_pk + be64(bond) + payee_fp


def exit_body(node_pk):
    assert len(node_pk) == NODE_PK_LEN
    return bytes(node_pk)


# ── item 6: exit release UTXO ─────────────────────────────────────────────

def exit_id_preimage(chain_id, release_height, node_fp):
    assert len(chain_id) == CHAIN_ID_LEN and len(node_fp) == FP_LEN
    return (tag(T_STEXIT) + chain_id + be32(DNA_DOMAIN_CORE) +
            be64(release_height) + node_fp)


def exit_id(*a):
    return h(exit_id_preimage(*a))


def exit_nullifier_preimage(eid):
    return eid + bytes([STEXIT_KIND]) + be32(STEXIT_OUT_IDX)


def exit_nullifier(eid):
    return h(exit_nullifier_preimage(eid))


# ── item 7: probe seed (off-chain) ────────────────────────────────────────

def probe_seed_preimage(chain_id, epoch_start, s_h, target_fp, reporter_fp):
    return (tag(T_STPROBE) + chain_id + be64(epoch_start) + s_h +
            target_fp + reporter_fp)


def probe_seed(*a):
    return h(probe_seed_preimage(*a))


# ── deterministic test inputs ─────────────────────────────────────────────

def d(label: str) -> bytes:
    return h(("storage_reward_kat/" + label).encode("ascii"))


def fp(label):
    return d("fp/" + label)


def node_pk(label):
    out = b""
    j = 0
    while len(out) < NODE_PK_LEN:
        out += d("pk/%s/%d" % (label, j))
        j += 1
    return out[:NODE_PK_LEN]


def chain_id():
    return d("chain_id")[:CHAIN_ID_LEN]


def X(b):
    return b.hex()


AMBIGUITIES = [
    "Integer widths for which the spec gives a byte count but no endianness "
    "word (count(4), seat(4), bitmap_len(2), out_index(4)) are encoded "
    "big-endian, per the doc's 'Integers big-endian' reference line; "
    "bitmap_len(2) is a u16 BE.",
    "Tags shorter than 16 bytes are right-padded with 0x00 to exactly 16 "
    "bytes (the doc's TAG_LEN rule); this includes the probe tag "
    "'NDS.STPROBE.v1', the exit tag 'NDS.STEXIT.v1', and every empty tag.",
    "Empty roots follow dna_v2_empty_root: SHA3-512 over the 16-byte padded "
    "empty tag ALONE (no length, no further bytes).",
    "Merkle inputs are the 64-byte leaf HASHES (tagged leaf already hashed), "
    "as in the treasury precedent; n == 1 root = that leaf hash itself (no "
    "node tag applied), odd node promoted.",
    "'Ascending' is read as STRICTLY ascending (duplicates rejected) for "
    "registry node_fp, S(H) member list, sets H, and report (epoch_start, "
    "seat); the oracle refuses non-canonical input instead of sorting it. "
    "fp comparison = unsigned bytewise (memcmp) order. Report order is "
    "lexicographic on (epoch_start u64, seat u32) as integers.",
    "Item 2 S(H): the doc says the member list is node_fp of ACTIVE rows; "
    "S(H) here is computed over the given list only — selection (ACTIVE "
    "status filter) is not part of the hash and is not exercised.",
    "Item 3: the committed report leaf hashes bitmap_len as given; the doc "
    "states bitmap_len = ceil(count/8) and unused high bits 0 but count is "
    "NOT in the report bytes. Vectors always use a canonical bitmap "
    "(bitmap_len = ceil(count/8), unused high bits 0); the length-0 case "
    "uses count 0 with S(H) of the empty set; the length-32 case uses "
    "count 256 (full bytes) and count 250 (high bits of the last byte 0).",
    "Item 3: the doc gives no tag for the call body; the body vector is "
    "the untagged concatenation epoch_start(8) | seat(4) | S(H) | "
    "bitmap_len(2) | bitmap, and the leaf preimage = 'NDS.STREP.v1' tag | "
    "that body.",
    "Item 5: STORAGE_STAKE_MIN is not given a value in the doc; register "
    "body vectors carry the bond as an explicit input and do not check it "
    "against a minimum.",
    "Item 5/6: node_fp = SHA3-512(node_pk) with NO prefix byte (doc "
    "reference line 'fp = SHA3-512(node_pk)'), which differs from EPGRAD's "
    "pubkey_hash = SHA3-512(NODUS_TREE_TAG_VALIDATOR | pubkey) "
    "(nodus_witness_v2_epoch.c:65-71). exit_id uses this plain fp, as the "
    "doc writes node_fp[64].",
    "Item 6: DNA_DOMAIN_CORE has no value in the doc; the oracle uses 1, "
    "read from shared/dnac/ledger_ids.h:53, encoded u32 BE as in EPGRAD. "
    "release_height is an explicit input; its relation to the registry "
    "exit_height is not specified by the doc and is not assumed.",
    "Item 6: the nullifier kind is 1 byte (0x11) and out_index is u32 BE "
    "201, the EPGRAD nullifier shape (id | kind(1) | out_index(4)). The doc "
    "flags uniqueness of 0x11/201 as to-be-verified; the oracle does not "
    "verify it.",
    "Item 4: the 8 v4 legs are opaque 64-byte inputs here; their order is "
    "the v4 order (validator, delegation, chain_config, validator_set, "
    "domain_registry, manifest, attendance, treasury) and the vector simply "
    "labels them leg0..leg7 in that order.",
]


def build():
    vec = {}
    count = 0

    # tags
    vec["tags"] = {t: X(tag(t)) for t in ALL_TAGS}
    vec["empty_roots"] = {
        T_E_STREG: X(empty_root(T_E_STREG)),
        T_E_STSET: X(empty_root(T_E_STSET)),
        T_E_STREP: X(empty_root(T_E_STREP)),
    }
    count += 3

    # item 1 — leaf vectors
    leaf_cases = [
        ("bond0_active_h0", 0, STATUS_ACTIVE, 0, 0),
        ("bondmax_active", U64_MAX, STATUS_ACTIVE, 1, 0),
        ("exiting", 1000000000000000, STATUS_EXITING, 4242, 99999),
        ("released_large_h", 123456789, STATUS_RELEASED,
         U64_MAX - 1, U64_MAX),
        ("bondmax_released_hmax", U64_MAX, STATUS_RELEASED, U64_MAX, U64_MAX),
    ]
    leaves = []
    for name, bond, status, rh, eh in leaf_cases:
        nf = fp("leaf/node/" + name)
        pf = fp("leaf/payee/" + name)
        pre = registry_leaf_preimage(nf, pf, bond, status, rh, eh)
        leaves.append({
            "name": name, "node_fp": X(nf), "payee_fp": X(pf),
            "bond": str(bond), "status": status,
            "registered_height": str(rh), "exit_height": str(eh),
            "preimage": X(pre), "leaf": X(h(pre)),
        })
        count += 1
    vec["registry_leaf"] = leaves

    # item 1 — registry roots
    statuses = [STATUS_ACTIVE, STATUS_EXITING, STATUS_RELEASED]
    roots = []
    for n in (0, 1, 2, 3, 7):
        rows = []
        for i in range(n):
            rows.append((fp("reg/n%d/node/%d" % (n, i)),
                         fp("reg/n%d/payee/%d" % (n, i)),
                         [0, 1, 10 ** 15, U64_MAX][i % 4],
                         statuses[i % 3],
                         i * 1000,
                         0 if statuses[i % 3] == STATUS_ACTIVE
                         else i * 1000 + 720))
        rows.sort(key=lambda r: r[0])
        roots.append({
            "n": n,
            "rows_sorted": [{
                "node_fp": X(r[0]), "payee_fp": X(r[1]), "bond": str(r[2]),
                "status": r[3], "registered_height": str(r[4]),
                "exit_height": str(r[5]), "leaf": X(registry_leaf(*r)),
            } for r in rows],
            "root": X(registry_root(rows)),
        })
        count += 1
    vec["registry_root"] = roots

    # item 2 — S(H)
    shs = []
    for cnt, H in ((0, 0), (0, 720), (5, 1440), (5, U64_MAX)):
        fps = sorted(fp("set/H%d/c%d/%d" % (H, cnt, i)) for i in range(cnt))
        pre = set_hash_preimage(H, fps)
        shs.append({"epoch_start": str(H), "count": cnt,
                    "members_sorted": [X(f) for f in fps],
                    "preimage": X(pre), "S": X(h(pre))})
        count += 1
    vec["set_hash"] = shs

    # item 2 — sets root
    sroots = []
    for n in (0, 1, 2, 3, 7):
        entries = []
        for i in range(n):
            H = i * 720
            c = i % 4
            fps = sorted(fp("sets/n%d/H%d/%d" % (n, H, k)) for k in range(c))
            entries.append((H, fps))
        out_entries = []
        pairs = []
        for H, fps in entries:
            s = set_hash(H, fps)
            pairs.append((H, s))
            out_entries.append({"epoch_start": str(H), "count": len(fps),
                                "members_sorted": [X(f) for f in fps],
                                "S": X(s), "leaf": X(sets_leaf(H, s))})
        sroots.append({"n": n, "entries": out_entries,
                       "root": X(sets_root(pairs))})
        count += 1
    vec["sets_root"] = sroots

    # item 3 — report body / leaf, bitmap lengths 0 and 32
    reps = []
    rep_cases = [
        ("len0_count0", 0, 0, 0, []),
        ("len32_count256_all", 1440, 3, 256, list(range(256))),
        ("len32_count256_even", 2160, 6, 256, list(range(0, 256, 2))),
        ("len32_count250_mixed", U64_MAX, 0xFFFFFFFF, 250,
         [i for i in range(250) if d("rep/bit/%d" % i)[0] & 1]),
        ("len1_count5_bits0_2_4", 720, 1, 5, [0, 2, 4]),
    ]
    for name, H, seat, cnt, present in rep_cases:
        fps = sorted(fp("rep/%s/%d" % (name, i)) for i in range(cnt))
        s = set_hash(H, fps)
        bm = make_bitmap(cnt, present)
        body = report_body(H, seat, s, bm)
        pre = report_leaf_preimage(H, seat, s, bm)
        reps.append({"name": name, "epoch_start": str(H), "seat": seat,
                     "set_count": cnt, "members_present": present,
                     "S": X(s), "bitmap_len": len(bm), "bitmap": X(bm),
                     "call_body": X(body), "leaf_preimage": X(pre),
                     "leaf": X(h(pre))})
        count += 1
    vec["report"] = reps

    # item 3 — reports root
    rroots = []
    for n in (0, 1, 2, 3, 7):
        items = []
        for i in range(n):
            H = (i // 3) * 720         # several seats per epoch
            seat = (i % 3) * 2 + 1
            c = (i * 3) % 11
            fps = sorted(fp("reps/n%d/%d/%d" % (n, i, k)) for k in range(c))
            s = set_hash(H, fps)
            present = [k for k in range(c) if (k + i) % 2 == 0]
            items.append((H, seat, s, make_bitmap(c, present)))
        items.sort(key=lambda r: (r[0], r[1]))
        rroots.append({
            "n": n,
            "reports_sorted": [{
                "epoch_start": str(r[0]), "seat": r[1], "S": X(r[2]),
                "bitmap_len": len(r[3]), "bitmap": X(r[3]),
                "leaf": X(report_leaf(*r))} for r in items],
            "root": X(reports_root(items)),
        })
        count += 1
    vec["reports_root"] = rroots

    # item 4 — storage_root (empty and populated) and SYSTEM v5
    reg_r = bytes.fromhex(roots[4]["root"])
    sets_r = bytes.fromhex(sroots[4]["root"])
    reps_r = bytes.fromhex(rroots[4]["root"])
    st_full = storage_root(reg_r, sets_r, reps_r)
    st_empty = storage_root(empty_root(T_E_STREG), empty_root(T_E_STSET),
                            empty_root(T_E_STREP))
    vec["storage_root"] = [
        {"name": "all_empty",
         "registry_root": X(empty_root(T_E_STREG)),
         "sets_root": X(empty_root(T_E_STSET)),
         "reports_root": X(empty_root(T_E_STREP)),
         "storage_root": X(st_empty)},
        {"name": "n7_each",
         "registry_root": X(reg_r), "sets_root": X(sets_r),
         "reports_root": X(reps_r), "storage_root": X(st_full)},
    ]
    count += 2

    leg_names = ["validator_root", "delegation_root", "chain_config_root",
                 "validator_set_root", "domain_registry_root",
                 "manifest_root", "attendance_root", "treasury_root"]
    legs = [d("sys/leg/" + nm) for nm in leg_names]
    sysv = []
    for nm, st in (("storage_empty", st_empty), ("storage_n7", st_full)):
        pre = tag(T_SYS5) + b"".join(legs) + st
        sysv.append({"name": nm,
                     "v4_legs_in_order": [{"leg": ln, "value": X(v)}
                                          for ln, v in zip(leg_names, legs)],
                     "storage_root": X(st), "preimage": X(pre),
                     "system_state_root": X(system_v5(legs, st))})
        count += 1
    vec["system_v5"] = sysv

    # item 5 — register / exit bodies
    bodies = []
    for name, bond in (("bond0", 0), ("bond1e15", 10 ** 15),
                       ("bondmax", U64_MAX)):
        pk = node_pk("reg/" + name)
        pf = fp("regbody/payee/" + name)
        bodies.append({"name": name, "node_pk": X(pk),
                       "node_fp": X(node_fp_of(pk)), "bond": str(bond),
                       "payee_fp": X(pf),
                       "register_body": X(register_body(pk, bond, pf)),
                       "exit_body": X(exit_body(pk))})
        count += 1
    vec["register_exit_body"] = bodies

    # item 6 — exit id + nullifier
    cid = chain_id()
    exits = []
    for name, rh in (("h0", 0), ("h1440", 1440), ("hmax", U64_MAX)):
        pk = node_pk("exit/" + name)
        nf = node_fp_of(pk)
        pre = exit_id_preimage(cid, rh, nf)
        eid = h(pre)
        npre = exit_nullifier_preimage(eid)
        exits.append({"name": name, "chain_id": X(cid),
                      "domain": DNA_DOMAIN_CORE, "release_height": str(rh),
                      "node_pk": X(pk), "node_fp": X(nf),
                      "exit_id_preimage": X(pre), "exit_id": X(eid),
                      "kind": "0x11", "out_index": STEXIT_OUT_IDX,
                      "nullifier_preimage": X(npre),
                      "nullifier": X(h(npre))})
        count += 1
    vec["exit_release"] = exits

    # item 7 — probe seed
    probes = []
    for name, H, cnt in (("empty_set_H0", 0, 0), ("set5_H1440", 1440, 5),
                         ("set5_Hmax", U64_MAX, 5)):
        fps = sorted(fp("probe/%s/%d" % (name, i)) for i in range(cnt))
        s = set_hash(H, fps)
        tf = fp("probe/target/" + name)
        rf = fp("probe/reporter/" + name)
        pre = probe_seed_preimage(cid, H, s, tf, rf)
        probes.append({"name": name, "chain_id": X(cid),
                       "epoch_start": str(H), "set_count": cnt, "S": X(s),
                       "target_fp": X(tf), "reporter_fp": X(rf),
                       "preimage": X(pre), "seed": X(h(pre))})
        count += 1
    vec["probe_seed"] = probes

    return {
        "spec": "docs/plans/2026-10-04-storage-reward-bytes.md "
                "(Storage reward v1 byte layouts, PROPOSAL, 2026-10-04)",
        "oracle": "nodus/tests/vectors/storage_reward_oracle.py",
        "label": "SELF-CONSISTENT (independent re-implementation of the "
                 "same document; not an external reference)",
        "conventions": {
            "hash": "SHA3-512 (hashlib.sha3_512)",
            "tag": "16 bytes, ASCII, right-padded with 0x00",
            "integers": "big-endian; u64 values given as decimal strings",
            "hex": "lowercase, no prefix",
            "inputs": "derived as SHA3-512('storage_reward_kat/' + label); "
                      "node_pk = concatenated SHA3-512('storage_reward_kat/"
                      "pk/<label>/<j>') truncated to 2592 bytes; chain_id = "
                      "first 32 bytes of SHA3-512('storage_reward_kat/"
                      "chain_id')",
            "DNA_DOMAIN_CORE": DNA_DOMAIN_CORE,
        },
        "ambiguities": AMBIGUITIES,
        "vector_count": count,
        "vectors": vec,
    }


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "storage_reward_kat.json")
    doc = build()
    with open(out, "w", encoding="ascii") as f:
        json.dump(doc, f, indent=1, sort_keys=False)
        f.write("\n")
    sys.stdout.write("wrote %s (%d vectors)\n" % (out, doc["vector_count"]))


if __name__ == "__main__":
    main()
