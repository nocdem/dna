#!/usr/bin/env python3
r"""
Independent oracle for HF-6 slice 1 byte formats (validator binding:
node consent message, validator_id derivations, validator-set snapshot v2).

INDEPENDENCE DISCIPLINE
-----------------------
Written WITHOUT reading any HF-6 C code. Every value is computed here from
the WRITTEN specification only:

  * design   docs/plans/2026-10-03-hf5-validator-owner-stake-design.md
             (rev 5) §6 "Baytlar" (operator-approved 2026-10-08):
               §6.1 node consent message (2765 B); rev 6 §6.1 / §11.3
                    adds op 3 = STORAGE_REGISTER (subject 64 x 0x00),
                    operator 2026-10-09 "approved"
               §6.2 validator_id (new / migrated, 112-byte preimages)
               §6.3 validator leaf v2 (5390 B)      -- lengths only
               §6.4 delegation leaf v2 (145 B)      -- lengths only
               §6.5 vset v2 (header 78 B, entry 2770 B, tag NDS.VSET.v2)
  * decision docs/plans/decisions/2026-10-08-kurultay-14-hf6-summary.md
             K6: vset v2 sortition_seed = 64 x 0x00.
  * v1 layout: the header comment of shared/dnac/vset_wire.h ONLY
             (header 78 B; entry 2642 B = voter_id 32 ‖ pubkey 2592 ‖
             total_stake u64 ‖ self_bond u64 ‖ commission_bps u16;
             voter_id = SHA3-512(pubkey)[0..31]; tag NDS.VSET.v1).

Conventions (spec §6 preamble): integers big-endian; tags 16 bytes, ASCII
zero-padded on the right. Hash = SHA3-512 (hashlib.sha3_512, stdlib).

Deterministic inputs: fill(label, n) = SHA3-512(label ‖ u32BE(0)) ‖
SHA3-512(label ‖ u32BE(1)) ‖ ... truncated to n bytes.

ENTRY ORDER: the snapshots below are encoded in the GIVEN order i = 0,1,2.
§6.5 does not state an entry ordering for v2. If the C codec imposes or
checks an ordering, the C side must state which, and these vectors must be
re-derived in that order.

Usage:  python3 valbind_oracle.py   (prints labelled hex lines; exit 1 on
        any length assertion failure)
"""

import hashlib
import struct
import sys


def sha3(b: bytes) -> bytes:
    return hashlib.sha3_512(b).digest()


def tag16(s: str) -> bytes:
    a = s.encode("ascii")
    assert len(a) <= 16, s
    return a + b"\x00" * (16 - len(a))


def u8(v):  return struct.pack(">B", v)
def u16(v): return struct.pack(">H", v)
def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)


def fill(label: str, n: int) -> bytes:
    out = b""
    i = 0
    lb = label.encode("ascii")
    while len(out) < n:
        out += sha3(lb + u32(i))
        i += 1
    return out[:n]


PK_LEN = 2592
MAX_VOTERS = 128   # from the spec's max-length formulas 78 + 128 x entry

# ── §6.1 consent message ────────────────────────────────────────────────
def consent_msg(chain32, op, subject64, owner64, pk, expiry):
    assert len(chain32) == 32 and len(subject64) == 64
    assert len(owner64) == 64 and len(pk) == PK_LEN
    m = u32(1) + chain32 + u8(op) + subject64 + owner64 + pk + u64(expiry)
    return m

# ── §6.2 validator_id ───────────────────────────────────────────────────
def vid_new_preimage(chain32, intent64):
    return tag16("NDS.VALID.v1") + chain32 + intent64

def vid_mig_preimage(chain32, old_pubkey):
    return tag16("NDS.VALMIG.v1") + chain32 + sha3(old_pubkey)

# ── vset header (v1 and v2 share the 78-byte layout) ────────────────────
def vset_header(epoch, count, ruleset):
    return u64(epoch) + u16(count) + u32(ruleset) + b"\x00" * 64

def vset_v2_entry(pk, vid, owner, total, selfb, comm):
    assert len(pk) == PK_LEN and len(vid) == 64 and len(owner) == 64
    return sha3(pk)[:32] + vid + owner + pk + u64(total) + u64(selfb) + u16(comm)

def vset_v1_entry(pk, total, selfb, comm):
    assert len(pk) == PK_LEN
    return sha3(pk)[:32] + pk + u64(total) + u64(selfb) + u16(comm)


def line(label, b):
    print(f"{label} = {b.hex()}")


def main():
    fails = []

    def check(name, got, want):
        ok = got == want
        print(f"ASSERT {name}: {got} == {want} -> {'OK' if ok else 'FAIL'}")
        if not ok:
            fails.append(name)

    chain = fill("chain", 32)
    owner = fill("owner", 64)
    pk = fill("pk", PK_LEN)

    print("# HF-6 slice 1 valbind oracle (spec: hf5-validator-owner-stake-design rev5 §6, K6; rev6 §6.1/§11.3 op 3)")
    print("# inputs")
    line("chain32", chain)
    line("owner_fp", owner)
    line("sha3_512(pk)", sha3(pk))

    # 1. consent messages
    print("# 1. consent message §6.1")
    m_rot = consent_msg(chain, 2, fill("subject", 64), owner, pk, 1000)
    check("consent_rotate_len", len(m_rot), 2765)
    line("consent_rotate.msg", m_rot)
    line("consent_rotate.sha3_512", sha3(m_rot))
    m_stk = consent_msg(chain, 1, b"\x00" * 64, owner, pk, 1000)
    check("consent_stake_len", len(m_stk), 2765)
    line("consent_stake.msg", m_stk)
    line("consent_stake.sha3_512", sha3(m_stk))
    # rev 6 §6.1 / §11.3: op 3 = STORAGE_REGISTER, subject 64 x 0x00, the
    # 2592-byte key field = the storage node_pk (here: the same fixture pk)
    m_sto = consent_msg(chain, 3, b"\x00" * 64, owner, pk, 1000)
    check("consent_storage_register_len", len(m_sto), 2765)
    line("consent_storage_register.msg", m_sto)
    line("consent_storage_register.sha3_512", sha3(m_sto))
    check("consent_storage_register_off_op", m_sto[36], 3)
    check("consent_storage_register_subject_zero",
          m_sto[37:101] == b"\x00" * 64, True)
    check("consent_storage_register_vs_stake_only_op",
          m_sto[:36] == m_stk[:36] and m_sto[37:] == m_stk[37:]
          and m_sto[36] != m_stk[36], True)
    # field offsets per §6.1 table
    check("consent_off_op", m_rot[36], 2)
    check("consent_off_owner", m_rot[101:165] == owner, True)
    check("consent_off_pk", m_rot[165:2757] == pk, True)
    check("consent_off_expiry", m_rot[2757:], u64(1000))

    # 2. validator_id new
    print("# 2. validator_id (new) §6.2")
    pre_new = vid_new_preimage(chain, fill("intent", 64))
    check("vid_new_preimage_len", len(pre_new), 112)
    line("vid_new.preimage", pre_new)
    line("vid_new", sha3(pre_new))

    # 3. validator_id migrated
    print("# 3. validator_id (migrated) §6.2")
    oldpk = fill("oldpk", PK_LEN)
    pre_mig = vid_mig_preimage(chain, oldpk)
    check("vid_mig_preimage_len", len(pre_mig), 112)
    line("vid_mig.sha3_512(old_pubkey)", sha3(oldpk))
    line("vid_mig.preimage", pre_mig)
    line("vid_mig", sha3(pre_mig))

    # 4. vset v2
    print("# 4. vset v2 §6.5 (entries in GIVEN order i=0,1,2; §6.5 states no "
          "entry ordering -- if the C codec imposes one, the C side must say which)")
    entries = []
    for i in range(3):
        entries.append(dict(pk=fill(f"pk{i}", PK_LEN), vid=fill(f"vid{i}", 64),
                            own=fill(f"own{i}", 64), total=10**15 + i,
                            selfb=2 * 10**14, comm=500 + i))
    hdr2 = vset_header(1440, 3, 2)
    check("vset_hdr_len", len(hdr2), 78)
    body2 = b""
    for i, e in enumerate(entries):
        ent = vset_v2_entry(e["pk"], e["vid"], e["own"], e["total"], e["selfb"], e["comm"])
        check(f"vset_v2_entry{i}_len", len(ent), 2770)
        line(f"vset_v2.entry{i}.voter_id", ent[:32])
        body2 += ent
    enc2 = hdr2 + body2
    check("vset_v2_len", len(enc2), 78 + 3 * 2770)
    line("vset_v2.header", hdr2)
    print(f"vset_v2.encoding_len = {len(enc2)}")
    line("vset_v2.sha3_512(encoding)", sha3(enc2))
    line("vset_v2.snapshot_hash", sha3(tag16("NDS.VSET.v2") + enc2))

    # 5. vset v1, same entries
    print("# 5. vset v1 (same entries, ruleset 1) -- 'v1 unchanged' check")
    hdr1 = vset_header(1440, 3, 1)
    enc1 = hdr1 + b"".join(vset_v1_entry(e["pk"], e["total"], e["selfb"], e["comm"])
                           for e in entries)
    check("vset_v1_len", len(enc1), 78 + 3 * 2642)
    line("vset_v1.header", hdr1)
    print(f"vset_v1.encoding_len = {len(enc1)}")
    line("vset_v1.snapshot_hash", sha3(tag16("NDS.VSET.v1") + enc1))

    # 6. length assertions
    print("# 6. lengths")
    check("max_vset_v2", 78 + MAX_VOTERS * 2770, 354638)
    check("max_vset_v1", 78 + MAX_VOTERS * 2642, 338254)
    leaf_v2 = [1, 64, 64, PK_LEN, PK_LEN,           # tag, vid, owner, pk, pending pk
               8, 8, 8, 8,                           # cons_key_eff_epoch, self, total_del, ext_del
               2, 2, 8,                              # comm, pending_comm, pending_eff_block
               1, 8, 8, 8, 8]                        # status, active_since, unstake_commit, last_upd, missed
    check("validator_leaf_v2_len", sum(leaf_v2), 5390)
    deleg_v2 = [1, 64, 64, 8, 8]                     # tag, delegator_fp, vid, amount, delegated_at
    check("delegation_leaf_v2_len", sum(deleg_v2), 145)

    if fails:
        print(f"RESULT FAIL: {fails}")
        return 1
    print("RESULT OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
