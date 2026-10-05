#!/usr/bin/env python3
"""
Independent reference implementation (oracle) of the Nodus Connect groups byte
layouts, written from the specification document ONLY:

    docs/plans/2026-10-05-connect-groups-bytes.md  items 1-7 as amended by REV 2
    (approval: docs/plans/decisions/2026-10-05-groups-apt-bytes-approved.md)

Primitives used (as cited by the spec):
  - SHA3-512 / SHA3-256 (FIPS 202)               -> hashlib
  - HKDF-SHA3-256, RFC 5869 extract-then-expand,
    single expand block (hkdf_sha3.c shape)      -> implemented here with hmac
  - AES-256 key wrap, RFC 3394 default IV        -> cryptography.keywrap
  - AES-256-GCM, 12-byte nonce, 16-byte tag      -> cryptography AESGCM

NOT available in Python: ML-KEM-1024 and ML-DSA-87.
  - KEM: (ss, kem_ct) per member are FIXED TEST INPUTS (see fixed()).
  - Signatures: every signed structure is emitted as its exact SIGNED PREIMAGE
    (byte-compare this) and, in the full-structure bytes, a FIXED 4,627-byte
    DUMMY signature that is NOT a valid ML-DSA-87 signature (ML-DSA signing is
    randomized; real signatures are verified, never byte-compared).

Honest label: self-consistency vectors from the spec text; they prove that an
implementation matches THIS reading of the spec, not that the spec is sound.

Regenerate (deterministic, byte-identical on every run):
    python3 web-wallet/test/fixtures/groups_oracle.py
which writes groups_kat.json next to this file.
"""

import hashlib
import hmac
import json
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)

# ---------------------------------------------------------------------------
# Constants from the spec
# ---------------------------------------------------------------------------

TAG_LEN = 16            # "Tags 16 bytes ASCII right-padded 0x00"
FP_LEN = 64             # fingerprint = SHA3-512 sized
GID_LEN = 32
KEM_CT_LEN = 1568       # ML-KEM-1024 ciphertext
SS_LEN = 32
WRAPPED_LEN = 40        # RFC 3394 of a 32-byte key
ENTRY_LEN = KEM_CT_LEN + WRAPPED_LEN   # R2-1: 1,608
SIG_LEN = 4627          # ML-DSA-87
NONCE_LEN = 12
GCM_TAG_LEN = 16
MAX_MEMBERS = 64
NAME_MAX = 64
TEXT_MAX = 4000
RECORD_PT_MAX = 1 + NAME_MAX + 2 + MAX_MEMBERS * FP_LEN + 8   # R2-8: 4,171
BUCKET_MAX = 1 << 20
MS_PER_DAY = 86_400_000

PURPOSE_HEAD = 1
PURPOSE_KEY_PACKET = 2
PURPOSE_RECORD = 3
PURPOSE_OUTBOX = 4

TAG_NAMES = [
    "NDS.GSALT.v1",
    "NDS.GADDR.v1",
    "NDS.GKP.v1",
    "NDS.GKEK.v1",
    "NDS.GREC.v1",
    "NDS.GHEAD.v1",
    "NDS.GMSG.v1",
    "NDS.GBKT.v1",
    # "NDS.GMTAG.v1" (the 9th tag) was removed by R2-1 (no lookup tag); not emitted.
]


def tag(name: str) -> bytes:
    raw = name.encode("ascii")
    assert len(raw) <= TAG_LEN
    return raw + b"\x00" * (TAG_LEN - len(raw))


def u8(x: int) -> bytes:
    return struct.pack(">B", x)


def u16(x: int) -> bytes:
    return struct.pack(">H", x)


def u32(x: int) -> bytes:
    return struct.pack(">I", x)


def u64(x: int) -> bytes:
    return struct.pack(">Q", x)


def sha3_512(b: bytes) -> bytes:
    return hashlib.sha3_512(b).digest()


def hx(b: bytes) -> str:
    return b.hex()


# ---------------------------------------------------------------------------
# Fixed test inputs. NOT secret, NOT random: every input byte string is
#   fixed(label, n) = SHAKE-256("NDS-groups-oracle-v1/" || label)[0:n]
# so a reimplementation may either copy the hex from the JSON or rederive it.
# ---------------------------------------------------------------------------

FIXED_PREFIX = b"NDS-groups-oracle-v1/"


def fixed(label: str, n: int) -> bytes:
    return hashlib.shake_256(FIXED_PREFIX + label.encode("ascii")).digest(n)


DUMMY_SIG = fixed("dummy-signature-NOT-VALID-ML-DSA-87", SIG_LEN)


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def hkdf_sha3_256(salt: bytes, ikm: bytes, info: bytes, okm_len: int = 32) -> bytes:
    """RFC 5869 with HMAC-SHA3-256; one expand block (okm_len <= 32, info <= 255)."""
    assert okm_len <= 32 and len(info) <= 255
    prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()
    t1 = hmac.new(prk, info + b"\x01", hashlib.sha3_256).digest()
    return t1[:okm_len]


def gcm_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes):
    out = AESGCM(key).encrypt(nonce, pt, aad)
    return out[:-GCM_TAG_LEN], out[-GCM_TAG_LEN:]


def gcm_decrypt(key: bytes, nonce: bytes, aad: bytes, ct: bytes, gtag: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct + gtag, aad)


# ---------------------------------------------------------------------------
# Secrets per group / §1 addresses
# ---------------------------------------------------------------------------

def salt_v(group_id: bytes, group_key: bytes, v: int) -> bytes:
    info = tag("NDS.GSALT.v1") + u32(v)
    assert len(info) == 20
    return hkdf_sha3_256(group_id, group_key, info)


def dht_addr(purpose: int, group_id: bytes, secret: bytes, x: int) -> bytes:
    pre = tag("NDS.GADDR.v1") + u8(purpose) + group_id + secret + u64(x)
    assert len(pre) == 16 + 1 + 32 + 32 + 8 == 89
    return sha3_512(pre)


def dht_key_string(k: bytes) -> str:
    return "ncg:" + k.hex()


# ---------------------------------------------------------------------------
# §2 key packet (R2-1 entries, R2-2 digest)
# ---------------------------------------------------------------------------

def kek(ss: bytes, group_id: bytes, v: int, member_fp: bytes, owner_fp: bytes) -> bytes:
    info = tag("NDS.GKEK.v1") + u32(v) + member_fp + owner_fp
    assert len(info) == 148
    return hkdf_sha3_256(group_id, ss, info)


def kp_header(group_id, owner_fp, v, prev_digest, record_digest, issued_at_ms, count) -> bytes:
    h = (tag("NDS.GKP.v1") + group_id + owner_fp + u32(v) + prev_digest +
         record_digest + u64(issued_at_ms) + u16(count))
    assert len(h) == 254
    return h


def kp_preimage(header: bytes, entries) -> bytes:
    return header + b"".join(entries)


def with_sig(preimage: bytes, sig: bytes = DUMMY_SIG) -> bytes:
    return preimage + u16(len(sig)) + sig


# ---------------------------------------------------------------------------
# §3 record
# ---------------------------------------------------------------------------

def record_plaintext(name: bytes, members, created_at_ms: int) -> bytes:
    assert len(name) <= NAME_MAX
    return u8(len(name)) + name + u16(len(members)) + b"".join(members) + u64(created_at_ms)


def record_value(group_key, group_id, v, nonce, pt) -> dict:
    aad = tag("NDS.GREC.v1") + group_id + u32(v)
    assert len(aad) == 52
    head = aad + nonce
    ct, gtag = gcm_encrypt(group_key, nonce, aad, pt)
    value = head + u32(len(ct)) + ct + gtag
    return {"aad": aad, "ct": ct, "gcm_tag": gtag, "value": value}


# ---------------------------------------------------------------------------
# §4 HEAD (R2-4)
# ---------------------------------------------------------------------------

def head_preimage(group_id, owner_fp, v, kp_digest, issued_at_ms) -> bytes:
    p = tag("NDS.GHEAD.v1") + group_id + owner_fp + u32(v) + kp_digest + u64(issued_at_ms)
    assert len(p) == 188
    return p


# ---------------------------------------------------------------------------
# §5 message + bucket (R2-5)
# ---------------------------------------------------------------------------

def day_of(timestamp_ms: int):
    """Returns the u32 day or None when it cannot be represented (refuse)."""
    if timestamp_ms < 0 or timestamp_ms > 0xFFFFFFFFFFFFFFFF:
        return None
    d = timestamp_ms // MS_PER_DAY
    if d > 0xFFFFFFFF:
        return None
    return d


def message(group_key, group_id, v, sender_fp, message_id, timestamp_ms, nonce, text: bytes) -> dict:
    assert len(text) <= TEXT_MAX
    d = day_of(timestamp_ms)
    assert d is not None
    h_wo_nonce = (tag("NDS.GMSG.v1") + group_id + u32(v) + sender_fp + message_id +
                  u64(timestamp_ms) + u32(d))
    assert len(h_wo_nonce) == 144
    aad = h_wo_nonce                      # R2-5: H minus its last 12 bytes
    ct, gtag = gcm_encrypt(group_key, nonce, aad, text)
    H = h_wo_nonce + nonce                # nonce placed into H after encrypt
    assert len(H) == 156 and H[:-12] == aad
    signed = H + u32(len(ct)) + ct + gtag
    item = with_sig(signed)
    return {"day": d, "H": H, "aad": aad, "ct": ct, "gcm_tag": gtag,
            "signed_preimage": signed, "item": item}


def bucket(items) -> bytes:
    return tag("NDS.GBKT.v1") + u16(len(items)) + b"".join(items)


# ---------------------------------------------------------------------------
# Test-only strict parsers (used to prove the reject vectors are refused by
# this reading; a reimplementation must refuse them as well).
# ---------------------------------------------------------------------------

class Refuse(Exception):
    pass


def parse_kp(b: bytes) -> dict:
    if len(b) < 254:
        raise Refuse("short header")
    if b[:16] != tag("NDS.GKP.v1"):
        raise Refuse("tag")
    count = struct.unpack(">H", b[252:254])[0]
    if not 1 <= count <= MAX_MEMBERS:
        raise Refuse("count out of range")
    off = 254 + count * ENTRY_LEN
    if len(b) < off + 2:
        raise Refuse("truncated: fewer entries than count")
    sl = struct.unpack(">H", b[off:off + 2])[0]
    if sl != SIG_LEN:
        raise Refuse("sig_len != 4627")
    if len(b) != off + 2 + SIG_LEN:
        raise Refuse("length != exact (trailing or missing bytes)")
    cts = [b[254 + i * ENTRY_LEN:254 + i * ENTRY_LEN + KEM_CT_LEN] for i in range(count)]
    for i in range(1, count):
        if cts[i - 1] == cts[i]:
            raise Refuse("duplicate kem_ct")
        if cts[i - 1] > cts[i]:
            raise Refuse("entries not ascending by kem_ct")
    return {"count": count, "preimage": b[:off]}


def parse_record_pt(pt: bytes) -> dict:
    if len(pt) > RECORD_PT_MAX:
        raise Refuse("plaintext over cap")
    if len(pt) < 1:
        raise Refuse("short")
    nl = pt[0]
    if nl > NAME_MAX:
        raise Refuse("name too long")
    p = 1 + nl
    if len(pt) < p + 2:
        raise Refuse("short")
    count = struct.unpack(">H", pt[p:p + 2])[0]
    p += 2
    if not 1 <= count <= MAX_MEMBERS:
        raise Refuse("count out of range")
    if len(pt) != p + count * FP_LEN + 8:
        raise Refuse("length != exact")
    fps = [pt[p + i * FP_LEN:p + (i + 1) * FP_LEN] for i in range(count)]
    for i in range(1, count):
        if fps[i - 1] == fps[i]:
            raise Refuse("duplicate member")
        if fps[i - 1] > fps[i]:
            raise Refuse("members not ascending")
    return {"count": count, "members": fps}


def parse_record_value(b: bytes, group_key: bytes) -> dict:
    if len(b) < 52 + 12 + 4 + 16:
        raise Refuse("short")
    if b[:16] != tag("NDS.GREC.v1"):
        raise Refuse("tag")
    ct_len = struct.unpack(">I", b[64:68])[0]
    if ct_len > RECORD_PT_MAX:              # cap checked on the length field, before decrypt
        raise Refuse("ct_len over 4,171-byte cap")
    if len(b) != 68 + ct_len + 16:
        raise Refuse("length != exact")
    try:
        pt = gcm_decrypt(group_key, b[52:64], b[:52], b[68:68 + ct_len], b[68 + ct_len:])
    except InvalidTag:
        raise Refuse("gcm auth")
    return parse_record_pt(pt)


def parse_head(b: bytes) -> bytes:
    if len(b) < 190:
        raise Refuse("short")
    if b[:16] != tag("NDS.GHEAD.v1"):
        raise Refuse("tag")
    if struct.unpack(">H", b[188:190])[0] != SIG_LEN:
        raise Refuse("sig_len != 4627")
    if len(b) != 190 + SIG_LEN:
        raise Refuse("length != exact")
    return b[:188]


def find_own_entry(packet: bytes, group_id, v, member_fp, owner_fp, ss_of_ct) -> bytes:
    """Trial unwrap (R2-1). ss_of_ct stands in for ML-KEM decapsulation."""
    count = struct.unpack(">H", packet[252:254])[0]
    for i in range(count):
        e = packet[254 + i * ENTRY_LEN:254 + (i + 1) * ENTRY_LEN]
        ss = ss_of_ct(e[:KEM_CT_LEN])
        if ss is None:
            continue
        try:
            return aes_key_unwrap(kek(ss, group_id, v, member_fp, owner_fp), e[KEM_CT_LEN:])
        except InvalidUnwrap:
            continue
    raise Refuse("no entry unwraps")


def expect_refuse(fn, *a) -> str:
    try:
        fn(*a)
    except Refuse as r:
        return str(r)
    raise AssertionError("oracle failed to refuse a reject vector")


# ---------------------------------------------------------------------------
# Vector generation
# ---------------------------------------------------------------------------

def build():
    # Layout self-checks against the spec's own numbers.
    assert ENTRY_LEN == 1608
    assert 254 + 64 * ENTRY_LEN + 2 + SIG_LEN == 107_795      # R2-1
    assert RECORD_PT_MAX == 4171                              # R2-8
    # Cross-check the hand-written HKDF against the cryptography library's RFC 5869 HKDF.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    s, i, n = fixed("hkdf_xcheck_salt", 32), fixed("hkdf_xcheck_ikm", 32), fixed("hkdf_xcheck_info", 148)
    assert HKDF(hashes.SHA3_256(), 32, s, n).derive(i) == hkdf_sha3_256(s, i, n)

    out = {}
    out["meta"] = {
        "spec": "docs/plans/2026-10-05-connect-groups-bytes.md items 1-7 as amended by REV 2",
        "approval": "docs/plans/decisions/2026-10-05-groups-apt-bytes-approved.md",
        "generator": "web-wallet/test/fixtures/groups_oracle.py",
        "regenerate": "python3 web-wallet/test/fixtures/groups_oracle.py",
        "label": "self-consistency vectors from the spec text (independent oracle, not an audit)",
        "encoding": "all byte strings are lowercase hex; integers big-endian",
        "fixed_input_derivation": "fixed(label, n) = SHAKE-256(\"NDS-groups-oracle-v1/\" || label)[0:n]; "
                                  "every *_label field names the label used",
        "kem": "ML-KEM-1024 not available in Python: (ss, kem_ct) per member are fixed test inputs; "
               "a C test that wants a real encapsulation must use these as given, not compare its own",
        "signatures": "ML-DSA-87 not available in Python and randomized anyway: compare *preimage* fields "
                      "byte-for-byte; the 4,627-byte dummy_signature inside full structures is NOT a valid "
                      "signature and exists only to fix the layout",
        "test_only_fixed_nonce": "every GCM nonce here is fixed for vectors only; production nonces are random",
        "dummy_signature_label": "dummy-signature-NOT-VALID-ML-DSA-87",
        "dummy_signature": hx(DUMMY_SIG),
    }

    out["tags"] = [{"name": n, "bytes": hx(tag(n))} for n in TAG_NAMES]

    # --- the group ----------------------------------------------------------
    group_id = fixed("group_id", GID_LEN)
    owner_fp = fixed("owner_fp", FP_LEN)
    addr_secret = fixed("addr_secret", 32)
    name = "Kurultay çay grubu".encode("utf-8")    # non-ASCII UTF-8 on purpose
    created_at_ms = 1_791_158_400_000                    # 2026-10-05T00:00:00Z
    versions = {1: 1, 2: 2, 3: 64}                       # v -> member count

    group_keys = {v: fixed("group_key_v%d" % v, 32) for v in versions}
    salts = {v: salt_v(group_id, group_keys[v], v) for v in versions}

    # Member fingerprints: owner + member_01..member_63.
    other_fps = [fixed("member_fp_%02d" % i, FP_LEN) for i in range(1, MAX_MEMBERS)]

    out["inputs"] = {
        "group_id_label": "group_id", "group_id": hx(group_id),
        "owner_fp_label": "owner_fp", "owner_fp": hx(owner_fp),
        "addr_secret_label": "addr_secret", "addr_secret": hx(addr_secret),
        "group_name_utf8": hx(name),
        "created_at_ms": created_at_ms,
        "group_keys": [{"v": v, "label": "group_key_v%d" % v, "group_key": hx(group_keys[v])}
                       for v in versions],
        "member_fp_label_pattern": "member_fp_NN (NN = 01..63, two digits)",
    }

    # --- salt_v ---------------------------------------------------------------
    out["salt_v"] = [{
        "group_id": hx(group_id), "v": v, "group_key": hx(group_keys[v]),
        "hkdf_salt": hx(group_id), "hkdf_ikm": hx(group_keys[v]),
        "hkdf_info": hx(tag("NDS.GSALT.v1") + u32(v)),
        "salt_v": hx(salts[v]),
    } for v in versions]

    # --- §1 addresses -------------------------------------------------------
    addrs = []
    def add_addr(purpose, name_, secret, x, v_note):
        pre = tag("NDS.GADDR.v1") + u8(purpose) + group_id + secret + u64(x)
        k = dht_addr(purpose, group_id, secret, x)
        addrs.append({"purpose": purpose, "purpose_name": name_, "secret_is": v_note,
                      "secret": hx(secret), "x": x, "preimage": hx(pre),
                      "K": hx(k), "key_string": dht_key_string(k)})
    add_addr(PURPOSE_HEAD, "HEAD", addr_secret, 0, "addr_secret")
    for v in versions:
        add_addr(PURPOSE_KEY_PACKET, "KEY_PACKET", addr_secret, v, "addr_secret")
    for v in versions:
        add_addr(PURPOSE_RECORD, "RECORD", salts[v], v, "salt_v (v=%d)" % v)
    msg_ts = created_at_ms + 12 * 3600 * 1000 + 34 * 60 * 1000 + 56_789
    msg_day = day_of(msg_ts)
    add_addr(PURPOSE_OUTBOX, "OUTBOX", salts[2], msg_day, "salt_v (v=2)")
    add_addr(PURPOSE_OUTBOX, "OUTBOX", salts[2], 0xFFFFFFFF, "salt_v (v=2), max u32 day")
    out["addresses"] = addrs

    # --- KEK / wrap single vector -------------------------------------------
    m1 = other_fps[0]
    ss_single = fixed("kek_vector_ss", SS_LEN)
    kek_single = kek(ss_single, group_id, 2, m1, owner_fp)
    out["kek_wrap"] = [{
        "ss_label": "kek_vector_ss", "ss": hx(ss_single), "v": 2,
        "group_id": hx(group_id), "member_fp": hx(m1), "owner_fp": hx(owner_fp),
        "group_key": hx(group_keys[2]),
        "hkdf_salt": hx(group_id),
        "hkdf_info": hx(tag("NDS.GKEK.v1") + u32(2) + m1 + owner_fp),
        "kek": hx(kek_single),
        "wrapped": hx(aes_key_wrap(kek_single, group_keys[2])),
    }]

    # --- per version: record, packet, HEAD ---------------------------------
    records = {}
    packets = {}
    kp_list = []
    rec_list = []
    head_list = []
    prev_digest = b"\x00" * 64
    member_ss = {}      # (v, fp) -> ss ; kem_ct -> ss for trial decap
    ct_to_ss = {}
    for v, n in versions.items():
        members = sorted([owner_fp] + other_fps[:n - 1])
        assert len(set(members)) == n
        pt = record_plaintext(name, members, created_at_ms)
        nonce = fixed("record_nonce_v%d" % v, NONCE_LEN)
        rec = record_value(group_keys[v], group_id, v, nonce, pt)
        rdig = sha3_512(rec["value"])
        assert parse_record_value(rec["value"], group_keys[v])["members"] == members
        records[v] = {"rec": rec, "digest": rdig, "members": members, "pt": pt}
        rec_list.append({
            "v": v, "count": n, "group_key": hx(group_keys[v]),
            "nonce_label": "record_nonce_v%d" % v, "nonce": hx(nonce),
            "plaintext": hx(pt), "aad": hx(rec["aad"]),
            "ct_len": len(rec["ct"]), "gcm_tag": hx(rec["gcm_tag"]),
            "value": hx(rec["value"]), "record_digest": hx(rdig),
            "address_key_string": dht_key_string(dht_addr(PURPOSE_RECORD, group_id, salts[v], v)),
        })

        member_rows = []
        entries = []
        for fp in members:
            idx = "owner" if fp == owner_fp else "%02d" % (other_fps.index(fp) + 1)
            ss = fixed("ss_v%d_%s" % (v, idx), SS_LEN)
            ct = fixed("kem_ct_v%d_%s" % (v, idx), KEM_CT_LEN)
            k = kek(ss, group_id, v, fp, owner_fp)
            w = aes_key_wrap(k, group_keys[v])
            assert aes_key_unwrap(k, w) == group_keys[v]
            ct_to_ss[ct] = ss
            member_ss[(v, fp)] = ss
            entries.append((ct, w, fp, ss, k, idx))
        entries.sort(key=lambda e: e[0])     # kem_ct ascending, unsigned bytewise
        assert len(set(e[0] for e in entries)) == n
        issued = created_at_ms + v * 60_000
        hdr = kp_header(group_id, owner_fp, v, prev_digest, rdig, issued, n)
        ent_bytes = [e[0] + e[1] for e in entries]
        pre = kp_preimage(hdr, ent_bytes)
        full = with_sig(pre)
        kdig = sha3_512(pre)                 # R2-2: bytes BEFORE sig_len
        assert parse_kp(full)["preimage"] == pre
        assert len(full) == 254 + n * ENTRY_LEN + 2 + SIG_LEN
        # trial-unwrap check for every member
        for fp in members:
            assert find_own_entry(full, group_id, v, fp, owner_fp,
                                  lambda c: ct_to_ss.get(c)) == group_keys[v]
        for pos, e in enumerate(entries):
            row = {"entry_index": pos, "member": e[5], "member_fp": hx(e[2]),
                   "ss_label": "ss_v%d_%s" % (v, e[5]), "ss": hx(e[3]),
                   "kem_ct_label": "kem_ct_v%d_%s" % (v, e[5]),
                   "kem_ct_offset_in_packet": 254 + pos * ENTRY_LEN,
                   "kek": hx(e[4]), "wrapped": hx(e[1])}
            if n <= 2:
                row["kem_ct"] = hx(e[0])
            member_rows.append(row)
        packets[v] = {"full": full, "pre": pre, "digest": kdig, "entries": entries, "hdr": hdr}
        kp_list.append({
            "v": v, "count": n, "issued_at_ms": issued,
            "prev_digest": hx(prev_digest), "record_digest": hx(rdig),
            "header": hx(hdr), "entries": member_rows,
            "signed_preimage": hx(pre), "digest": hx(kdig),
            "sig_len": SIG_LEN, "full_with_dummy_signature": hx(full),
            "full_length": len(full),
            "address_key_string": dht_key_string(dht_addr(PURPOSE_KEY_PACKET, group_id, addr_secret, v)),
        })

        hpre = head_preimage(group_id, owner_fp, v, kdig, issued)
        hfull = with_sig(hpre)
        assert parse_head(hfull) == hpre
        head_list.append({
            "v": v, "kp_digest_of_packet_v": v, "kp_digest": hx(kdig), "issued_at_ms": issued,
            "signed_preimage": hx(hpre), "full_with_dummy_signature": hx(hfull),
            "full_length": len(hfull),
            "address_key_string": dht_key_string(dht_addr(PURPOSE_HEAD, group_id, addr_secret, 0)),
        })
        prev_digest = kdig

    out["key_packets"] = kp_list
    out["records"] = rec_list
    out["heads"] = head_list

    # --- §5 messages / buckets ---------------------------------------------
    msgs = []
    sender = other_fps[0]                    # member of v=2 (owner + member_01)
    assert sender in records[2]["members"]
    texts = ["Merhaba grup — ilk mesaj".encode("utf-8"), b""]
    for i, text in enumerate(texts):
        mid = fixed("message_id_%d" % i, 16)
        nonce = fixed("message_nonce_%d" % i, NONCE_LEN)
        ts = msg_ts + i * 1000
        m = message(group_keys[2], group_id, 2, sender, mid, ts, nonce, text)
        assert m["day"] == msg_day
        assert gcm_decrypt(group_keys[2], m["H"][-12:], m["aad"], m["ct"], m["gcm_tag"]) == text
        msgs.append(m)
        out.setdefault("messages", []).append({
            "group_key_v": 2, "v": 2, "sender_fp": hx(sender),
            "message_id_label": "message_id_%d" % i, "message_id": hx(mid),
            "timestamp_ms": ts, "day": m["day"],
            "nonce_label": "message_nonce_%d" % i, "nonce": hx(nonce),
            "text_utf8": hx(text),
            "H": hx(m["H"]), "aad": hx(m["aad"]),
            "ct": hx(m["ct"]), "gcm_tag": hx(m["gcm_tag"]),
            "signed_preimage": hx(m["signed_preimage"]),
            "item_with_dummy_signature": hx(m["item"]),
        })
    out["buckets"] = [
        {"items": [0], "address_key_string":
            dht_key_string(dht_addr(PURPOSE_OUTBOX, group_id, salts[2], msg_day)),
         "bytes": hx(bucket([msgs[0]["item"]]))},
        {"items": [0, 1], "address_key_string":
            dht_key_string(dht_addr(PURPOSE_OUTBOX, group_id, salts[2], msg_day)),
         "bytes": hx(bucket([msgs[0]["item"], msgs[1]["item"]]))},
    ]

    # --- day edges ------------------------------------------------------------
    max_ok = (1 << 32) * MS_PER_DAY - 1
    edges = []
    for ts, note in [(0, "epoch"), (MS_PER_DAY - 1, "last ms of day 0"),
                     (MS_PER_DAY, "first ms of day 1"), (msg_ts, "vector message"),
                     (max_ok, "largest timestamp whose day fits u32"),
                     (max_ok + 1, "day = 2^32: does not fit u32 -> refuse"),
                     ((1 << 64) - 1, "u64 max -> refuse")]:
        d = day_of(ts)
        # timestamps above 2^53 do not survive JSON.parse as numbers: decimal string + BE64 hex
        edges.append({"timestamp_ms": str(ts), "timestamp_be64": hx(u64(ts)), "note": note,
                      "day": d, "valid": d is not None,
                      "day_be32": hx(u32(d)) if d is not None else None})
    out["day_edges"] = edges

    # --- §7 JSON ----------------------------------------------------------------
    invite_id = fixed("invite_id", 16)
    def cj(o):
        return json.dumps(o, separators=(",", ":"), ensure_ascii=False)
    invite = {"type": "nodus_group_invite", "v": 1, "group_id": hx(group_id),
              "owner": hx(owner_fp), "name": name.decode("utf-8"), "invite_id": hx(invite_id)}
    accept = {"type": "nodus_group_accept", "v": 1, "group_id": hx(group_id),
              "invite_id": hx(invite_id)}
    welcome = {"type": "nodus_group_welcome", "v": 1, "group_id": hx(group_id),
               "owner": hx(owner_fp), "addr_secret": hx(addr_secret), "key_version": 2,
               "kp_digest": hx(packets[2]["digest"]), "invite_id": hx(invite_id)}
    out["json_1to1"] = {
        "invite_id_label": "invite_id", "invite_id": hx(invite_id),
        "invite": cj(invite), "invite_utf8": hx(cj(invite).encode("utf-8")),
        "accept": cj(accept), "accept_utf8": hx(cj(accept).encode("utf-8")),
        "welcome": cj(welcome), "welcome_utf8": hx(cj(welcome).encode("utf-8")),
        "welcome_binds": "key_version 2, kp_digest = key_packets[v=2].digest",
    }

    # --- reject cases -----------------------------------------------------------
    rej = []
    p2 = packets[2]
    gk2 = group_keys[2]

    # 1a. packet count field says 3 but 2 entries present
    hdr_bad = p2["hdr"][:252] + u16(3)
    b = with_sig(hdr_bad + b"".join(e[0] + e[1] for e in p2["entries"]))
    rej.append({"id": "kp_count_field_vs_entries",
                "description": "key packet count field = 3, only 2 entries present (fixed-offset parse lands "
                               "sig_len inside the signature area) -> refuse before any allocation/decap",
                "oracle_refusal": expect_refuse(parse_kp, b), "bytes": hx(b)})

    # 1b. packet count (2) vs record count: packet v=2 bound to a 1-member record
    rec_one = record_value(gk2, group_id, 2, fixed("reject_record_nonce_1b", NONCE_LEN),
                           record_plaintext(name, [owner_fp], created_at_ms))
    hdr_1b = kp_header(group_id, owner_fp, 2, packets[1]["digest"], sha3_512(rec_one["value"]),
                       created_at_ms + 120_000, 2)
    b_kp = with_sig(kp_preimage(hdr_1b, [e[0] + e[1] for e in p2["entries"]]))
    parse_kp(b_kp)
    rc = parse_record_value(rec_one["value"], gk2)["count"]
    assert rc != 2
    rej.append({"id": "kp_count_vs_record_count",
                "description": "packet (count 2) whose record_digest binds a record with count 1; each is "
                               "well-formed alone, the reader must refuse because record count != packet count "
                               "(§3; R2-3 entries exactly the record's members)",
                "oracle_refusal": "record count 1 != packet count 2",
                "packet_bytes": hx(b_kp), "record_bytes": hx(rec_one["value"]),
                "record_digest": hx(sha3_512(rec_one["value"])), "group_key": hx(gk2)})

    # 1c. record plaintext count field vs fps present
    pt_bad = u8(len(name)) + name + u16(3) + b"".join(records[2]["members"]) + u64(created_at_ms)
    rb = record_value(gk2, group_id, 2, fixed("reject_record_nonce_1c", NONCE_LEN), pt_bad)
    rej.append({"id": "record_count_field_vs_members",
                "description": "record plaintext count = 3, 2 fingerprints present -> refuse (exact length)",
                "oracle_refusal": expect_refuse(parse_record_value, rb["value"], gk2),
                "plaintext": hx(pt_bad), "bytes": hx(rb["value"]), "group_key": hx(gk2)})

    # 2a. duplicate member in record
    dup = [owner_fp, owner_fp] if owner_fp < m1 else [m1, m1]
    pt_dup = record_plaintext(name, dup, created_at_ms)
    rd = record_value(gk2, group_id, 2, fixed("reject_record_nonce_2a", NONCE_LEN), pt_dup)
    rej.append({"id": "record_duplicate_member",
                "description": "record lists the same member fingerprint twice -> refuse",
                "oracle_refusal": expect_refuse(parse_record_value, rd["value"], gk2),
                "plaintext": hx(pt_dup), "bytes": hx(rd["value"]), "group_key": hx(gk2)})

    # 2b. duplicate kem_ct in packet
    e0 = p2["entries"][0]
    b = with_sig(kp_preimage(p2["hdr"], [e0[0] + e0[1], e0[0] + e0[1]]))
    rej.append({"id": "kp_duplicate_kem_ct",
                "description": "key packet with two entries carrying the same kem_ct -> refuse (R2-1 unique)",
                "oracle_refusal": expect_refuse(parse_kp, b), "bytes": hx(b)})

    # 3. trailing byte
    b = p2["full"] + b"\x00"
    rej.append({"id": "kp_trailing_byte", "description": "valid v=2 key packet + one 0x00 byte -> refuse",
                "oracle_refusal": expect_refuse(parse_kp, b), "bytes": hx(b)})
    h2 = with_sig(head_preimage(group_id, owner_fp, 2, p2["digest"], created_at_ms + 120_000))
    b = h2 + b"\x00"
    rej.append({"id": "head_trailing_byte", "description": "valid v=2 HEAD + one 0x00 byte -> refuse (R2-4)",
                "oracle_refusal": expect_refuse(parse_head, b), "bytes": hx(b)})
    b = records[2]["rec"]["value"] + b"\x00"
    rej.append({"id": "record_trailing_byte", "description": "valid v=2 record + one 0x00 byte -> refuse",
                "oracle_refusal": expect_refuse(parse_record_value, b, gk2), "bytes": hx(b),
                "group_key": hx(gk2)})

    # 4. wrong sig_len
    b = head_preimage(group_id, owner_fp, 2, p2["digest"], created_at_ms + 120_000) + u16(4626) + DUMMY_SIG[:4626]
    rej.append({"id": "head_sig_len_4626",
                "description": "HEAD with sig_len = 4626 and 4626 signature bytes -> refuse (R2-4: must be 4627)",
                "oracle_refusal": expect_refuse(parse_head, b), "bytes": hx(b)})
    b = p2["pre"] + u16(4626) + DUMMY_SIG[:4626]
    rej.append({"id": "kp_sig_len_4626",
                "description": "key packet with sig_len = 4626 -> refuse (§2 sig_len(2) = 4627)",
                "oracle_refusal": expect_refuse(parse_kp, b), "bytes": hx(b)})

    # 5. unwrap failure (tampered wrapped key)
    tgt = None
    for pos, e in enumerate(p2["entries"]):
        if e[2] == m1:
            tgt = (pos, e)
    pos, e = tgt
    w_bad = bytearray(e[1]); w_bad[0] ^= 0x01; w_bad = bytes(w_bad)
    ents = [x[0] + x[1] for x in p2["entries"]]
    ents[pos] = e[0] + w_bad
    b = with_sig(kp_preimage(p2["hdr"], ents))
    parse_kp(b)    # structurally valid
    try:
        aes_key_unwrap(e[4], w_bad)
        raise AssertionError("tampered wrap unwrapped")
    except InvalidUnwrap:
        pass
    refusal = expect_refuse(find_own_entry, b, group_id, 2, m1, owner_fp, lambda c: ct_to_ss.get(c))
    rej.append({"id": "kp_unwrap_failure",
                "description": "v=2 packet whose entry for member_01 has wrapped[0] ^= 0x01; structure valid, "
                               "the signature (if real) would no longer verify; for the unwrap path alone: "
                               "member_01 trial-unwraps every entry with its KEK, RFC 3394 integrity check "
                               "fails on all -> refuse",
                "member_fp": hx(m1), "ss": hx(e[3]), "kek": hx(e[4]),
                "tampered_entry_index": pos, "tampered_wrapped": hx(w_bad),
                "oracle_refusal": refusal, "bytes": hx(b)})

    # 6. record over the 4,171-byte cap
    pt_big = record_plaintext(b"N" * NAME_MAX, sorted([owner_fp] + other_fps), created_at_ms) + b"\x00"
    assert len(pt_big) == RECORD_PT_MAX + 1
    big = record_value(gk2, group_id, 2, fixed("reject_record_nonce_6", NONCE_LEN), pt_big)
    rej.append({"id": "record_over_cap",
                "description": "record with ct_len = 4,172 (plaintext = max-size 4,171-byte record + one byte), "
                               "correctly encrypted -> refuse on the ct_len field BEFORE decrypt/allocation (R2-8)",
                "ct_len": len(big["ct"]),
                "oracle_refusal": expect_refuse(parse_record_value, big["value"], gk2),
                "bytes": hx(big["value"]), "group_key": hx(gk2)})
    out["reject_cases"] = rej

    out["readings"] = READINGS
    return out


READINGS = [
    "Tags: every tag (NDS.GSALT.v1, NDS.GADDR.v1, NDS.GKP.v1, NDS.GKEK.v1, NDS.GREC.v1, NDS.GHEAD.v1, "
    "NDS.GMSG.v1, NDS.GBKT.v1) is the 16-byte 0x00-padded form wherever it appears, including inside the "
    "HKDF info strings and the GADDR hash preimage. Confirmed by the spec's own numbers: 254 (KP header), "
    "148 (KEK info), 52 (record AAD), 188 (HEAD) all require 16-byte tags.",
    "NDS.GMTAG.v1 is not emitted: R2-1 removed the lookup tag.",
    "HKDF-SHA3-256: RFC 5869 extract (PRK = HMAC-SHA3-256(key = salt, msg = ikm)) then one expand block "
    "(OKM = HMAC-SHA3-256(PRK, info || 0x01)), output 32 bytes. salt_v info = tag(16) || v(4) = 20 bytes; "
    "KEK info = tag(16) || v(4) || member_fp(64) || owner_fp(64) = 148 bytes; both with salt = group_id(32).",
    "AES-256 key wrap: RFC 3394 with the default IV A6A6A6A6A6A6A6A6 (aes_keywrap.h does not state the IV; "
    "assumed default).",
    "§1 x is 8 bytes big-endian: v for purposes 2 and 3, day (u32 value zero-extended) for purpose 4, 0 for "
    "purpose 1. DHT key string = \"ncg:\" + lowercase hex of the 64-byte K (132 ASCII chars). Any further "
    "hashing of the key string by the DHT layer (R2 note on nc_key_str) is outside this oracle.",
    "Entry order: kem_ct ascending by unsigned byte-wise (memcmp) comparison over all 1,568 bytes; equal "
    "kem_ct = duplicate = refuse. Record member order: same comparison on the 64-byte fingerprints.",
    "Key packet versions are chained in these vectors: v=1 (1 member, prev_digest = 64 zero bytes), v=2 "
    "(2 members, prev_digest = digest(KP v1)), v=3 (64 members, prev_digest = digest(KP v2)). Each packet's "
    "record_digest is the SHA3-512 of the record vector with the same v and count.",
    "digest(KP) = SHA3-512(every byte before sig_len) (R2-2, replacing §2's whole-packet digest); HEAD "
    "kp_digest and welcome kp_digest are that value. record_digest = SHA3-512 of the WHOLE record value "
    "(tag through gcm_tag) per §3 — R2 did not change it.",
    "HEAD issued_at_ms is set equal to the packet's issued_at_ms in these vectors (the spec does not relate them).",
    "Record value: ct_len(4) is the ciphertext length = plaintext length (GCM, no padding); the 4,171-byte cap "
    "(R2-8) is applied to the ct_len field before decryption and allocation. Over-cap vector uses ct_len = 4,172.",
    "Record plaintext count is 1..64 and must equal exactly the number of fingerprints present (exact "
    "consumption). name_len > 64 is refused. The name is not normalised (raw UTF-8 bytes).",
    "Packet count is 1..64 (§2). Parsing order in the oracle: count range -> sig_len at the offset implied by "
    "count -> exact total length -> entry uniqueness/order. A count larger than the entries present is "
    "refused because the fixed-offset sig_len no longer reads 4,627 or the length is not exact.",
    "Message: H = tag(16) || group_id(32) || v(4) || sender_fp(64) || message_id(16) || timestamp_ms(8) || "
    "day(4) || nonce(12) = 156 bytes; GCM AAD = first 144 bytes of H (R2-5); signed preimage = H || ct_len(4) "
    "|| ct || gcm_tag(16); item = preimage || sig_len(2) = 4627 || sig. Empty text (ct_len 0) is a valid item "
    "in these vectors; the spec sets only an upper bound (4,000 bytes).",
    "Bucket = tag(16) || count(2) || item x count; items carry their own lengths (ct_len, sig_len), parsed "
    "in sequence. Order of items inside the bucket is the order written (the spec sets none); the two-item "
    "vector has both items from the same sender and day.",
    "Day: day = floor(timestamp_ms / 86,400,000) over the u64 timestamp; a day that does not fit u32 "
    "(timestamp_ms >= 2^32 * 86,400,000) is refused. Largest valid timestamp = 2^32 * 86,400,000 - 1.",
    "JSON (§7 + R2-7): 'canonical' read as compact separators (',' ':'), no whitespace, key order exactly as "
    "the spec lists the fields, new R2-7 fields appended after them; UTF-8 not escaped; hex lowercase. "
    "invite = type, v, group_id, owner, name, invite_id; accept = type, v, group_id, invite_id; welcome = "
    "type, v, group_id, owner, addr_secret, key_version, kp_digest, invite_id. Field order where R2-7 does not "
    "fix a position is this oracle's choice; a parser must not depend on order. invite_id = 32 hex chars "
    "(16 bytes), group_id 64 hex, owner 128 hex, addr_secret 64 hex, kp_digest 128 hex; v and key_version "
    "JSON integers.",
    "Integers are unsigned big-endian everywhere (§ Reference: 'Integers BE'). In this JSON, day_edges "
    "timestamps are decimal strings plus BE64 hex because values above 2^53 lose precision in JSON.parse; "
    "every other integer here is below 2^53.",
    "KP issued_at_ms / record created_at_ms are opaque u64 milliseconds; the vectors use 2026-10-05T00:00:00Z "
    "= 1,791,158,400,000 plus offsets.",
]


def main():
    data = build()
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "groups_kat.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
