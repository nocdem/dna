#!/usr/bin/env python3
"""Independent reference oracle for the apt / QGP package-signing byte layouts.

Written from these sources ONLY:
  - docs/plans/2026-10-05-apt-qgp-signing-bytes.md, items 1-3 as amended by its
    "REV 2" section (REV 2 wins on conflict);
  - deb(5) (dpkg suite, read on the build machine);
  - /usr/include/ar.h (glibc struct ar_hdr) -- ar(5) is not installed on the build
    machine, so the ar header field widths come from ar.h;
  - shared/crypto/sign/qgp_dilithium.h for the ML-DSA-87 sizes
    (public key 2592 B, signature 4627 B).

No C implementation of these formats was read. This oracle is a self-consistency
check of the specification, NOT an external standard.

ML-DSA-87 is not available in Python. The oracle therefore:
  - emits the exact signed preimages (M_pkg 152 B, M_trust 216 B per REV 2 R2-3),
    which the C side must reproduce byte for byte;
  - puts a fixed DUMMY 4627-byte string into every signature slot. It is NOT an
    ML-DSA-87 signature; a real verifier must reject it. The C side verifies real
    signatures over the preimages instead of byte-comparing signatures (ML-DSA
    signing is randomized).
  - uses fixed DUMMY 2592-byte public keys (not valid ML-DSA-87 keys); fp = key_id =
    SHA3-512(pk).

Usage:
  python3 scripts/qgp-sign/qgp_deb_oracle.py            # (re)write qgp_deb_kat.json
  python3 scripts/qgp-sign/qgp_deb_oracle.py --check    # regenerate, compare to the file
  python3 scripts/qgp-sign/qgp_deb_oracle.py --make-payloads
      # prints how the pinned control.tar.gz / data.tar.xz constants below were made
      # (one-off; the KAT path never compresses anything, so it is library-independent)
"""

import hashlib
import json
import os
import sys

# ---------------------------------------------------------------------------
# Constants (spec section in brackets)
# ---------------------------------------------------------------------------

PK_LEN = 2592            # qgp_dilithium.h QGP_DSA87_PUBLICKEYBYTES
SIG_LEN = 4627           # qgp_dilithium.h QGP_DSA87_SIGNATURE_BYTES
HASH_LEN = 64            # SHA3-512

TAG_PKG = b"NDS.QGPDEB.v1".ljust(16, b"\x00")      # [1] 13 chars + 3 x 0x00
TAG_TRUST = b"NDS.QGPTRUST.v1".ljust(16, b"\x00")  # [2] 15 chars + 1 x 0x00
assert len(TAG_PKG) == 16 and len(TAG_TRUST) == 16

FORMAT_VERSION = 0x01
MEMBER_LEN = 1 + HASH_LEN + 8 + 2 + SIG_LEN         # [1] 4702
assert MEMBER_LEN == 4702

BODY_MAX = 64 * 1024                                # [R2-6] 65536, inclusive
TRUST_FIXED = 1 + 8 + HASH_LEN + 4                  # version, serial, signer, body_len

ARMAG = b"!<arch>\n"                                # ar.h ARMAG
ARFMAG = b"`\n"                                     # ar.h ARFMAG
AR_HDR_LEN = 16 + 12 + 6 + 6 + 8 + 10 + 2           # ar.h struct ar_hdr
assert AR_HDR_LEN == 60

QGP_NAME = "_qgp.sig"
CONTROL_NAMES = ("control.tar", "control.tar.gz", "control.tar.xz", "control.tar.zst")
DATA_NAMES = ("data.tar", "data.tar.gz", "data.tar.xz", "data.tar.zst",
              "data.tar.bz2", "data.tar.lzma")

ZERO64 = b"\x00" * HASH_LEN

KAT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qgp_deb_kat.json")


def sha3(b):
    return hashlib.sha3_512(b).digest()


def be(n, width):
    return n.to_bytes(width, "big")


def dummy_bytes(label, n):
    """Deterministic filler: SHA3-512(label || be32(i)) blocks, truncated to n."""
    out = b""
    i = 0
    while len(out) < n:
        out += sha3(label + be(i, 4))
        i += 1
    return out[:n]


DUMMY_SIG_LABEL = b"QGP-KAT/dummy-signature/v1"
DUMMY_SIG = dummy_bytes(DUMMY_SIG_LABEL, SIG_LEN)


def dummy_pk(i):
    return dummy_bytes(b"QGP-KAT/dummy-pk/K%d" % i, PK_LEN)


# ---------------------------------------------------------------------------
# Pinned member payloads (made once with --make-payloads; never recompressed)
# ---------------------------------------------------------------------------

DEBIAN_BINARY = b"2.0\n"
CONTROL_TAR_GZ = bytes.fromhex(           # 209 bytes: ODD, exercises the ar pad byte
    "1f8b0800000000000203edcdc14a033110c6f13de729f202ae1b5a141691160a1e446841bc87186a68d8"
    "6c67a73ebfe97a103ce8411484ff0fc20c932f99f6329441a5e4e6f774d5d57239d7ea73eddcf5473fcf"
    "9d5bb84563bbe60f9c26f552d74b29fa55eebbfb7f6aebc3c1ef636f8ffbf1e2e0d53c459952197aebda"
    "ceac25bc248d414f52233e67f3e0d3a0f544e9edee6e6befd78ff6a6be5ba5e1d5e7f47c6b36710a9246"
    "9d3f39478af890a3d538a91ddfd7b5a60100000000000000000000000000fcc81b7a3643f000280000"
)
DATA_TAR_XZ = bytes.fromhex(              # 200 bytes: even
    "fd377a585a0000016922de360200210116000000742fe5a3e027ff008b5d00170bcb2789f2ed37ed41d3"
    "a9b02718abc4ef5a85d8852253f9e704fa472f3b1a6c0d0b25f55d28d51f15e86ecba384b3ae7e2b71a3"
    "3e2c9c207f6baf954f79b3c2b835c29674920f088f01b03f81e0f3f53d7a2b6c95a8041372dc7a04a687"
    "81e0a59d4773ee6565fd84aa837ee8e6526e0e18ee91e70645b834560b3a8fee9de5a7f9cfb462a1bb89"
    "60000000823fda8c0001a30180500000a60658e03e300d8b020000000001595a"
)
DATA_TAR_GZ = bytes.fromhex(              # 153 bytes: ODD, its pad byte ends the prefix
    "1f8b0800000000000203edd13d0ec2300c86e1cc9c221780a410ba23d191a537b0daf0232a0592f4fea4"
    "2c480cb02004d2fb2c9f655bf2e085195334e928d19b3e74e67ab8cccf924ddb6cb6bb467d842d6ae7ee"
    "593ca7b5cbf5a39efa95abab95d2567dc198b2c4723e86905fedbd9bffa9f26f1da27483d7bd64d1fbd3"
    "e0670a00000000000000000000000000f0eb6e823fda8c00280000"
)
assert len(CONTROL_TAR_GZ) == 209 and len(DATA_TAR_XZ) == 200 and len(DATA_TAR_GZ) == 153


def make_payloads():
    import io
    import tarfile
    import gzip
    import lzma

    def mktar(name, data):
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w", format=tarfile.USTAR_FORMAT) as t:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 0
            ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            t.addfile(ti, io.BytesIO(data))
        return b.getvalue()

    # An .xz stream came out a multiple of 4 bytes in every trial (64/64 sizes tried), so the
    # odd-sized member that exercises the pad byte is control.tar.gz: the description line
    # is lengthened until the gzip output is odd.
    for extra in range(64):
        control = (b"Package: qgp-kat\nVersion: 1.0\nArchitecture: all\n"
                   b"Maintainer: QGP KAT <kat@invalid>\nDescription: QGP oracle test package"
                   + b"." * extra + b"\n")
        cg = gzip.compress(mktar("./control", control), compresslevel=9, mtime=0)
        if len(cg) % 2 == 1:
            break
    data = b"qgp oracle data file\n"
    dx = lzma.compress(mktar("./usr/share/doc/qgp-kat/README", data),
                       format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, preset=6)
    print("control.tar.gz len %d (extra=%d)\n%s" % (len(cg), extra, cg.hex()))
    print("data.tar.xz len %d\n%s" % (len(dx), dx.hex()))
    # second package: an ODD data member (data.tar.gz) so the pad byte that ends the prefix
    # is exercised
    for extra in range(64):
        dg = gzip.compress(mktar("./usr/share/doc/qgp-kat/README", data + b"." * extra),
                           compresslevel=9, mtime=0)
        if len(dg) % 2 == 1:
            break
    print("data.tar.gz len %d (extra=%d)\n%s" % (len(dg), extra, dg.hex()))


# ---------------------------------------------------------------------------
# ar writer
# ---------------------------------------------------------------------------

def ar_field(value, width):
    s = value.encode("ascii") if isinstance(value, str) else value
    assert len(s) <= width
    return s.ljust(width, b" ")


def ar_header(name, size, mtime="0", uid="0", gid="0", mode="100644", size_field=None):
    """Left-justified, space-padded ASCII fields (observed in a dpkg-deb-written .deb)."""
    h = (ar_field(name, 16) + ar_field(mtime, 12) + ar_field(uid, 6) + ar_field(gid, 6)
         + ar_field(mode, 8) + ar_field(size_field if size_field is not None else str(size), 10)
         + ARFMAG)
    assert len(h) == AR_HDR_LEN
    return h


QGP_HDR = ar_header(QGP_NAME, MEMBER_LEN)
assert QGP_HDR == b"_qgp.sig        0           0     0     100644  4702      `\n"


def ar_member(name, data, **kw):
    out = ar_header(name, len(data), **kw) + data
    if len(data) % 2 == 1:
        out += b"\n"
    return out


def build_ar(members, **kw):
    return ARMAG + b"".join(ar_member(n, d, **kw) for n, d in members)


BASE_MEMBERS = [("debian-binary", DEBIAN_BINARY),
                ("control.tar.gz", CONTROL_TAR_GZ),
                ("data.tar.xz", DATA_TAR_XZ)]


# ---------------------------------------------------------------------------
# [1] package signature
# ---------------------------------------------------------------------------

def m_pkg(key_id, prefix):
    m = TAG_PKG + key_id + be(len(prefix), 8) + sha3(prefix)
    assert len(m) == 152
    return m


def qgp_member(key_id, prefix_len, sig=DUMMY_SIG, version=FORMAT_VERSION, sig_len=SIG_LEN):
    m = bytes([version]) + key_id + be(prefix_len, 8) + be(sig_len, 2) + sig
    return m


def sign_deb(prefix, pk, sig=DUMMY_SIG):
    key_id = sha3(pk)
    member = qgp_member(key_id, len(prefix), sig)
    assert len(member) == MEMBER_LEN
    return prefix + QGP_HDR + member


class Reject(Exception):
    def __init__(self, reason):
        Exception.__init__(self, reason)
        self.reason = reason


def parse_size_field(field):
    # [R2-6] decimal digits only; reading R-AR-SIZE: 1..10 digits left-aligned, rest spaces
    s = field.rstrip(b" ")
    if len(s) == 0 or not all(0x30 <= c <= 0x39 for c in s):
        raise Reject("bad_size_field")
    return int(s)


def name_ok(field, allowed, slash_ok):
    for n in allowed:
        nb = n.encode("ascii")
        if field == nb.ljust(16, b" "):
            return True
        if slash_ok and field == (nb + b"/").ljust(16, b" "):
            return True
    return False


def verify_deb_layout(data, trust_state):
    """Layout verification of a signed .deb. Returns (M_pkg, key_id, sig).

    The ML-DSA-87 verification of sig over M_pkg against the pk pinned for key_id is
    the caller's (C side's) step; this oracle stops at the preimage.
    """
    if len(data) < len(ARMAG) or data[:len(ARMAG)] != ARMAG:
        raise Reject("bad_ar_magic")
    off = len(ARMAG)
    idx = 0
    qgp_off = None
    qgp_body = None
    positions = [(("debian-binary",), True),
                 (CONTROL_NAMES, True),
                 (DATA_NAMES, True)]
    while off < len(data):
        if idx >= 4:
            raise Reject("member_after_qgp_sig")
        if len(data) - off < AR_HDR_LEN:
            raise Reject("truncated_header")
        hdr = data[off:off + AR_HDR_LEN]
        if hdr[58:60] != ARFMAG:
            raise Reject("bad_fmag")
        size = parse_size_field(hdr[48:58])
        name = hdr[0:16]
        if idx < 3:
            allowed, slash_ok = positions[idx]
            if not name_ok(name, allowed, slash_ok):
                raise Reject("unexpected_member_name")
        else:
            if name != QGP_NAME.encode().ljust(16, b" "):
                raise Reject("unexpected_member_name")
            if hdr != QGP_HDR:
                raise Reject("qgp_sig_header_not_exact")
        start = off + AR_HDR_LEN
        end = start + size
        if end > len(data):
            raise Reject("truncated_member")
        if size % 2 == 1:
            if end >= len(data) or data[end] != 0x0A:
                raise Reject("bad_or_missing_padding")
            nxt = end + 1
        else:
            nxt = end
        if idx == 3:
            qgp_off = off
            qgp_body = data[start:end]
        off = nxt
        idx += 1
    if idx < 4:
        raise Reject("missing_member")
    # [R2-6] version first, before any other parse of the member content
    if qgp_body[0] != FORMAT_VERSION:
        raise Reject("member_version")
    key_id = qgp_body[1:65]
    prefix_len = int.from_bytes(qgp_body[65:73], "big")
    sig_len = int.from_bytes(qgp_body[73:75], "big")
    if sig_len != SIG_LEN:
        raise Reject("sig_len")
    sig = qgp_body[75:]
    prefix = data[:qgp_off]
    if prefix_len != len(prefix):
        raise Reject("prefix_len_mismatch")
    if key_id in trust_state["revoked"]:
        raise Reject("revoked_key")
    if key_id not in trust_state["keys"]:
        raise Reject("unknown_key")
    return m_pkg(key_id, prefix), key_id, sig


# ---------------------------------------------------------------------------
# [2] trust state
# ---------------------------------------------------------------------------

HEX = set(b"0123456789abcdef")


def is_lower_hex(tok, n):
    return len(tok) == n and all(c in HEX for c in tok)


def version_key(v):
    """Deliberately MINIMAL comparator: dot-separated decimal integers only.

    The full Debian version comparison is the C side's obligation; the vectors use
    only versions such as 0.9 / 1.0 / 1.1 where no comparison rule can disagree.
    Anything else raises, so a vector can never depend on an unimplemented rule.
    """
    parts = v.split(b".")
    if not parts or not all(p and all(0x30 <= c <= 0x39 for c in p) for p in parts):
        raise ValueError("oracle comparator: version outside its scope: %r" % v)
    return tuple(int(p) for p in parts)


def parse_body(body):
    """Canonical-body check [2] + [R2-1] + [R2-6]. Returns the parsed state."""
    if len(body) > BODY_MAX:
        raise Reject("body_too_large")
    for c in body:
        if c != 0x0A and not (0x20 <= c <= 0x7E):
            raise Reject("non_printable_ascii_byte")   # catches CR (CRLF), TAB, NUL, non-ASCII
    if len(body) == 0 or body[-1] != 0x0A:
        raise Reject("missing_final_lf")
    lines = body[:-1].split(b"\n")
    keys = {}
    revoked = set()
    floors = {}
    for ln in lines:
        if ln == b"":
            raise Reject("blank_line")
        if ln.endswith(b" "):
            raise Reject("trailing_space")
        toks = ln.split(b" ")
        if any(t == b"" for t in toks):
            raise Reject("bad_field_separator")
        kind = toks[0]
        if kind == b"key":
            if len(toks) != 3:
                raise Reject("bad_field_count")
            fp, pkh = toks[1], toks[2]
            if not is_lower_hex(fp, 2 * HASH_LEN):
                raise Reject("bad_fingerprint_hex")
            if not is_lower_hex(pkh, 2 * PK_LEN):
                raise Reject("bad_pk_hex_or_length")
            pk = bytes.fromhex(pkh.decode())
            if sha3(pk) != bytes.fromhex(fp.decode()):
                raise Reject("key_fp_mismatch")
        elif kind == b"revoked":
            if len(toks) != 2:
                raise Reject("bad_field_count")
            if not is_lower_hex(toks[1], 2 * HASH_LEN):
                raise Reject("bad_fingerprint_hex")
        elif kind == b"floor":
            if len(toks) != 3:
                raise Reject("bad_field_count")
        else:
            raise Reject("unknown_record_type")
    if len(set(lines)) != len(lines):
        raise Reject("duplicate_line")
    if lines != sorted(lines):
        raise Reject("unsorted")
    for ln in lines:
        toks = ln.split(b" ")
        if toks[0] == b"key":
            fp = bytes.fromhex(toks[1].decode())
            if fp in keys:
                raise Reject("duplicate_key_fp")
            keys[fp] = bytes.fromhex(toks[2].decode())
        elif toks[0] == b"revoked":
            revoked.add(bytes.fromhex(toks[1].decode()))
        else:
            if toks[1] in floors:
                raise Reject("duplicate_floor")
            floors[toks[1]] = toks[2]
    if set(keys) & revoked:
        raise Reject("key_and_revoked")
    if not keys:
        raise Reject("no_key")
    # [R2-6] re-canonicalise and compare (redundant after the explicit checks above)
    assert b"".join(l + b"\n" for l in sorted(set(lines))) == body
    return {"keys": keys, "revoked": revoked, "floors": floors}


def m_trust(serial, prev_digest, signer, body):
    m = TAG_TRUST + be(serial, 8) + prev_digest + signer + sha3(body)
    assert len(m) == 216
    return m


def trust_file(serial, signer, body, sig=DUMMY_SIG, version=FORMAT_VERSION, sig_len=SIG_LEN,
               body_len=None):
    return (bytes([version]) + be(serial, 8) + signer
            + be(len(body) if body_len is None else body_len, 4) + body
            + be(sig_len, 2) + sig)


def parse_trust_file(f):
    if len(f) < 1:
        raise Reject("file_length")
    if f[0] != FORMAT_VERSION:
        raise Reject("file_version")
    if len(f) < TRUST_FIXED:
        raise Reject("file_length")
    serial = int.from_bytes(f[1:9], "big")
    signer = f[9:73]
    body_len = int.from_bytes(f[73:77], "big")
    if body_len > BODY_MAX:
        raise Reject("body_too_large")
    if len(f) != TRUST_FIXED + body_len + 2 + SIG_LEN:
        raise Reject("file_length")
    body = f[77:77 + body_len]
    sig_len = int.from_bytes(f[77 + body_len:79 + body_len], "big")
    if sig_len != SIG_LEN:
        raise Reject("sig_len")
    sig = f[79 + body_len:]
    state = parse_body(body)
    return serial, signer, body, sig, state


def accept_trust(f, stored):
    """stored = None (bootstrap) or dict(serial, file, state).

    Returns (M_trust the verifier verifies, new stored dict). The ML-DSA-87 check of
    sig over M_trust against the signer's pinned pk is the caller's step.
    """
    serial, signer, body, sig, state = parse_trust_file(f)
    if stored is None:
        # reading R-BOOT: hand-checked bootstrap; signer must be an unrevoked key of its own body
        if signer not in state["keys"]:
            raise Reject("signer_not_trusted")
        prev = ZERO64
    else:
        old = stored["state"]
        if serial <= stored["serial"]:
            raise Reject("serial_not_increasing")
        if signer in old["revoked"]:
            raise Reject("signer_revoked")
        if signer not in old["keys"]:
            raise Reject("signer_not_trusted")
        for r in old["revoked"]:
            if r not in state["revoked"]:
                raise Reject("revocation_dropped")
        for pkg, v in old["floors"].items():
            if pkg not in state["floors"]:
                raise Reject("floor_dropped")
            if version_key(state["floors"][pkg]) < version_key(v):
                raise Reject("floor_lowered")
        prev = sha3(stored["file"])
    m = m_trust(serial, prev, signer, body)
    return m, {"serial": serial, "file": f, "state": state}


# ---------------------------------------------------------------------------
# KAT construction
# ---------------------------------------------------------------------------

def hexblob(b, limit=1 << 16):
    d = {"len": len(b), "sha3_512": sha3(b).hex()}
    if len(b) <= limit:
        d["hex"] = b.hex()
    return d


def key_line(pk):
    return b"key " + sha3(pk).hex().encode() + b" " + pk.hex().encode()


def revoked_line(pk):
    return b"revoked " + sha3(pk).hex().encode()


def body_of(lines):
    return b"".join(l + b"\n" for l in sorted(lines))


def must_reject(fn, reason):
    try:
        fn()
    except Reject as e:
        if e.reason != reason:
            raise AssertionError("expected reject %s, got %s" % (reason, e.reason))
        return
    raise AssertionError("expected reject %s, got accept" % reason)


def build_kat():
    K = {i: dummy_pk(i) for i in range(1, 13)}
    FP = {i: sha3(K[i]) for i in K}

    kat = {
        "meta": {
            "title": "apt/QGP package-signing byte layouts - independent oracle KAT",
            "spec": "docs/plans/2026-10-05-apt-qgp-signing-bytes.md items 1-3 as amended by REV 2 "
                    "(R2-1..R2-7)",
            "approval": "docs/plans/decisions/2026-10-05-groups-apt-bytes-approved.md",
            "container_refs": ["deb(5) dpkg 1.21.23",
                               "/usr/include/ar.h (glibc struct ar_hdr; ar(5) not installed)"],
            "generator": "scripts/qgp-sign/qgp_deb_oracle.py",
            "label": "self-consistency vectors of the specification, not an external standard",
            "signature_policy": "every signature slot holds DUMMY_SIG (not ML-DSA-87). Compare "
                                "preimages (M_pkg, M_trust) and all non-signature bytes; verify "
                                "real signatures, never byte-compare them (randomized ML-DSA).",
            "hex_policy": "binary blobs give len + sha3_512, plus hex when len <= 65536",
        },
        "constants": {
            "tag_pkg_hex": TAG_PKG.hex(),
            "tag_trust_hex": TAG_TRUST.hex(),
            "pk_len": PK_LEN, "sig_len": SIG_LEN, "member_len": MEMBER_LEN,
            "body_max": BODY_MAX, "m_pkg_len": 152, "m_trust_len": 216,
            "qgp_sig_ar_header_hex": QGP_HDR.hex(),
            "qgp_sig_ar_header_ascii": QGP_HDR.decode("ascii"),
        },
        "dummy": {
            "signature": {"derivation": "concat_i SHA3-512(%r || be32(i)) truncated to 4627"
                                        % DUMMY_SIG_LABEL.decode(),
                          "label": "DUMMY - not an ML-DSA-87 signature",
                          **hexblob(DUMMY_SIG)},
            "public_keys": {
                "derivation": "K<i> = concat_j SHA3-512('QGP-KAT/dummy-pk/K<i>' || be32(j)) "
                              "truncated to 2592; fp = key_id = SHA3-512(pk)",
                "label": "DUMMY - not valid ML-DSA-87 public keys",
                "keys": {"K%d" % i: {"pk_hex": K[i].hex(), "fp": FP[i].hex()} for i in K},
            },
        },
    }

    # ---------------- trust chain (needed first: the package is checked against it) -------
    floor_10 = b"floor qgp-kat 1.0"
    floor_11 = b"floor qgp-kat 1.1"
    b1 = body_of([key_line(K[1])])
    b2 = body_of([key_line(K[1]), key_line(K[2]), floor_10])
    b3 = body_of([key_line(K[2]), revoked_line(K[1]), floor_11])
    f1 = trust_file(1, FP[1], b1)
    f2 = trust_file(2, FP[1], b2)
    f3 = trust_file(3, FP[2], b3)
    m1, s1 = accept_trust(f1, None)
    m2, s2 = accept_trust(f2, s1)
    m3, s3 = accept_trust(f3, s2)
    chain = []
    for n, (f, b, m, ser, signer, prev) in enumerate([
            (f1, b1, m1, 1, "K1", ZERO64),
            (f2, b2, m2, 2, "K1", sha3(f1)),
            (f3, b3, m3, 3, "K2", sha3(f2))], 1):
        assert m[24:88] == prev
        chain.append({
            "name": "trust_file_%d" % n,
            "serial": ser, "signer": signer, "signer_key_id": f[9:73].hex(),
            "prev_digest": prev.hex(),
            "prev_digest_is": "zeros (first file)" if n == 1 else
                              "SHA3-512 of trust_file_%d file bytes" % (n - 1),
            "verified_against": "bootstrap (no stored state)" if n == 1 else
                                "stored state = trust_file_%d" % (n - 1),
            "body": b.decode("ascii"), "body_len": len(b), "body_sha3_512": sha3(b).hex(),
            "M_trust_hex": m.hex(),
            "file": hexblob(f),
            "file_layout": "version(1)=01 | serial(8,BE) | signer key_id(64) | body_len(4,BE) | "
                           "body | sig_len(2,BE)=4627 | sig(4627, DUMMY)",
        })
    kat["trust_chain"] = chain

    # ---------------- trust accept extras ---------------------------------------------------
    trust_accept = []
    # boundary: body exactly 65536 bytes (12 key lines + 1 floor with a long package name)
    keys12 = [key_line(K[i]) for i in range(1, 13)]
    base_len = sum(len(l) + 1 for l in keys12)
    name_len = BODY_MAX - base_len - len(b"floor  1.0\n")
    b_max = body_of(keys12 + [b"floor " + b"a" * name_len + b" 1.0"])
    assert len(b_max) == BODY_MAX
    f_max = trust_file(1, FP[1], b_max)
    m_max, _ = accept_trust(f_max, None)
    trust_accept.append({
        "name": "body_exactly_64KiB_bootstrap",
        "construction": "bootstrap, serial 1, signer K1; body = key lines K1..K12 + "
                        "'floor ' + 'a'*%d + ' 1.0' (sorted); body_len = 65536" % name_len,
        "M_trust_hex": m_max.hex(), "body_len": len(b_max), "body_sha3_512": sha3(b_max).hex(),
        "file": hexblob(f_max, limit=0),
    })
    # self-revocation: K2 signs a file revoking K2 and keeping K3 (reading R-SELFREVOKE)
    b_sr = body_of([key_line(K[3]), revoked_line(K[1]), revoked_line(K[2]), floor_11])
    f_sr = trust_file(4, FP[2], b_sr)
    m_sr, _ = accept_trust(f_sr, s3)
    trust_accept.append({
        "name": "self_revocation_signed_by_revoked_key",
        "construction": "stored = trust_file_3; serial 4, signer K2; body = key K3, revoked K1, "
                        "revoked K2, floor qgp-kat 1.1",
        "M_trust_hex": m_sr.hex(), "body": b_sr.decode(), "file": hexblob(f_sr),
    })
    # new floor for a new package is allowed; serial gap allowed
    b_nf = body_of([key_line(K[2]), revoked_line(K[1]), floor_11, b"floor qgp-other 2.0"])
    f_nf = trust_file(9, FP[2], b_nf)
    m_nf, _ = accept_trust(f_nf, s3)
    trust_accept.append({
        "name": "serial_gap_and_new_floor",
        "construction": "stored = trust_file_3; serial 9 (gap), signer K2; adds floor qgp-other 2.0",
        "M_trust_hex": m_nf.hex(), "body": b_nf.decode(), "file": hexblob(f_nf),
    })
    kat["trust_accept"] = trust_accept

    # ---------------- package --------------------------------------------------------------
    trust_for_pkg = s3["state"]   # K2 trusted, K1 revoked

    def package_vector(member_list, note):
        pre = build_ar(member_list)
        full = sign_deb(pre, K[2])
        mpv, kidv, _ = verify_deb_layout(full, trust_for_pkg)
        mems = []
        o = len(ARMAG)
        for n, d in member_list:
            h = ar_header(n, len(d))
            mems.append({"name": n, "offset": o, "size": len(d), "padded": len(d) % 2 == 1,
                         "pad_offset": o + AR_HDR_LEN + len(d) if len(d) % 2 else None,
                         "header_ascii": h.decode("ascii"), "header_hex": h.hex(),
                         "data_hex": d.hex()})
            o += AR_HDR_LEN + len(d) + (len(d) % 2)
        assert o == len(pre)
        mem = qgp_member(kidv, len(pre))
        vec = {
            "trust_state": "trust_file_3 (K2 key, K1 revoked)",
            "signer": "K2", "key_id": kidv.hex(),
            "members": mems,
            "prefix": hexblob(pre), "prefix_len": len(pre),
            "prefix_len_be8_hex": be(len(pre), 8).hex(),
            "M_pkg_hex": mpv.hex(),
            "M_pkg_layout": "tag(16) | key_id(64) | prefix_len(8,BE) | SHA3-512(prefix)(64)",
            "qgp_sig_offset": len(pre),
            "qgp_sig_header_hex": QGP_HDR.hex(),
            "qgp_sig_member": hexblob(mem),
            "qgp_sig_member_layout": "version(1)=01 | key_id(64) | prefix_len(8,BE) | "
                                     "sig_len(2,BE)=4627 | sig(4627, DUMMY)",
            "full_deb": hexblob(full),
            "note": note,
        }
        return vec, pre, full, mems, mpv, kidv

    kat["package"], prefix, deb, members, mp, kid = package_vector(
        BASE_MEMBERS,
        "debian-binary (4, even) | control.tar.gz (209, ODD: one 0x0A pad byte inside the "
        "prefix) | data.tar.xz (200, even: the prefix ends at its last byte). Every .xz stream "
        "the payload generator produced was a multiple of 4 bytes, so the odd data member is in "
        "package_odd_data.")
    odd_members = [BASE_MEMBERS[0], BASE_MEMBERS[1], ("data.tar.gz", DATA_TAR_GZ)]
    kat["package_odd_data"], prefix_od, deb_od, members_od, _, _ = package_vector(
        odd_members,
        "debian-binary (4) | control.tar.gz (209, ODD, padded) | data.tar.gz (153, ODD): the "
        "prefix ENDS with the 0x0A pad byte of data.tar.gz.")
    assert prefix_od[-1] == 0x0A and len(DATA_TAR_GZ) % 2 == 1

    pkg_accept = []
    # variant: dpkg members with trailing '/' and non-zero mtime, uncompressed tar names
    pre_v = ARMAG + b"".join(
        ar_member(n + "/", d, mtime="1673995855") for n, d in
        [("debian-binary", DEBIAN_BINARY), ("control.tar.gz", CONTROL_TAR_GZ),
         ("data.tar.xz", DATA_TAR_XZ)])
    deb_v = sign_deb(pre_v, K[2])
    mp_v, _, _ = verify_deb_layout(deb_v, trust_for_pkg)
    pkg_accept.append({
        "name": "slash_names_nonzero_mtime",
        "construction": "base members, names written 'debian-binary/' 'control.tar.gz/' "
                        "'data.tar.xz/', mtime 1673995855 on the three dpkg members",
        "prefix_len": len(pre_v), "M_pkg_hex": mp_v.hex(), "full_deb": hexblob(deb_v),
    })
    pre_u = build_ar([("debian-binary", DEBIAN_BINARY), ("control.tar", b"C" * 7),
                      ("data.tar", b"D" * 9)])
    deb_u = sign_deb(pre_u, K[2])
    mp_u, _, _ = verify_deb_layout(deb_u, trust_for_pkg)
    pkg_accept.append({
        "name": "uncompressed_member_names_two_odd_members",
        "construction": "members debian-binary '2.0\\n', control.tar = 'C'*7, data.tar = 'D'*9 "
                        "(both odd, both padded; contents opaque to the ar layer)",
        "prefix_len": len(pre_u), "M_pkg_hex": mp_u.hex(), "full_deb": hexblob(deb_u),
    })
    kat["package_accept"] = pkg_accept

    # ---------------- package rejects ----------------------------------------------------
    pr = []

    def add_pkg_reject(name, data, reason, construction, ref, state=trust_for_pkg):
        must_reject(lambda: verify_deb_layout(data, state), reason)
        pr.append({"name": name, "construction": construction, "expected_reason": reason,
                   "spec_ref": ref, "bytes": hexblob(data)})

    q_off = len(prefix)
    data_off = members[2]["offset"]
    ctl_pad = members[1]["pad_offset"]          # pad byte after control.tar.gz (base package)
    od_pad = members_od[2]["pad_offset"]        # pad byte after data.tar.gz (last prefix byte)
    assert od_pad == len(prefix_od) - 1
    q_off_od = len(prefix_od)

    pre5 = prefix + ar_member("_extra", b"EXTRA!")
    add_pkg_reject("five_members_extra_before_qgp_sig", sign_deb(pre5, K[2]),
                   "unexpected_member_name",
                   "base three members + '_extra' (6 bytes) + _qgp.sig (prefix covers _extra)",
                   "§1 strict structure")
    add_pkg_reject("member_after_qgp_sig", deb + ar_member("_extra", b"EXTRA!"),
                   "member_after_qgp_sig", "full_deb + appended member '_extra' (6 bytes)",
                   "§1, R2-6 nothing after _qgp.sig")
    add_pkg_reject("second_qgp_sig", deb + QGP_HDR + qgp_member(kid, len(prefix)),
                   "member_after_qgp_sig", "full_deb + a second identical _qgp.sig member",
                   "§1 a second _qgp.sig")
    pre_r = build_ar([BASE_MEMBERS[0], BASE_MEMBERS[2], BASE_MEMBERS[1]])
    add_pkg_reject("reordered_data_before_control", sign_deb(pre_r, K[2]),
                   "unexpected_member_name", "members debian-binary, data.tar.xz, control.tar.gz",
                   "§1 order; deb(5)")
    pre_r2 = build_ar([BASE_MEMBERS[1], BASE_MEMBERS[0], BASE_MEMBERS[2]])
    add_pkg_reject("reordered_control_first", sign_deb(pre_r2, K[2]),
                   "unexpected_member_name", "members control.tar.gz, debian-binary, data.tar.xz",
                   "§1 order")
    add_pkg_reject("unsigned_three_members", prefix, "missing_member",
                   "the unsigned prefix alone (no _qgp.sig)", "§1 exactly four members")
    add_pkg_reject("truncated_qgp_header", deb[:q_off + 30], "truncated_header",
                   "full_deb cut 30 bytes into the _qgp.sig header", "R2-6 bounds")
    add_pkg_reject("truncated_qgp_member", deb[:-1], "truncated_member",
                   "full_deb without its last byte", "R2-6 member boundaries from size")
    bad = bytearray(deb)
    bad[data_off + 48:data_off + 58] = ar_field("2a9", 10)
    add_pkg_reject("non_digit_size", bytes(bad), "bad_size_field",
                   "full_deb with data.tar.xz size field replaced by '2a9' space-padded",
                   "R2-6 sizes decimal digits only")
    bad = bytearray(deb)
    bad[data_off + 48:data_off + 58] = b" " + str(len(DATA_TAR_XZ)).encode().ljust(9, b" ")
    add_pkg_reject("size_with_leading_space", bytes(bad), "bad_size_field",
                   "full_deb with data.tar.xz size field right-shifted by one leading space",
                   "R2-6; reading R-AR-SIZE")
    pl_off = q_off + AR_HDR_LEN + 1 + HASH_LEN
    wrong = bytearray(deb)
    wrong[pl_off:pl_off + 8] = be(len(prefix) + 1, 8)
    add_pkg_reject("wrong_prefix_len_plus_one", bytes(wrong), "prefix_len_mismatch",
                   "full_deb with member prefix_len = actual + 1", "§1 recompute prefix_len")
    pl_off_od = q_off_od + AR_HDR_LEN + 1 + HASH_LEN
    wrong = bytearray(deb_od)
    wrong[pl_off_od:pl_off_od + 8] = be(len(prefix_od) - 1, 8)
    add_pkg_reject("odd_data_prefix_len_excluding_pad", bytes(wrong), "prefix_len_mismatch",
                   "package_odd_data full_deb with member prefix_len = actual - 1 (as if the "
                   "data.tar.gz pad byte were not part of the prefix)",
                   "§1 prefix INCLUDES the data.tar pad byte")
    nopad = deb_od[:od_pad] + deb_od[od_pad + 1:]
    add_pkg_reject("odd_data_missing_padding_byte", nopad, "bad_or_missing_padding",
                   "package_odd_data full_deb with the 0x0A pad byte after data.tar.gz removed",
                   "§1 ar pads odd members; R2-6 exact sum incl. padding")
    pre_np = prefix_od[:od_pad]
    add_pkg_reject("odd_data_missing_padding_byte_resigned", sign_deb(pre_np, K[2]),
                   "bad_or_missing_padding",
                   "package_odd_data prefix without its final pad byte, then _qgp.sig computed "
                   "over that shorter prefix (prefix_len = actual - 1)", "§1; R2-6")
    nopad = deb[:ctl_pad] + deb[ctl_pad + 1:]
    add_pkg_reject("control_missing_padding_byte", nopad, "bad_or_missing_padding",
                   "full_deb with the 0x0A pad byte after control.tar.gz removed",
                   "§1; R2-6 exact sum incl. padding")
    badpad = bytearray(deb)
    badpad[ctl_pad] = 0x00
    add_pkg_reject("control_pad_byte_not_lf", bytes(badpad), "bad_or_missing_padding",
                   "full_deb with the pad byte after control.tar.gz set to 0x00", "§1 pad is '\\n'")
    badpad = bytearray(deb_od)
    badpad[od_pad] = 0x20
    add_pkg_reject("odd_data_pad_byte_space", bytes(badpad), "bad_or_missing_padding",
                   "package_odd_data full_deb with the data.tar.gz pad byte set to 0x20",
                   "§1 pad is '\\n'")
    v2 = bytearray(deb)
    v2[q_off + AR_HDR_LEN] = 0x02
    add_pkg_reject("member_version_2", bytes(v2), "member_version",
                   "full_deb with _qgp.sig version byte 0x02", "R2-6 version != 1")
    v0 = bytearray(deb)
    v0[q_off + AR_HDR_LEN] = 0x00
    add_pkg_reject("member_version_0", bytes(v0), "member_version",
                   "full_deb with _qgp.sig version byte 0x00", "R2-6 version != 1")
    sl = bytearray(deb)
    sl[pl_off + 8:pl_off + 10] = be(4626, 2)
    add_pkg_reject("sig_len_4626", bytes(sl), "sig_len",
                   "full_deb with sig_len field 4626 (member length unchanged)", "§1 sig_len=4627")
    hm = bytearray(deb)
    hm[q_off + 40:q_off + 48] = ar_field("100600", 8)
    add_pkg_reject("qgp_sig_mode_100600", bytes(hm), "qgp_sig_header_not_exact",
                   "full_deb with _qgp.sig header mode 100600", "§1 mode 100644; reading R-QGPHDR")
    hs = bytearray(deb)
    hs[q_off:q_off + 16] = ar_field("_qgp.sig/", 16)
    add_pkg_reject("qgp_sig_trailing_slash", bytes(hs), "unexpected_member_name",
                   "full_deb with _qgp.sig name written '_qgp.sig/'", "R2-6 no '/'")
    hf = bytearray(deb)
    hf[q_off + 58:q_off + 60] = b"`\x00"
    add_pkg_reject("bad_fmag", bytes(hf), "bad_fmag",
                   "full_deb with _qgp.sig ar_fmag bytes '`\\x00'", "ar.h ARFMAG")
    add_pkg_reject("bad_ar_magic", b"!<arch>\r" + deb[8:], "bad_ar_magic",
                   "full_deb with byte 7 = 0x0D", "deb(5) magic")
    add_pkg_reject("signed_by_revoked_key", sign_deb(prefix, K[1]), "revoked_key",
                   "prefix signed by K1 (revoked in trust_file_3)", "§1 key not revoked")
    add_pkg_reject("signed_by_unknown_key", sign_deb(prefix, K[3]), "unknown_key",
                   "prefix signed by K3 (absent from trust_file_3)", "§1 key in pinned state")
    kat["package_reject"] = pr

    # ---------------- trust rejects ------------------------------------------------------
    tr = []

    def add_trust_reject(name, f, reason, construction, ref, stored=s2, stored_name="trust_file_2",
                         full_hex=True):
        must_reject(lambda: accept_trust(f, stored), reason)
        tr.append({"name": name, "stored_state": stored_name, "construction": construction,
                   "expected_reason": reason, "spec_ref": ref,
                   "file": hexblob(f, limit=(1 << 16) if full_hex else 0)})

    def body_reject(name, body, reason, construction, ref):
        f = trust_file(3, FP[2], body)
        must_reject(lambda: parse_body(body), reason)
        add_trust_reject(name, f, reason, "serial 3, signer K2, body: " + construction, ref)
        tr[-1]["body_json"] = body.decode("latin-1")

    good3 = [key_line(K[2]), revoked_line(K[1]), floor_11]
    s_lines = sorted(good3)
    body_reject("body_unsorted", b"".join(l + b"\n" for l in reversed(s_lines)), "unsorted",
                "trust_file_3 body lines in reverse order", "§2 sorted bytewise")
    body_reject("body_blank_line", b"\n".join(s_lines[:1] + [b""] + s_lines[1:]) + b"\n",
                "blank_line", "trust_file_3 body with an empty line after the first",
                "R2-6 no blank lines")
    body_reject("body_duplicate_line", body_of(good3 + [floor_11]), "duplicate_line",
                "trust_file_3 body with 'floor qgp-kat 1.1' twice", "R2-6 no duplicates")
    body_reject("body_missing_final_lf", b3[:-1], "missing_final_lf",
                "trust_file_3 body without its final LF", "R2-6 one LF after every line")
    body_reject("body_crlf", b3.replace(b"\n", b"\r\n"), "non_printable_ascii_byte",
                "trust_file_3 body with CRLF line ends", "§2 LF line ends")
    body_reject("body_trailing_space", b3.replace(floor_11 + b"\n", floor_11 + b" \n"),
                "trailing_space", "trust_file_3 body, floor line ends in a space",
                "§2 no trailing spaces")
    body_reject("body_double_space", b3.replace(b"floor qgp-kat", b"floor  qgp-kat"),
                "bad_field_separator", "trust_file_3 body, floor line with two spaces",
                "reading R-SEP")
    body_reject("body_double_lf_at_end", b3 + b"\n", "blank_line",
                "trust_file_3 body + one extra LF", "R2-6 exactly one LF")
    body_reject("body_uppercase_fp",
                body_of([key_line(K[2]), b"revoked " + FP[1].hex().upper().encode(), floor_11]),
                "bad_fingerprint_hex", "revoked fp written in uppercase hex",
                "§2 128 hex lowercase")
    body_reject("body_short_pk",
                body_of([b"key " + FP[2].hex().encode() + b" " + K[2][:-1].hex().encode(),
                         revoked_line(K[1]), floor_11]),
                "bad_pk_hex_or_length", "key line for K2 with pk truncated to 2591 bytes",
                "R2-1 len(pk) = 2592")
    body_reject("body_key_without_pk",
                body_of([b"key " + FP[2].hex().encode(), revoked_line(K[1]), floor_11]),
                "bad_field_count", "fingerprint-only key line (pre-REV-2 form)", "R2-1")
    body_reject("body_key_fp_mismatch",
                body_of([b"key " + FP[2].hex().encode() + b" " + K[3].hex().encode(),
                         revoked_line(K[1]), floor_11]),
                "key_fp_mismatch", "key line carrying fp(K2) with pk K3",
                "R2-1 SHA3-512(pk) == fp")
    body_reject("body_key_and_revoked", body_of([key_line(K[2]), revoked_line(K[2]), floor_11]),
                "key_and_revoked", "key K2 and revoked K2", "R2-6 never both key and revoked")
    body_reject("body_two_floors_one_package",
                body_of([key_line(K[2]), revoked_line(K[1]), floor_11, b"floor qgp-kat 1.2"]),
                "duplicate_floor", "floor qgp-kat 1.1 and floor qgp-kat 1.2",
                "R2-6 one floor per package")
    body_reject("body_unknown_record_type",
                body_of(good3 + [b"note hello"]), "unknown_record_type",
                "extra line 'note hello'", "R2-6 unknown record types refused")
    body_reject("body_no_key", body_of([revoked_line(K[1]), floor_11]), "no_key",
                "only revoked + floor lines", "§2 at least one key; R2-2")
    body_reject("body_non_ascii", body_of(good3 + [b"floor qgp-k\xc3\xa4t 1.0"]),
                "non_printable_ascii_byte", "floor line with UTF-8 'a-umlaut' in the name",
                "reading R-ASCII")
    body_reject("body_tab_separator", b3.replace(b"floor qgp-kat", b"floor\tqgp-kat"),
                "non_printable_ascii_byte", "floor line with a TAB separator", "reading R-ASCII")

    # over 64 KiB: one byte longer than the accepted boundary body
    b_over = body_of(keys12 + [b"floor " + b"a" * (name_len + 1) + b" 1.0"])
    assert len(b_over) == BODY_MAX + 1
    f_over = trust_file(1, FP[1], b_over)
    must_reject(lambda: accept_trust(f_over, None), "body_too_large")
    tr.append({"name": "body_over_64KiB", "stored_state": "none (bootstrap)",
               "construction": "body_exactly_64KiB_bootstrap with the floor package name one "
                               "byte longer ('a'*%d); body_len = 65537" % (name_len + 1),
               "expected_reason": "body_too_large", "spec_ref": "R2-6 body <= 64 KiB before hashing",
               "file": hexblob(f_over, limit=0)})
    f_lie = trust_file(3, FP[2], b3, body_len=BODY_MAX + 1)
    add_trust_reject("body_len_field_over_64KiB", f_lie, "body_too_large",
                     "trust_file_3 with body_len field = 65537 (body itself unchanged)",
                     "R2-6 checked on body_len before the body is read")

    fv = bytearray(f3)
    fv[0] = 0x02
    add_trust_reject("file_version_2", bytes(fv), "file_version",
                     "trust_file_3 with version byte 0x02", "R2-6 version != 1 first")
    fv = bytearray(f3)
    fv[0] = 0x00
    add_trust_reject("file_version_0", bytes(fv), "file_version",
                     "trust_file_3 with version byte 0x00", "R2-6")
    add_trust_reject("file_trailing_byte", f3 + b"\x00", "file_length",
                     "trust_file_3 + one 0x00 byte", "§2 layout")
    add_trust_reject("file_truncated", f3[:-1], "file_length",
                     "trust_file_3 without its last byte", "§2 layout")
    add_trust_reject("file_sig_len_4626", trust_file(3, FP[2], b3, sig_len=4626), "sig_len",
                     "trust_file_3 with sig_len field 4626 (sig still 4627 bytes)", "§2 sig_len")

    add_trust_reject("serial_rollback", trust_file(1, FP[2], b3), "serial_not_increasing",
                     "trust_file_3 with serial 1", "§2 serial > stored")
    add_trust_reject("serial_replay_equal", trust_file(2, FP[2], b3), "serial_not_increasing",
                     "trust_file_3 with serial 2 (= stored)", "§2 serial > stored")
    add_trust_reject("floor_lowered",
                     trust_file(3, FP[2], body_of([key_line(K[2]), revoked_line(K[1]),
                                                   b"floor qgp-kat 0.9"])),
                     "floor_lowered", "trust_file_3 with floor qgp-kat 0.9 (stored 1.0)",
                     "R2-2 floor >= stored")
    add_trust_reject("floor_dropped",
                     trust_file(3, FP[2], body_of([key_line(K[2]), revoked_line(K[1])])),
                     "floor_dropped", "trust_file_3 without its floor line (stored has one)",
                     "R2-2 no floor disappears")
    add_trust_reject("revocation_dropped",
                     trust_file(4, FP[2], body_of([key_line(K[2]), floor_11])),
                     "revocation_dropped",
                     "serial 4, signer K2, body = key K2, floor qgp-kat 1.1 (revoked K1 missing)",
                     "R2-2 tombstones are permanent", stored=s3, stored_name="trust_file_3")
    add_trust_reject("signer_revoked", trust_file(4, FP[1], b3), "signer_revoked",
                     "serial 4, signer K1 (revoked in stored), body = trust_file_3 body",
                     "§2 signer not revoked", stored=s3, stored_name="trust_file_3")
    add_trust_reject("signer_not_in_stored_state",
                     trust_file(3, FP[3], body_of([key_line(K[3]), revoked_line(K[1]), floor_11])),
                     "signer_not_trusted",
                     "serial 3, signer K3 (not a key of trust_file_2), body lists K3",
                     "§2 signer in CURRENTLY pinned state")
    add_trust_reject("bootstrap_signer_not_in_body", trust_file(1, FP[3], b1),
                     "signer_not_trusted", "bootstrap file, signer K3, body = key K1",
                     "reading R-BOOT", stored=None, stored_name="none (bootstrap)")

    # prev_digest mismatch: not detectable from bytes alone; the signature fails because the
    # signer's preimage differs from the one the verifier builds.
    wrong_prev = m_trust(3, sha3(f1), FP[2], b3)
    tr.append({
        "name": "prev_digest_mismatch",
        "stored_state": "trust_file_2",
        "construction": "trust_file_3 bytes, but the signer signed M_trust with prev_digest = "
                        "SHA3-512(trust_file_1) instead of SHA3-512(trust_file_2)",
        "expected_reason": "signature_verify_fails (layout accepts; preimages differ)",
        "spec_ref": "R2-3 chain",
        "signer_preimage_hex": wrong_prev.hex(),
        "verifier_preimage_hex": m3.hex(),
        "c_side_test": "sign signer_preimage with the real K2 secret key, put the signature into "
                       "trust_file_3, verify against stored trust_file_2: must fail",
    })
    zero_prev = m_trust(2, ZERO64, FP[1], b2)
    tr.append({
        "name": "prev_digest_zeros_on_non_first",
        "stored_state": "trust_file_1",
        "construction": "trust_file_2 bytes, signer signed M_trust with prev_digest = zeros",
        "expected_reason": "signature_verify_fails (layout accepts; preimages differ)",
        "spec_ref": "R2-3 zeros only for the first",
        "signer_preimage_hex": zero_prev.hex(),
        "verifier_preimage_hex": m2.hex(),
    })
    kat["trust_reject"] = tr

    kat["readings"] = READINGS
    kat["counts"] = {
        "package_accept": 1 + len(pkg_accept),
        "package_reject": len(pr),
        "trust_chain": len(chain),
        "trust_accept": len(trust_accept),
        "trust_reject": len(tr),
        "readings": len(READINGS),
    }
    return kat


READINGS = [
    {"id": "R-ARREF", "topic": "ar container reference",
     "reading": "ar(5) is not installed on the build machine; ar header widths are taken from "
                "/usr/include/ar.h (name 16, date 12, uid 6, gid 6, mode 8, size 10, fmag '`\\n' "
                "= 60 bytes). Fields are written left-justified and space-padded, as observed in "
                "a dpkg-deb-written .deb (acl_2.3.1-3_amd64.deb) on the build machine."},
    {"id": "R-TAGS", "topic": "tags",
     "reading": "'NDS.QGPDEB.v1' (13 B) is followed by 3 x 0x00, 'NDS.QGPTRUST.v1' (15 B) by "
                "1 x 0x00, to 16 bytes (spec: right-padded 0x00)."},
    {"id": "R-FP", "topic": "fp vs key_id",
     "reading": "The trust-file fp (R2-1), the package key_id (§1) and the trust-file signer "
                "key_id are the same value: SHA3-512 of the 2592-byte public key."},
    {"id": "R-FILE", "topic": "trust file layout after R2-3",
     "reading": "R2-3 changes M_trust only. The trust FILE layout of §2 is unchanged: "
                "version | serial | signer key_id | body_len | body | sig_len | sig. "
                "prev_digest is NOT carried in the file; the verifier supplies it from the stored "
                "(previously accepted) file."},
    {"id": "R-PREV", "topic": "prev_digest",
     "reading": "prev_digest = SHA3-512 of the entire previously accepted trust file bytes "
                "including its signature. In these vectors the chain is computed over "
                "DUMMY-signed files; with real (randomized) signatures the digests differ, so the "
                "C side must recompute the chain from the files it actually signed."},
    {"id": "R-SERIAL", "topic": "serial",
     "reading": "serial must be strictly greater than the stored serial; gaps are allowed "
                "(spec says 'serial > stored serial'). Order is enforced by prev_digest."},
    {"id": "R-SIGNER", "topic": "who may sign an update",
     "reading": "The signer is checked only against the CURRENTLY pinned (stored) state: a key "
                "of the stored state not revoked there. It need not be a key of the new body, so "
                "a key may sign the file that revokes itself (vector "
                "self_revocation_signed_by_revoked_key). FLAG for the operator."},
    {"id": "R-BOOT", "topic": "bootstrap file",
     "reading": "The first (bootstrap) file is hand-checked; the oracle requires prev_digest = "
                "zeros and its signer to be a key of its own body (self-signed). Any serial is "
                "accepted for the bootstrap file."},
    {"id": "R-QGPHDR", "topic": "_qgp.sig ar header strictness",
     "reading": "The _qgp.sig header is fully determined by §1 + R2-6 and must be byte-exact: "
                "'_qgp.sig' + 8 spaces, mtime '0', uid '0', gid '0', mode '100644', size '4702', "
                "fmag. For the three dpkg members only the name field, the size field and fmag are "
                "checked; mtime/uid/gid/mode are not (they are inside the signed prefix anyway). "
                "FLAG for the operator."},
    {"id": "R-NAMES", "topic": "dpkg member names",
     "reading": "Name field = name, or name + '/', space-padded to 16; any other byte pattern "
                "refuses. Accepted names: debian-binary; control.tar[.gz|.xz|.zst]; "
                "data.tar[.gz|.xz|.zst|.bz2|.lzma] (§1 list)."},
    {"id": "R-AR-SIZE", "topic": "ar size field",
     "reading": "1..10 ASCII digits, left-aligned, remainder spaces. Leading spaces, signs, or "
                "any non-digit before the padding refuse. Leading zeros are accepted (they are "
                "digits; the field is inside the signed prefix)."},
    {"id": "R-PAD", "topic": "padding",
     "reading": "An odd-sized member must be followed by exactly one 0x0A byte; a missing or "
                "different pad byte refuses. The pad byte after data.tar is part of the prefix. "
                "_qgp.sig is 4702 bytes (even): no pad, and the file must end there."},
    {"id": "R-ODD", "topic": "where the odd member is",
     "reading": "The dispatch asked for data.tar.xz with an odd data member. Every .xz stream the "
                "payload generator produced (64 sizes tried) was a multiple of 4 bytes, so the "
                "base package keeps data.tar.xz (200 B, even) and makes control.tar.gz odd "
                "(209 B, pad byte inside the prefix); a second full vector package_odd_data uses "
                "data.tar.gz (153 B, odd) so the prefix ENDS with the data.tar pad byte, which "
                "the spec's 'INCLUDING its ar padding byte' is about. Observation from trials, "
                "not a claim read from the xz specification."},
    {"id": "R-ORDER", "topic": "parse order (which reason fires first)",
     "reading": "Per member: bounds of the 60-byte header, fmag, size digits, name/position, "
                "_qgp.sig header exactness, member bounds, pad byte. After the four members: "
                "member version byte first, then sig_len, then prefix_len, then revoked, then "
                "unknown key. A member after _qgp.sig refuses as member_after_qgp_sig; an extra "
                "member before it refuses as unexpected_member_name. The C side may use its own "
                "reason codes; only accept/refuse is normative."},
    {"id": "R-MEMBERVER", "topic": "'version != 1 before any other parse' in the .deb",
     "reading": "The ar container must be parsed to locate _qgp.sig; the version byte is then the "
                "first field read inside the member. For the trust file it is byte 0, checked "
                "before anything else."},
    {"id": "R-BODYMAX", "topic": "body size limit",
     "reading": "64 KiB = 65536 bytes, inclusive (65536 accepted, 65537 refused), checked on the "
                "body_len field before the body is read or hashed."},
    {"id": "R-ASCII", "topic": "body character set",
     "reading": "Every valid record is ASCII, so the oracle refuses any byte outside 0x20..0x7E "
                "other than LF (this catches CR/CRLF, TAB, NUL and non-ASCII UTF-8). §2 says "
                "'UTF-8'; this is the narrowest reading consistent with the grammar. FLAG."},
    {"id": "R-SEP", "topic": "field separator",
     "reading": "Fields are separated by exactly one 0x20; key = 3 fields, revoked = 2, floor = 3."},
    {"id": "R-HEX", "topic": "hex case",
     "reading": "Both fp (128) and pk (5184) hex are lowercase only; the pk rule mirrors §2's "
                "fp rule (R2-1 does not state the case)."},
    {"id": "R-FLOORTOK", "topic": "floor package / version grammar",
     "reading": "The oracle only requires non-empty printable ASCII tokens without spaces for "
                "<package> and <debian-version>; the Debian package-name and version grammars are "
                "not stated in the spec and are not asserted here. FLAG."},
    {"id": "R-VERCMP", "topic": "Debian version comparison",
     "reading": "The oracle compares floors with a minimal dot-separated-integer comparator and "
                "the vectors use only versions where every comparison rule agrees (0.9 < 1.0 < "
                "1.1, 2.0). Full Debian comparison (epoch, '~', revision) is the C side's "
                "obligation and is not covered by these vectors."},
    {"id": "R-MONO", "topic": "monotonic policy",
     "reading": "Against the stored state: every stored floor package must still have a floor "
                "and it must be >= (equal allowed); new floor packages are allowed; every stored "
                "revoked fp must still be revoked. 'At least one unrevoked key' collapses to "
                "'at least one key line' because key and revoked are disjoint (R2-6)."},
    {"id": "R-DUPKEY", "topic": "duplicates",
     "reading": "Identical lines refuse as duplicate_line. Two key lines with the same fp would "
                "need different pk (else duplicate line) and one would then fail the fp check; "
                "a dedicated duplicate_key_fp check exists but no SHA3 collision vector is possible."},
    {"id": "R-SCOPE", "topic": "out of scope",
     "reading": "The ar layer never parses inside members: the control.tar.gz / data.tar.xz "
                "payloads are fixed bytes pinned in the script (made once with --make-payloads), "
                "and their tar/compression validity is not asserted by the KAT path. dpkg-deb -f, "
                "the floor application to a package, the per-package highest-version record "
                "(R2-5), and the debian-binary content are out of scope (no bytes defined)."},
    {"id": "R-PREVREJ", "topic": "prev_digest mismatch reject",
     "reading": "prev_digest is not in the file, so a mismatch is a signature failure, not a "
                "layout failure. The vector gives the preimage the signer used and the preimage "
                "the verifier builds; the C side signs the former and asserts verify fails."},
]


def render():
    return json.dumps(build_kat(), indent=1) + "\n"


def main(argv):
    if "--make-payloads" in argv:
        make_payloads()
        return 0
    out = render()
    if "--check" in argv:
        with open(KAT_PATH, "r", encoding="ascii") as fh:
            committed = fh.read()
        if committed != out:
            sys.stderr.write("qgp_deb_kat.json differs from the regenerated vectors\n")
            return 1
        sys.stdout.write("qgp_deb_kat.json matches (%d bytes)\n" % len(out))
        return 0
    with open(KAT_PATH, "w", encoding="ascii") as fh:
        fh.write(out)
    sys.stdout.write("wrote %s (%d bytes)\n" % (KAT_PATH, len(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
