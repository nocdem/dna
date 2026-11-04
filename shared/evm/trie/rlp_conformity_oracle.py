#!/usr/bin/env python3
"""
rlp_conformity_oracle.py - independent vector generator for the RLP code of
the Nodus EVM state trie (trie/evm_trie_rlp.c; HF-9 review T-2, plan
docs/plans/approved/2026-11-04-hf9.md section 12, review row 4 / section 3.3).

The expected values come from the PINNED package ethereum-rlp 0.1.6
(PyPI sdist ethereum_rlp-0.1.6.tar.gz, sha256
ede36f53b53c8da21f19259a676eed8790950d47f0b42cb928ac8a3c562282f3, the version
execution-specs @a87891f7 pins in uv.lock), src/ethereum_rlp/rlp.py:
    encode            :66-130   (encode, encode_bytes, encode_sequence)
    decode            :143-159
    decode_to_bytes   :387-425
    decode_to_sequence:427-462
    decode_item_length:487-543
This script contains NO RLP rules of its own: every `out` / `tree` / `ok` in
the output is what rlp.py returned or raised. The only thing it decides is
which inputs to feed (a fixed list of hand-chosen boundary and non-canonical
inputs, plus pseudo-random trees from a fixed seed).

Environment (nothing is fetched; the script never touches the network):
  - the sdist tarball (argv[1]) is checked against EXPECTED_SHA256 BEFORE
    anything is extracted or imported; a mismatch stops the run;
  - the sdist is extracted into a fresh temporary directory and its src/ is
    put on sys.path, so the package is loaded from the verified tarball;
  - rlp.py itself needs two packages the sdist does not carry:
    ethereum-types (setup.cfg: >=0.2.1,<0.5) and typing-extensions
    (>=4.12.2). They are taken from a directory given as argv[2] that holds
    the two pinned wheels (execution-specs a87891f7 uv.lock pins
    ethereum_types-0.4.1 and typing_extensions-4.15.0) and a sibling
    `<dir>.SOURCE` file listing "<wheel name> sha256 <hex>" per wheel. Each
    wheel's sha256 is checked against that file AND against the constants
    below before it is unzipped into the temporary directory; nothing is
    installed and the pre-unzipped copy beside the wheels is not used.
    A missing wheel or a mismatch stops the run with no output.

Usage:
    python3 -I rlp_conformity_oracle.py <ethereum_rlp-0.1.6.tar.gz> \
        <deps dir with the two wheels> <out.json>
(-I keeps the working directory off sys.path; run it from anywhere.)

Output (rlp_vectors_0_1_6.json): {"source": ..., "sha256_of_sdist": ...,
"vectors": [...]}. Each vector:
    {"id": "...", "op": "encode", "in": TREE, "out": HEX}
    {"id": "...", "op": "decode", "in": HEX, "ok": true,  "tree": TREE}
    {"id": "...", "op": "decode", "in": HEX, "ok": false, "error": NAME}
where TREE is {"b": HEX} for a byte string or a JSON array of TREEs for a
list. Ordering and seed are fixed, so two runs give identical bytes (the
test header records the sha256 of the committed file).
"""

import hashlib
import json
import os
import random
import sys
import tarfile
import tempfile
import zipfile

EXPECTED_SHA256 = (
    "ede36f53b53c8da21f19259a676eed8790950d47f0b42cb928ac8a3c562282f3")
WHEELS = {   # execution-specs a87891f7 uv.lock pins
    "ethereum_types-0.4.1-py3-none-any.whl":
        "33de3e2a0c0e57ea1b67802485de556b92d557aae7c8c640070800f2b4f639e3",
    "typing_extensions-4.15.0-py3-none-any.whl":
        "f0fa19c6845758ab08074a0cfa8b7aecb71c999ca73d62883bc25cc018c4e548",
}
SDIST_SRC ="ethereum_rlp-0.1.6/src"
SEED = 0x524C5030          # "RLP0"
# intended list headers of the payload-boundary fixtures (checked against
# what the reference returned: a wrong fixture stops the run)
HEADER_CHECK = {
    "list-payload-55": bytes([0xF7]),
    "list-payload-56": bytes([0xF8, 0x38]),
    "list-payload-57": bytes([0xF8, 0x39]),
    "list-payload-256": bytes([0xF9, 0x01, 0x00]),
}

sys.dont_write_bytecode = True


def fail(msg, code=2):
    sys.stderr.write("rlp_conformity_oracle: " + msg + "\n")
    sys.exit(code)


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load_deps(deps_dir, tmp):
    """Verify the two pinned wheels, unzip them into tmp/deps, put it on
    sys.path. Hashes must match the sibling .SOURCE file and WHEELS."""
    listed = {}
    try:
        with open(deps_dir.rstrip("/") + ".SOURCE") as f:
            for line in f:
                p = line.split()
                if len(p) == 3 and p[1] == "sha256":
                    listed[p[0]] = p[2]
    except OSError as e:
        fail("cannot read %s.SOURCE: %s" % (deps_dir, e), 1)
    target = os.path.join(tmp, "deps")
    os.mkdir(target)
    for name, want in WHEELS.items():
        path = os.path.join(deps_dir, name)
        if not os.path.isfile(path):
            fail("missing wheel %s" % path, 1)
        got = sha256_file(path)
        if got != want or listed.get(name) != want:
            fail("wheel %s sha256 %s: pinned %s, .SOURCE %s" %
                 (name, got, want, listed.get(name)), 1)
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if os.path.isabs(n) or ".." in n.split("/"):
                    fail("unexpected wheel member %r" % n, 1)
            z.extractall(target)
    sys.path.insert(0, target)


def load_reference(tarball, deps_dir):
    got = sha256_file(tarball)
    if got != EXPECTED_SHA256:
        fail("sdist sha256 %s != pinned %s" % (got, EXPECTED_SHA256), 1)
    tmp = tempfile.mkdtemp(prefix="rlp016-")
    load_deps(deps_dir, tmp)
    with tarfile.open(tarball, "r:gz") as tf:
        for m in tf.getmembers():
            # a plain extraction guard: no absolute path, no parent escape,
            # regular files and directories only
            n = os.path.normpath(m.name)
            if (os.path.isabs(n) or n.startswith("..") or
                    not (m.isreg() or m.isdir())):
                fail("unexpected tar member %r" % m.name, 1)
        tf.extractall(tmp)
    sys.path.insert(0, os.path.join(tmp, SDIST_SRC))
    import ethereum_rlp
    from ethereum_rlp import rlp as rlp_mod
    if not os.path.realpath(rlp_mod.__file__).startswith(
            os.path.realpath(tmp)):
        fail("ethereum_rlp was not loaded from the verified sdist", 1)
    return ethereum_rlp


def tree_to_py(t):
    """TREE (json) -> the Python value rlp.encode takes."""
    if isinstance(t, dict):
        return bytes.fromhex(t["b"])
    return [tree_to_py(x) for x in t]


def py_to_tree(v):
    """What rlp.decode returned (bytes or a sequence) -> TREE."""
    if isinstance(v, (bytes, bytearray)):
        return {"b": bytes(v).hex()}
    return [py_to_tree(x) for x in v]


def b(hexs):
    return {"b": hexs}


def fixed_trees():
    """Boundary inputs: every length class edge of both encodings."""
    out = []
    out.append(("empty-string", b("")))
    out.append(("empty-list", []))
    for v in ("00", "01", "7f", "80", "81", "ff"):
        out.append(("byte-" + v, b(v)))
    for n in (2, 54, 55, 56, 57, 63, 64, 65, 255, 256, 257, 1023, 1024,
              65535, 65536):
        out.append(("str-len-%d" % n, b(("ab" * n))))
    out.append(("list-of-empty-lists", [[], [[]], [[], [[]]]]))
    for n in (1, 2, 17):
        out.append(("list-of-%d-empty-strings" % n, [b("")] * n))
    # list payload boundaries: payload 55 / 56 / 57 / 256 bytes (the header
    # byte is asserted against the reference's output in main())
    out.append(("list-payload-55", [b("ab" * 53), b("")]))
    out.append(("list-payload-56", [b("ab" * 54), b("")]))
    out.append(("list-payload-57", [b("ab" * 54), b("00"), b("00")]))
    out.append(("list-payload-256", [b("cd" * 127), b("ee" * 125)]))
    # the trie's own node shapes: 17-item branch, 2-item leaf / extension
    out.append(("branch-17", [b("ee" * 64)] + [b("")] * 15 + [b("")]))
    out.append(("leaf-2", [b("20" + "11" * 63), b("78")]))
    out.append(("ext-2", [b("0012"), b("fa" * 64)]))
    return out


def random_tree(rng, depth):
    if depth == 0 or rng.random() < 0.55:
        n = rng.choice((0, 1, 1, 2, 3, 20, 54, 55, 56, 64, 70, 300))
        return b(bytes(rng.randrange(256) for _ in range(n)).hex())
    k = rng.choice((0, 1, 2, 3, 5, 17, 20))
    return [random_tree(rng, depth - 1) for _ in range(k)]


def reject_inputs():
    """Hand-chosen decode inputs; the reference decides each verdict."""
    r = []
    r.append(("empty-input", ""))
    r.append(("wrapped-single-byte-00", "8100"))
    r.append(("wrapped-single-byte-7f", "817f"))
    r.append(("byte-80-in-81-form", "81" + "80"))
    r.append(("long-form-short-string", "b801" + "41"))
    r.append(("long-form-len-55", "b837" + "aa" * 55))
    r.append(("long-form-leading-zero", "b900" + "38" + "aa" * 56))
    r.append(("long-form-leading-zero-3-length-bytes", "ba000038" + "aa" * 56))
    r.append(("long-form-len-56", "b838" + "aa" * 56))
    r.append(("string-truncated-short", "83aabb"))
    r.append(("string-truncated-long", "b838" + "aa" * 55))
    r.append(("string-trailing-short", "82aabbcc"))
    r.append(("string-trailing-long", "b838" + "aa" * 56 + "00"))
    r.append(("long-form-length-bytes-missing", "b9"))
    r.append(("long-form-length-bytes-truncated", "ba01"))
    r.append(("list-long-form-short", "f801" + "80"))
    r.append(("list-long-form-len-55", "f837" + "80" * 55))
    r.append(("list-long-form-leading-zero", "f90038" + "80" * 56))
    r.append(("list-long-form-len-56", "f838" + "80" * 56))
    r.append(("list-truncated", "c3" + "8080"))
    r.append(("list-trailing", "c1" + "80" + "80"))
    r.append(("list-item-overruns", "c2" + "83" + "aa"))
    r.append(("list-nested-wrapped-single-byte", "c3" + "c2" + "8100"))
    r.append(("list-nested-non-canonical-length", "c4" + "c3" + "b801" + "41"))
    r.append(("list-item-truncated-long-length", "c2" + "b9" + "00"))
    r.append(("list-empty", "c0"))
    r.append(("string-empty", "80"))
    r.append(("byte-7f", "7f"))
    r.append(("byte-trailing", "7f00"))
    r.append(("0xbf-length-8", "bf" + "00" * 8))
    r.append(("0xff-length-8", "ff" + "00" * 8))
    r.append(("huge-length-claim", "bb" + "ff" * 4 + "00"))
    return r


def main():
    if len(sys.argv) != 4:
        fail("usage: rlp_conformity_oracle.py <sdist.tar.gz> <deps dir> "
             "<out.json>", 64)
    ref = load_reference(sys.argv[1], sys.argv[2])
    vectors = []

    def add_encode(vid, tree):
        enc = ref.encode(tree_to_py(tree))
        want = HEADER_CHECK.get(vid)
        if want is not None and bytes(enc)[:len(want)] != want:
            fail("fixture %s does not have the intended payload size "
                 "(header %s)" % (vid, bytes(enc)[:4].hex()), 1)
        vectors.append({"id": vid, "op": "encode", "in": tree,
                        "out": bytes(enc).hex()})
        # every encoded value is also a decode vector (round trip, as the
        # REFERENCE decodes it)
        add_decode("rt-" + vid, bytes(enc).hex())

    def add_decode(vid, hexs):
        raw = bytes.fromhex(hexs)
        try:
            val = ref.decode(raw)
        except Exception as e:                       # noqa: BLE001
            vectors.append({"id": vid, "op": "decode", "in": hexs,
                            "ok": False, "error": type(e).__name__})
            return
        vectors.append({"id": vid, "op": "decode", "in": hexs, "ok": True,
                        "tree": py_to_tree(val)})

    for vid, tree in fixed_trees():
        add_encode(vid, tree)
    rng = random.Random(SEED)
    for i in range(300):
        add_encode("rand-%03d" % i, random_tree(rng, 4))
    for vid, hexs in reject_inputs():
        add_decode(vid, hexs)

    doc = {"source": "ethereum-rlp 0.1.6 sdist",
           "sha256_of_sdist": EXPECTED_SHA256,
           "seed": SEED, "vectors": vectors}
    text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    with open(sys.argv[3], "w") as f:
        f.write(text)
    print("wrote %s: %d vectors, sha256 %s" % (
        sys.argv[3], len(vectors),
        hashlib.sha256(text.encode()).hexdigest()))


if __name__ == "__main__":
    main()
