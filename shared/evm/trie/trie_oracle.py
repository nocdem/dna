#!/usr/bin/env python3
"""
trie_oracle.py — independent oracle for the Nodus EVM state trie
(trie/evm_trie.c, trie/evm_trie_full.c; decision
docs/plans/decisions/2026-10-04-nodus-evm-kurultay-k2-summary.md #1, design
docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3 §6).

The trie functions below are COPIED from the pinned reference
execution-specs @a87891f7 src/ethereum/merkle_patricia_trie.py (line
numbers cited per function). The only changes are the §6 substitutions,
expressed as two parameters every copied function takes:
    H  the node / secure-key hash   (reference: keccak256)
    T  the inline threshold          (reference: 32)
Nodus EVM mode is H = SHA3-512 (hashlib.sha3_512), T = 64; the empty root
follows from the copied code: H(rlp(b"")) = H(0x80). Leaf values are
opaque bytes (encode_node :266-267 returns Bytes unchanged).
Node classes are replaced by tuples ("leaf"/"ext"/"branch", ...) — same
fields, same order.

Before anything is emitted the oracle checks itself and refuses to write
on any failure:
  1. SHA3-512: hashlib.sha3_512 equals a SHA3-512 built here from the
     Keccak-f[1600] permutation of tests/addr32_oracle.py (keccak_f,
     FIPS 202 sponge: rate 72, domain padding 0x06 .. 0x80), on inputs
     straddling the rate.
  2. Keccak-256 (tests/addr32_oracle.py keccak256 — itself checked there
     against two vectors) and this file's RLP encoder: the dispatch vectors
     keccak256("") / ("abc") and the yellow-paper RLP examples.
  3. UNSUBSTITUTED mode (H = keccak256, T = 32) over every Prague post
     state of two official fixtures (execution-spec-tests v5.4.0
     fixtures_stable, given as argv[1]):
       static/state_tests/stRevertTest/RevertInCreateInInit_Paris.json
       paris/eip7610_create_collision/test_init_collision_create_tx.json
     must reproduce each entry's post.Prague[i].hash. Account leaf =
     rlp([nonce, balance, storage_root, keccak(code)]) (encode_account
     :193-210); storage trie secured, value rlp(uint), zero = absent.
This proves the copied structure code is the reference's; Nodus EVM mode then
differs only in H and T.

Vector scenarios (fixed seed 0x5145564d, no time, no unordered output):
see SCENARIOS in main(). Also asserted here, before writing: the
"boundary" scenario really produces node encodings of 63, 64 and 65
bytes; the 1000-key root is the same for two insertion orders; a
delete-then-reinsert returns the earlier root.

Usage: python3 trie/trie_oracle.py <fixtures/state_tests dir> <out.h>
"""

import hashlib
import json
import os
import random
import sys

sys.dont_write_bytecode = True     # no __pycache__ in tests/
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "tests"))
from addr32_oracle import keccak256, keccak_f  # noqa: E402  (FIPS 202 code)


# ── SHA3-512 cross-check (FIPS 202 sponge over addr32_oracle.keccak_f) ──

def sha3_512_sponge(data):
    rate = 72
    msg = bytearray(data)
    pad = rate - (len(msg) % rate)
    if pad == 1:
        msg += b"\x86"
    else:
        msg += b"\x06" + b"\x00" * (pad - 2) + b"\x80"
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        a = keccak_f(a)
    out = b""
    for i in range(8):                       # 64 bytes < rate: one squeeze
        x, y = i % 5, i // 5
        out += a[x][y].to_bytes(8, "little")
    return out


def sha3_512(data):
    return hashlib.sha3_512(bytes(data)).digest()


# ── minimal RLP (what ethereum_rlp's rlp.encode does for bytes / lists) ─

def _be(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def rlp_encode(x):
    if isinstance(x, (bytes, bytearray)):
        b = bytes(x)
        if len(b) == 1 and b[0] < 0x80:
            return b
        if len(b) < 56:
            return bytes([0x80 + len(b)]) + b
        ln = _be(len(b))
        return bytes([0xb7 + len(ln)]) + ln + b
    if isinstance(x, (list, tuple)):
        payload = b"".join(rlp_encode(i) for i in x)
        if len(payload) < 56:
            return bytes([0xc0 + len(payload)]) + payload
        ln = _be(len(payload))
        return bytes([0xf7 + len(ln)]) + ln + payload
    raise AssertionError("rlp: unsupported type %r" % type(x))


def rlp_uint(n):
    return rlp_encode(_be(n) if n else b"")


# ── copied reference (merkle_patricia_trie.py @a87891f7) ────────────────

# Encoding sizes seen by encode_internal_node (for the boundary assertion).
ENCODED_SIZES = []


def encode_internal_node(node, H, T):
    """:213-249 — keccak256 -> H, 32 -> T."""
    if node is None:
        unencoded = b""
    elif node[0] == "leaf":
        unencoded = (nibble_list_to_compact(node[1], True), node[2])
    elif node[0] == "ext":
        unencoded = (nibble_list_to_compact(node[1], False), node[2])
    elif node[0] == "branch":
        unencoded = list(node[1]) + [node[2]]
    else:
        raise AssertionError("Invalid internal node type")

    encoded = rlp_encode(unencoded)
    if node is not None:
        ENCODED_SIZES.append((len(encoded), node[0]))
    if len(encoded) < T:
        return unencoded
    else:
        return H(encoded)


def common_prefix_length(a, b):
    """:350-357"""
    for i in range(len(a)):
        if i >= len(b) or a[i] != b[i]:
            return i
    return len(a)


def nibble_list_to_compact(x, is_leaf):
    """:360-392"""
    compact = bytearray()
    if len(x) % 2 == 0:  # ie even length
        compact.append(16 * (2 * is_leaf))
        for i in range(0, len(x), 2):
            compact.append(16 * x[i] + x[i + 1])
    else:
        compact.append(16 * ((2 * is_leaf) + 1) + x[0])
        for i in range(1, len(x), 2):
            compact.append(16 * x[i] + x[i + 1])
    return bytes(compact)


def bytes_to_nibble_list(bytes_):
    """:395-404"""
    nibble_list = bytearray(2 * len(bytes_))
    for byte_index, byte in enumerate(bytes_):
        nibble_list[byte_index * 2] = (byte & 0xF0) >> 4
        nibble_list[byte_index * 2 + 1] = byte & 0x0F
    return bytes(nibble_list)


def _prepare_data(data, secured, H):
    """:407-448 — values are already-encoded opaque bytes (encode_node
    :266-267); secure key keccak256 -> H (:441-443)."""
    mapped = {}
    for preimage, value in data.items():
        encoded_value = value
        if encoded_value == b"":
            raise AssertionError
        if secured:
            key = H(preimage)
        else:
            key = preimage
        mapped[bytes_to_nibble_list(key)] = encoded_value
    return mapped


def root(data, secured, H, T):
    """:478-504 — keccak256 -> H, 32 -> T (both at :500 and inside
    encode_internal_node, :246)."""
    obj = _prepare_data(data, secured, H)
    root_node = encode_internal_node(patricialize(obj, 0, H, T), H, T)
    if len(rlp_encode(root_node)) < T:
        return H(rlp_encode(root_node))
    else:
        assert isinstance(root_node, bytes)
        return root_node


def patricialize(obj, level, H, T):
    """:507-581"""
    if len(obj) == 0:
        return None

    arbitrary_key = next(iter(obj))

    # if leaf node
    if len(obj) == 1:
        return ("leaf", arbitrary_key[level:], obj[arbitrary_key])

    substring = arbitrary_key[level:]
    prefix_length = len(substring)
    for key in obj:
        prefix_length = min(
            prefix_length, common_prefix_length(substring, key[level:])
        )
        if prefix_length == 0:
            break

    # if extension node
    if prefix_length > 0:
        prefix = arbitrary_key[level:level + prefix_length]
        return ("ext", prefix,
                encode_internal_node(
                    patricialize(obj, level + prefix_length, H, T), H, T))

    branches = []
    for _ in range(16):
        branches.append({})
    value = b""
    for key in obj:
        if len(key) == level:
            value = obj[key]
        else:
            branches[key[level]][key] = obj[key]

    subnodes = tuple(
        encode_internal_node(patricialize(branches[k], level + 1, H, T), H, T)
        for k in range(16)
    )
    return ("branch", subnodes, value)


def qroot(data, secured):
    """Nodus EVM root: substitutions (1)-(4)."""
    return root(data, secured, sha3_512, 64)


# ── self-checks ─────────────────────────────────────────────────────────

FIXTURE_FILES = [
    "static/state_tests/stRevertTest/RevertInCreateInInit_Paris.json",
    "paris/eip7610_create_collision/test_init_collision_create_tx.json",
]


def _hexint(s):
    return int(s, 16)


def _hexbytes(s):
    s = s[2:] if s.startswith("0x") else s
    return bytes.fromhex(s)


def fixture_state_root(state):
    """state_mpt: secured state trie of encode_account(...) leaves, each
    with its secured storage trie (default 0 = absent)."""
    accounts = {}
    for addr_hex, acct in state.items():
        storage = {}
        for k, v in acct["storage"].items():
            iv = _hexint(v)
            if iv == 0:
                continue                    # trie_set: default removes
            storage[_hexint(k).to_bytes(32, "big")] = rlp_uint(iv)
        sroot = root(storage, True, keccak256, 32)
        leaf = rlp_encode([_be(_hexint(acct["nonce"])),
                           _be(_hexint(acct["balance"])),
                           sroot,
                           keccak256(_hexbytes(acct["code"]))])
        accounts[_hexbytes(addr_hex)] = leaf
    return root(accounts, True, keccak256, 32)


def self_check(fixtures_dir):
    h = bytes.fromhex
    for n in (0, 1, 3, 71, 72, 73, 143, 144, 145, 300):
        data = bytes((i * 7 + n) & 0xff for i in range(n))
        assert sha3_512_sponge(data) == sha3_512(data), "sha3-512 len %d" % n
    assert keccak256(b"") == h(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    assert keccak256(b"abc") == h(
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    assert rlp_uint(0) == h("80")
    assert rlp_encode(b"dog") == h("83646f67")
    assert rlp_encode([b"cat", b"dog"]) == h("c88363617483646f67")
    assert rlp_uint(1024) == h("820400")
    assert rlp_encode([]) == h("c0")
    # EMPTY_TRIE_ROOT :71-75 from the copied code, unsubstituted
    assert root({}, True, keccak256, 32) == h(
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

    checked = 0
    for rel in FIXTURE_FILES:
        path = os.path.join(fixtures_dir, rel)
        with open(path) as f:
            doc = json.load(f)
        for name in sorted(doc):
            if "fork_Prague" not in name:
                continue
            for i, post in enumerate(doc[name]["post"]["Prague"]):
                got = fixture_state_root(post["state"])
                want = _hexbytes(post["hash"])
                if got != want:
                    raise AssertionError("fixture root mismatch: %s [%d]"
                                         % (name, i))
                checked += 1
    if checked < 2:
        raise AssertionError("fewer than two fixture roots checked")
    print("self-check: sha3-512 sponge == hashlib on 10 inputs; keccak/RLP "
          "vectors ok; EMPTY_TRIE_ROOT ok; %d official Prague post-state "
          "roots reproduced (keccak256, threshold 32)" % checked)
    return checked


# ── scenarios ───────────────────────────────────────────────────────────

SET, DEL = 0, 1
SECURE, PATH = 0, 1


class Scenario:
    def __init__(self, name, mode):
        self.name = name
        self.mode = mode
        self.steps = []          # (op, key, value, root or None)
        self.data = {}

    def _root(self):
        return qroot(self.data, self.mode == SECURE)

    def set(self, key, value, check=True):
        if self.mode == PATH:
            assert len(key) == 64
        assert len(value) > 0
        self.data[key] = value
        self.steps.append([SET, key, value, self._root() if check else None])

    def delete(self, key, check=True):
        self.data.pop(key, None)             # trie_set with default :334-336
        self.steps.append([DEL, key, b"", self._root() if check else None])

    def last_root(self):
        return self.steps[-1][3]


def path_with(base, nibble_pos, new_nibble):
    """base (64 bytes) with the nibble at nibble_pos replaced."""
    nibs = bytearray(bytes_to_nibble_list(base))
    nibs[nibble_pos] = new_nibble
    out = bytearray(64)
    for i in range(64):
        out[i] = nibs[2 * i] * 16 + nibs[2 * i + 1]
    return bytes(out)


def other(n):
    return (n + 1) % 16


def build(rng):
    sc = []

    # 1. empty trie: no steps; the root is the empty root
    sc.append(Scenario("empty", SECURE))

    # 2. single key: set, overwrite, delete -> empty
    s = Scenario("single", SECURE)
    s.set(b"key-1", b"value-1")
    s.set(b"key-1", b"value-1-overwritten")
    s.delete(b"key-1")
    sc.append(s)

    # 3. inline-threshold boundary (path mode). Leaves under a branch at
    #    depth 127 have a 0-nibble key (compact 0x20); value lengths 58 /
    #    59 / 60 make the leaf encode to 63 / 64 / 65 bytes. A second group
    #    builds embedded branches at depth 126/127 with 1..3-byte values,
    #    whose sizes straddle 64 as values grow.
    s = Scenario("boundary", PATH)
    base = bytes(rng.getrandbits(8) for _ in range(64))
    p = [path_with(base, 127, k) for k in range(4)]
    s.set(p[0], bytes([0xa0]) * 58)
    s.set(p[1], bytes([0xa1]) * 59)
    s.set(p[2], bytes([0xa2]) * 60)
    s.set(p[0], bytes([0xb0]) * 59)
    s.set(p[0], bytes([0xb1]) * 60)
    s.set(p[0], bytes([0xb2]) * 58)
    s.delete(p[1])
    s.delete(p[2])
    s.set(p[3], b"\x01")
    s.delete(p[0])
    s.delete(p[3])
    base2 = bytes(rng.getrandbits(8) for _ in range(64))
    q = []
    for n126 in range(3):
        for n127 in range(3):
            q.append(path_with(path_with(base2, 126, n126), 127, n127))
    for i, k in enumerate(q):
        s.set(k, bytes([0x10 + i]))
    for ln in (2, 3, 4, 5, 6):
        for i, k in enumerate(q):
            s.set(k, bytes([0x20 + i]) * ln)
    for k in q[::2]:
        s.delete(k)
    for k in q[1::2]:
        s.delete(k)
    # a branch at depth 127 over two embedded leaves [0x20, v]: value
    # lengths (20,20) / (20,21) / (21,21) make it encode to 63 / 64 / 65
    base3 = bytes(rng.getrandbits(8) for _ in range(64))
    r0, r1 = path_with(base3, 127, 0), path_with(base3, 127, 1)
    s.set(r0, b"\xc0" * 20)
    s.set(r1, b"\xc1" * 20)
    s.set(r1, b"\xc2" * 21)
    s.set(r0, b"\xc3" * 21)
    s.set(r0, b"\xc4" * 20)
    s.delete(r1)
    s.delete(r0)
    sc.append(s)

    # 4. shared prefixes (path mode): extension splits and merges
    s = Scenario("shared_prefix", PATH)
    base = bytes(rng.getrandbits(8) for _ in range(64))
    nb = bytes_to_nibble_list(base)
    pos = [100, 20, 63, 127, 1, 5, 0, 126, 64]
    keys = [base] + [path_with(base, i, other(nb[i])) for i in pos]
    for k in keys:
        s.set(k, bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 80))))
    for k in [keys[3], keys[0], keys[7], keys[1], keys[5]]:
        s.delete(k)
    for k in [keys[0], keys[3]]:
        s.set(k, b"\x42" * 33)
    for k in [keys[2], keys[4], keys[6], keys[8], keys[9], keys[0], keys[3]]:
        s.delete(k)
    assert not s.data
    sc.append(s)

    # 5. insert / delete / reinsert
    s = Scenario("reinsert", SECURE)
    ks = [b"reinsert-%d" % i for i in range(10)]
    for i, k in enumerate(ks):
        s.set(k, b"v%d" % i)
    full = s.last_root()
    s.delete(ks[3])
    s.set(ks[3], b"v3")
    assert s.last_root() == full, "reinsert must restore the root"
    s.delete(ks[3])
    s.set(ks[3], b"v3-changed")
    s.set(ks[3], b"v3")
    assert s.last_root() == full
    s.delete(b"never-inserted")
    assert s.last_root() == full, "deleting an absent key is a no-op"
    for k in ks:
        s.delete(k)
    sc.append(s)

    # 6. delete to empty, random order
    s = Scenario("delete_to_empty", SECURE)
    ks = [b"dte-%02d" % i for i in range(20)]
    for k in ks:
        s.set(k, bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 40))))
    order = ks[:]
    rng.shuffle(order)
    for k in order:
        s.delete(k)
    assert not s.data
    sc.append(s)

    # 7. 1000 random keys in random order, 200 updates, 300 deletes
    s = Scenario("random1000", SECURE)
    keys = set()
    while len(keys) < 1000:
        keys.add(bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 32))))
    keys = sorted(keys)
    order = keys[:]
    rng.shuffle(order)
    vals = {}
    n = 0
    for k in order:
        vals[k] = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 48)))
        n += 1
        s.set(k, vals[k], check=(n % 25 == 0))
    after_insert = s.last_root()
    other_order = keys[:]
    rng.shuffle(other_order)
    assert qroot({k: vals[k] for k in other_order}, True) == after_insert, \
        "1000-key root depends on insertion order"
    for i in range(200):
        k = keys[rng.randrange(len(keys))]
        s.set(k, bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 48))),
              check=(i % 25 == 24))
    dels = keys[:]
    rng.shuffle(dels)
    for i, k in enumerate(dels[:300]):
        s.delete(k, check=(i % 25 == 24))
    if s.steps[-1][3] is None:
        s.steps[-1][3] = qroot(s.data, True)
    sc.append(s)

    # 8. large values (8192 bytes)
    s = Scenario("large_values", SECURE)
    for i in range(6):
        s.set(b"large-%d" % i, bytes(rng.getrandbits(8) for _ in range(8192)))
    s.set(b"small", b"\x01")
    s.set(b"large-2", bytes(rng.getrandbits(8) for _ in range(8192)))
    s.delete(b"large-0")
    s.delete(b"large-4")
    s.set(b"large-0", bytes(rng.getrandbits(8) for _ in range(8192)))
    sc.append(s)
    return sc


def build_full_only():
    """Unsecured, variable-length keys — evm_trie_full only (the
    incremental trie takes 128-nibble paths). Exercises branch values,
    embedded nodes and a root node < 64 bytes (root() :500-501)."""
    cases = [
        ("one_short_key", {b"\x01": b"\x02"}),
        ("prefix_keys", {b"do": b"verb", b"dog": b"puppy", b"doge": b"coin",
                         b"horse": b"stallion"}),
        ("empty_key", {b"": b"root-value", b"a": b"x", b"ab": b"y"}),
    ]
    return [(n, d, qroot(d, False)) for n, d in cases]


# ── header emission ─────────────────────────────────────────────────────

def c_bytes(data, indent="    "):
    lines = []
    for i in range(0, len(data), 16):
        lines.append(indent + ",".join("0x%02x" % b for b in data[i:i + 16])
                     + ",")
    return lines


def emit(scenarios, full_only, checked, out_path):
    blob = bytearray()
    roots = []
    steps = []
    scen = []

    def add(b):
        off = len(blob)
        blob.extend(b)
        return off, len(b)

    for s in scenarios:
        first = len(steps)
        for op, key, value, r in s.steps:
            ko, kl = add(key)
            vo, vl = add(value)
            ri = -1
            if r is not None:
                ri = len(roots)
                roots.append(r)
            steps.append((op, ko, kl, vo, vl, ri))
        final = qroot(s.data, s.mode == SECURE)
        if s.steps:
            assert s.steps[-1][3] == final
        fi = len(roots)
        roots.append(final)
        scen.append((s.name, s.mode, first, len(steps) - first, fi))

    fo = []
    fkv = []
    for name, d, r in full_only:
        first = len(fkv)
        for k in sorted(d):
            ko, kl = add(k)
            vo, vl = add(d[k])
            fkv.append((ko, kl, vo, vl))
        ri = len(roots)
        roots.append(r)
        fo.append((name, first, len(fkv) - first, ri))

    o = []
    o.append("/* GENERATED by trie/trie_oracle.py — do not edit.")
    o.append(" * Regenerate: make -C shared/evm trie-vectors FIXTURES=<dir>")
    o.append(" * Roots: execution-specs @a87891f7 merkle_patricia_trie.py with")
    o.append(" * the design §6 substitutions (SHA3-512, threshold 64).")
    o.append(" * Oracle self-check: %d official Prague post-state roots" % checked)
    o.append(" * reproduced by the same code with keccak256 / threshold 32. */")
    o.append("#ifndef EVM_TRIE_VECTORS_H")
    o.append("#define EVM_TRIE_VECTORS_H")
    o.append("")
    o.append("#include <stdint.h>")
    o.append("")
    o.append("#define TV_SET    0")
    o.append("#define TV_DEL    1")
    o.append("#define TV_SECURE 0   /* raw key, hashed by the trie        */")
    o.append("#define TV_PATH   1   /* key is the 64-byte path (unsecured) */")
    o.append("")
    o.append("typedef struct {")
    o.append("    uint8_t  op;")
    o.append("    uint32_t key_off, key_len, val_off, val_len;")
    o.append("    int32_t  root;     /* index into tv_roots, -1 = not given */")
    o.append("} tv_step;")
    o.append("")
    o.append("typedef struct {")
    o.append("    const char *name;")
    o.append("    uint8_t     mode;")
    o.append("    uint32_t    first, n;  /* steps */")
    o.append("    int32_t     final_root;")
    o.append("} tv_scenario;")
    o.append("")
    o.append("typedef struct { uint32_t key_off, key_len, val_off, val_len; } tv_kv;")
    o.append("")
    o.append("typedef struct {")
    o.append("    const char *name;")
    o.append("    uint32_t    first, n;  /* tv_full_kvs */")
    o.append("    int32_t     root;")
    o.append("} tv_full_case;")
    o.append("")
    o.append("static const uint8_t tv_empty_root[64] = {")
    o.extend(c_bytes(qroot({}, True)))
    o.append("};")
    o.append("")
    o.append("static const uint8_t tv_blob[%d] = {" % max(len(blob), 1))
    o.extend(c_bytes(bytes(blob) if blob else b"\x00"))
    o.append("};")
    o.append("")
    o.append("static const uint8_t tv_roots[%d][64] = {" % len(roots))
    for r in roots:
        o.append("  {")
        o.extend(c_bytes(r))
        o.append("  },")
    o.append("};")
    o.append("")
    o.append("static const tv_step tv_steps[%d] = {" % len(steps))
    for st in steps:
        o.append("    {%d,%d,%d,%d,%d,%d}," % st)
    o.append("};")
    o.append("")
    o.append("static const tv_scenario tv_scenarios[%d] = {" % len(scen))
    for name, mode, first, n, fi in scen:
        o.append('    {"%s", %d, %d, %d, %d},' % (name, mode, first, n, fi))
    o.append("};")
    o.append("")
    o.append("static const tv_kv tv_full_kvs[%d] = {" % len(fkv))
    for kv in fkv:
        o.append("    {%d,%d,%d,%d}," % kv)
    o.append("};")
    o.append("")
    o.append("static const tv_full_case tv_full_cases[%d] = {" % len(fo))
    for name, first, n, ri in fo:
        o.append('    {"%s", %d, %d, %d},' % (name, first, n, ri))
    o.append("};")
    o.append("")
    o.append("#endif /* EVM_TRIE_VECTORS_H */")
    with open(out_path, "w", newline="\n") as f:
        f.write("\n".join(o) + "\n")
    return len(steps), len(roots), len(blob)


def main():
    if len(sys.argv) != 3:
        sys.stderr.write(
            "usage: trie_oracle.py <fixtures/state_tests dir> <out.h>\n")
        return 2
    checked = self_check(sys.argv[1])

    ENCODED_SIZES.clear()
    rng = random.Random(0x5145564d)
    scenarios = build(rng)
    boundary_sizes = None
    # re-run the boundary scenario's roots alone to see its node sizes
    for s in scenarios:
        if s.name == "boundary":
            ENCODED_SIZES.clear()
            d = {}
            for op, k, v, _ in s.steps:
                if op == SET:
                    d[k] = v
                else:
                    d.pop(k, None)
                qroot(d, False)
            boundary_sizes = set(ENCODED_SIZES)
    for kind in ("leaf", "branch"):
        for want in (63, 64, 65):
            if (want, kind) not in boundary_sizes:
                raise AssertionError("boundary scenario never encodes a %s "
                                     "of %d bytes" % (kind, want))
    print("boundary: node encodings of 63/64/65 bytes occur; (size, kind) "
          "at those sizes: %s" % sorted((sz, k) for sz, k in boundary_sizes
                                        if sz in (63, 64, 65)))

    full_only = build_full_only()
    n_steps, n_roots, n_blob = emit(scenarios, full_only, checked,
                                    sys.argv[2])
    print("wrote %s: %d scenarios, %d steps, %d roots, %d blob bytes, %d "
          "full-only cases" % (sys.argv[2], len(scenarios), n_steps, n_roots,
                               n_blob, len(full_only)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
