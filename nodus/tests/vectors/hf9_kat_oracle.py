#!/usr/bin/env python3
"""Independent oracle (test T-4) for the HF-9 keyed Patricia legs, the new
composition tags, the rendezvous (HRW) selector, the composition chains of
the proof service, and the vote value D6.

Plan: docs/plans/approved/2026-11-04-hf9.md section 12 row T-4 (approved by
the operator 2026-11-04, "1 eveg 2 duzelt 3 evet"). Output: hf9_kat.json next
to this script.

PROVENANCE (what was read; nothing else)
  Author != the author of the HF-9 C code. No HF-9 C file (no file of the
  worktree that implements plan sections 5, 8.3-8.4, 10 or the new
  shared/evm/trie/evm_trie_proof.*) was opened.
  Written from
    * the approved plan, sections 4.1, 4.2, 6, 7.1, 8.3, 10.1-10.3, 12 (T-4),
      15 (AD-1 .. AD-10), 15a (A1, A2, A3, A5, A8, A9, A13, F-2, F-5, F-7,
      F-9, F-10, F-17, F-23, F-27, F-29);
    * the pinned references (commit / version, path:line cited at the code):
        execution-specs a87891f7e69eab1f903233c61c5514d8c94bd5d1
          src/ethereum/merkle_patricia_trie.py  -- the file is PARSED and
          EXECUTED here (not retyped): see load_reference(). Only two kinds
          of change are applied to its syntax tree: the 32 -> 64 threshold
          constant at :246 and :500, and the names bound for the imports of
          ethereum.crypto.hash.keccak256 (-> SHA3-512, plan 4.1 substitution
          1 and 3), ethereum.state.{Account, Address, Root} (stubs: no
          Account value is ever stored) and ethereum.utils.hexadecimal.
        ethereum-rlp 0.1.6 (sdist sha256 ede36f53...2f3, execution-specs
          uv.lock:1183-1190), src/ethereum_rlp/rlp.py, imported by path; its
          dependency wheels ethereum_types 0.4.1, typing_extensions 4.15.0
          from /home/nocdem/refs/ethereum-rlp-deps/site.
        go-ethereum v1.17.8 a579077007b98217c3e253a66e4b452ca0c32b96
          trie/proof.go:37-95 (Prove: emit a node when len >= threshold or
          it is the first), :111-135 (VerifyProof: index by own hash, walk
          from the root); trie/trie_test.go TestInsert (:175-193), the
          unsubstituted control values are PARSED from that file.
        HRW paper (Thaler & Ravishankar 1998), sha256 00e280e2...e3ef:
          eq. (9) argument order, p. 6; ties p. 9 (plan 8.2). Only through
          the plan's reading of it.
    * EXISTING functions (not HF-9), read because plan 4.2 defines every
      trie value as "the output of the leg's existing leaf-hash function,
      byte-identical (D7)" and 6 keeps "same legs in the same order" with a
      new tag only. Read at the base commit f2ea9d5d0 of this worktree:
        shared/dnac/ledger_roots_v2.c  tags :41-124; tagged_merkle :198-220;
          dna_v2_token_leaf_hash :226-262;
          dna_v2_vset_root leaf :293-320; dna_v2_attendance_leaf_hash
          :351-360; dna_v2_name_leaf_hash :437-449;
          dna_v2_storage_node_leaf_hash :513-534; dna_v2_storage_root
          :665-683; dna_v2_segment_assign_key :743-749; seg_distance
          :752-758 (memcmp order); dna_v2_core_root; dna_v2_system_root_v6
          :1161-1191; dna_v2_segment_leaf_hash_v2 :1195-1210;
          dna_v2_domain_head_hash_v2 / dna_v2_domains_root_v2 :1239-1274;
          dna_v2_global_root_v2 :1336-1345; dna_v2_domain_head_encode
          :869-880.
        shared/dnac/ledger_roots_v2.h :262-305 (A(k), holders(k) text).
        shared/dnac/manifest_wire.c dna_claims_leaf_hash :663-677.
        nodus/src/witness/nodus_witness_merkle.c :78-88 (leaf_hash 0x00),
          :136-187 (the 340-byte untagged UTXO preimage), :371-381.
        dnac/src/ledger/merkle_verify.c :60-65 (client outer 0x00 step).
        shared/dnac/domain_wire.c :290-349 dna_rolegen_vote_digest (the
          preimage layout, read).
        shared/dnac/tests/hf7_vote_oracle.py (read; the RulesetDescriptor
          v2 and meter-policy-identity layouts, and the descriptor contents
          of generations 4 / 5, are taken from it and re-written here; they
          are not independently confirmed except by the CONTROLS that
          reproduce the pinned G4 / G5 hashes, D4 and D5 from the pins
          header and dnac.h).
        shared/dnac/ledger_ids.h :52-53 (domain ids).
        Data parsed at run time (text read, no C called):
          nodus/include/nodus/nodus_ruleset_pins.h NODUS_PIN_G4_* / G5_*,
          dnac/include/dnac/dnac.h DNAC_HF6_FOUNDATION_OWNER, D4, D5,
          nodus/tests/vectors/hf7_root_coverage_kat.json (HF-7 oracle
          vectors, a separately authored source, used as controls for the
          unchanged existing compositions, DomainHead v2, domains_root,
          GLOBAL v2, segment leaf v2).
        shared/evm/tests/addr32_oracle.py keccak256 / keccak_f (FIPS 202
          Keccak-f[1600] from its definition) -- used only for the
          unsubstituted-mode control and the SHA3-512 sponge cross-check.

HONEST LABEL
  Trie structure and roots: GROUNDED. They are produced by executing the
  pinned reference file (with only the substitutions above), and the same
  loader reproduces go-ethereum's TestInsert roots and the reference's
  EMPTY_TRIE_ROOT in unsubstituted mode.
  Leaf / composition / tag / selector / D6 byte layouts: SELF-CONSISTENT
  only. They follow the approved plan and the existing C layouts read above;
  an agreement with the HF-9 C proves two implementations of the same
  decisions agree, not that the decisions are sound (CLAUDE.md:127). For
  the unchanged existing layouts the oracle is a COPY of the existing C
  layouts (it cannot be independent of them); the controls against the
  separately authored HF-7 KAT are the independence evidence for those.
  The plan-defined new bytes (tags, score preimage, ranking, D6 constants,
  step tables) are written from the plan text only.

READINGS (a plan sentence read one way; the reviewer checks each)
  R1  "empty-leg vector of every leg under the new composition tags" (A3 /
      F-7): for every leg L1..L8 a vector in which that leg's root is the
      empty root SHA3-512(0x80) at its position of the new composition,
      every other leg a fixed filler or a fixed non-empty trie root; plus,
      per composition, one vector with every trie leg empty.
  R2  "one complete authenticated composition chain per leg" (A13 / F-29):
      eight chains, each with the batch response fields of plan 10.2 /
      10.3 as JSON content (CBOR bytes not produced, see LEFT OUT); each
      chain's request has two present keys and one absent key.
  R3  The F-23 empty-leg proof vector: for every leg, a chain whose leg
      root is SHA3-512(0x80), nodes empty, every result absent.
  R4  Selector (plan 8.3): the strict-ascent check covers EVERY member of
      the set, eligible or not (the existing selector checks every member,
      ledger_roots_v2.c:765-775); a duplicate or a descending neighbour
      refuses the call. fail_streak >= 3 is ineligible (existing
      DNA_V2_STORAGE_FAIL_LIMIT 3, ledger_roots_v2.h:285-288).
  R5  A real SHA3-512 score tie cannot be constructed; the tie rule is
      emitted as a comparator-only vector with SUPPLIED (score, fp) pairs,
      labelled "injected_scores".
  R6  Root(k) of a segment (a 1,105,948-byte plain hash) is NOT derived;
      A(k) = SHA3-512(TAG16("NDS.STASGN.v1") ‖ Root(k)) is applied to a
      fixed 64-byte fixture standing for Root(k).
  R7  Fixture field values (amounts, heights, statuses, names, ruleset
      versions of the EVM head, domain heights ...) are labelled fixtures:
      every byte string is SHA3-512("hf9_kat/" + label) (counter-extended),
      every integer is the leading bits of such a digest. No random module,
      no clock.
  R8  A trie value for the claims leg is built from a claim entry with
      target_domain_id = 1 (CORE), the only rows plan 4.2 selects.
  R9  The attendance leaf takes its 64-byte digest as an opaque stored
      column (plan 4.2 gives the leaf function dna_v2_attendance_leaf_hash
      (epoch_start, digest)); the digest-from-rows function is not part of
      this oracle.
  R10 Chain height h = 1000 and header height 1001 are fixtures. Domains
      0 (SYSTEM), 1 (CORE) and 2 (a third head, fixture only) are used so
      that the Merkle odd-node promotion rule has a case; its own vectors
      (merkle_steps) cover every index of every n = 1..7.
  R11 SYSTEM ruleset version 12 and CORE 11 for generation 6 with
      "generation-5 descriptors, only ruleset_version bumped" (plan 7.1).

LEFT OUT (plan or reference silent / not this oracle's subject)
  * CBOR byte encodings of the plan 10.2 / 10.3 envelope (no reference
    defines the bytes; the JSON carries the field content).
  * A real score tie (R5); the behaviour for R outside 1..16 (plan 8.3 says
    "explicit runtime argument (1..16)" and does not say what happens
    outside); Root(k) derivation (R6); the tag-collision scan of plan 6
    (the orchestrator's; only a narrow cross-check is run here).
  * shared/dnac/tests/hf9_vote_oracle.py (plan 7.1 names that file for D6;
    this dispatch's whitelist puts D6 in this script instead).

Usage:  python3 -I -B hf9_kat_oracle.py [out.json]
        default output: hf9_kat.json next to this script.
Dependencies: Python 3 standard library; the pinned packages above by path.
"""

import sys

sys.dont_write_bytecode = True      # no __pycache__ in the refs or the tree

import ast  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import struct  # noqa: E402
import types  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
REFS = "/home/nocdem/refs"

EXEC_SPECS = os.path.join(REFS, "execution-specs-a87891f7")
MPT_PY = os.path.join(EXEC_SPECS, "src", "ethereum", "merkle_patricia_trie.py")
EXEC_SPECS_PIN = "a87891f7e69eab1f903233c61c5514d8c94bd5d1"
RLP_SRC = os.path.join(REFS, "ethereum-rlp-0.1.6", "ethereum_rlp-0.1.6", "src")
RLP_PY = os.path.join(RLP_SRC, "ethereum_rlp", "rlp.py")
RLP_DEPS = os.path.join(REFS, "ethereum-rlp-deps", "site")
GETH = os.path.join(REFS, "go-ethereum-v1.17.8")
GETH_PIN = "a579077007b98217c3e253a66e4b452ca0c32b96"
GETH_PROOF = os.path.join(GETH, "trie", "proof.go")
GETH_TRIE_TEST = os.path.join(GETH, "trie", "trie_test.go")
HRW_PDF = os.path.join(REFS, "papers", "HRW_1998_Thaler_Ravishankar.pdf")
HRW_SHA256 = ("00e280e2ccbd3bdc9cfa5dea05e188da666c63247700e9e351f3d04c14b5e3"
              "ef")
KECCAK_PY = os.path.join(REPO, "shared", "evm", "tests", "addr32_oracle.py")
PINS_H = os.path.join(REPO, "nodus", "include", "nodus",
                      "nodus_ruleset_pins.h")
DNAC_H = os.path.join(REPO, "dnac", "include", "dnac", "dnac.h")
HF7_KAT = os.path.join(HERE, "hf7_root_coverage_kat.json")
LEDGER_C = os.path.join(REPO, "shared", "dnac", "ledger_roots_v2.c")
MANIFEST_C = os.path.join(REPO, "shared", "dnac", "manifest_wire.c")

# mypy_extensions 1.1.0 is only present as a wheel (a zip): zipimport
sys.path.insert(0, os.path.join(REFS, "ethereum-rlp-deps",
                                "mypy_extensions-1.1.0-py3-none-any.whl"))
sys.path.insert(0, RLP_DEPS)
sys.path.insert(0, RLP_SRC)
import ethereum_rlp  # noqa: E402  (pinned 0.1.6, by path)
from ethereum_rlp import rlp as rlp_mod  # noqa: E402

CHECKS = []          # (name, ok, detail) in order, printed before output


def check(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))
    print("  %-4s %s%s" % ("OK" if ok else "FAIL", name,
                           (" -- " + detail) if detail else ""))
    if not ok:
        print("SELF-CHECK FAILED -- nothing is written")
        sys.exit(1)


# ── primitives ──────────────────────────────────────────────────────────

def sha3(b):
    return hashlib.sha3_512(bytes(b)).digest()


def be2(x):
    return struct.pack(">H", x)


def be4(x):
    return struct.pack(">I", x)


def be8(x):
    return struct.pack(">Q", x)


def le4(x):
    return struct.pack("<I", x)


def le8(x):
    return struct.pack("<Q", x)


def tag16(s):
    raw = s.encode("ascii")
    assert len(raw) <= 16
    return raw + b"\x00" * (16 - len(raw))


def lab(label, n=64):
    """R7: n deterministic bytes = SHA3-512("hf9_kat/" + label [/ counter])."""
    out = b""
    i = 0
    while len(out) < n:
        out += sha3(b"hf9_kat/" + label.encode("ascii") +
                    (b"" if i == 0 else b"/" + str(i).encode("ascii")))
        i += 1
    return out[:n]


def labint(label, bits):
    return int.from_bytes(sha3(b"hf9_kat/" + label.encode("ascii"))[:8],
                          "big") >> (64 - bits)


def X(b):
    return bytes(b).hex()


def D(n):
    return str(int(n))


EMPTY_ROOT = sha3(b"\x80")           # plan 4.1 substitution 4

# tags (16 bytes, zero padded) -- the existing ones read at the cited lines,
# the three new composition tags and the rendezvous tag from the plan
T_CORE_V4 = "NDS.CORE.v4"            # plan 6, D23
T_STOR_V3 = "NDS.STOR.v3"            # plan 6, AD-4
T_SYS_V7 = "NDS.SYS.v7"              # plan 6, AD-4
T_STHRW = "NDS.STHRW.v1"             # plan 8.3, AD-5
T_STASGN = "NDS.STASGN.v1"           # ledger_roots_v2.c:108
T_DOMHEAD2 = "NDS.DOMHEAD.v2"        # :121
T_DOMNODE = "NDS.DOMNODE.v1"         # :55
T_GLOBAL2 = "NDS.GLOBAL.v2"          # :124
T_TOKLEAF = "NDS.TOKLEAF.v1"         # :49
T_NMLEAF = "NDS.NMLEAF.v1"           # :78
T_CLLEAF = "NDS.CLLEAF.v1"           # manifest_wire.c:28
T_STLEAF2 = "NDS.STLEAF.v2"          # :93
T_STSGLEAF2 = "NDS.STSGLEAF.v2"      # :120
T_VSLEAF = "NDS.VSLEAF.v1"           # :56
T_ATLEAF = "NDS.ATLEAF.v1"           # :62
T_CORE_V2 = "NDS.CORE.v2"            # :46 (control only)
T_STOR_V2 = "NDS.STOR.v2"            # :92 (control only)
T_SYS_V6 = "NDS.SYS.v6"              # :119 (control only)
T_STSGNODE = "NDS.STSGNODE.v1"       # :107 (control only)

LEG_NAMES = {1: "utxo", 2: "tokens", 3: "claims", 4: "names",
             5: "registry", 6: "segments", 7: "vset", 8: "attendance"}
CORE_LEGS = ["utxo", "token", "pools", "claims", "name", "supply", "accrual"]
STOR_LEGS = ["registry", "sets", "reports", "segments"]
SYS_LEGS = ["validator", "delegation", "chain_config", "validator_set",
            "domain_registry", "manifest", "attendance", "treasury",
            "storage", "bcopy", "vstat", "stmem"]
# leg -> (composition, position)   plan 6 and 10.3
LEG_POS = {1: ("CORE", 0), 2: ("CORE", 1), 3: ("CORE", 3), 4: ("CORE", 4),
           5: ("STOR", 0), 6: ("STOR", 3), 7: ("SYS", 3), 8: ("SYS", 6)}
STOR_IN_SYS = 8
DOMAIN_SYSTEM, DOMAIN_CORE, DOMAIN_EVM = 0, 1, 2   # ledger_ids.h:52-53, 60
LEG_DOMAIN = {1: DOMAIN_CORE, 2: DOMAIN_CORE, 3: DOMAIN_CORE, 4: DOMAIN_CORE,
              5: DOMAIN_SYSTEM, 6: DOMAIN_SYSTEM, 7: DOMAIN_SYSTEM,
              8: DOMAIN_SYSTEM}


# ── SHA3-512 cross-check (FIPS 202 sponge over addr32_oracle.keccak_f) ──

def load_keccak_module():
    spec = importlib.util.spec_from_file_location("addr32_oracle", KECCAK_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha3_512_sponge(keccak_f, data):
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
            a[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8],
                                               "little")
        a = keccak_f(a)
    out = b""
    for i in range(8):
        out += a[i % 5][i // 5].to_bytes(8, "little")
    return out


# ── the reference trie: parsed from the pinned file and executed ───────

class Ref:
    """execution-specs merkle_patricia_trie.py with H and T substituted.

    H(bytes) -> digest replaces ethereum.crypto.hash.keccak256 (three call
    sites: :246-249 node digest, :441-445 secured key, :500-503 root).
    T replaces the two threshold constants 32 (:246, :500).
    Every H call stores {digest: input} in self.db; the node database used
    by prove() is read from it (a hashed node's RLP is exactly what the
    reference hashes).
    """

    count = 0

    def __init__(self, H, T, hlen):
        self.H, self.T, self.hlen = H, T, hlen
        self.db = {}
        src = open(MPT_PY, "r", encoding="utf-8").read()
        tree = ast.parse(src, MPT_PY)
        dropped = []
        keep = []
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module and \
                    node.module.split(".")[0] == "ethereum":
                dropped.append(node.module)
                continue
            keep.append(node)
        assert sorted(dropped) == ["ethereum.crypto.hash",
                                   "ethereum.state",
                                   "ethereum.utils.hexadecimal"], dropped
        tree.body = keep
        self.patched = 0
        outer = self

        class Patch(ast.NodeTransformer):
            def visit_Compare(self, n):
                self.generic_visit(n)
                if (isinstance(n.left, ast.Call) and
                        isinstance(n.left.func, ast.Name) and
                        n.left.func.id == "len" and
                        len(n.ops) == 1 and isinstance(n.ops[0], ast.Lt) and
                        isinstance(n.comparators[0], ast.Constant) and
                        n.comparators[0].value == 32 and
                        type(n.comparators[0].value) is int):
                    n.comparators[0] = ast.copy_location(
                        ast.Constant(value=T), n.comparators[0])
                    outer.patched += 1
                return n

        before = [n for n in ast.walk(tree)
                  if isinstance(n, ast.Constant) and type(n.value) is int and
                  n.value == 32]
        tree = Patch().visit(tree)
        ast.fix_missing_locations(tree)
        # the file holds exactly two int constants 32 and both are the
        # thresholds (:246, :500)
        assert self.patched == 2 and len(before) == 2, \
            (self.patched, len(before))
        calls = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and
                 isinstance(n.func, ast.Name) and n.func.id == "keccak256"]
        assert len(calls) == 3, len(calls)

        class _Account:     # stub: never instantiated, isinstance is False
            pass

        def keccak256(data):
            d = H(bytes(data))
            self.db[d] = bytes(data)
            return d

        def hex_to_bytes(s):
            return bytes.fromhex(s[2:] if s.startswith("0x") else s)

        # a registered module object: dataclasses looks its module up
        Ref.count += 1
        modname = "hf9_ref_merkle_patricia_trie_%d" % Ref.count
        mod = types.ModuleType(modname)
        sys.modules[modname] = mod
        ns = mod.__dict__
        ns.update({"keccak256": keccak256, "Account": _Account,
                   "Address": bytes, "Root": lambda b: b,
                   "hex_to_bytes": hex_to_bytes})
        exec(compile(tree, MPT_PY, "exec"), ns)
        self.ns = ns

    def root(self, items, secured=True, order=None):
        """items: dict preimage-key -> value bytes (opaque, non-empty)."""
        trie = self.ns["Trie"](secured, None)
        keys = list(items.keys()) if order is None else order
        for k in keys:
            self.ns["trie_set"](trie, k, items[k])
        return bytes(self.ns["root"](trie))

    def path(self, key, secured=True):
        k = self.H(key) if secured else key
        return bytes(self.ns["bytes_to_nibble_list"](k))


def nibbles_of(b):
    out = []
    for x in b:
        out += [x >> 4, x & 15]
    return out


def compact_decode(c):
    """Inverse of nibble_list_to_compact (:355-382)."""
    flag = c[0] >> 4
    leaf = bool(flag & 2)
    odd = flag & 1
    nibs = [c[0] & 15] if odd else []
    for b in c[1:]:
        nibs += [b >> 4, b & 15]
    return leaf, nibs


class ProofError(Exception):
    pass


def _decode(enc):
    d = rlp_mod.decode(enc)
    return d


def _walk(read_node, root_ref_enc, path):
    """Shared walk. read_node(hash) -> encoding or None. Returns
    (kind, value, emitted_hashes) with kind 'present' | 'absent'."""
    key = list(path)
    enc = root_ref_enc
    emitted = [None]            # None = the root (always emitted)
    node = _decode(enc)
    while True:
        if isinstance(node, bytes):
            raise ProofError("node is a string")
        if len(node) == 17:
            if not key:
                v = bytes(node[16])
                return ("present", v, emitted) if v else \
                    ("absent", None, emitted)
            child = node[key[0]]
            key = key[1:]
        elif len(node) == 2:
            leaf, nibs = compact_decode(bytes(node[0]))
            if leaf:
                if key == nibs:
                    return ("present", bytes(node[1]), emitted)
                return ("absent", None, emitted)
            if key[:len(nibs)] != nibs:
                return ("absent", None, emitted)    # mismatching extension
            key = key[len(nibs):]
            child = node[1]
        else:
            raise ProofError("node has %d items" % len(node))
        if isinstance(child, bytes):
            if len(child) == 0:
                return ("absent", None, emitted)    # nil child
            enc2 = read_node(bytes(child))
            if enc2 is None:
                raise ProofError("missing node %s" % bytes(child).hex()[:16])
            emitted.append(bytes(child))
            node = _decode(enc2)
        else:
            node = child                            # embedded (inline) node


def prove(ref, root_hash, key_preimage, secured=True):
    """proof.go:37-95: nodes on the path; the first always, others when
    their encoding is >= the threshold (every hashed node is)."""
    path = nibbles_of(ref.H(key_preimage) if secured else key_preimage)
    root_enc = ref.db[root_hash]
    kind, val, emitted = _walk(lambda h: ref.db.get(h), root_enc, path)
    nodes = [root_enc]
    for h in emitted[1:]:
        nodes.append(ref.db[h])
    return nodes


def verify(H, root_hash, key_preimage, nodes, secured=True):
    """proof.go:111-135: index by the verifier's own hash; walk from the
    authenticated root; a missing node is an error, never absence."""
    idx = {H(n): n for n in nodes}
    if root_hash not in idx:
        raise ProofError("root node missing")
    path = nibbles_of(H(key_preimage) if secured else key_preimage)
    kind, val, _ = _walk(lambda h: idx.get(h), idx[root_hash], path)
    return kind, val


def node_kind(ref, root_hash):
    n = _decode(ref.db[root_hash])
    if len(n) == 17:
        return "branch"
    leaf, nibs = compact_decode(bytes(n[0]))
    return "leaf" if leaf else "extension"


# ── tagged merkle (existing: ledger_roots_v2.c:198-220) ────────────────

def tagged_merkle(tag, leaves):
    level = list(leaves)
    assert level
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(sha3(tag16(tag) + level[i] + level[i + 1]))
        if len(level) & 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def merkle_siblings(tag, leaves, i):
    """Builder side: explicit levels; returns (sibs, root)."""
    level = list(leaves)
    sibs = []
    while len(level) > 1:
        nxt = []
        for j in range(0, len(level) - 1, 2):
            nxt.append(sha3(tag16(tag) + level[j] + level[j + 1]))
        if len(level) & 1:
            nxt.append(level[-1])
        if i % 2 == 1:
            sibs.append(level[i - 1])
        elif i + 1 < len(level):
            sibs.append(level[i + 1])
        level = nxt
        i //= 2
    return sibs, level[0]


def verify_merkle_step(tag, n, i, sibs, x):
    """F-27 / A13 rule, verifier side (plan 10.3 table row 3)."""
    if n < 1 or not (0 <= i < n):
        raise ProofError("merkle: bad n/i")
    used = 0
    while n > 1:
        if i % 2 == 0 and i + 1 < n:
            if used >= len(sibs):
                raise ProofError("merkle: too few siblings")
            x = sha3(tag16(tag) + x + sibs[used])
            used += 1
        elif i % 2 == 1:
            if used >= len(sibs):
                raise ProofError("merkle: too few siblings")
            x = sha3(tag16(tag) + sibs[used] + x)
            used += 1
        # else i == n-1 with n odd: promoted unchanged
        n = (n + 1) // 2
        i //= 2
    if used != len(sibs):
        raise ProofError("merkle: unconsumed siblings")
    return x


# ── leaf-value functions of the eight legs (existing layouts, D7) ───────

def utxo_preimage340(nullifier, owner, amount, token_id, tx_hash, out_idx,
                     unlock):
    ob = owner.encode("ascii")
    assert len(ob) <= 128
    ob = ob + b"\x00" * (128 - len(ob))
    pre = (nullifier + ob + le8(amount) + token_id + tx_hash +
           le4(out_idx) + le8(unlock))
    assert len(nullifier) == 64 and len(token_id) == 64 and \
        len(tx_hash) == 64 and len(pre) == 340
    return pre


def utxo_value(pre340):
    d = sha3(pre340)                         # D: inner digest, never a value
    return d, sha3(b"\x00" + d)              # trie value (D21, AD-2)


def token_leaf(token_id, decimals, flags, supply, height, name, symbol,
               creator_fp):
    pre = (tag16(T_TOKLEAF) + token_id + bytes([decimals, flags]) +
           be8(supply) + be8(height) + be2(len(name)) + name +
           be2(len(symbol)) + symbol + be2(len(creator_fp)) + creator_fp)
    return pre, sha3(pre)


def claims_leaf(nullifier, manifest_hash, domain, leaf_index, amount,
                claimed_height):
    pre = (tag16(T_CLLEAF) + nullifier + manifest_hash + be4(domain) +
           be8(leaf_index) + be8(amount) + be8(claimed_height))
    assert len(pre) == 172
    return pre, sha3(pre)


def name_leaf(name, owner, registered_height):
    assert 1 <= len(name) <= 36
    pre = (tag16(T_NMLEAF) + bytes([len(name)]) + name + owner +
           be8(registered_height))
    return pre, sha3(pre)


def registry_leaf(node_fp, payee_fp, bond, status, reg_h, exit_h, streak,
                  grace):
    assert 1 <= status <= 3
    pre = (tag16(T_STLEAF2) + node_fp + payee_fp + be8(bond) +
           bytes([status]) + be8(reg_h) + be8(exit_h) + be4(streak) +
           be8(grace))
    assert len(pre) == 181
    return pre, sha3(pre)


def segment_leaf_v2(k, root_k, pub_h):
    assert 1 <= k <= (1 << 63) - 1 and 1 <= pub_h <= (1 << 63) - 1
    pre = tag16(T_STSGLEAF2) + be8(k) + root_k + be8(pub_h)
    assert len(pre) == 96
    return pre, sha3(pre)


def vset_leaf(epoch, snapshot_hash):
    pre = tag16(T_VSLEAF) + be8(epoch) + snapshot_hash
    return pre, sha3(pre)


def attendance_leaf(epoch, digest):
    pre = tag16(T_ATLEAF) + be8(epoch) + digest
    return pre, sha3(pre)


def make_row(leg, idx):
    """Deterministic record of leg `leg`, index idx (R7). Returns dict:
    key (bytes), value (bytes), rec (JSON-ready dict), pre (leaf preimage)."""
    L = LEG_NAMES[leg]
    p = "%s/%d/" % (L, idx)
    if leg == 1:
        nul = lab(p + "nullifier")
        owner = lab(p + "owner").hex()                    # 128 hex chars
        amount = labint(p + "amount", 40)
        tok = lab(p + "token_id")
        txh = lab(p + "tx_hash")
        oi = labint(p + "output_index", 8)
        ub = labint(p + "unlock_block", 32)
        pre = utxo_preimage340(nul, owner, amount, tok, txh, oi, ub)
        d, val = utxo_value(pre)
        rec = {"nullifier": X(nul), "owner": owner, "amount": D(amount),
               "token_id": X(tok), "tx_hash": X(txh),
               "output_index": D(oi), "unlock_block": D(ub),
               "preimage340": X(pre), "inner_digest_D": X(d)}
        return {"key": nul, "value": val, "rec": rec, "pre": pre}
    if leg == 2:
        tid = lab(p + "token_id")
        name = ("Token%d" % idx).encode()
        sym = ("TK%d" % idx).encode()
        cfp = lab(p + "creator").hex().encode()
        dec, flg = 8, idx % 4
        sup = labint(p + "supply", 50)
        bh = labint(p + "block_height", 30)
        pre, val = token_leaf(tid, dec, flg, sup, bh, name, sym, cfp)
        rec = {"token_id": X(tid), "decimals": D(dec), "flags": D(flg),
               "supply": D(sup), "block_height": D(bh),
               "name": name.decode(), "symbol": sym.decode(),
               "creator_fp": cfp.decode(), "preimage": X(pre)}
        return {"key": tid, "value": val, "rec": rec, "pre": pre}
    if leg == 3:
        nul = lab(p + "nullifier")
        mh = lab(p + "manifest_hash")
        li = labint(p + "leaf_index", 20)
        amt = labint(p + "amount", 40)
        ch = labint(p + "claimed_height", 30)
        pre, val = claims_leaf(nul, mh, DOMAIN_CORE, li, amt, ch)
        rec = {"nullifier": X(nul), "manifest_hash": X(mh),
               "target_domain_id": D(DOMAIN_CORE), "leaf_index": D(li),
               "amount": D(amt), "claimed_height": D(ch),
               "preimage": X(pre)}
        return {"key": nul, "value": val, "rec": rec, "pre": pre}
    if leg == 4:
        ln = 3 + (idx * 7) % 34                          # 3..36
        name = lab(p + "name", 32).hex()[:ln].encode("ascii")
        own = lab(p + "owner")
        rh = labint(p + "registered_height", 30)
        pre, val = name_leaf(name, own, rh)
        rec = {"name": name.decode(), "owner": X(own),
               "registered_height": D(rh), "preimage": X(pre)}
        return {"key": name, "value": val, "rec": rec, "pre": pre}
    if leg == 5:
        pk = lab(p + "pk_fixture", 128)
        fp = sha3(pk)             # row check of plan 4.2: fp = SHA3-512(pk)
        payee = lab(p + "payee")
        bond = labint(p + "bond", 50)
        status = 1 + idx % 3
        rh = labint(p + "registered_height", 30)
        eh = 0 if status == 1 else labint(p + "exit_height", 30)
        fs = idx % 4
        gu = labint(p + "grace_until", 30)
        pre, val = registry_leaf(fp, payee, bond, status, rh, eh, fs, gu)
        rec = {"node_pk_fixture": X(pk), "node_fp": X(fp),
               "payee_fp": X(payee), "bond": D(bond), "status": D(status),
               "registered_height": D(rh), "exit_height": D(eh),
               "fail_streak": D(fs), "grace_until": D(gu),
               "preimage": X(pre)}
        return {"key": fp, "value": val, "rec": rec, "pre": pre}
    if leg == 6:
        k = idx + 1
        rk = lab(p + "Root_k_fixture")
        ph = 1 + labint(p + "published_height", 30)
        pre, val = segment_leaf_v2(k, rk, ph)
        rec = {"k": D(k), "root_k_fixture": X(rk),
               "published_height": D(ph), "preimage": X(pre)}
        return {"key": be8(k), "value": val, "rec": rec, "pre": pre}
    if leg == 7:
        e = 720 * idx + 1
        sh = lab(p + "snapshot_hash")
        pre, val = vset_leaf(e, sh)
        rec = {"epoch_start": D(e), "snapshot_hash": X(sh),
               "preimage": X(pre)}
        return {"key": be8(e), "value": val, "rec": rec, "pre": pre}
    if leg == 8:
        e = 720 * idx + 1
        dg = lab(p + "digest")
        pre, val = attendance_leaf(e, dg)
        rec = {"epoch_start": D(e), "digest": X(dg), "preimage": X(pre)}
        return {"key": be8(e), "value": val, "rec": rec, "pre": pre}
    raise AssertionError(leg)


def absent_key(leg, idx):
    """A canonical key of leg `leg` that is in no row set (R7)."""
    p = "absent/%s/%d" % (LEG_NAMES[leg], idx)
    if leg in (1, 2, 3, 5):
        return lab(p)
    if leg == 4:
        return lab(p, 32).hex()[:5 + idx % 20].encode("ascii")
    return be8(900000 + idx)           # 6, 7, 8


# ── controls and the trie vectors ─────────────────────────────────────

def parse_geth_test_inserts():
    """trie_test.go TestInsert: [(items, expected_root_hex)] x 2."""
    src = open(GETH_TRIE_TEST, "r", encoding="utf-8").read()
    m = re.search(r"func TestInsert\(t \*testing\.T\) \{(.*?)\n\}\n", src,
                  re.S)
    body = m.group(1)
    cases = []
    cur = []
    for ln in body.split("\n"):
        u = re.search(r'updateString\(trie, "([^"]*)", "([^"]*)"\)', ln)
        e = re.search(r'common\.HexToHash\("([0-9a-f]{64})"\)', ln)
        if u:
            cur.append((u.group(1).encode(), u.group(2).encode()))
        if e:
            cases.append((cur, e.group(1)))
            cur = []
    return cases


def controls_trie(refS, keccak256, keccak_f):
    """Run every self-check that gates the output (returns the unsub ref)."""
    print("-- CONTROLS: trie reference ----------------------------------")
    # pins
    head = open(os.path.join(EXEC_SPECS, ".git", "refs", "heads", "forks",
                             "amsterdam")).read().strip()
    check("execution-specs checkout = pin %s" % EXEC_SPECS_PIN[:8],
          head == EXEC_SPECS_PIN)
    check("go-ethereum checkout = pin %s" % GETH_PIN[:8],
          open(os.path.join(GETH, ".git", "HEAD")).read().strip() == GETH_PIN)
    check("HRW paper sha256",
          hashlib.sha256(open(HRW_PDF, "rb").read()).hexdigest() ==
          HRW_SHA256)
    check("ethereum_rlp is 0.1.6", ethereum_rlp.__version__ == "0.1.6")
    # SHA3-512
    for n in (0, 1, 71, 72, 73, 144, 200):
        d = bytes(range(256)) * 2
        check("SHA3-512 sponge == hashlib, len %d" % n,
              sha3_512_sponge(keccak_f, d[:n]) == sha3(d[:n]))
    # reference loader facts
    check("patched thresholds (32 -> 64) at exactly 2 sites",
          refS.patched == 2)
    # unsubstituted mode
    refU = Ref(keccak256, 32, 32)
    emp = refU.root({}, secured=True)
    check("unsubstituted: empty root == reference EMPTY_TRIE_ROOT (:71-75)",
          emp == bytes(refU.ns["EMPTY_TRIE_ROOT"]) and
          emp.hex() == "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc0016"
          "22fb5e363b421")
    cases = parse_geth_test_inserts()
    check("go-ethereum TestInsert parsed: 2 cases", len(cases) == 2 and
          len(cases[0][0]) == 3 and len(cases[1][0]) == 1)
    for n, (kvs, exp) in enumerate(cases, 1):
        items = dict(kvs)
        got = refU.root(items, secured=False)
        check("unsubstituted: go-ethereum TestInsert case %d root" % n,
              got.hex() == exp, got.hex()[:16])
    # proofs in unsubstituted mode over the TestInsert case 1 trie
    kvs = cases[0][0]
    items = dict(kvs)
    rt = refU.root(items, secured=False)
    for k, v in kvs + [(b"unknown", None), (b"do", None)]:
        nodes = prove(refU, rt, k, secured=False)
        kind, val = verify(keccak256, rt, k, nodes, secured=False)
        check("unsubstituted: prove/verify %r" % k,
              (kind, val) == (("present", v) if v else ("absent", None)))
    return refU


def controls_rlp(keccak_mod):
    cases = [b"", b"\x00", b"\x7f", b"\x80", b"a" * 55, b"a" * 56,
             b"a" * 300, [], [b"cat", b"dog"], [[b"", [b"x" * 60]], b"y"],
             [b"z" * 70] * 3]

    def mine(x):
        if isinstance(x, bytes):
            return keccak_mod.rlp_bytes(x)
        return keccak_mod.rlp_list([mine(i) for i in x])

    ok = all(bytes(rlp_mod.encode(c if isinstance(c, bytes) else tuple(
        tuple(i) if isinstance(i, list) else i for i in c))) == mine(c)
        for c in cases)
    check("ethereum_rlp.encode == addr32_oracle RLP on %d inputs" % len(cases),
          ok)


def trie_of_rows(ref, rows):
    items = {r["key"]: r["value"] for r in rows}
    assert len(items) == len(rows)
    return ref.root(items)


def controls_substituted(ref):
    print("-- CONTROLS: substituted trie --------------------------------")
    check("empty root == SHA3-512(0x80)", ref.root({}) == EMPTY_ROOT)
    r = make_row(2, 0)
    one = ref.root({r["key"]: r["value"]})
    enc = ref.db[one]
    check("single-leaf root node is 135 bytes (plan 10.2)", len(enc) == 135)
    leaf, nibs = compact_decode(bytes(_decode(enc)[0]))
    check("single-leaf path = the 128 nibbles of SHA3-512(key)",
          leaf and nibs == nibbles_of(sha3(r["key"])) and len(nibs) == 128)
    rows = [make_row(1, i) for i in range(32)]
    items = {x["key"]: x["value"] for x in rows}
    a = ref.root(items)
    b = ref.root(items, order=list(reversed(list(items))))
    c = ref.root(items, order=sorted(items))
    check("32-key root independent of insertion order", a == b == c)
    # compact round trip against the reference's own encoder
    ok = True
    for ln in range(0, 9):
        for leaf_flag in (False, True):
            nb = [(i * 5 + ln) % 16 for i in range(ln)]
            cmp = bytes(ref.ns["nibble_list_to_compact"](bytes(nb),
                                                         leaf_flag))
            ok = ok and compact_decode(cmp) == (leaf_flag, nb)
    check("compact_decode inverts the reference nibble_list_to_compact", ok)


def trie_vectors(ref):
    """Leg vectors, row-set roots, structure vectors. Returns dict + the
    n=5 chain roots/rows (used again by chains)."""
    leg_vectors = []
    row_sets = []
    for leg in range(1, 9):
        r = make_row(leg, 1)
        path = sha3(r["key"])
        single = ref.root({r["key"]: r["value"]})
        vec = {"leg": leg, "leg_name": LEG_NAMES[leg],
               "key": X(r["key"]), "key_len": len(r["key"]),
               "path_sha3_512_of_key": X(path),
               "path_nibbles": len(nibbles_of(path)),
               "record": r["rec"], "value_preimage": X(r["pre"]),
               "value": X(r["value"]),
               "single_leaf_trie": {"root": X(single),
                                    "root_node_rlp_len": len(ref.db[single]),
                                    "root_node_rlp": X(ref.db[single])}}
        if leg == 1:
            vec["utxo"] = {
                "preimage340": r["rec"]["preimage340"],
                "preimage340_len": 340,
                "inner_digest_D": r["rec"]["inner_digest_D"],
                "outer_input": "00" + r["rec"]["inner_digest_D"],
                "trie_value_sha3_512_0x00_D": X(r["value"]),
                "D_is_not_the_value": r["rec"]["inner_digest_D"] !=
                X(r["value"])}
            # NUL-padded short owner variant (nodus_witness_merkle.c:136-
            # 187: owner strings shorter than 128 are NUL padded)
            ob = "abcdef0123456789"
            pre = utxo_preimage340(lab("utxo/short/n"), ob, 12345,
                                   lab("utxo/short/t"), lab("utxo/short/x"),
                                   7, 99)
            d, v = utxo_value(pre)
            vec["utxo"]["short_owner_variant"] = {
                "owner": ob, "preimage340": X(pre), "inner_digest_D": X(d),
                "trie_value": X(v), "owner_bytes_128_nul_padded":
                X(pre[64:192])}
        leg_vectors.append(vec)

        sets = []
        pool = [make_row(leg, i) for i in range(16)]
        assert len({x["key"] for x in pool}) == 16
        for n in (0, 1, 2, 3, 16):
            rows = pool[:n]
            root = trie_of_rows(ref, rows)
            srt = sorted(rows, key=lambda z: z["key"])
            sets.append({
                "n": n, "root": X(root),
                "root_node": ("empty" if n == 0 else node_kind(ref, root)),
                "rows_sorted_by_key": [
                    {"key": X(z["key"]), "path": X(sha3(z["key"])),
                     "value": X(z["value"])} for z in srt]})
        # an extension at the root: two rows whose paths share >= 3 nibbles
        base = make_row(leg, 0)
        bp = nibbles_of(sha3(base["key"]))
        pair = None
        for j in range(1, 40000):
            other = make_row(leg, 1000 + j)
            op = nibbles_of(sha3(other["key"]))
            sh = 0
            while sh < 128 and bp[sh] == op[sh]:
                sh += 1
            if sh >= 3:
                pair = (other, sh)
                break
        assert pair is not None
        rows = [base, pair[0]]
        root = trie_of_rows(ref, rows)
        assert node_kind(ref, root) == "extension"
        sets.append({"n": 2, "kind": "extension_at_root",
                     "shared_nibbles": pair[1], "root": X(root),
                     "root_node": "extension",
                     "rows_sorted_by_key": [
                         {"key": X(z["key"]), "path": X(sha3(z["key"])),
                          "value": X(z["value"])}
                         for z in sorted(rows, key=lambda z: z["key"])]})
        row_sets.append({"leg": leg, "leg_name": LEG_NAMES[leg],
                         "sets": sets})
    return leg_vectors, row_sets


# ── compositions ───────────────────────────────────────────────────────

def compose(tag, legs):
    for x in legs:
        assert len(x) == 64
    return sha3(tag16(tag) + b"".join(legs))


FILL = {n: lab("filler/" + n) for n in
        ["pools", "supply", "accrual", "sets", "reports", "validator",
         "delegation", "chain_config", "domain_registry", "manifest",
         "treasury", "bcopy", "vstat", "stmem", "replay", "evm_state",
         "luh0", "luh1", "luh2"]}


def build_state(roots, core_tag=T_CORE_V4, stor_tag=T_STOR_V3,
                sys_tag=T_SYS_V7):
    core_legs = [roots[1], roots[2], FILL["pools"], roots[3], roots[4],
                 FILL["supply"], FILL["accrual"]]
    stor_legs = [roots[5], FILL["sets"], FILL["reports"], roots[6]]
    stor = compose(stor_tag, stor_legs)
    sys_legs = [FILL["validator"], FILL["delegation"], FILL["chain_config"],
                roots[7], FILL["domain_registry"], FILL["manifest"],
                roots[8], FILL["treasury"], stor, FILL["bcopy"],
                FILL["vstat"], FILL["stmem"]]
    core = compose(core_tag, core_legs)
    sysr = compose(sys_tag, sys_legs)
    return {"core_legs": core_legs, "stor_legs": stor_legs,
            "sys_legs": sys_legs, "stor": stor, "core": core, "sys": sysr}


def domain_head(domain_id, state_root, height, lu, rv, status):
    assert len(state_root) == 64
    return (be4(domain_id) + state_root + be8(height) + be8(lu) + be4(rv) +
            bytes([status]))


def head_hash_v2(head89, luh):
    assert len(head89) == 89
    return sha3(tag16(T_DOMHEAD2) + head89 + luh)


H_CHAIN = 1000          # R10
SYS_RV_G6, CORE_RV_G6 = 12, 11


def build_world(roots):
    st = build_state(roots)
    heads = [
        domain_head(DOMAIN_SYSTEM, st["sys"], H_CHAIN, H_CHAIN - 3,
                    SYS_RV_G6, 1),
        domain_head(DOMAIN_CORE, st["core"], H_CHAIN, H_CHAIN - 1,
                    CORE_RV_G6, 1),
        domain_head(DOMAIN_EVM, FILL["evm_state"], H_CHAIN, H_CHAIN - 7,
                    1 + labint("evm/rv", 4), 1),
    ]
    lu = [FILL["luh0"], FILL["luh1"], FILL["luh2"]]
    hh = [head_hash_v2(h, l) for h, l in zip(heads, lu)]
    domains_root = tagged_merkle(T_DOMNODE, hh)
    g = compose(T_GLOBAL2, [domains_root, FILL["replay"]])
    st.update({"heads": heads, "luhs": lu, "head_hashes": hh,
               "domains_root": domains_root, "app_hash": g})
    return st


def compiled_sequence(leg):
    """Compiled contract of plan 10.3 (tags, leg counts, positions)."""
    comp, pos = LEG_POS[leg]
    seq = []
    if comp == "CORE":
        seq.append(("COMPOSE", T_CORE_V4, 7, pos))
    elif comp == "STOR":
        seq.append(("COMPOSE", T_STOR_V3, 4, pos))
        seq.append(("COMPOSE", T_SYS_V7, 12, STOR_IN_SYS))
    else:
        seq.append(("COMPOSE", T_SYS_V7, 12, pos))
    seq.append(("HEAD", LEG_DOMAIN[leg]))
    seq.append(("MERKLE", T_DOMNODE))
    seq.append(("COMPOSE", T_GLOBAL2, 2, 0))
    return seq


def build_cp(leg, world):
    comp, pos = LEG_POS[leg]
    cp = []
    if comp == "CORE":
        cp.append({"t": 1, "tag": X(tag16(T_CORE_V4)),
                   "legs": [X(x) for x in world["core_legs"]], "i": pos})
    elif comp == "STOR":
        cp.append({"t": 1, "tag": X(tag16(T_STOR_V3)),
                   "legs": [X(x) for x in world["stor_legs"]], "i": pos})
        cp.append({"t": 1, "tag": X(tag16(T_SYS_V7)),
                   "legs": [X(x) for x in world["sys_legs"]],
                   "i": STOR_IN_SYS})
    else:
        cp.append({"t": 1, "tag": X(tag16(T_SYS_V7)),
                   "legs": [X(x) for x in world["sys_legs"]], "i": pos})
    di = LEG_DOMAIN[leg]            # SYSTEM 0 / CORE 1 are the head indexes
    cp.append({"t": 2, "head": X(world["heads"][di]),
               "luh": X(world["luhs"][di])})
    sibs, root = merkle_siblings(T_DOMNODE, world["head_hashes"], di)
    assert root == world["domains_root"]
    cp.append({"t": 3, "tag": X(tag16(T_DOMNODE)),
               "n": len(world["head_hashes"]), "i": di,
               "sib": [X(s) for s in sibs]})
    cp.append({"t": 1, "tag": X(tag16(T_GLOBAL2)),
               "legs": [X(world["domains_root"]), X(FILL["replay"])],
               "i": 0})
    return cp


def verify_chain(leg, lr, cp, app_hash):
    """Verifier of plan 10.3 over the JSON content only. Returns the
    AppHash computed; raises ProofError on any compiled-contract breach."""
    seq = compiled_sequence(leg)
    if len(cp) != len(seq):
        raise ProofError("step count")
    x = lr
    for step, want in zip(cp, seq):
        if want[0] == "COMPOSE":
            if step["t"] != 1:
                raise ProofError("t")
            tag = bytes.fromhex(step["tag"])
            legs = [bytes.fromhex(v) for v in step["legs"]]
            if tag != tag16(want[1]) or len(legs) != want[2] or \
                    step["i"] != want[3]:
                raise ProofError("compiled tag / count / position")
            if legs[step["i"]] != x:
                raise ProofError("leg at position != running value")
            x = sha3(tag + b"".join(legs))
        elif want[0] == "HEAD":
            if step["t"] != 2:
                raise ProofError("t")
            head = bytes.fromhex(step["head"])
            luh = bytes.fromhex(step["luh"])
            if len(head) != 89 or len(luh) != 64 or \
                    head[0:4] != be4(want[1]) or head[4:68] != x:
                raise ProofError("head domain / state root")
            x = sha3(tag16(T_DOMHEAD2) + head + luh)
        else:
            if step["t"] != 3:
                raise ProofError("t")
            if bytes.fromhex(step["tag"]) != tag16(want[1]):
                raise ProofError("merkle tag")
            x = verify_merkle_step(want[1], step["n"], step["i"],
                                   [bytes.fromhex(s) for s in step["sib"]],
                                   x)
    if x != app_hash:
        raise ProofError("chain does not end at the AppHash")
    return x


def verify_response(ref_H, leg, req_keys, resp, app_hash, records):
    """Client side of plan 10.2 / 10.3 on the JSON content: results vs the
    trie proof walk, the empty-leg rule, then the chain to the AppHash.
    records: key_hex -> expected 64-byte leaf hash (client recomputed)."""
    lr = bytes.fromhex(resp["lr"])
    nodes = [bytes.fromhex(n) for n in resp["nodes"]]
    digests = [ref_H(n) for n in nodes]
    if digests != sorted(digests) or len(set(digests)) != len(digests):
        raise ProofError("nodes not strictly ascending by digest")
    if len(resp["res"]) != len(req_keys):
        raise ProofError("result count")
    verify_chain(leg, lr, resp["cp"], app_hash)       # authenticates lr
    for kx, res in zip(req_keys, resp["res"]):
        key = bytes.fromhex(kx)
        if lr == EMPTY_ROOT:
            if nodes or res["f"] or "v" in res:
                raise ProofError("empty-leg rule")
            continue
        kind, val = verify(ref_H, lr, key, nodes)
        if kind == "present":
            if not res["f"] or bytes.fromhex(res["v"]) != val or \
                    set(res) != {"f", "v"}:
                raise ProofError("present result mismatch")
            if kx in records and records[kx] != val:
                raise ProofError("value != client recomputed leaf hash")
        else:
            if res["f"] or "v" in res:
                raise ProofError("absent result mismatch")
    return True


def chain_vectors(ref):
    """Eight populated chains + eight empty-leg chains (R2, R3)."""
    pool = {leg: [make_row(leg, i) for i in range(5)] for leg in range(1, 9)}
    roots = {leg: trie_of_rows(ref, pool[leg]) for leg in range(1, 9)}
    world = build_world(roots)
    chains = []
    for leg in range(1, 9):
        present = [pool[leg][0], pool[leg][3]]
        ab = absent_key(leg, 0)
        assert all(ab != r["key"] for r in pool[leg])
        keys = [present[0]["key"], ab, present[1]["key"]]
        res = []
        union = {}
        for k in keys:
            nodes = prove(ref, roots[leg], k)
            for n in nodes:
                union[sha3(n)] = n
            kind, val = verify(sha3, roots[leg], k, nodes)
            if kind == "present":
                res.append({"f": True, "v": X(val)})
            else:
                res.append({"f": False})
        ordered = [union[d] for d in sorted(union)]
        cp = build_cp(leg, world)
        resp = {"h": H_CHAIN, "lr": X(roots[leg]),
                "nodes": [X(n) for n in ordered], "res": res, "cp": cp}
        records = {X(r["key"]): r["value"] for r in present}
        req = [X(k) for k in keys]
        verify_response(sha3, leg, req, resp, world["app_hash"], records)
        chains.append({
            "leg": leg, "leg_name": LEG_NAMES[leg],
            "domain": LEG_DOMAIN[leg],
            "step_sequence": [s[0] + (":" + s[1] if isinstance(s[1], str)
                                      else "") for s in
                              compiled_sequence(leg)],
            "request": {"leg": leg, "keys": req},
            "response": resp,
            "present_records": [r["rec"] for r in present],
            "client_recomputed_leaf_hash": {X(r["key"]): X(r["value"])
                                            for r in present},
            "header_height": H_CHAIN + 1,
            "app_hash": X(world["app_hash"]),
            "leg_trie_rows_sorted_by_key": [
                {"key": X(z["key"]), "value": X(z["value"])}
                for z in sorted(pool[leg], key=lambda z: z["key"])]})
    # empty-leg proof vectors (F-23): the leg root is SHA3-512(0x80)
    empties = []
    for leg in range(1, 9):
        roots_e = dict(roots)
        roots_e[leg] = EMPTY_ROOT
        w = build_world(roots_e)
        ab = absent_key(leg, 1)
        cp = build_cp(leg, w)
        resp = {"h": H_CHAIN, "lr": X(EMPTY_ROOT), "nodes": [],
                "res": [{"f": False}], "cp": cp}
        verify_response(sha3, leg, [X(ab)], resp, w["app_hash"], {})
        # negative controls the verifier must refuse (labelled)
        bad = json.loads(json.dumps(resp))
        bad["res"] = [{"f": True, "v": X(lab("neg/v"))}]
        refused = False
        try:
            verify_response(sha3, leg, [X(ab)], bad, w["app_hash"], {})
        except ProofError:
            refused = True
        assert refused
        bad2 = json.loads(json.dumps(resp))
        bad2["nodes"] = [X(ref.db[roots[leg]])]
        refused2 = False
        try:
            verify_response(sha3, leg, [X(ab)], bad2, w["app_hash"], {})
        except ProofError:
            refused2 = True
        assert refused2
        empties.append({
            "leg": leg, "leg_name": LEG_NAMES[leg],
            "request": {"leg": leg, "keys": [X(ab)]},
            "response": resp, "header_height": H_CHAIN + 1,
            "app_hash": X(w["app_hash"]),
            "negative_controls_must_refuse": [
                "result f=true for the empty leg",
                "non-empty nodes with lr = SHA3-512(0x80)"]})
    return chains, empties, world, roots


def merkle_step_vectors():
    out = []
    for n in range(1, 8):
        leaves = [lab("merkle_steps/%d/%d" % (n, i)) for i in range(n)]
        root = tagged_merkle(T_DOMNODE, leaves)
        proofs = []
        for i in range(n):
            sibs, r = merkle_siblings(T_DOMNODE, leaves, i)
            assert r == root
            x = verify_merkle_step(T_DOMNODE, n, i, sibs, leaves[i])
            assert x == root
            proofs.append({"i": i, "sib": [X(s) for s in sibs],
                           "promoted_unchanged_at_some_level":
                           (len(sibs) < (n - 1).bit_length() if n > 1
                            else False)})
        out.append({"tag": X(tag16(T_DOMNODE)), "n": n,
                    "leaves": [X(x) for x in leaves], "root": X(root),
                    "proofs": proofs})
    # refusals (A13: n >= 1, 0 <= i < n, exactly the pairings' siblings)
    leaves = [lab("merkle_steps/4/%d" % i) for i in range(4)]
    sibs, root = merkle_siblings(T_DOMNODE, leaves, 1)
    refs = []

    def refuse(name, n, i, sb):
        try:
            verify_merkle_step(T_DOMNODE, n, i, sb, leaves[1])
        except ProofError:
            refs.append({"name": name, "n": n, "i": i,
                         "sib": [X(s) for s in sb]})
            return
        raise AssertionError(name)
    refuse("n = 0", 0, 0, [])
    refuse("i = n", 4, 4, sibs)
    refuse("one sibling too many", 4, 1, sibs + [lab("neg/s")])
    refuse("one sibling too few", 4, 1, sibs[:-1])
    return out, refs


# ── HRW selector (plan 8.3) ───────────────────────────────────────────

FAIL_LIMIT = 3          # ledger_roots_v2.h:285-288


def a_key(root_k):
    assert len(root_k) == 64
    return sha3(tag16(T_STASGN) + root_k)


def hrw_score(a, fp):
    pre = tag16(T_STHRW) + a + fp
    assert len(pre) == 144
    return sha3(pre), pre


def rank_pairs(pairs):
    """pairs: [(score, fp)] -> descending score, then descending fp
    (memcmp order = Python bytes order for equal length)."""
    return sorted(pairs, key=lambda p: (p[0], p[1]), reverse=True)


def hrw_holders(a, members, R):
    """members: [(fp, fail_streak)]. Raises ProofError on refusal."""
    fps = [m[0] for m in members]
    for x, y in zip(fps, fps[1:]):
        if not x < y:
            raise ProofError("not strictly ascending / duplicate")
    elig = [(hrw_score(a, fp)[0], fp) for fp, fs in members
            if fs < FAIL_LIMIT]
    ranked = rank_pairs(elig)
    return ranked, [fp for _, fp in ranked[:min(R, len(ranked))]]


def hrw_vectors():
    cases = []

    def mem(label, n, streaks=None):
        fps = sorted(sha3(lab("hrw/%s/pk/%d" % (label, i), 96))
                     for i in range(n))
        sts = streaks if streaks is not None else [0] * n
        return list(zip(fps, sts))

    def case(name, label, kseed, n, R, streaks=None, members=None):
        rk = lab("hrw/Root_k_fixture/%s" % kseed)
        a = a_key(rk)
        m = members if members is not None else mem(label, n, streaks)
        ranked, holders = hrw_holders(a, m, R)
        return {
            "name": name, "root_k_fixture": X(rk), "a_key": X(a),
            "R": R,
            "members": [{"node_fp": X(fp), "fail_streak": fs}
                        for fp, fs in m],
            "eligible_count": len(ranked),
            "ranked_eligible": [{"rank": i, "node_fp": X(fp),
                                 "score": X(sc)}
                                for i, (sc, fp) in enumerate(ranked)],
            "holders": [X(h) for h in holders],
            "n_holders": len(holders),
            "score_preimage_sample": X(hrw_score(a, ranked[0][1])[1])
            if ranked else None}

    cases.append(case("R4_all_eligible_10", "m10", "k1", 10, 4))
    cases.append(case("R4_some_ineligible",
                      "m10b", "k2", 10, 4,
                      streaks=[0, 3, 1, 7, 0, 2, 3, 0, 0, 5]))
    cases.append(case("R4_fewer_eligible_than_R_two", "m6", "k3", 6, 4,
                      streaks=[3, 0, 3, 3, 1, 3]))
    cases.append(case("R4_one_eligible", "m5", "k4", 5, 4,
                      streaks=[3, 3, 3, 3, 2]))
    cases.append(case("R4_no_eligible", "m3", "k5", 3, 4,
                      streaks=[3, 4, 9]))
    cases.append(case("R4_empty_set", "m0", "k6", 0, 4))
    cases.append(case("R16_40_eligible", "m40", "k7", 40, 16))
    cases.append(case("R16_12_eligible_fewer_than_R", "m12", "k8", 12, 16))
    cases.append(case("R4_exactly_4_eligible", "m4", "k9", 4, 4))
    cases.append(case("R4_exactly_5_eligible", "m5e", "k10", 5, 4))
    sweep = []
    for R in (1, 2, 3, 4, 5, 8, 15, 16):
        sweep.append(case("R%d_prefix_sweep_20" % R, "m20", "k11", 20, R,
                          streaks=[0, 0, 3, 0, 0, 1, 0, 0, 0, 0, 3, 0, 0, 0,
                                   2, 0, 0, 0, 0, 3]))
    # the holders of R are the first R of the full ranking: asserted here
    full = [h["node_fp"] for h in sweep[-1]["ranked_eligible"]]
    for s in sweep:
        assert [h for h in s["holders"]] == full[:min(s["R"], len(full))]
    many_k = [case("same_set_other_segment_%d" % i, "m10", "kk%d" % i, 10, 4)
              for i in range(4)]
    # different segments rank the same members differently (A(k) differs)
    assert len({tuple(c["holders"]) for c in many_k}) > 1

    # refusals
    refusals = []
    m = mem("dup", 6)
    dup = m[:3] + [m[2]] + m[3:]
    # ensure the duplicate is ineligible too (R4: every member is checked)
    dup_inel = [(fp, 3 if i in (2, 3) else fs)
                for i, (fp, fs) in enumerate(dup)]
    desc = [m[1], m[0]] + m[2:]
    for name, mm in (("duplicate_fp_eligible", dup),
                     ("duplicate_fp_both_ineligible", dup_inel),
                     ("descending_neighbour", desc)):
        try:
            hrw_holders(a_key(lab("hrw/refuse")), mm, 4)
        except ProofError:
            refusals.append({
                "name": name, "R": 4, "root_k_fixture": X(lab("hrw/refuse")),
                "members": [{"node_fp": X(fp), "fail_streak": fs}
                            for fp, fs in mm],
                "expected": "refused (no holders written)"})
            continue
        raise AssertionError(name)

    # comparator-only tie vectors (R5): injected scores
    fpA = sha3(b"hf9_kat/tie/fpA")
    fpB = sha3(b"hf9_kat/tie/fpB")
    fpC = sha3(b"hf9_kat/tie/fpC")
    fpD = sha3(b"hf9_kat/tie/fpD")
    fpE = sha3(b"hf9_kat/tie/fpE")
    s_hi = b"\xff" * 63 + b"\x01"
    s_mid = b"\x80" + b"\x00" * 63
    s_lo = b"\x00" * 63 + b"\x05"
    s_lo2 = b"\x00" * 63 + b"\x04"
    pairs = [(s_mid, fpA), (s_hi, fpB), (s_mid, fpC), (s_lo, fpD),
             (s_lo2, fpE)]
    ranked = rank_pairs(pairs)
    ties = {
        "label": "injected_scores (comparator only; SHA3-512 cannot "
                 "produce a tie, R5)",
        "rule": "descending 64-byte score (memcmp), then descending "
                "64-byte node_fp (memcmp)",
        "entries": [{"score": X(s), "node_fp": X(f)} for s, f in pairs],
        "ranked": [{"score": X(s), "node_fp": X(f)} for s, f in ranked],
        "tie_winner_of_equal_scores": X(max(fpA, fpC)),
        "holders_R2": [X(f) for _, f in ranked[:2]],
        "holders_R4": [X(f) for _, f in ranked[:4]],
        "holders_R16_fewer_than_R": [X(f) for _, f in ranked[:16]]}
    assert ranked[1][1] == max(fpA, fpC) and ranked[2][1] == min(fpA, fpC)
    return cases, sweep, many_k, refusals, ties


# ── new tag vectors and compositions ──────────────────────────────────

def tag_vectors():
    names = [T_CORE_V4, T_STOR_V3, T_SYS_V7, T_STHRW]
    tags = {n: X(tag16(n)) for n in names}
    # narrow cross-check: the new tags differ from every NDS.* tag string in
    # the two existing files read (NOT the plan-6 collision scan)
    seen = set()
    for path in (LEDGER_C, MANIFEST_C):
        for ln in open(path, "r", encoding="utf-8"):
            if "static const uint8_t TAG" in ln or "TAG_EMPTY" in ln or \
                    ln.lstrip().startswith('"NDS.'):
                for m in re.finditer(r'"(NDS\.[A-Za-z0-9.]+?)(?:\\0)*"', ln):
                    seen.add(m.group(1))
    clash = [n for n in names if n in seen]
    check("new tags are absent from the tag strings of ledger_roots_v2.c and "
          "manifest_wire.c (%d strings; narrow cross-check only)" % len(seen),
          not clash and len(seen) > 30, ",".join(clash))
    check("new tags are 16 bytes, zero padded ASCII",
          all(len(v) == 32 for v in tags.values()))
    return tags


def composition_vectors(ref, row_sets, chain_roots):
    """Fixed-filler compositions, derived-root compositions, and the
    empty-leg vectors (R1)."""
    legs_fixed = {leg: lab("comp/fixed/leg%d" % leg) for leg in range(1, 9)}
    out = {}
    # (a) fixed inputs
    st = build_state(legs_fixed)
    out["fixed_filler_all_legs"] = {
        "trie_legs": {str(l): X(v) for l, v in legs_fixed.items()},
        "CORE_v4": {"tag": X(tag16(T_CORE_V4)),
                    "legs": [X(x) for x in st["core_legs"]],
                    "preimage_len": 16 + 7 * 64, "root": X(st["core"])},
        "STOR_v3": {"tag": X(tag16(T_STOR_V3)),
                    "legs": [X(x) for x in st["stor_legs"]],
                    "preimage_len": 16 + 4 * 64, "root": X(st["stor"])},
        "SYS_v7": {"tag": X(tag16(T_SYS_V7)),
                   "legs": [X(x) for x in st["sys_legs"]],
                   "preimage_len": 16 + 12 * 64, "root": X(st["sys"])}}
    # (b) derived: roots of the n=5 row sets (chain world)
    stc = build_state(chain_roots)
    out["derived_from_trie_roots_n5"] = {
        "trie_legs": {str(l): X(v) for l, v in chain_roots.items()},
        "CORE_v4": X(stc["core"]), "STOR_v3": X(stc["stor"]),
        "SYS_v7": X(stc["sys"])}
    # (c) all trie legs empty
    empt = {leg: EMPTY_ROOT for leg in range(1, 9)}
    ste = build_state(empt)
    out["all_trie_legs_empty"] = {
        "empty_root_sha3_512_0x80": X(EMPTY_ROOT),
        "CORE_v4": {"legs": [X(x) for x in ste["core_legs"]],
                    "root": X(ste["core"])},
        "STOR_v3": {"legs": [X(x) for x in ste["stor_legs"]],
                    "root": X(ste["stor"])},
        "SYS_v7": {"legs": [X(x) for x in ste["sys_legs"]],
                   "root": X(ste["sys"])}}
    # (d) one empty leg at a time, others the n=5 roots (A3 / F-7, R1)
    per_leg = []
    for leg in range(1, 9):
        r = dict(chain_roots)
        r[leg] = EMPTY_ROOT
        s = build_state(r)
        comp, pos = LEG_POS[leg]
        entry = {"leg": leg, "leg_name": LEG_NAMES[leg],
                 "empty_root": X(EMPTY_ROOT), "composition": comp,
                 "position": pos}
        if comp == "CORE":
            entry.update({"tag": X(tag16(T_CORE_V4)),
                          "legs": [X(x) for x in s["core_legs"]],
                          "root": X(s["core"])})
        elif comp == "STOR":
            entry.update({"tag": X(tag16(T_STOR_V3)),
                          "legs": [X(x) for x in s["stor_legs"]],
                          "root": X(s["stor"]),
                          "then_SYS_v7_root": X(s["sys"])})
        else:
            entry.update({"tag": X(tag16(T_SYS_V7)),
                          "legs": [X(x) for x in s["sys_legs"]],
                          "root": X(s["sys"])})
        assert (comp != "CORE" or s["core_legs"][pos] == EMPTY_ROOT)
        assert (comp != "STOR" or s["stor_legs"][pos] == EMPTY_ROOT)
        assert (comp != "SYS" or s["sys_legs"][pos] == EMPTY_ROOT)
        per_leg.append(entry)
    out["one_empty_leg_each"] = per_leg
    return out


# ── controls against the HF-7 KAT (existing layouts, separate author) ──

def controls_hf7():
    print("-- CONTROLS: existing layouts vs the HF-7 oracle KAT ----------")
    kat = json.load(open(HF7_KAT, "r", encoding="utf-8"))
    v = kat["vectors"]
    n = 0
    # S5 segments v2 root (segment leaf v2 + STSGNODE tagged merkle)
    for r in v["S5_segments_v2"]["roots"]:
        leaves = []
        for row in r["rows_sorted"]:
            pre, lf = segment_leaf_v2(int(row["k"]),
                                      bytes.fromhex(row["root_k"]),
                                      int(row["published_height"]))
            assert X(pre) == row["preimage"] and X(lf) == row["leaf"]
            leaves.append(lf)
        root = (sha3(tag16("NDS.E.STSEG.v1")) if not leaves
                else tagged_merkle(T_STSGNODE, leaves))
        assert X(root) == r["root"]
        n += 1
    # S6 head hashes and domains roots
    for hv in v["S6_domainhead_v2"]["head_hashes"]:
        h89 = domain_head(int(hv["domain_id"]),
                          bytes.fromhex(hv["domain_state_root"]),
                          int(hv["domain_height"]),
                          int(hv["last_updated_global_height"]),
                          int(hv["ruleset_version"]), int(hv["status"]))
        assert X(h89) == hv["enc89"]
        assert X(head_hash_v2(h89, bytes.fromhex(hv["last_upd_hash"]))) == \
            hv["head_hash"]
        n += 1
    for dr in v["S6_domainhead_v2"]["domains_roots"]:
        hs = []
        for hv in dr["heads"]:
            h89 = domain_head(int(hv["domain_id"]),
                              bytes.fromhex(hv["domain_state_root"]),
                              int(hv["domain_height"]),
                              int(hv["last_updated_global_height"]),
                              int(hv["ruleset_version"]), int(hv["status"]))
            hs.append(head_hash_v2(h89, bytes.fromhex(hv["last_upd_hash"])))
        assert X(tagged_merkle(T_DOMNODE, hs)) == dr["domains_root"]
        n += 1
    # S8 GLOBAL v2
    for g in v["S8_global_v2"]["compositions"]:
        assert X(compose(T_GLOBAL2, [bytes.fromhex(g["domains_root"]),
                                     bytes.fromhex(g["replay_root"])])) == \
            g["global_state_root"]
        n += 1
    # S4 SYSTEM v6 composition (same code path with the OLD tag)
    for c in v["S4_system_v6"]["compositions"]:
        legs = [bytes.fromhex(x["value"]) for x in c["v5_legs_in_order"]]
        legs += [bytes.fromhex(c["bcopy_root"]), bytes.fromhex(c["vstat"]),
                 bytes.fromhex(c["stmem_root"])]
        assert len(legs) == 12
        assert X(compose(T_SYS_V6, legs)) == c["system_state_root"]
        n += 1
    check("HF-7 KAT: segments v2 root, DomainHead v2, domains_root, GLOBAL v2 "
          "and SYSTEM v6 reproduced by this file's encoders (%d vectors)" % n,
          n > 20)
    return n


# ── D6 with D4 and D5 as controls (plan 7.1, AD-7) ────────────────────

RULESET_DESC_VERSION = 2
METER_POLICY_VERSION = 2
MAX_BLOCK_ENV_BYTES = 2 * 1048576
OP_SPACE = 256
SYS_RULES = [1, 2, 3, 4, 5, 6, 7, 8, 9]
SYS_TYPES = [4, 5, 6, 7, 9, 10]
CORE_RULES = [1, 2, 3, 4, 5, 6, 7, 8, 9]
CORE_TYPES = [1, 2, 3, 11, 12, 13]
GEN4_VOTE_CONSTS = [2000000 * 10 ** 8, 100000 * 10 ** 8, 3000, 500, 3000,
                    1000000 * 10 ** 8, 100000 * 10 ** 8, 1000000 * 10 ** 8,
                    720]
HF9_VOTE_CONSTS = [1024, 4, 4, 16]       # cap, copies default, min, max


def name32(s):
    raw = s.encode("ascii")
    return raw + b"\x00" * (32 - len(raw))


def meter_policy_identity(max_op):
    w_op = [0] * OP_SPACE
    present = [0] * (OP_SPACE // 64)
    for op in range(1, max_op + 1):
        w_op[op] = 1
        present[op // 64] |= 1 << (op % 64)
    pre = tag16("NDS.METPOLID.v1") + be4(METER_POLICY_VERSION)
    for w in (1, 1, 1, 1, 1, 1, 1, MAX_BLOCK_ENV_BYTES):
        pre += be8(w)
    for w in w_op:
        pre += be8(w)
    for w in present:
        pre += be8(w)
    assert len(pre) == 2164
    return sha3(pre)


def ruleset_preimage(domain_id, name, version, rules, types, policy):
    pre = tag16("NDS.RULESET.v1") + be4(RULESET_DESC_VERSION) + \
        be4(domain_id) + name32(name) + be4(1) + be4(version) + \
        be2(len(rules)) + b"".join(be4(r) for r in rules) + \
        be2(len(types)) + bytes(types) + policy
    assert len(policy) == 64
    return pre


def rolegen_preimage(gen, base, sys_h, core_h, spec, owner, consts):
    assert len(sys_h) == 64 and len(core_h) == 64 and len(owner) == 64
    pre = (tag16("NDS.ROLEGEN.v1") + be4(gen) + be4(base) + sys_h + core_h +
           be4(spec) + owner + be4(len(consts)) +
           b"".join(be8(c) for c in consts))
    assert len(pre) == 16 + 4 + 4 + 128 + 4 + 64 + 4 + 8 * len(consts)
    dig = sha3(pre)
    raw = int.from_bytes(dig[:8], "big")
    return pre, dig, raw, raw & 0x7FFFFFFFFFFFFFFF


def pins_bytes(text, macro):
    m = re.search(r"#define\s+%s\s*\{\s*\\?(.*?)\}" % re.escape(macro), text,
                  re.S)
    vals = re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))
    assert len(vals) == 64, macro
    return bytes.fromhex("".join(vals))


def d6_vectors():
    print("-- CONTROLS: D4 and D5 re-derived before D6 -------------------")
    pins = open(PINS_H, "r", encoding="utf-8").read()
    dnac = open(DNAC_H, "r", encoding="utf-8").read()
    m = re.search(r"#define\s+DNAC_HF6_FOUNDATION_OWNER\s*\{(.*?)\}", dnac,
                  re.S)
    owner = bytes.fromhex("".join(re.findall(r"0x([0-9a-fA-F]{2})",
                                             m.group(1))))
    assert len(owner) == 64
    d4_lit = int(re.search(r"#define\s+DNAC_CFG_RULESET_GEN_ROLES_D\s+"
                           r"0x([0-9a-fA-F]+)ULL", dnac).group(1), 16)
    d5_lit = int(re.search(r"#define\s+DNAC_CFG_RULESET_GEN_ROOTS_D\s+"
                           r"0x([0-9a-fA-F]+)ULL", dnac).group(1), 16)
    zero = b"\x00" * 64
    pol = meter_policy_identity(9)
    check("meter policy digest (ops 1..9) == NODUS_PIN_G5_SYS_METER_POLICY_"
          "DIGEST_INIT",
          pol == pins_bytes(pins, "NODUS_PIN_G5_SYS_METER_POLICY_DIGEST_"
                            "INIT"))

    def sysh(v):
        return sha3(ruleset_preimage(DOMAIN_SYSTEM, "SYSTEM", v, SYS_RULES,
                                     SYS_TYPES, pol))

    def coreh(v):
        return sha3(ruleset_preimage(DOMAIN_CORE, "DNA_CORE", v, CORE_RULES,
                                     CORE_TYPES, zero))
    check("SYSTEM v10 ruleset hash == NODUS_PIN_G4_SYS_RULESET_HASH_INIT",
          sysh(10) == pins_bytes(pins, "NODUS_PIN_G4_SYS_RULESET_HASH_INIT"))
    check("CORE v9 ruleset hash == NODUS_PIN_G4_CORE_RULESET_HASH_INIT",
          coreh(9) == pins_bytes(pins, "NODUS_PIN_G4_CORE_RULESET_HASH_INIT"))
    check("SYSTEM v11 ruleset hash == NODUS_PIN_G5_SYS_RULESET_HASH_INIT",
          sysh(11) == pins_bytes(pins, "NODUS_PIN_G5_SYS_RULESET_HASH_INIT"))
    check("CORE v10 ruleset hash == NODUS_PIN_G5_CORE_RULESET_HASH_INIT",
          coreh(10) == pins_bytes(pins, "NODUS_PIN_G5_CORE_RULESET_HASH_INIT"))
    pre4, _, _, d4 = rolegen_preimage(4, 3, sysh(10), coreh(9), 1, owner,
                                      GEN4_VOTE_CONSTS)
    check("D4 re-derived == dnac.h DNAC_CFG_RULESET_GEN_ROLES_D "
          "0x%016x (preimage %d B)" % (d4_lit, len(pre4)),
          d4 == d4_lit and len(pre4) == 296)
    pre5, _, _, d5 = rolegen_preimage(5, 4, sysh(11), coreh(10), 1, owner,
                                      [720])
    check("D5 re-derived == dnac.h DNAC_CFG_RULESET_GEN_ROOTS_D "
          "0x%016x (preimage %d B)" % (d5_lit, len(pre5)),
          d5 == d5_lit and len(pre5) == 232)
    # D6: generation 6, base 5, gen-5 descriptors with ruleset_version only
    # bumped (SYSTEM 12 / CORE 11, plan 7.1 / R11)
    s6, c6 = sysh(SYS_RV_G6), coreh(CORE_RV_G6)
    a = ruleset_preimage(DOMAIN_SYSTEM, "SYSTEM", 11, SYS_RULES, SYS_TYPES,
                         pol)
    b = ruleset_preimage(DOMAIN_SYSTEM, "SYSTEM", SYS_RV_G6, SYS_RULES,
                         SYS_TYPES, pol)
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    check("gen-6 SYSTEM descriptor differs from gen-5 only in ruleset_version "
          "bytes 60..63", len(a) == len(b) and diff and min(diff) >= 60 and
          max(diff) <= 63)
    pre6, dig6, raw6, d6 = rolegen_preimage(6, 5, s6, c6, 1, owner,
                                            HF9_VOTE_CONSTS)
    check("D6 preimage is 256 bytes (n = 4)", len(pre6) == 256)
    others = {"D2 (param 9)": 0x44dfbe7ad3c75adf,
              "EVM_ACTIVE (param 14)": 0x029f47596864d407,
              "slice-6a gen 4 (param 16, dev)": 0x329b0ea92c8b8c58,
              "D4": d4_lit, "D5": d5_lit}
    check("D6 differs from D2, D4, D5 and the other shipped literals",
          all(d6 != x for x in others.values()))
    return {
        "controls": {
            "D4": {"derived": "0x%016x" % d4, "dnac_h_literal":
                   "0x%016x" % d4_lit, "preimage_len": len(pre4),
                   "consts": [D(c) for c in GEN4_VOTE_CONSTS]},
            "D5": {"derived": "0x%016x" % d5, "dnac_h_literal":
                   "0x%016x" % d5_lit, "preimage_len": len(pre5),
                   "consts": [D(720)]},
            "gen4_sys_ruleset_hash": X(sysh(10)),
            "gen4_core_ruleset_hash": X(coreh(9)),
            "gen5_sys_ruleset_hash": X(sysh(11)),
            "gen5_core_ruleset_hash": X(coreh(10)),
            "meter_policy_digest_ops_1_9": X(pol)},
        "D6": {
            "generation": 6, "base_generation": 5, "spec_version": 1,
            "foundation_owner": X(owner),
            "consts": [D(c) for c in HF9_VOTE_CONSTS],
            "consts_meaning": "cap, copies default, copies min, copies max",
            "sys_gen6_ruleset_version": SYS_RV_G6,
            "core_gen6_ruleset_version": CORE_RV_G6,
            "sys_gen6_ruleset_hash": X(s6), "core_gen6_ruleset_hash": X(c6),
            "preimage": X(pre6), "preimage_len": len(pre6),
            "sha3_512": X(dig6), "first_8_bytes_be": "0x%016x" % raw6,
            "top_bit_cleared": bool(raw6 >> 63),
            "value": "0x%016x" % d6, "value_decimal": D(d6)}}


# ── main ──────────────────────────────────────────────────────────────

def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(HERE, "hf9_kat.json")
    keccak_mod = load_keccak_module()
    refS = Ref(sha3, 64, 64)
    controls_trie(refS, keccak_mod.keccak256, keccak_mod.keccak_f)
    controls_rlp(keccak_mod)
    controls_substituted(refS)
    n_hf7 = controls_hf7()
    tags = tag_vectors()

    leg_vectors, row_sets = trie_vectors(refS)
    chains, empties, world, chain_roots = chain_vectors(refS)
    msteps, mrefusals = merkle_step_vectors()
    comps = composition_vectors(refS, row_sets, chain_roots)
    hrw_cases, hrw_sweep, hrw_seg, hrw_ref, hrw_ties = hrw_vectors()
    votes = d6_vectors()

    # a final cross-check: the chain world's AppHash is reproduced from
    # scratch by the verifier path for every leg (done at build time) and
    # the CORE / SYS roots equal the composition vectors
    check("chain world roots == composition vectors",
          X(world["core"]) == comps["derived_from_trie_roots_n5"]["CORE_v4"]
          and X(world["sys"]) == comps["derived_from_trie_roots_n5"]["SYS_v7"])
    check("8 chains + 8 empty-leg chains verified by the plan-10 verifier",
          len(chains) == 8 and len(empties) == 8)

    counts = {
        "leg_vectors": len(leg_vectors),
        "leg_row_sets": sum(len(s["sets"]) for s in row_sets),
        "new_tags": len(tags),
        "composition_groups": 4,
        "composition_one_empty_leg": len(comps["one_empty_leg_each"]),
        "hrw_cases": len(hrw_cases) + len(hrw_sweep) + len(hrw_seg),
        "hrw_refusals": len(hrw_ref),
        "hrw_tie_comparator": 1,
        "composition_chains": len(chains),
        "empty_leg_proofs": len(empties),
        "merkle_step_groups": len(msteps),
        "merkle_step_refusals": len(mrefusals),
        "d6": 1, "d4_d5_controls": 2,
        "hf7_kat_controls_reproduced": n_hf7}
    doc = {
        "spec": "docs/plans/approved/2026-11-04-hf9.md section 12 row T-4",
        "oracle": "nodus/tests/vectors/hf9_kat_oracle.py",
        "label": "trie structure and roots: GROUNDED (pinned reference "
                 "executed); every other byte layout: SELF-CONSISTENT "
                 "(plan text and existing C layouts; not an external "
                 "reference)",
        "pins": {
            "execution-specs": EXEC_SPECS_PIN,
            "execution-specs merkle_patricia_trie.py sha256":
                hashlib.sha256(open(MPT_PY, "rb").read()).hexdigest(),
            "ethereum-rlp": "0.1.6",
            "ethereum_rlp rlp.py sha256":
                hashlib.sha256(open(RLP_PY, "rb").read()).hexdigest(),
            "go-ethereum": GETH_PIN,
            "go-ethereum trie/proof.go sha256":
                hashlib.sha256(open(GETH_PROOF, "rb").read()).hexdigest(),
            "HRW paper sha256": HRW_SHA256},
        "conventions": {
            "hash": "SHA3-512 (hashlib.sha3_512); trie node digest, secured "
                    "key hash and inline threshold 64 per plan 4.1",
            "tag": "16 bytes ASCII right-padded with 0x00",
            "integers": "big-endian in preimages except the UTXO leaf (LE, "
                        "existing); decimal strings in JSON for record "
                        "fields",
            "hex": "lowercase, no prefix",
            "fixtures": "byte strings = SHA3-512('hf9_kat/' + label) "
                        "(counter-extended); integers = leading bits of "
                        "such a digest",
            "empty_root": X(EMPTY_ROOT),
            "constraints_kept_from_the_existing_C": {
                "registry status": "1..3 (ledger_roots_v2.c:513-534)",
                "segment k and published_height": "1..2^63-1 (:1195-1210)",
                "name length": "1..36 (3..36 as a proof request key)",
                "claims target_domain_id": "1 (CORE), plan 4.2 row L3"},
            "domains": {"SYSTEM": 0, "CORE": 1, "EVM (fixture head)": 2}},
        "checks": [{"name": n, "ok": ok, "detail": d}
                   for n, ok, d in CHECKS],
        "readings": "see the READINGS section of the oracle docstring",
        "vector_counts": counts,
        "vectors": {
            "new_tags": tags,
            "leg_vectors": leg_vectors,
            "leg_row_sets": row_sets,
            "compositions": comps,
            "hrw": {"score_preimage": "TAG16(NDS.STHRW.v1) || A(k)[64] || "
                                      "node_fp[64] = 144 bytes",
                    "A_k": "SHA3-512(TAG16(NDS.STASGN.v1) || Root(k)[64]), "
                           "Root(k) a 64-byte fixture (R6)",
                    "order": "descending score (memcmp), then descending "
                             "node_fp (memcmp)",
                    "eligible": "fail_streak < 3",
                    "cases": hrw_cases, "R_sweep_same_set": hrw_sweep,
                    "same_set_other_segments": hrw_seg,
                    "refusals": hrw_ref, "tie_comparator": hrw_ties},
            "composition_chains": chains,
            "empty_leg_proofs": empties,
            "merkle_steps": {"vectors": msteps, "refusals": mrefusals},
            "votes": votes}}
    text = json.dumps(doc, sort_keys=True, indent=1) + "\n"
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("-- wrote %s (%d bytes)" % (out_path, len(text)))
    print("-- vector counts: %s" % json.dumps(counts, sort_keys=True))
    print("-- D6 = %s" % votes["D6"]["value"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
