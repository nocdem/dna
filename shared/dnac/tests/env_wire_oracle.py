#!/usr/bin/env python3
"""
LEDGER V2-C1 K1 — INDEPENDENT ORACLE for the generic envelope wire + hashes.

PROVENANCE: written by the ORCHESTRATOR directly from the approved K1
pre-implementation specification (offsets, field order, tag literals), NOT by
reading or transcribing the C implementation. It shares no code with the C.
Hash primitive: python3 hashlib.sha3_512 (stdlib, FIPS-202).

Run:  python3 env_wire_oracle.py
"""
import hashlib
import struct

# ── constants (spec) ────────────────────────────────────────────────────
WIRE_FAMILY   = b"DNA.ENVWIRE.v1".ljust(16, b"\0")
TAG_CALL      = b"DNA.ENVCALL.v1".ljust(16, b"\0")
TAG_AUTHCTX   = b"DNA.ENVCTX.v1".ljust(16, b"\0")
TAG_AUTH      = b"DNA.ENVAUTH.v1".ljust(16, b"\0")
TAG_TXID      = b"DNA.ENVTXID.v1".ljust(16, b"\0")

ENV_VERSION      = 1
FIXED_HEAD       = 43
LEG_HDR_LEN      = 30
MAX_TOTAL_LEN    = 1048576   # capacity season: the derived 2^20 V2 bound


def capacity_derivation():
    """Capacity-season worst-case arithmetic — the INDEPENDENT second
    derivation of DNA_ENV_MAX_TOTAL_LEN cited by env_wire.h and
    nodus_witness_rt_native.c. Recomputed here from the participating
    source constants (ML-DSA-87 pk 2592 / sig 4627; committee ceiling
    128; signer cap 15; SPEND shape 15 in / 16 out / 232 B out; CC call
    v2 = 41 B); the C-side third derivation is test_v2_capacity.c."""
    signer = 2592 + 4627          # kind-1 unit (pk + sig)
    appr = 2 + 4627               # kind-2 approval unit (seat + sig)
    cc_single = 43 + 30 + 41 + (1 + 15 * signer) + (2 + 128 * appr)
    two_leg = cc_single + 30 + (2 + 15 * 64 + 16 * 232) + (1 + 15 * signer)
    assert cc_single == 700914, cc_single
    assert two_leg == 813904, two_leg
    # burn season: TOKEN_CREATE (109-byte fixed head, 14 in / 16 out) is
    # now the worst CORE leg — 4717 call bytes, 43 over the maximal
    # SPEND call; the BURN call (SPEND + 8) is dominated.
    tc_call = 64 + 1 + 32 + 1 + 8 + 1 + 1 + 14 * 64 + 1 + 16 * 232
    two_leg_tc = cc_single + 30 + tc_call + (1 + 15 * signer)
    assert tc_call == 4717, tc_call
    assert two_leg_tc == 813947, two_leg_tc
    assert 2 ** 19 < two_leg_tc <= 2 ** 20 == MAX_TOTAL_LEN
    return cc_single, two_leg_tc


capacity_derivation()
MAX_LEGS         = 64

assert len(WIRE_FAMILY) == 16 and len(TAG_CALL) == 16
assert len(TAG_AUTHCTX) == 16 and len(TAG_AUTH) == 16 and len(TAG_TXID) == 16

def be8(v):  return struct.pack(">B", v)
def be16(v): return struct.pack(">H", v)
def be32(v): return struct.pack(">I", v)
def be64(v): return struct.pack(">Q", v)
def sha3(b): return hashlib.sha3_512(b).digest()


class Leg:
    def __init__(self, domain_id, runtime_op, ruleset_version, access_mode,
                 auth_kind, res_max_effects, res_max_effect_bytes,
                 call_data, auth_data, ruleset_hash):
        self.domain_id = domain_id
        self.runtime_op = runtime_op
        self.ruleset_version = ruleset_version
        self.access_mode = access_mode
        self.auth_kind = auth_kind
        self.res_max_effects = res_max_effects
        self.res_max_effect_bytes = res_max_effect_bytes
        self.call_data = call_data
        self.auth_data = auth_data
        self.ruleset_hash = ruleset_hash      # contextual, 64 B, NOT serialized

    def header_bytes(self):
        b = (be32(self.domain_id) + be32(self.runtime_op) +
             be32(self.ruleset_version) + be8(self.access_mode) +
             be8(self.auth_kind) + be32(len(self.call_data)) +
             be32(len(self.auth_data)) + be32(self.res_max_effects) +
             be32(self.res_max_effect_bytes))
        assert len(b) == LEG_HDR_LEN, len(b)
        return b


class Envelope:
    def __init__(self, expiry_height, fee_amount, res_max_total_units, legs,
                 chain_id):
        self.expiry_height = expiry_height
        self.fee_amount = fee_amount
        self.res_max_total_units = res_max_total_units
        self.legs = legs
        self.chain_id = chain_id              # contextual, 32 B, NOT serialized

    # ── wire ────────────────────────────────────────────────────────────
    def encode(self):
        n = len(self.legs)
        head = (WIRE_FAMILY + be8(ENV_VERSION) + be64(self.expiry_height) +
                be64(self.fee_amount) + be64(self.res_max_total_units) +
                be16(n))
        assert len(head) == FIXED_HEAD, len(head)
        out = head
        for lg in self.legs:
            out += lg.header_bytes()
        assert len(out) == FIXED_HEAD + LEG_HDR_LEN * n
        for lg in self.legs:
            out += lg.call_data
        for lg in self.legs:
            out += lg.auth_data
        assert len(out) <= MAX_TOTAL_LEN
        return out

    # ── hashes ──────────────────────────────────────────────────────────
    def call_commit(self, i):
        lg = self.legs[i]
        pre = (TAG_CALL + be32(lg.domain_id) + be32(lg.runtime_op) +
               be32(lg.ruleset_version) + lg.ruleset_hash +
               be8(lg.access_mode) + be32(len(lg.call_data)) + lg.call_data)
        assert len(pre) == 97 + len(lg.call_data), len(pre)
        return sha3(pre)

    def authctx_bytes(self):
        n = len(self.legs)
        b = (WIRE_FAMILY + be8(ENV_VERSION) + self.chain_id +
             be64(self.expiry_height) + be64(self.fee_amount) +
             be64(self.res_max_total_units) + be16(n))
        assert len(b) == 75, len(b)
        for i, lg in enumerate(self.legs):
            seg = (be32(lg.domain_id) + be32(lg.runtime_op) +
                   be32(lg.ruleset_version) + be8(lg.access_mode) +
                   be8(lg.auth_kind) + be32(len(lg.call_data)) +
                   be32(len(lg.auth_data)) + be32(lg.res_max_effects) +
                   be32(lg.res_max_effect_bytes) + self.call_commit(i))
            assert len(seg) == 94, len(seg)
            b += seg
        assert len(b) == 75 + 94 * n
        return b

    def auth_context_commit(self):
        pre = TAG_AUTHCTX + self.authctx_bytes()
        assert len(pre) == 91 + 94 * len(self.legs)
        return sha3(pre)

    def auth_digest(self, i):
        lg = self.legs[i]
        pre = (TAG_AUTH + self.auth_context_commit() + be16(i) +
               be32(lg.domain_id) + be32(lg.runtime_op))
        assert len(pre) == 90, len(pre)
        return sha3(pre)

    def tx_id(self):
        env = self.encode()
        pre = TAG_TXID + self.auth_context_commit() + be32(len(env)) + env
        assert len(pre) == 84 + len(env)
        return sha3(pre)


def c_array(name, data):
    body = ",".join("0x%02x" % b for b in data)
    return "static const uint8_t %s[%d] = {%s};" % (name, len(data), body)


def main():
    # ── the EXACT fixture pinned in tests/test_env_wire.c ───────────────
    # KAT_ENV_BYTES (119 B) and the two contextual inputs. The oracle
    # re-parses the wire bytes rather than re-declaring the fields, so the
    # pinned bytes and the pinned digests cannot drift apart.
    wire = bytes.fromhex(
        "444e412e454e56574952452e7631000001000000000011223300000000000003"
        "e8000000000000c3500002000000010000000700000003020100000008000000"
        "0500000010000004000000002a00000000000000010102000000000000000300"
        "000000000000000001020304050607a0a1a2a3a4b0b1b2")
    chain_id = bytes.fromhex(
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
    rulesets = [
        bytes.fromhex("404142434445464748494a4b4c4d4e4f"
                      "505152535455565758595a5b5c5d5e5f"
                      "606162636465666768696a6b6c6d6e6f"
                      "707172737475767778797a7b7c7d7e7f"),
        bytes.fromhex("808182838485868788898a8b8c8d8e8f"
                      "909192939495969798999a9b9c9d9e9f"
                      "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
                      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"),
    ]

    assert wire[:16] == WIRE_FAMILY and wire[16] == ENV_VERSION
    n = struct.unpack(">H", wire[41:43])[0]
    hdrs, off = [], FIXED_HEAD
    for _ in range(n):
        h = wire[off:off + LEG_HDR_LEN]; off += LEG_HDR_LEN
        d, op, rv = struct.unpack(">III", h[0:12])
        cl, al, rme, rmeb = struct.unpack(">IIII", h[14:30])
        hdrs.append((d, op, rv, h[12], h[13], cl, al, rme, rmeb))
    cb = off
    calls = []
    for h in hdrs:
        calls.append(wire[cb:cb + h[5]]); cb += h[5]
    ab = cb
    auths = []
    for h in hdrs:
        auths.append(wire[ab:ab + h[6]]); ab += h[6]
    assert ab == len(wire), (ab, len(wire))

    legs = [Leg(h[0], h[1], h[2], h[3], h[4], h[7], h[8],
                calls[i], auths[i], rulesets[i]) for i, h in enumerate(hdrs)]
    env = Envelope(struct.unpack(">Q", wire[17:25])[0],
                   struct.unpack(">Q", wire[25:33])[0],
                   struct.unpack(">Q", wire[33:41])[0],
                   legs, chain_id)
    assert env.encode() == wire, "oracle re-encode differs from the pinned bytes"

    print("/* ORACLE: python3 hashlib.sha3_512 — env_wire_oracle.py */")
    print("/* ENV_LEN = %d */" % len(wire))
    print(c_array("K_ENV_WIRE", wire))
    print(c_array("K_CHAIN_ID", chain_id))
    print(c_array("K_RULESET_HASH0", rulesets[0]))
    print(c_array("K_RULESET_HASH1", rulesets[1]))
    print(c_array("K_CALL_COMMIT0", env.call_commit(0)))
    print(c_array("K_CALL_COMMIT1", env.call_commit(1)))
    print(c_array("K_AUTHCTX_COMMIT", env.auth_context_commit()))
    print(c_array("K_AUTH_DIGEST0", env.auth_digest(0)))
    print(c_array("K_AUTH_DIGEST1", env.auth_digest(1)))
    print(c_array("K_TX_ID", env.tx_id()))

    # ── binding property the oracle can assert on its own ───────────────
    import copy
    m = copy.deepcopy(env)
    m.legs[0].auth_data = bytes([0xFF]) * len(m.legs[0].auth_data)
    assert m.auth_context_commit() == env.auth_context_commit(), \
        "auth_data must NOT affect authctx"
    assert m.auth_digest(0) == env.auth_digest(0), \
        "auth_data must NOT affect its own auth_digest"
    assert m.auth_digest(1) == env.auth_digest(1)
    assert m.tx_id() != env.tx_id(), "auth_data MUST affect tx_id"
    print("/* oracle self-check: auth_data affects tx_id only — OK */")


if __name__ == "__main__":
    main()
