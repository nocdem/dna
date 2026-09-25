#!/usr/bin/env python3
"""
LEDGER V2 — INTENT SEASON — INDEPENDENT ORACLE for the canonical intent
identity (intent_leg_commit / intent_id).

PROVENANCE: written by the ORCHESTRATOR directly from the locked season
preimage specification (tag literals, field order, widths), NOT by reading
or transcribing the C implementation (env_wire.c). It shares no code and no
serialized buffers with the C side; the only shared artifact is the PINNED
KAT fixture wire bytes (the test vector itself). Hash primitive: python3
hashlib.sha3_512 (stdlib, FIPS-202).

What it proves, standalone:
  1. the existing FULL-WIRE identity KAT (K_TX_ID) is byte-identical to the
     pre-season pin — the wire identity did not move;
  2. the committed intent KATs (K_ILEG*, K_INTENT_ID) for the pinned
     fixture;
  3. same-intent / different-authorization twins: mutating auth_data, and
     changing auth_len (witness cardinality), move tx_id — and auth_len
     also moves auth_context_commit — while intent_id stays byte-identical;
  4. every classified SEMANTIC field moves intent_id (mutation matrix).

Run:  python3 env_intent_oracle.py
"""
import copy
import hashlib
import struct

# ── constants (season spec) ─────────────────────────────────────────────
WIRE_FAMILY = b"DNA.ENVWIRE.v1".ljust(16, b"\0")
TAG_CALL    = b"DNA.ENVCALL.v1".ljust(16, b"\0")
TAG_AUTHCTX = b"DNA.ENVCTX.v1".ljust(16, b"\0")
TAG_TXID    = b"DNA.ENVTXID.v1".ljust(16, b"\0")
TAG_ILEG    = b"DNA.ENVILEG.v1".ljust(16, b"\0")
TAG_INTENT  = b"DNA.ENVINTID.v1".ljust(16, b"\0")

ENV_VERSION = 1
FIXED_HEAD  = 43
LEG_HDR_LEN = 30

for t in (WIRE_FAMILY, TAG_CALL, TAG_AUTHCTX, TAG_TXID, TAG_ILEG, TAG_INTENT):
    assert len(t) == 16
# tag distinctness inside the ENV namespace (collision scan, exact bytes)
assert len({WIRE_FAMILY, TAG_CALL, TAG_AUTHCTX, TAG_TXID, TAG_ILEG,
            TAG_INTENT}) == 6


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
        self.ruleset_hash = ruleset_hash   # contextual, 64 B, NOT serialized

    def header_bytes(self):
        b = (be32(self.domain_id) + be32(self.runtime_op) +
             be32(self.ruleset_version) + be8(self.access_mode) +
             be8(self.auth_kind) + be32(len(self.call_data)) +
             be32(len(self.auth_data)) + be32(self.res_max_effects) +
             be32(self.res_max_effect_bytes))
        assert len(b) == LEG_HDR_LEN
        return b


class Envelope:
    def __init__(self, expiry_height, fee_amount, res_max_total_units, legs,
                 chain_id):
        self.expiry_height = expiry_height
        self.fee_amount = fee_amount
        self.res_max_total_units = res_max_total_units
        self.legs = legs
        self.chain_id = chain_id           # contextual, 32 B, NOT serialized

    def encode(self):
        n = len(self.legs)
        out = (WIRE_FAMILY + be8(ENV_VERSION) + be64(self.expiry_height) +
               be64(self.fee_amount) + be64(self.res_max_total_units) +
               be16(n))
        assert len(out) == FIXED_HEAD
        for lg in self.legs:
            out += lg.header_bytes()
        for lg in self.legs:
            out += lg.call_data
        for lg in self.legs:
            out += lg.auth_data
        return out

    def call_commit(self, i):
        lg = self.legs[i]
        pre = (TAG_CALL + be32(lg.domain_id) + be32(lg.runtime_op) +
               be32(lg.ruleset_version) + lg.ruleset_hash +
               be8(lg.access_mode) + be32(len(lg.call_data)) + lg.call_data)
        assert len(pre) == 97 + len(lg.call_data)
        return sha3(pre)

    def auth_context_commit(self):
        n = len(self.legs)
        b = (WIRE_FAMILY + be8(ENV_VERSION) + self.chain_id +
             be64(self.expiry_height) + be64(self.fee_amount) +
             be64(self.res_max_total_units) + be16(n))
        for i, lg in enumerate(self.legs):
            b += (be32(lg.domain_id) + be32(lg.runtime_op) +
                  be32(lg.ruleset_version) + be8(lg.access_mode) +
                  be8(lg.auth_kind) + be32(len(lg.call_data)) +
                  be32(len(lg.auth_data)) + be32(lg.res_max_effects) +
                  be32(lg.res_max_effect_bytes) + self.call_commit(i))
        return sha3(TAG_AUTHCTX + b)

    def tx_id(self):
        env = self.encode()
        return sha3(TAG_TXID + self.auth_context_commit() +
                    be32(len(env)) + env)

    # ── the season's NEW derivations (spec transcription) ───────────────
    def intent_leg_commit(self, i):
        lg = self.legs[i]
        pre = (TAG_ILEG + be32(lg.domain_id) + be32(lg.runtime_op) +
               be32(lg.ruleset_version) + be8(lg.access_mode) +
               be8(lg.auth_kind) + be32(lg.res_max_effects) +
               be32(lg.res_max_effect_bytes) + self.call_commit(i))
        assert len(pre) == 102, len(pre)     # NO auth_len anywhere
        return sha3(pre)

    def intent_id(self):
        n = len(self.legs)
        pre = (TAG_INTENT + WIRE_FAMILY + be8(ENV_VERSION) + self.chain_id +
               be64(self.expiry_height) + be64(self.fee_amount) +
               be64(self.res_max_total_units) + be16(n))
        assert len(pre) == 91
        for i in range(n):
            pre += self.intent_leg_commit(i)
        return sha3(pre)


def c_array(name, data):
    body = ",".join("0x%02x" % b for b in data)
    return "static const uint8_t %s[%d] = {%s};" % (name, len(data), body)


def main():
    # ── the EXACT fixture pinned in tests/test_env_wire.c (unchanged) ───
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

    # parse the pinned bytes back into fields (as the wire oracle does)
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
    assert ab == len(wire)

    legs = [Leg(h[0], h[1], h[2], h[3], h[4], h[7], h[8],
                calls[i], auths[i], rulesets[i]) for i, h in enumerate(hdrs)]
    env = Envelope(struct.unpack(">Q", wire[17:25])[0],
                   struct.unpack(">Q", wire[25:33])[0],
                   struct.unpack(">Q", wire[33:41])[0],
                   legs, chain_id)
    assert env.encode() == wire, "oracle re-encode differs from the pin"

    # ── 1. the FULL-WIRE identity did not move: the PRE-SEASON frozen
    # KAT_TX_ID pin (test_env_wire.c:1418, unchanged by this season and
    # committed at parent ae95a01d / HEAD c4f1b563), re-derived here from
    # the wire bytes by this oracle's own code. ─────────────────────────
    K_TX_ID_FROZEN = bytes.fromhex(
        "0932456cd60db567b054b4002a8d6be47671bb78d98f367d"
        "6bd92f15a3d671ba5470505904373398b6c1df8d97d408d5"
        "b7d15d39635c01c96fafec4bc61b94c7")
    txid = env.tx_id()
    assert txid == K_TX_ID_FROZEN, \
        "FULL-WIRE identity KAT moved — the season broke the frozen tx_id"

    print("/* ORACLE: python3 hashlib.sha3_512 — env_intent_oracle.py */")
    print(c_array("K_TX_ID_CHECK", txid))
    print(c_array("K_ILEG0", env.intent_leg_commit(0)))
    print(c_array("K_ILEG1", env.intent_leg_commit(1)))
    print(c_array("K_INTENT_ID", env.intent_id()))

    # ── 2. same-intent / different-authorization twins ──────────────────
    base_intent = env.intent_id()
    m = copy.deepcopy(env)
    m.legs[0].auth_data = bytes([0xFF]) * len(m.legs[0].auth_data)
    assert m.tx_id() != env.tx_id(), "auth bytes must move tx_id"
    assert m.intent_id() == base_intent, "auth bytes must NOT move intent"

    m = copy.deepcopy(env)
    m.legs[0].auth_data = m.legs[0].auth_data + b"\xAA\xBB"   # auth_len +2
    assert m.tx_id() != env.tx_id(), "auth_len must move tx_id"
    assert m.auth_context_commit() != env.auth_context_commit(), \
        "auth_len must move the signing commitment (why authctx is not " \
        "a valid intent key)"
    assert m.intent_id() == base_intent, "auth_len must NOT move intent"

    # ── 3. every SEMANTIC field moves intent_id ─────────────────────────
    def mut(fn):
        e2 = copy.deepcopy(env)
        fn(e2)
        assert e2.intent_id() != base_intent, fn
        return e2.intent_id()

    seen = {base_intent}
    muts = [
        lambda e: setattr(e, "chain_id", bytes(32)),
        lambda e: setattr(e, "expiry_height", e.expiry_height + 1),
        lambda e: setattr(e, "fee_amount", e.fee_amount + 1),
        lambda e: setattr(e, "res_max_total_units",
                          e.res_max_total_units + 1),
        lambda e: e.legs.pop(),                          # leg count
        lambda e: e.legs.reverse(),                      # leg order
        lambda e: setattr(e.legs[0], "domain_id", e.legs[0].domain_id + 1),
        lambda e: setattr(e.legs[0], "runtime_op", e.legs[0].runtime_op + 1),
        lambda e: setattr(e.legs[0], "ruleset_version",
                          e.legs[0].ruleset_version + 1),
        lambda e: setattr(e.legs[0], "ruleset_hash", bytes(64)),
        lambda e: setattr(e.legs[0], "access_mode", 1),  # INVOKE(2) -> READ
        lambda e: setattr(e.legs[0], "auth_kind", e.legs[0].auth_kind + 1),
        lambda e: setattr(e.legs[0], "res_max_effects",
                          e.legs[0].res_max_effects + 1),
        lambda e: setattr(e.legs[0], "res_max_effect_bytes",
                          e.legs[0].res_max_effect_bytes + 1),
        lambda e: setattr(e.legs[0], "call_data",
                          e.legs[0].call_data[:-1] + b"\x99"),
        lambda e: setattr(e.legs[0], "call_data",
                          e.legs[0].call_data + b"\x00"),   # call_len
    ]
    for fn in muts:
        v = mut(fn)
        assert v not in seen, "two distinct semantic mutations collided"
        seen.add(v)

    print("/* oracle self-check: %d semantic mutations move intent_id; "
          "auth bytes and auth_len do not; frozen K_TX_ID reproduced "
          "— OK */" % len(muts))


if __name__ == "__main__":
    main()
