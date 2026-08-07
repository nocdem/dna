#!/usr/bin/env python3
"""
LEDGER V2 — INDEPENDENT ORACLE for the deterministic envelope PREFLIGHT.

PROVENANCE: written directly from the frozen wire/commitment specification
documented in shared/dnac/env_wire.h:37-118 (tag literals, field order, byte
offsets, preimage shapes). It reads no C source, imports no C code, and runs
no C binary. Hash primitive: python3 hashlib.sha3_512 (stdlib, FIPS-202).

The preflight adds NO new preimage: it is the fixed ORDER in which the four
frozen commitments are derived (call_commit per leg -> auth_context_commit ->
auth_digest per leg -> tx_id) plus purely structural gates (expiry compare,
positional contextual-ruleset match) that hash nothing. So the values this
oracle emits are exactly the env_wire commitments for one season fixture,
and pinning them in test_env_preflight.c pins the preflight's derivation
order as well as its arithmetic.

Deterministic output: no timestamps, no randomness, no environment reads.

Run:  python3 env_preflight_oracle.py
"""
import copy
import hashlib
import struct

# -- constants (spec: env_wire.h:37-44, :46-75) --------------------------
WIRE_FAMILY = b"DNA.ENVWIRE.v1".ljust(16, b"\0")
TAG_CALL    = b"DNA.ENVCALL.v1".ljust(16, b"\0")
TAG_AUTHCTX = b"DNA.ENVCTX.v1".ljust(16, b"\0")
TAG_AUTH    = b"DNA.ENVAUTH.v1".ljust(16, b"\0")
TAG_TXID    = b"DNA.ENVTXID.v1".ljust(16, b"\0")

ENV_VERSION   = 1
FIXED_HEAD    = 43
LEG_HDR_LEN   = 30
MAX_TOTAL_LEN = 65536
MAX_LEGS      = 64

ACCESS_READ   = 1
ACCESS_INVOKE = 2

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
        self.ruleset_hash = ruleset_hash   # contextual, 64 B, NOT serialized

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
        self.chain_id = chain_id           # contextual, 32 B, NOT serialized

    # -- wire (env_wire.h:46-75) -----------------------------------------
    def encode(self):
        n = len(self.legs)
        assert 1 <= n <= MAX_LEGS
        for i in range(1, n):
            assert self.legs[i - 1].domain_id < self.legs[i].domain_id, \
                "legs must be STRICTLY ascending by domain_id"
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

    # -- commitments (env_wire.h:77-103) ---------------------------------
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
    """Emit in this tree's pinned-literal style (8 bytes per line, matching
    tests/test_env_wire.c:1367-1376) so the values are copied VERBATIM into
    the C test rather than re-flowed by hand."""
    lines = []
    for off in range(0, len(data), 8):
        chunk = data[off:off + 8]
        lines.append("    " + ", ".join("0x%02x" % b for b in chunk) + ",")
    lines[-1] = lines[-1].rstrip(",")
    return ("static const uint8_t %s[%d] = {\n%s\n};"
            % (name, len(data), "\n".join(lines)))


def season_fixture():
    """The ONE season fixture the C KATs pin. Three legs; every contextual
    input distinct and non-degenerate; chain_id non-zero in every byte so a
    truncation regression at byte 16..31 is observable."""
    chain_id = bytes(range(0xA0, 0xC0))
    assert len(chain_id) == 32
    assert all(b != 0 for b in chain_id)
    # bytes 0, 15, 16, 31 pairwise distinct -> four independent detectors
    assert len({chain_id[0], chain_id[15], chain_id[16], chain_id[31]}) == 4

    # Non-degenerate ruleset digests: derived, never a repeated byte pattern.
    rulesets = [sha3(b"DNA.TEST.RULESET." + bytes([i])) for i in range(3)]
    assert len(set(rulesets)) == 3

    legs = [
        Leg(2,   1, 3, ACCESS_INVOKE, 1,   4,  256, b"alpha-call",
            b"AUTH0", rulesets[0]),
        Leg(7,   0, 1, ACCESS_READ,   2,   0,    0, b"",
            b"", rulesets[1]),
        Leg(9, 255, 2, ACCESS_INVOKE, 3,   9, 4096, bytes(range(64)),
            b"\xEE" * 128, rulesets[2]),
    ]
    return Envelope(1000, 77, 500, legs, chain_id)


def flip(buf, index):
    """One byte, +1 mod 256 — the chain-id mutation the C test mirrors."""
    b = bytearray(buf)
    b[index] = (b[index] + 1) & 0xFF
    return bytes(b)


def main():
    env = season_fixture()
    wire = env.encode()

    # Layout arithmetic, independent of any digest:
    # 43 + 3*30 + (10 + 0 + 64) + (5 + 0 + 128) = 340.
    assert len(wire) == 340, len(wire)

    print("/* ORACLE: python3 hashlib.sha3_512 — env_preflight_oracle.py */")
    print("/* season fixture: 3 legs (domains 2/7/9), ENV_LEN = %d */"
          % len(wire))
    print(c_array("K_PF_ENV", wire))
    print(c_array("K_PF_CHAIN_ID", env.chain_id))
    for i in range(3):
        print(c_array("K_PF_RULESET%d" % i, env.legs[i].ruleset_hash))
    for i in range(3):
        print(c_array("K_PF_CALL_COMMIT%d" % i, env.call_commit(i)))
    print(c_array("K_PF_AUTHCTX", env.auth_context_commit()))
    for i in range(3):
        print(c_array("K_PF_AUTH_DIGEST%d" % i, env.auth_digest(i)))
    print(c_array("K_PF_TX_ID", env.tx_id()))

    # -- chain-id mutation battery ---------------------------------------
    # Bytes 16 and 31 are the TRUNCATION detectors: an implementation that
    # fed only the first 16 chain-id bytes (or treated the value as a
    # C string) would leave these two commitments unchanged.
    print("/* chain-id single-byte mutations (+1 mod 256) — each MUST move "
          "authctx, every auth_digest and tx_id, and MUST NOT move any "
          "call_commit (chain_id is absent from the call preimage, "
          "env_wire.h:78-84) */")
    for idx in (0, 15, 16, 31):
        m = copy.deepcopy(env)
        m.chain_id = flip(env.chain_id, idx)
        assert m.encode() == wire, "chain_id must not touch the wire bytes"
        for i in range(3):
            assert m.call_commit(i) == env.call_commit(i), \
                "chain_id leaked into call_commit"
        assert m.auth_context_commit() != env.auth_context_commit()
        assert m.auth_digest(0) != env.auth_digest(0)
        assert m.tx_id() != env.tx_id()
        print(c_array("K_PF_CHAIN_B%d_AUTHCTX" % idx,
                      m.auth_context_commit()))
        print(c_array("K_PF_CHAIN_B%d_AUTH_DIGEST0" % idx, m.auth_digest(0)))
        print(c_array("K_PF_CHAIN_B%d_TX_ID" % idx, m.tx_id()))

    # -- properties the oracle asserts on its own ------------------------
    m = copy.deepcopy(env)
    m.legs[0].auth_data = b"\xFF" * len(env.legs[0].auth_data)
    assert m.auth_context_commit() == env.auth_context_commit(), \
        "auth_data must NOT affect authctx"
    for i in range(3):
        assert m.auth_digest(i) == env.auth_digest(i), \
            "auth_data must NOT affect any auth_digest"
    assert m.tx_id() != env.tx_id(), "auth_data MUST affect tx_id"
    print("/* oracle self-check: auth_data affects tx_id ONLY — OK */")

    m = copy.deepcopy(env)
    m.legs[1].ruleset_hash = flip(env.legs[1].ruleset_hash, 7)
    assert m.call_commit(1) != env.call_commit(1)
    assert m.call_commit(0) == env.call_commit(0)
    assert m.call_commit(2) == env.call_commit(2)
    assert m.tx_id() != env.tx_id()
    print("/* oracle self-check: contextual ruleset_hash binds leg 1 only "
          "— OK */")


if __name__ == "__main__":
    main()
