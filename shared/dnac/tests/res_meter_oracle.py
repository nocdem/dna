#!/usr/bin/env python3
"""Independent oracle for shared/dnac/res_meter.{h,c} — the policy-seal
KAT pinned by test_res_meter.c.

Written from the res_meter.h specification only; shares no code with the
C implementation. The seal preimage is:

    tag(16, "DNA.METPOL.v1" zero-padded)
    || policy_version u32 BE
    || w_base || w_callbyte || w_authbyte || w_effect || w_effectbyte
    || w_read || w_write                      (u64 BE each)
    || w_op[0..255]                           (u64 BE each)
    || op_present[0..3]                       (u64 BE each)

and the seal is SHA3-512 over those 2156 bytes.

Reproduce:  python3 shared/dnac/tests/res_meter_oracle.py
"""

import hashlib
import struct


def be32(x):
    return struct.pack(">I", x)


def be64(x):
    return struct.pack(">Q", x)


def policy_hash(tag_str, version, w_base, w_callbyte, w_authbyte,
                w_effect, w_effectbyte, w_read, w_write, w_op,
                present_bits):
    tag = tag_str.encode() + b"\x00" * (16 - len(tag_str))
    assert len(tag) == 16
    present = [0, 0, 0, 0]
    for b in present_bits:
        present[b // 64] |= 1 << (b % 64)
    pre = (tag + be32(version) + be64(w_base) + be64(w_callbyte)
           + be64(w_authbyte) + be64(w_effect) + be64(w_effectbyte)
           + be64(w_read) + be64(w_write))
    for v in w_op:
        pre += be64(v)
    for m in present:
        pre += be64(m)
    assert len(pre) == 2156, len(pre)
    return hashlib.sha3_512(pre).hexdigest()


def seal(*args):
    """The LOCAL integrity checksum ("DNA.METPOL.v1")."""
    return policy_hash("DNA.METPOL.v1", *args)


def identity(*args):
    """The CONSENSUS identity digest ("DNA.METPOLID.v1", execution
    season): same canonical fields, DIFFERENT tag, seal field excluded
    by construction (it is not part of the serialization)."""
    return policy_hash("DNA.METPOLID.v1", *args)


def main():
    # HONEST LABEL: this oracle was written the same day as the C, from
    # the same header spec — the KAT proves SPEC<->C SELF-CONSISTENCY of
    # a LOCAL integrity checksum, not external grounding. The seal never
    # enters any wire or consensus commitment (res_meter.h authority
    # model), so no external reference exists to ground it against.
    #
    # THE test fixture policy (mirrors fixture_policy() in test_res_meter.c):
    # version 1; w_base=7, callbyte=1, authbyte=2, effect=100,
    # effectbyte=3, read=5, write=11; w_op[0]=50, w_op[1]=60,
    # w_op[255]=2**63 (a deliberate >2^32 weight — the u64-truncation
    # tripwire); presence bits exactly {0, 1, 255}.
    w_op = [0] * 256
    w_op[0] = 50
    w_op[1] = 60
    w_op[255] = 2 ** 63
    print("seal     =", seal(1, 7, 1, 2, 100, 3, 5, 11, w_op, (0, 1, 255)))
    print("identity =", identity(1, 7, 1, 2, 100, 3, 5, 11, w_op,
                                 (0, 1, 255)))


if __name__ == "__main__":
    main()
