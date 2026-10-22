#!/usr/bin/env python3
r"""
Oracle for the ML-DSA-87 verification precompile's activation vote literal
(chain_config param 23 MLDSA_ACTIVE, dnac.h DNAC_CFG_MLDSA_ACTIVE_D).

Decision docs/plans/decisions/2026-10-21-mldsa87-evm-precompile.md (items
1-8, "Measurement", "Activation route and grace": Route B); design
docs/plans/2026-10-21-mldsa87-evm-precompile-design.md rev 2 §1.7 "Common to
both": "The vote literal D BINDS the constants — tag address, the 19 ctx
bytes, 25 000 / 12, 65 536". Kurultay #31 round 3 (both members): "The vote
literal D is the sole committed binding of the precompile's constants; its
preimage must be specified (it must carry the 32-byte tag address and the 19
ctx bytes)".

⚠ PROVENANCE — SELF-DERIVED, NOT INDEPENDENT
--------------------------------------------
Written by the SAME agent that wrote the C re-derivation
(nodus/src/witness/nodus_witness.c, the start-up check of this literal). It
proves only that the C and THIS file agree on the layout the agent wrote
down — "self-consistent", NOT an independent pin (the CLAUDE.md "NO CRYPTO
FROM MEMORY" rule: the same author writing code and audit is circular).
Before any MLDSA_ACTIVE vote, an agent that has NOT read the C must
re-derive D from the layout below and the decision file.

DECIDED — operator "Onaylıyorum", 2026-10-22
--------------------------------------------
The tag string "NDS.MLDSAACT.v1" AND the whole preimage layout below were
proposed by the implementing agent and approved by the operator (decision
file, "Vote literal tag and preimage"). The existing constructors
(shared/dnac/domain_wire.c dna_evm_activation_digest, dna_rolegen_vote_digest)
take 64-byte hashes and u64 lists only, so a 32-byte address and 19 context
bytes need a new shape. The tag follows the NDS.* naming of the param-14
literal's "NDS.EVMACT.v1" (collision scan 2026-10-21: no other
"NDS.MLDSAACT" in the tree).

Preimage (115 bytes), SHA3-512 over:
  offset  len  field
       0   16  TAG16("NDS.MLDSAACT.v1")  (15 ASCII bytes, zero-padded to 16)
      16   32  precompile address = SHA3-512("NDS.EVMMLDSA87.v1")[0..32]
      48    4  ctx_len u32 BE  (19)
      52   19  FIPS 204 context, the ASCII bytes "nodus.evm.attest.v1"
      71    4  n_consts u32 BE (5)
      75   40  5 x u64 BE, in this order:
                 25000  EVM_G_PRECOMPILE_MLDSA87_BASE     (gas, fixed part)
                    12  EVM_G_PRECOMPILE_MLDSA87_PER_WORD (gas per 32-B word)
                 65536  EVM_MLDSA87_MSG_MAX               (message bound)
                  2592  EVM_MLDSA87_PK_BYTES              (public key width)
                  4627  EVM_MLDSA87_SIG_BYTES             (signature width)
D = the first 8 digest bytes read big-endian, top bit cleared (<= INT64_MAX,
the SQLite int64 column) — the param-14 reduction (nodus_evm_activation_
oracle.py d_of).

Stages, fail-closed:
  CONTROL (byte-exact, else exit 1):
    C0 the param-14 oracle's own control stage (C1-C7) passes, and its
       EVM_ACTIVE literal E7 equals the shipped DNAC_CFG_EVM_ACTIVE_D
       0x029f47596864d407 — the shared helpers (tag16, be32, be64) are the
       ones that reproduce shipped literals
    C8 SHA3-512("NDS.EVMMLDSA87.v1")[0..32] equals the decision's pinned
       address 0x66e24906…9cce (decision item 5)
  EMIT:
    M1 the 115-byte preimage (hex)
    M2 D (MLDSA_ACTIVE literal)

Run:  python3 shared/dnac/tests/nodus_mldsa_activation_oracle.py

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import contextlib
import hashlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ruleset_desc_oracle import be32, be64, tag16  # noqa: E402
import nodus_evm_activation_oracle as evm_oracle  # noqa: E402

# dnac/include/dnac/dnac.h DNAC_CFG_EVM_ACTIVE_D (shipped)
SHIPPED_EVM_ACTIVE_D = 0x029f47596864d407

# decision 2026-10-21-mldsa87-evm-precompile.md item 5 (pinned there,
# computed with hashlib.sha3_512) = shared/evm/evm.h EVM_MLDSA87_ADDR_BYTES
PINNED_ADDR = bytes.fromhex(
    "66e24906024f903b345880bf43c39224c772b9acf62cd78299ced278cb3c9cce")

# DECIDED — operator "Onaylıyorum", 2026-10-22 (see PROVENANCE)
MLDSA_ACT_TAG = "NDS.MLDSAACT.v1"

ADDR_TAG = b"NDS.EVMMLDSA87.v1"          # evm.h EVM_MLDSA87_TAG, 17 bytes
CTX = b"nodus.evm.attest.v1"              # evm.h EVM_MLDSA87_CTX, 19 bytes

# the bound constants, in preimage order
CONSTS = [
    25000,   # EVM_G_PRECOMPILE_MLDSA87_BASE     (shared/evm/evm_gas.h)
    12,      # EVM_G_PRECOMPILE_MLDSA87_PER_WORD (shared/evm/evm_gas.h)
    65536,   # EVM_MLDSA87_MSG_MAX               (shared/evm/evm.h)
    2592,    # EVM_MLDSA87_PK_BYTES              (shared/evm/evm.h)
    4627,    # EVM_MLDSA87_SIG_BYTES             (shared/evm/evm.h)
]

PREIMAGE_LEN = 16 + 32 + 4 + 19 + 4 + 8 * 5      # 115


def sha3(b: bytes) -> bytes:
    return hashlib.sha3_512(b).digest()


def preimage(addr: bytes) -> bytes:
    if len(addr) != 32 or len(CTX) != 19:
        raise AssertionError("address / context width")
    pre = (tag16(MLDSA_ACT_TAG) + addr + be32(len(CTX)) + CTX
           + be32(len(CONSTS)))
    for c in CONSTS:
        pre += be64(c)
    if len(pre) != PREIMAGE_LEN:
        raise AssertionError("preimage %d != %d" % (len(pre), PREIMAGE_LEN))
    return pre


def main() -> int:
    # C0: the param-14 oracle's control stage, then its E7 vs the shipped
    # literal (its output is captured; only the verdict is printed)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = evm_oracle.main()
    want_e7 = "#define DNAC_CFG_EVM_ACTIVE_D 0x%016xULL" % SHIPPED_EVM_ACTIVE_D
    c0 = rc == 0 and want_e7 in buf.getvalue()
    print("[%s] C0 param-14 oracle control + E7 == shipped EVM_ACTIVE_D"
          % ("PASS" if c0 else "FAIL"))
    addr = sha3(ADDR_TAG)[:32]
    c8 = addr == PINNED_ADDR
    print("[%s] C8 SHA3-512(\"NDS.EVMMLDSA87.v1\")[0..32] == pinned address"
          % ("PASS" if c8 else "FAIL"))
    if not c8:
        print("   got    %s\n   pinned %s" % (addr.hex(), PINNED_ADDR.hex()))
    if not (c0 and c8):
        print("CONTROL FAILED — emitting nothing")
        return 1

    pre = preimage(addr)
    d = int.from_bytes(sha3(pre)[:8], "big") & 0x7FFFFFFFFFFFFFFF
    print()
    print("M1 preimage (%d bytes)  %s" % (len(pre), pre.hex()))
    print("M2 D                    0x%016x (%d)" % (d, d))
    print()
    print("#define DNAC_CFG_MLDSA_ACTIVE_D 0x%016xULL" % d)
    print()
    print("control green — D above is SELF-DERIVED; its layout is DECIDED "
          "(see PROVENANCE)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
