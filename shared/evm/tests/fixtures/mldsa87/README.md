# ML-DSA-87 fixtures (Nodus EVM ML-DSA-87 precompile)

Primitive-layer known answers for the verifier behind the Nodus EVM ML-DSA-87
precompile (`evm.h` `mldsa_precompile`; decision
`docs/plans/decisions/2026-10-21-mldsa87-evm-precompile.md` item 7(c); design
`docs/plans/2026-10-21-mldsa87-evm-precompile-design.md` rev 2 §1.8 layer 1).

## `acvp_sigver_group5.txt`

- **Source:** NIST ACVP-Server, https://github.com/usnistgov/ACVP-Server,
  commit `975de31eb83d87039ec88934fdc47d8c312b892d`, directory
  `gen-val/json-files/ML-DSA-sigVer-FIPS204/`:
  - `prompt.json` sha256 `e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e`
  - `expectedResults.json` sha256 `e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6`
- **Content:** test group `tgId` 5 only — `parameterSet` ML-DSA-87,
  `signatureInterface` external, `preHash` pure, test type AFT — 15 cases,
  `tcId` 61..75; 3 valid (63, 67, 70), 12 invalid. 14 cases carry a non-empty
  FIPS 204 context (6..255 bytes); `tcId` 64 has an empty one.
- **Format:** one line per case, in `tcId` order:
  `<tcId> <testPassed 0|1> <pk hex> <signature hex> <message hex> <context hex>`
  — lower-case hex, an empty field written as `-`, single spaces, `\n` line
  ends.
- **Made by:** `acvp_group5_extract.py` (this directory), which refuses inputs
  whose sha256 differs from the values above and writes nothing on any
  mismatch. It was run once through
  `make -C shared/evm mldsa-acvp-vectors ACVP=<dir with the two JSON files>`;
  `make -C shared/evm mldsa-acvp-vectors-check ACVP=<dir>` re-extracts into
  `build/` and compares byte for byte. The file's sha256 at commit time:
  `fa10d637be2217313999b2460a947489d2900bca91f52114b820230f2857f39c`
  (346 598 bytes).
- **Used by:** `shared/evm/tests/test_mldsa_precompile.c` check
  `m12_acvp_group5`: every case through `qgp_dsa87_verify_ctx`, all 15 must
  agree with `testPassed`; a missing or short fixture is a failure, not a
  skip. The ORCHESTRATOR ran the same 15 cases on 2026-10-21 with a scratch
  tool: 15 agree, 0 disagree.

What it proves: the vendored verifier accepts exactly the signatures NIST's
reference accepts for these 15 ML-DSA-87 inputs, contexts included. What it
does not prove: anything about the Nodus context string `nodus.evm.attest.v1`,
the precompile's framing or gas (that is the precompile layer of the same
test), or inputs outside these 15.
