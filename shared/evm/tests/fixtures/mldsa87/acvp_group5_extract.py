#!/usr/bin/env python3
"""
acvp_group5_extract.py — extracts the committed ML-DSA-87 primitive-layer
fixture tests/fixtures/mldsa87/acvp_sigver_group5.txt from the NIST
ACVP-Server JSON files (design docs/plans/2026-10-21-mldsa87-evm-precompile-
design.md rev 2 §1.8 layer 1; decision 2026-10-21-mldsa87-evm-precompile.md
item 7(c)).

Source: https://github.com/usnistgov/ACVP-Server at commit
975de31eb83d87039ec88934fdc47d8c312b892d,
gen-val/json-files/ML-DSA-sigVer-FIPS204/{prompt.json,expectedResults.json}.
Before anything is written both files are checked against the sha256 values
recorded when the source was pinned; any mismatch, a missing group, or a
group 5 that is not exactly ML-DSA-87 / external / pure with 15 cases exits
non-zero and writes nothing.

Output: test group tgId 5 only, in tcId order, one line per case:
    <tcId> <testPassed 0|1> <pk hex> <signature hex> <message hex> <context hex>
lower-case hex, an empty field written as "-", fields separated by one
space, lines ended by "\\n". Deterministic: the bytes depend on the two
pinned inputs only.

Usage: python3 acvp_group5_extract.py <dir with the two JSON files> <out.txt>
"""

import hashlib
import json
import os
import sys

PROMPT_SHA256 = "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e"
EXPECTED_SHA256 = "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6"
GROUP = 5
N_CASES = 15


def fail(msg):
    sys.stderr.write("acvp_group5_extract: %s\n" % msg)
    sys.exit(1)


def load(path, want_sha):
    with open(path, "rb") as f:
        raw = f.read()
    got = hashlib.sha256(raw).hexdigest()
    if got != want_sha:
        fail("%s: sha256 %s, pinned %s" % (path, got, want_sha))
    return json.loads(raw)


def hexfield(v):
    v = v.lower()
    bytes.fromhex(v)                       # must be well-formed hex
    return v if v else "-"


def main():
    if len(sys.argv) != 3:
        fail("usage: acvp_group5_extract.py <acvp dir> <out.txt>")
    src, out = sys.argv[1], sys.argv[2]
    prompt = load(os.path.join(src, "prompt.json"), PROMPT_SHA256)
    expected = load(os.path.join(src, "expectedResults.json"), EXPECTED_SHA256)

    groups = [g for g in prompt["testGroups"] if g["tgId"] == GROUP]
    egroups = [g for g in expected["testGroups"] if g["tgId"] == GROUP]
    if len(groups) != 1 or len(egroups) != 1:
        fail("test group %d missing or duplicated" % GROUP)
    g, eg = groups[0], egroups[0]
    if (g.get("parameterSet") != "ML-DSA-87" or
            g.get("signatureInterface") != "external" or
            g.get("preHash") != "pure"):
        fail("group %d is not ML-DSA-87 / external / pure" % GROUP)
    verdict = {t["tcId"]: t["testPassed"] for t in eg["tests"]}
    tests = sorted(g["tests"], key=lambda t: t["tcId"])
    if len(tests) != N_CASES or len(verdict) != N_CASES:
        fail("group %d has %d cases, %d verdicts (want %d)"
             % (GROUP, len(tests), len(verdict), N_CASES))

    lines = []
    for t in tests:
        tc = t["tcId"]
        if tc not in verdict or not isinstance(verdict[tc], bool):
            fail("no boolean verdict for tcId %d" % tc)
        lines.append("%d %d %s %s %s %s\n" % (
            tc, 1 if verdict[tc] else 0,
            hexfield(t["pk"]), hexfield(t["signature"]),
            hexfield(t["message"]), hexfield(t["context"])))
    with open(out, "w", newline="\n") as f:
        f.writelines(lines)


if __name__ == "__main__":
    main()
