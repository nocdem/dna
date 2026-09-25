# ML-KEM-1024 test vectors — pinned sources

## 1. NIST ACVP (FIPS 203 FINAL) — `acvp-ML-KEM-1024.txt.gz`  ← authoritative KeyGen / Encaps / Decaps / key-check KAT

Source: https://github.com/usnistgov/ACVP-Server, commit `975de31eb83d87039ec88934fdc47d8c312b892d` (fetched 2026-09-23)
- `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json` (vsId 42, revision FIPS203)
- `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json` (revision FIPS203)

Extracted subset (parameterSet == ML-KEM-1024 only), one record per line, `<kind> key=hex …`:

| kind | count | fields | what the test asserts |
|---|---|---|---|
| `keyGen` | 25 | d, z, ek, dk | `keypair_derand(d‖z)` == (ek, dk) byte-exact — FIPS 203 Alg 16 with G(d‖k) |
| `encap` | 25 | ek, dk, m, c, k | `encapsulate_derand(ek, m)` == (c, k); `decapsulate(dk, c)` == k |
| `decap` | 10 | dk, c, k, reason ∈ {valid_decapsulation, modified_ciphertext} | `decapsulate(dk, c)` == k (modified ciphertext ⇒ implicit rejection K̄ = J(z‖c) must still equal k) |
| `ekCheck` | 10 | ek, testPassed, reason ∈ {valid_encapsulation_key, noisy_linear_system_values_too_large} | `ek_check(ek) == 0` iff testPassed (FIPS 203 §7.2 modulus check) |
| `dkCheck` | 10 | dk, testPassed, reason ∈ {valid_decapsulation_key, modified_H} | `decapsulate(dk, any ct)` returns 0 iff testPassed (FIPS 203 §7.3 hash check) |

Verified against the FINAL standard before staging: for keyGen tcId 51, ek's trailing ρ equals SHA3-512(d ‖ 0x04)[0:32] (G(d‖k), k = 4) and NOT SHA3-512(d)[0:32].
Raw size 752 488 B; stored gzipped (342 KB); decompressed at CMake configure time into the build dir.

## 2. C2SP/CCTV — draft-era, kept ONLY for what is independent of KeyGen

Source: https://github.com/C2SP/CCTV/tree/main/ML-KEM, commit `4448f2097b2daa812c91a26141f9f36c2096b9ca`, last change to that directory 2024-01-30 (CC0 1.0).

⚠ FINDING (2026-09-23, computed, not assumed): these vectors implement the FIPS 203 **initial public draft** KeyGen — in `intermediate-ML-KEM-1024.txt`, ρ‖σ == SHA3-512(d) (no k byte); the FINAL FIPS 203 (Aug 2024, Alg 13 step 1, App. C.2) uses G(d‖k). Therefore any expectation of the form "d → ek/dk" from CCTV is WRONG for a final-FIPS-203 implementation and must not be tested. What remains valid (does not involve KeyGen's G input):

| File | Origin | Still used for |
|---|---|---|
| intermediate-ML-KEM-1024.txt | ML-KEM/intermediate/ML-KEM-1024.txt | `encapsulate_derand(ek, m)` == (c, K) and `decapsulate(dk, c)` == K using the file's own ek/dk (a valid key pair regardless of how it was generated). The `d`/`z` lines are NOT to be used. |
| modulus-ML-KEM-1024.txt.gz | ML-KEM/modulus/ML-KEM-1024.txt.gz (kept gzipped: 28 KB vs 3.2 MB; 1040 lines, one hex ek per line; decompressed at CMake configure time) | INVALID encapsulation keys (a coefficient ≥ q) — `ek_check` must reject every line |
| strcmp-ML-KEM-1024.txt | ML-KEM/strcmp/ML-KEM-1024.txt | dk / c / K triples where c contains a zero byte — catches `strcmp()`-style comparison in Decaps |

Removed 2026-09-23: `unluckysample-ML-KEM-1024.txt` (its "unlucky" ρ is G(d) of the draft; under G(d‖k) the same d is not unlucky) and the README's "accumulated" SHAKE-128 hash (`47ac888f…`, computed with draft KeyGen).

Note (CCTV README "Changes from the FIPS 203 draft"): the vectors use the (i, j) XOF input order of Kyber round 3, which the FINAL FIPS 203 also uses (App. C.2) — that part is fine.
