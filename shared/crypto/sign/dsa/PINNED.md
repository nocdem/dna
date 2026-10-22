# shared/crypto/sign/dsa — upstream pin

The ML-DSA-87 (Dilithium5, FIPS 204) code in this directory is vendored from
the pq-crystals reference implementation. Until 2026-10-21 no upstream commit
was recorded (`CMakeLists.txt` says only "vendored from pq-crystals"). The
Nodus EVM ML-DSA-87 precompile makes this code consensus crypto inside the
EVM rule set, and decision `2026-10-04-nodus-evm-kurultay-k1.md` (conclusion 3)
requires consensus crypto to be pinned (design
`docs/plans/2026-10-21-mldsa87-evm-precompile-design.md` rev 2 §1.8 item 3).

Every fact below is copied from the pin record taken by the ORCHESTRATOR on
2026-10-21 (`docs/plans/kurultay/2026-10-21-31-mldsa-precompile-questions/measure/dsa-pin-2026-10-21.txt`,
local); it was not re-derived here.

## Upstream

- Repository: https://github.com/pq-crystals/dilithium
- Directory: `ref/`
- Commit: `444cdcc84eb36b66fe27b3a2529ee48f6d8150c2`
  (2024-11-01 16:21:46 +0100, "Add internal functions")
- `ref/` is unchanged from `444cdcc` to upstream HEAD `d35ba3f` at the time of
  the record (`git log 444cdcc..HEAD -- ref` is empty; `d35ba3f`, 2026-06-03,
  touched `avx2/sign.c` only — the norm check it adds already exists in
  upstream `ref/sign.c:314` and in ours, `sign.c:412`).

## Files (sources compiled into the library)

Diff lines against upstream `444cdcc` `ref/`, and the sha256 of our file as
recorded at main `964cf34b8`:

| File | Diff lines vs upstream | sha256 (ours) |
|---|---|---|
| `fips202.c` | 3 | `91a503a9a947a25d3286a634dcd6b0b411b78d26479163e29b484a1012807393` |
| `ntt.c` | 0 | `921b76ae7a183305893800e69c0b9ea561bffd2a6e85621767eb789c02a0f8d0` |
| `packing.c` | 0 | `af51fe6b63164c17a765fcca14afa1ad2bfa11a1389a1964781951cdaf0f6016` |
| `poly.c` | 8 | `dc6c3a5ab3e15d183916bab01ef49d6c2e2c7817115cc19f3a711b4c3d6e9d6c` |
| `polyvec.c` | 3 | `cec34fafe74c07badaef856a750710eb17a0e164760dc92f579351eb0c5a5c22` |
| `reduce.c` | 0 | `3088cac3d23355a3f9adaac9fd4ee864be9caf5fb0ad30bcb4a4da17dba0e4f4` |
| `rounding.c` | 0 | `7223dbbe56b1fba226d536d64eaf05b1ad3f249d33ec767ee655eee471478816` |
| `sign.c` | 120 | `8a276b9fe17a7ecba1a04cae1453558dba1be61b8ff76b4e634133c6a92f794f` |
| `symmetric-shake.c` | 0 | `5b23002163d0dd4a1030e51fed8994a06972644e923df0feca6d1d183f4bdd45` |

Re-checked 2026-10-21 at `4bf1af617` (`sha256sum dsa/*.c`): all nine values
match; `git diff 964cf34b8 4bf1af617 -- shared/crypto/sign/dsa` is empty.

Not covered by the record: the headers (`*.h`), `nistkat/`, `test/`, and the
wrapper `../qgp_dilithium.c` (not upstream code). A pin of the headers needs
its own comparison against upstream; none was made.

## Deltas against upstream (from the record)

- **Verification path:** `crypto_sign_verify` (the context wrapper) is
  IDENTICAL to upstream. `crypto_sign_verify_internal` differs ONLY in the
  final `c` / `c2` comparison — ours is constant-time (`r |= c[i] ^ c2[i]`)
  with the same result.
- **Other deltas:** `dilithium_secure_clear` calls (`poly.c` ×5,
  `fips202.c` ×1, `polyvec.c` ×1); key-generation / signing handling of a
  randomness failure, and `crypto_sign_keypair_from_seed` (`sign.c`); blank
  lines in `fips202.c`, `poly.c`, `polyvec.c`.
- **No change to acceptance logic.**

## External known answers

NIST ACVP-Server commit `975de31eb83d87039ec88934fdc47d8c312b892d`,
`gen-val/json-files/ML-DSA-sigVer-FIPS204/`, test group 5 (ML-DSA-87, external
interface, pure; 15 cases) agrees 15/15 with `qgp_dsa87_verify_ctx` (ORCH run
2026-10-21). The group is committed as a test fixture:
`shared/evm/tests/fixtures/mldsa87/` (README there).

## Changing this code

Any change to a file listed above changes consensus behaviour of the Nodus
EVM once the ML-DSA-87 precompile is active (and of every chain signature
check today). Update this file in the same change: the new sha256, the new
diff against upstream, and the reason.
