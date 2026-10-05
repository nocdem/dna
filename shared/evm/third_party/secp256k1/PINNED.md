# libsecp256k1 (bitcoin-core) — vendored source (Nodus EVM precompile 0x01, ecrecover)

| Field | Value |
|---|---|
| Upstream | https://github.com/bitcoin-core/secp256k1 |
| Release tag | `v0.8.0` (annotated tag object `18f07c42218765cd46148d74d9fe575795f56dce`, PGP-signed with RSA key `6A8F9C266528E25AEB1D7731C2371D91CB716EA7`, Sebastian Falbesoner (theStack). VERIFIED 2026-10-05 in an isolated keyring: `git verify-tag v0.8.0` → "Good signature", key fetched from keys.openpgp.org / keyserver.ubuntu.com, and its fingerprint equals the one in `bitcoin-core/guix.sigs` `builder-keys/theStack.gpg` (an independent source for the key's owner). All 57 vendored files are byte-identical (`cmp`) to that signed tag's tree) |
| Commit | `6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d` (2026-08-03, "Merge bitcoin-core/secp256k1#1906: release: prepare for 0.8.0") |
| Release archive | `https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.8.0.tar.gz`, sha256 `eb52b0e9239dff7dc26be5f9623567141b8720ec47da29eb3c1e0a660d17c8bb` (fetched 2026-10-05). Informational only: GitHub generates these archives on demand and does not promise byte-stable output; the commit above is the pin. |
| License | MIT (`COPYING`, copied) |
| Fetched | `git clone --branch v0.8.0 https://github.com/bitcoin-core/secp256k1`, `git rev-parse HEAD` = the commit above, 2026-10-05 |

## Operator decision

`docs/plans/decisions/2026-10-05-nodus-evm-redteam1-operator.md`, D2
("Sabitle, kaynağı içeri al"): libsecp256k1 with the recovery module enters
under `shared/evm/third_party/` version-pinned, like blst / mcl / c-kzg-4844.
Before this, the engine linked the system library through an unversioned
`find_library(secp256k1)` (nodus/CMakeLists.txt) / `-lsecp256k1`
(shared/evm/Makefile) — the vendoring build host had the Debian package
`libsecp256k1-1 0.2.0-2` (`dpkg -l`, 2026-10-05).

## Files copied (byte-identical to the tagged tree; each verified with `cmp`)

- `COPYING`, `README.md`
- `include/secp256k1.h`, `include/secp256k1_preallocated.h`,
  `include/secp256k1_recovery.h` — the public API used
  (`secp256k1_context_static`, `secp256k1_ecdsa_recoverable_signature_parse_compact`,
  `secp256k1_ecdsa_recover`, `secp256k1_ec_pubkey_serialize`)
- `src/secp256k1.c`, `src/precomputed_ecmult.c`, `src/precomputed_ecmult_gen.c`
  — the three compilation units of upstream's library target
  (`src/CMakeLists.txt`: `secp256k1.c` + the `secp256k1_precomputed` objects)
- `src/modules/recovery/main_impl.h`
- the `src/*.h` headers those units include: the union of `gcc -MM` over the
  three units under the flags below, for the native `__int128` field
  (`field_5x52*`, `scalar_4x64*`, `modinv64*`, `int128_native*`) AND for the
  `USE_FORCE_WIDEMUL_INT64` / `USE_FORCE_WIDEMUL_INT128_STRUCT` variants
  (`field_10x26*`, `scalar_8x32*`, `modinv32*`, `int128_struct*`), so a
  compiler without `__int128` still finds its headers. 55 files + COPYING +
  README.md.

Not copied: tests, benchmarks, the table generators, the other modules
(ecdh, extrakeys, schnorrsig, musig, ellswift, silentpayments), the build
system, `src/asm/`.

## Build configuration (shared/evm/Makefile, nodus/CMakeLists.txt)

`src/secp256k1.c`, `src/precomputed_ecmult.c`, `src/precomputed_ecmult_gen.c`:
`cc -O2 -fPIC -Wall -Wextra -Wno-unused-function -I include -I src
-DENABLE_MODULE_RECOVERY=1
-DECMULT_WINDOW_SIZE=15 -DCOMB_BLOCKS=43 -DCOMB_TEETH=6
-DSECP256K1_NO_API_VISIBILITY_ATTRIBUTES`

- `ECMULT_WINDOW_SIZE=15`, `COMB_BLOCKS=43`, `COMB_TEETH=6`: upstream's
  defaults (`CMakeLists.txt`: `SECP256K1_ECMULT_WINDOW_SIZE 15`,
  `SECP256K1_ECMULT_GEN_KB 86` -> `COMB_BLOCKS=43 COMB_TEETH=6`). The
  precomputed tables in the two `precomputed_*.c` files are selected by these
  values at compile time (`#error` on a mismatch).
- `-Wno-unused-function`: upstream's own warning setting (`CMakeLists.txt`
  `try_append_c_flags(-Wno-unused-function)`); the single-unit build keeps
  static helpers that only other modules / tests call.
- `ENABLE_MODULE_RECOVERY=1`: upstream `src/CMakeLists.txt` for
  `SECP256K1_ENABLE_MODULE_RECOVERY`.
- `SECP256K1_NO_API_VISIBILITY_ATTRIBUTES`: upstream's definition for a
  static library without exported visibility (`src/CMakeLists.txt`).
- No `USE_ASM_X86_64` / `USE_EXTERNAL_ASM`: the portable C field
  arithmetic (`__int128` where the compiler has it), the same posture as mcl's
  plain-C++ build. Results are exact either way; speed only.
- Archived into `build/libevm_deps.a` (Makefile) / `nodus_evm_deps`
  (CMake) with blst, c-kzg-4844 and mcl.

## Local patches

None.

## Other copies in the monorepo

`messenger/vendor/secp256k1` is a separate, older copy (v0.7.1, CMake
subproject of the messenger build, EOL client). The nodus standalone build
never links it, so the two never meet in one binary.
