# RIPEMD-160 (trezor-crypto) — vendored source (Nodus EVM precompile 0x03, ripemd160)

| Field | Value |
|---|---|
| Upstream | https://github.com/trezor/trezor-firmware, directory `crypto/` (trezor-crypto) |
| Commit | `78184de0a4b840f4be1cf4c565eba4c6692af5ef` (2026-10-05 14:53:19 +0200, "ci: hw: run the permission debugging script even if uhubctl fails") — HEAD of the default branch on the fetch date. NOT a release tag and NOT a signed object: trezor-crypto has no release of its own; the commit hash is the pin. (Contrast libsecp256k1, pinned to a verified signed tag.) |
| Fetched | `git clone --filter=blob:none --sparse --depth 1 https://github.com/trezor/trezor-firmware`, `git sparse-checkout set crypto`, `git rev-parse HEAD` = the commit above, 2026-10-05 |
| License | see "License" below (`LICENSE` = upstream `crypto/LICENSE`, copied) |

## Operator decision

`docs/plans/decisions/2026-10-05-nodus-evm-redteam1-operator.md`, D2, as
extended by the operator on 2026-10-05: the EVM precompiles 0x02 (SHA-256)
and 0x03 (RIPEMD-160) take their digests from a FIXED, pinned
implementation instead of the system OpenSSL. SHA-256 comes from the
already-vendored blst v0.3.17 (`blst_sha256`, `third_party/blst`);
RIPEMD-160 from this directory. Before this, both came from the system
libcrypto through an explicit OpenSSL 3 library context, which required
OpenSSL >= 3.0.7 (RIPEMD-160 entered the "default" provider in 3.0.7) and
made the digest bytes depend on whichever libcrypto a host had installed.

## Files copied (byte-identical to the commit above; each verified with `cmp`)

| File | git blob at the commit | sha256 |
|---|---|---|
| `ripemd160.c` | `f6581bfa03bed822f4451dc30d270fc92e9dbf8d` | `819dbc7aa10c919feb7ede7aca303abd561379e5f816f680aab87a06f7181b7d` |
| `ripemd160.h` | `c3dbb48ef54007c85779cc3df8d0dedd401c3a19` | `1c9cafb5cb0444ae815c138801252c6f0ffe3306e85180d952ff21be943b0305` |
| `memzero.c`   | `1c5ea77a6cab21decee976c7a7358c4360509ef2` | `2f014e8d03420b42fb7b9df39f9150a33ac96d1c48a065f5a908a967561bca02` |
| `memzero.h`   | `0a959fbc2d4d14ecc1d432ae9279cf369ec240ac` | `ffec031a236dde8df1c0b95cd0c3bd28ca046f6dc62faff36be8401ba82b214a` |
| `LICENSE`     | `4b6a7d1e42254d3604fd69e5d179424e8e873d0f` | `7f9bd155903ca4266c19784715d1a274221fa67f268aae4d827c76491529abc0` |

Why these: `ripemd160.c` includes `ripemd160.h`, `<assert.h>`, `memzero.h`,
`<stdint.h>`, `<string.h>` and calls `memzero()` (wiping its state after use);
`memzero()` is defined in `memzero.c` and nowhere else in this monorepo. The
four files are the closed set; no header was written or changed here.

Not copied: everything else in `crypto/` (the rest of trezor-crypto, its
tests, its build system).

## License

`crypto/LICENSE` (copied as `LICENSE`) covers the files differently:

- `ripemd160.c`, `ripemd160.h`: listed under "PUBLIC DOMAIN AND CC0
  COMPONENTS" — "RIPEMD-160 -- Dwayne C. Litzenberger, adapted by Pieter
  Wuille" (https://github.com/sipa/Coin25519), public-domain dedication
  reproduced in the file header and in `LICENSE`.
- `memzero.c`, `memzero.h`: trezor-crypto's MIT license (the blanket
  "Throughout the library" holders in `LICENSE`).

## Build configuration (shared/evm/Makefile, nodus/CMakeLists.txt)

`ripemd160.c`, `memzero.c`: `cc -O2 -fPIC -std=gnu11 -Wall -Wextra`

- `-std=gnu11`: upstream's own (`crypto/Makefile` CFLAGS). `memzero.c` uses
  `explicit_bzero` on glibc >= 2.25, which glibc declares in GNU mode.
- `-O2 -fPIC -Wall -Wextra`: the optimisation / PIC / warning level every
  other vendored C library here is built with (blst, secp256k1). Upstream's
  further warnings, `-Werror` and `-ftrivial-auto-var-init=zero` are not
  used; none changes the computed digest.
- No `NDEBUG`: the `assert`s in `ripemd160.c` stay live, as upstream builds
  them. `ripemd160_process` asserts `p != NULL` even for length 0, so the
  caller (`evm_precompile.c` pc_ripemd160) never passes NULL.
- Archived into `build/libevm_deps.a` (Makefile) / `nodus_evm_deps`
  (CMake) with blst, c-kzg-4844, mcl and libsecp256k1.

## Byte order

`ripemd160.c` byte-swaps the message block and digest only when
`PCT_BIG_ENDIAN` is defined by hand (`ripemd160.c` `#ifdef PCT_BIG_ENDIAN`
blocks around `byteswap32` / `byteswap_digest`); nothing defines it. On a
big-endian host it would compute a wrong digest. `evm_precompile.c` refuses
to compile on a big-endian target (`#error`), and the start-up known-answer
self-test (`evm_precompile_selftest_report`) checks 0x03 before any vote.

## Local patches

None.
