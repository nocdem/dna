# c-kzg-4844 — vendored source (Nodus EVM precompile 0x0a, point evaluation)

| Field | Value |
|---|---|
| Upstream | https://github.com/ethereum/c-kzg-4844 |
| Release tag | `v2.1.8` (lightweight tag, points directly at the commit) |
| Commit | `e125905e5e01186e6ccb7a0ced4845bf7eddbcfe` (2026-07-09, "Bump version to v2.1.8 (#652)") |
| License | Apache License 2.0 (`LICENSE`, copied) |
| Fetched | `git clone --branch v2.1.8 https://github.com/ethereum/c-kzg-4844`, `git rev-parse HEAD` = the commit above, 2026-10-04 |

## Audit references (from upstream `README.md`, section "Audits", lines 93-98)

- EIP-4844 implementation audited by Sigma Prime (2023): upstream
  `audits/2023_sigp.pdf`
- EIP-7594 implementation audited by zkSecurity (2025): upstream
  `audits/2025_zksec.pdf`

(The PDFs are not copied; they are in the tagged upstream tree.)

## Dependency

blst, vendored at `../blst` (v0.3.17). c-kzg v2.1.8's own submodule pin is
blst `e7f90de551e8df682f3cc99067d204d8b90d27ad` (between v0.3.16 and v0.3.17);
see `../blst/PINNED.md`.

## Trusted setup

`src/trusted_setup.txt` — the setup file shipped in the tagged tree.

- sha256 `d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7`
- 8259 lines: `4096`, `65`, then 4096 G1 Lagrange points (48 B hex each),
  65 G2 monomial points (96 B), 4096 G1 monomial points (48 B) — the order
  `src/setup/setup.c:load_trusted_setup_file` reads.
- Its G2 monomial point 1 (line 4100) equals the constant
  `KZG_SETUP_G2_MONOMIAL_1` in execution-specs@a87891f7
  `src/ethereum/crypto/kzg.py` (`b5bfd7dd…c1def2`), the only setup element
  the reference's `verify_kzg_proof_impl` uses.

The engine embeds this file at build time (`xxd -i`, see
`shared/evm/Makefile`), and on first use checks the embedded bytes'
sha256 against the value above and point 1 against the reference constant
before handing the parsed points to `load_trusted_setup` (precompute 0).
Any mismatch or load error is a node fault (-2), never "proof invalid".

## Files copied (byte-identical to the tagged tree; each verified with `cmp`)

- `LICENSE`, `README.md`
- `src/ckzg.c` (the amalgamation unit that `#include`s every `.c` below),
  `src/ckzg.h`
- `src/common/{alloc,bytes,ec,fr,lincomb,utils}.{c,h}`, `src/common/ret.h`
- `src/eip4844/{blob,eip4844}.{c,h}`
- `src/eip7594/{cell,eip7594,fft,fk20,poly,recovery}.{c,h}` — needed because
  `load_trusted_setup` builds the EIP-7594 tables too
- `src/setup/{setup.c,setup.h,settings.h}`
- `src/trusted_setup.txt`

This set is exactly the closure `gcc -MM src/ckzg.c` reports (plus the
setup file and the licence/readme).

## Build configuration (shared/evm/Makefile)

`src/ckzg.c` compiled once with `-O2 -fPIC -Wall -Wextra -I src
-I ../blst/bindings`. Upstream's own Makefile adds a long warning list and,
under clang, `-Werror`; those are diagnostics, not code-generation flags.
