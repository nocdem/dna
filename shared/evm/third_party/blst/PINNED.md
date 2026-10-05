# blst — vendored source (Nodus EVM precompiles 0x0a-0x11)

| Field | Value |
|---|---|
| Upstream | https://github.com/supranational/blst |
| Release tag | `v0.3.17` (lightweight tag, points directly at the commit) |
| Commit | `54e6e55674722fc2797ebb4bbb71b26d881eb4b8` (2026-07-24, "bindings/rust/Cargo.toml: bump the version number.") |
| License | Apache License 2.0 (`LICENSE`, copied) |
| Fetched | `git clone --branch v0.3.17 https://github.com/supranational/blst`, `git rev-parse HEAD` = the commit above, 2026-10-04 |

## Audit references (from upstream `README.md`, lines 32-34)

- "An initial audit of this library was conducted by NCC Group in January 2021":
  https://research.nccgroup.com/wp-content/uploads/2021/01/NCC_Group_EthereumFoundation_ETHF002_Report_2021-01-20_v1.0.pdf
- "Formal verification of this library by Galois is on-going":
  https://github.com/GaloisInc/BLST-Verification

## Relation to c-kzg-4844

c-kzg-4844 v2.1.8 (vendored next to this directory) pins blst as a git
submodule at `e7f90de551e8df682f3cc99067d204d8b90d27ad`, a commit between
v0.3.16 and v0.3.17 (`git describe` = `v0.3.16`, 57 commits before v0.3.17).
The dispatch asked for the latest blst release, so c-kzg is compiled here
against v0.3.17, not against its own submodule pin. This gap is deliberate
and recorded; the conformance run is what checks it.

## Files copied (byte-identical to the tagged tree; each verified with `cmp`)

- `LICENSE`, `README.md`, `SECURITY.md`
- `bindings/blst.h`, `bindings/blst_aux.h` — the public C API
- `src/*.c`, `src/*.h` (36 files, every top-level file of `src/`): the
  single compilation unit is `src/server.c`, which `#include`s the rest.
  `src/no_asm.h` is only reached under `__BLST_NO_ASM__`.
- `build/assembly.S` + `build/elf/` (23 files), `build/coff/` (23),
  `build/mach-o/` (23): the pre-generated assembly `assembly.S` selects by
  platform (ELF: Linux x86_64 / aarch64 incl. Android; COFF: MinGW;
  Mach-O: macOS / iOS).

Not copied: `src/asm/` (perlasm generators of `build/*`), `build/win64/`
(MSVC `.asm`), `build/cheri/`, the language bindings, tests.

## Build configuration (shared/evm/Makefile)

`src/server.c` and `build/assembly.S`, each compiled with
`-O2 -fno-builtin -fPIC -Wall -Wextra -D__BLST_PORTABLE__`.

- `__BLST_PORTABLE__` is what c-kzg-4844's own Makefile passes to blst's
  build script (`BLST_BUILDSCRIPT_FLAGS = -D__BLST_PORTABLE__`). It includes
  both the ADX (`mulx`/`adcx`) and the plain `mulq` assembly paths and picks
  one at run time from CPUID (`src/cpuid.c`).
- blst's `build.sh` instead probes `/proc/cpuinfo` of the BUILD machine and
  adds `-D__ADX__`; that bakes the build host's CPU into the binary (it
  faults on a CPU without ADX). It is not used.
- Determinism: both assembly paths and the C fallback compute the same exact
  field arithmetic (Montgomery multiplication modulo p); the choice changes
  speed, never a result. No randomness and no clock are read by any blst
  function the engine calls.
