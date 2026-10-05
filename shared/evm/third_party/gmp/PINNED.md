# GMP (GNU Multiple Precision Arithmetic Library) — vendored release tarball (Nodus EVM precompile 0x05, modexp)

| Field | Value |
|---|---|
| Upstream | https://gmplib.org/ |
| Release | `6.3.0` (latest release listed on https://gmplib.org/download/gmp/ on 2026-10-05) |
| Source URL | https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz |
| Tarball | `gmp-6.3.0.tar.xz`, 2 094 196 bytes, sha256 `a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898` |
| Signature | `gmp-6.3.0.tar.xz.sig` (from https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz.sig), sha256 `94def8c1a731854de684689126046ec93589147abd4cd0025f12d741d323aa82`. `gpg --verify` 2026-10-05: "Good signature from Niels Möller <nisse@lysator.liu.se>", primary key fingerprint `343C 2FF0 FBEE 5EC2 EDBE  F399 F359 9FF8 28C6 7298` — the fingerprint https://gmplib.org/ publishes. gpg notes the key has since EXPIRED; the signature was made while it was valid. |
| License | dual LGPLv3+ / GPLv2+ (`COPYING.LESSERv3`, `COPYINGv2`, `COPYINGv3` inside the tarball) |
| Local patches | none |

## Operator decision

`docs/plans/decisions/2026-10-05-nodus-evm-redteam1-operator.md`, D2
("Sabitle, kaynağı içeri al"): GMP enters under `shared/evm/third_party/`
version-pinned. Before this, the engine linked the system library through an
unversioned `find_library(gmp)` / `-lgmp` (the vendoring build host had
Debian `libgmp10 2:6.2.1+dfsg1-1.1`).

## Form: the signed release tarball, not an extracted tree

Unlike blst / mcl / c-kzg-4844 (extracted, file-by-file `cmp`-verified
subsets), GMP is vendored as its upstream release tarball, unmodified, with
its detached signature:

- GMP's build is its own `configure` (it generates `gmp.h`, `config.h`,
  per-CPU `gmp-mparam.h` choices and the mpn assembly selection); a subset of
  files cannot be compiled by our Makefile the way mcl's two units are.
- The extracted tree is 2 156 files / 22 MB; the tarball is 2 MB and is
  reviewable as ONE hash against the upstream URL and signature above.
- Every build checks the tarball's sha256 against the value in this file
  BEFORE extracting it (shared/evm/Makefile `sha256sum -c`;
  nodus/CMakeLists.txt `ExternalProject_Add ... URL_HASH SHA256=`).

mini-gmp (inside the tarball) is deliberately NOT used: schoolbook
multiplication and no fast modular exponentiation, while the EIP-2565 modexp
gas schedule assumes a fast implementation — mini-gmp would turn priced work
into a DoS.

## Build configuration

Extracted into the build directory and configured with (shared/evm/Makefile
`$(GMP_LIB)`, nodus/CMakeLists.txt `nodus_evm_gmp_build`):

`configure --build=<arch>-unknown-linux-gnu --host=<arch>-unknown-linux-gnu
--enable-static --disable-shared --with-pic --disable-cxx` plus

- x86-64: `--enable-fat` — GMP selects its optimised mpn routines at run
  time by CPUID (GMP manual, "Fat binary, --enable-fat"), the same posture as
  blst's `__BLST_PORTABLE__`. With the generic `x86_64-unknown-linux-gnu`
  triple, configure picks `CFLAGS = -O2 -pedantic -fomit-frame-pointer -m64`
  (checked on the vendoring host, 2026-10-05): no `-march`, so a binary built
  on one CPU runs on another, and the configuration does not depend on the
  build machine's `config.guess` CPU name.
- any other architecture: `--disable-assembly` (portable C mpn).
- `CC` is passed explicitly (the same compiler as the engine).

GMP's results are exact integer arithmetic on every path; the CPU-dispatched
assembly changes speed, never a value. `make check` (GMP's own test suite) is
not part of the node build.

Installed into the build directory only (`<build>/gmp/install/{include,lib}`);
the engine is compiled with `-I <build>/gmp/install/include` ahead of the
system include path, so the vendored `gmp.h` (6.3.0, this configuration) is the
one that matches `libgmp.a` — never the system's `/usr/include/gmp.h`.

## License note

GMP is the only LGPL/GPL component of the EVM dependency set (blst Apache-2.0,
c-kzg-4844 Apache-2.0, mcl BSD-3-Clause, libsecp256k1 MIT). It is linked
statically into nodus binaries; LGPLv3 section 4 terms for distributing such a
binary are a project decision, not settled by this file.
