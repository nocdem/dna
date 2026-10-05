# mcl (herumi) — vendored source (Nodus EVM precompiles 0x06-0x08, alt_bn128)

| Field | Value |
|---|---|
| Upstream | https://github.com/herumi/mcl |
| Release tag | `v4.20` (lightweight tag, points directly at the commit) |
| Commit | `828c95660fdc9bffd351f069b2c4c20beebe2060` (2026-10-02) |
| License | modified BSD-3-Clause (`COPYRIGHT`, copied; upstream `readme.md` "License") |
| Fetched | `git clone --branch v4.20 https://github.com/herumi/mcl`, `git rev-parse HEAD` = the commit above, 2026-10-04 |

## Operator decision

`docs/plans/decisions/2026-10-04-nodus-evm-kurultay-k1.md`, OPERATÖR KARARLARI #5:
mcl is the ONE permitted C++ dependency of the engine, used only for bn254,
statically linked behind its C API (`mcl/bn.h`).

## Audit reference

Quarkslab, "Technical assessment of the herumi libraries" (commissioned by
the Ethereum Foundation):
https://blog.quarkslab.com/technical-assessment-of-the-herumi-libraries.html

This URL was given by the dispatching orchestrator; the upstream
`readme.md` at this tag does not itself carry an audit section.

## Curve

`MCL_BN_SNARK1` (= 4, `include/mcl/curve_type.h:15`), parameters at
`include/mcl/curve_type.hpp:46`:
`CurveParam BN_SNARK1("4965661367192848881", 3, 9, false, MCL_BN_SNARK1)` —
BN parameter z = 4965661367192848881 (0x44e992b44a6909f1), curve
y² = x³ + 3, Fp2 non-residue ξ = 9 + i, D-type twist (isMtype = false).
That is Ethereum's alt_bn128 (EIP-196/197; execution-specs uses
`py_ecc.optimized_bn128`: b = 3, b2 = 3 / (9 + i)). The engine additionally
compares `mclBn_getFieldOrder()` against the field modulus at init and
refuses (fault) on mismatch.

## Files copied (byte-identical to the tagged tree; each verified with `cmp`)

- `COPYRIGHT`, `readme.md`, `api.md`
- `src/fp.cpp`, `src/bn_c256.cpp` — the two compilation units
- `src/{bint_impl,bint_switch,bn_c_impl,cast,compress,conversion_impl,fp_tower_impl,glv,llvm_proto,low_func,map_impl,mapto_wb19,msm,pairing_impl}.hpp`
- `src/xbyak/xbyak_util.h` — included by `fp.cpp` on x86 for CPU
  identification only (`XBYAK_ONLY_CLASS_CPU`); no JIT is built
- `include/cybozu/*.hpp` (19 files), `include/mcl/*.h`, `include/mcl/*.hpp`

The `src/` set is the closure `g++ -MM` reports for the two units under the
flags below; `include/` is copied whole.

## Build configuration (shared/evm/Makefile)

`src/fp.cpp` and `src/bn_c256.cpp`, `c++ -O3 -fPIC -DNDEBUG -Wall -Wextra
-I include -DMCL_FP_BIT=256 -DMCL_FR_BIT=256 -DMCL_DONT_USE_XBYAK
-DMCL_BINT_ASM=0 -DMCL_MSM=0`.

- No GMP: `MCL_USE_GMP` is not defined, so `include/mcl/config.hpp:68-70`
  selects mcl's own `Vint` big integers (`MCL_USE_VINT`).
- No JIT: `MCL_DONT_USE_XBYAK` (Xbyak generates machine code at run time
  into executable memory; avoided).
- No LLVM-generated code (`MCL_USE_LLVM` undefined) and no bint assembly
  (`MCL_BINT_ASM=0`): plain C++ arithmetic, same source on x86_64, aarch64
  and MinGW.
- No AVX-512 MSM (`MCL_MSM=0`; that path is BLS12-381-only anyway).
- No `-mbmi2 -madx` (upstream `common.mk` adds them): with plain C++ they
  would let the compiler emit ADX instructions that fault on CPUs without
  them.
- Consequence: the slowest mcl configuration. Results are exact field
  arithmetic either way; speed is a DoS/gas-pricing question, not a
  determinism one.
- Linked with `-lstdc++`; our C sources include only the C header
  `mcl/bn_c256.h`.

## Local patches (Nodus) — the vendored tree is NOT byte-identical to upstream here
1. `src/fp.cpp` `getCpuType()`: the `MCL_CPU` environment-variable override
   (upstream lines ~47-67: "noadx" / "noifma" / "adx") is REMOVED. A consensus
   library must not change behaviour with the process environment (engine
   design D1). Found by the ORCHESTRATOR verifying precompile-agent risk 2,
   2026-10-04.
2. Hardware requirement that remains (upstream `src/fp.cpp` `Op::init`, x86-64
   with 64-bit units): mcl refuses to initialise without AVX + BMI2 + ADX
   even in this plain-C++ build — `Op::init` requires the `tAVX_BMI2_ADX`
   bit, which `detectCpuType()` sets only when
   `cpu.has(Cpu::tAVX | Cpu::tBMI2 | Cpu::tADX)` (all three). Consequence
   for Nodus validators: x86-64 nodes need AVX + BMI2 + ADX (Intel
   Broadwell 2014+, AMD Zen 2017+) or run on aarch64. The witness runs the
   engine's start-up self-test (`evm_precompile_selftest_report`, bn254
   vectors) on every start (`nodus_witness_init`, Nodus EVM red-team 1 F2) and
   refuses to start a node that cannot run bn254, naming the capability —
   never a mid-chain fault.
