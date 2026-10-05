/**
 * @file evm_precompile.h
 * @brief Precompile start-up check of the Nodus EVM engine.
 *
 * The precompiled contracts themselves are reached through the interpreter
 * (evm_internal.h: evm_precompile_run). This header exposes the one entry
 * point a node calls before it accepts work.
 */
#ifndef EVM_PRECOMPILE_H
#define EVM_PRECOMPILE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Known-answer self-test of the precompile set: one or more vectors per
 * library — 0x01-0x03, 0x05, 0x06, 0x08-0x0b, 0x0f, 0x11 (11 of the 17
 * addresses; PC_KATS in evm_precompile.c).
 *
 * Runs fixed vectors (sources cited next to each vector in
 * evm_precompile.c) through the same dispatch the interpreter uses, and
 * forces the one-time initialisation of every crypto library behind it
 * that has one: the KZG trusted setup (c-kzg-4844) and mcl (alt_bn128).
 * SHA-256 (blst) and RIPEMD-160 (trezor-crypto) are vendored, pinned code
 * with no initialisation; their vectors still run.
 *
 * The precompile set is part of the consensus ruleset (decision
 * 2026-10-04-nodus-evm-kurultay-k1, operator item #2): a node for which this
 * returns -2 must refuse to start.
 *
 * Thread-safe; may be called more than once.
 *
 * @return 0 when every vector matches, -2 (node fault) otherwise.
 */
int evm_precompile_selftest(void);

/**
 * evm_precompile_selftest() that also says WHAT failed.
 *
 * Checks, in order: mcl's bn254 initialisation (on x86-64 mcl refuses a
 * CPU without AVX + BMI2 + ADX), the KZG trusted setup (loaded here,
 * eagerly — never first inside block execution), then every known-answer
 * vector (0x02 SHA-256 and 0x03 RIPEMD-160 included).
 *
 * @param failed  NULL, or receives NULL on success and otherwise a static,
 *                human-readable name of the missing capability (for the
 *                node's refuse-to-start log line). Never freed.
 * @return 0 when every check passes, -2 (node fault) otherwise.
 */
int evm_precompile_selftest_report(const char **failed);

#ifdef __cplusplus
}
#endif

#endif /* EVM_PRECOMPILE_H */
