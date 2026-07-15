/**
 * @file zk_entropy.h
 * @brief Production draw-stream filler for the C STARK prover (G2 gate).
 *
 * The prover core NEVER calls an RNG (design pin D1-B): every random value is
 * caller-supplied through the instance's flat `draws` stream. Tests feed
 * oracle-dumped SmallRng(1) streams (byte-stable KATs); PRODUCTION fills the
 * stream with this helper before calling dnac_prover_prove /
 * dnac_conf_prover_prove.
 *
 * Sampling: uniform CANONICAL Goldilocks elements by REJECTION over raw
 * 64-bit OS entropy — accept v iff v < p, else redraw. This matches Plonky3's
 * `Distribution<Goldilocks> for StandardUniform` exactly (82cfad73
 * goldilocks/src/goldilocks.rs:184-193: loop next_u64, accept < ORDER_U64).
 * Reduce-mod-p is FORBIDDEN (distribution bias + divergence from the
 * documented canonical-accepted-stream convention). Expected reject rate
 * ~2^-32 per draw.
 *
 * Entropy source: a self-contained getrandom(2) reader with EINTR/partial-read
 * handling and a /dev/urandom fallback (zk_entropy.c `zk_os_random`, kept
 * dependency-free so the parked, standalone zk Makefile does not pull in the
 * platform logging chain; same semantics as shared/crypto/utils
 * qgp_platform_random). FAIL-CLOSE: any entropy error aborts the fill — never
 * zero-fill, never proceed with a partial stream (a zero-draw proof would
 * still self-verify but carry NO hiding).
 *
 * Scope note: the prover runs CLIENT-SIDE only (never in consensus); the
 * verifier is rng-free (fri_verifier.c / stark_constraints.c grep-clean), so
 * this module cannot affect determinism/chain state. `make test` gates MUST
 * NOT depend on the values produced here (only on structural properties) —
 * value-dependent assertions over OS entropy would be flaky, which is
 * forbidden project-wide.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_ENTROPY_H
#define DNAC_ZK_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fill out[0..n) with uniform canonical Goldilocks elements (< p) from OS
 * entropy via rejection sampling.
 *
 * @return 0 on success; -1 on entropy failure or NULL out with n > 0
 *         (fail-close — the caller MUST abort the prove).
 */
int dnac_zk_fill_draws(uint64_t *out, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_ENTROPY_H */
