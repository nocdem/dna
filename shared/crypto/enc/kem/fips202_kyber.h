/* SHIM — 2026-09-23 ML-KEM port. Old content (the round-3 vendored FIPS-202
 * declarations, namespace pqcrystals_fips202_ref_*) is gone; std@d5b791c's
 * own fips202.h is now the single fips202 implementation under kem/ (see
 * CMakeLists.txt). This file exists only because
 * shared/crypto/key/bip39/seed_derivation.c:22 includes
 * "crypto/enc/kem/fips202_kyber.h" and calls shake256(...) — the upstream
 * header #defines shake256 to its own namespaced symbol
 * (pqcrystals_kyber_fips202_ref_shake256), so that call site compiles
 * unchanged without editing seed_derivation.c. Do not add declarations here;
 * add them to fips202.h (upstream) instead. */
#include "fips202.h"
