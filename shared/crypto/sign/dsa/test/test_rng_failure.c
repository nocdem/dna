/* Standalone regression test. From the repository root (bash):
 * cc -O3 -Wall -Wextra -Werror -Ishared \
 *   shared/crypto/sign/dsa/test/test_rng_failure.c \
 *   shared/crypto/sign/qgp_dilithium.c \
 *   shared/crypto/sign/dsa/{sign,packing,polyvec,poly,ntt,rounding,reduce,fips202,symmetric-shake}.c \
 *   -o /tmp/test_mldsa_rng && /tmp/test_mldsa_rng
 * --vectors emits deterministic compatibility vectors for before/after comparison.
 * The RNG below is TEST ONLY; do not link it into a production binary.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "crypto/sign/dsa/sign.h"
#include "crypto/sign/qgp_dilithium.h"

static unsigned rng_calls;
static int rng_mode; /* 0: success; 1: no write; 2: partial write; 3: full write. */
static unsigned checks, failures;

int qgp_randombytes(uint8_t *buf, size_t len) {
  size_t i, written = len;
  ++rng_calls;
  if(rng_mode == 1) written = 0;
  if(rng_mode == 2) written = len / 2;
  for(i = 0; i < written; ++i)
    buf[i] = (uint8_t)(i * 17 + rng_calls * 29);
  return rng_mode ? -1 : 0;
}

#define CHECK(x) do { ++checks; if(!(x)) { \
  fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); ++failures; \
} } while(0)

static int all_zero(const uint8_t *p, size_t n) {
  size_t i;
  for(i = 0; i < n; ++i) if(p[i] != 0) return 0;
  return 1;
}

static int vectors(void) {
  uint8_t seed[32], rnd[32], msg[200], ctx[255], pre[257];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  const size_t sizes[] = {0, 1, 32, 200};
  const size_t contexts[] = {0, 1, 255, 32};
  size_t i, j, n;
  for(i = 0; i < sizeof(msg); ++i) msg[i] = (uint8_t)(i * 3);
  for(i = 0; i < sizeof(ctx); ++i) ctx[i] = (uint8_t)(255 - i);
  for(j = 0; j < 4; ++j) {
    for(i = 0; i < 32; ++i) {
      seed[i] = (uint8_t)(i + 7*j);
      rnd[i] = (uint8_t)(i*5 + j);
    }
    if(qgp_dsa87_keypair_derand(pk, sk, seed)) return 1;
    pre[0] = 0; pre[1] = (uint8_t)contexts[j];
    memcpy(pre+2, ctx, contexts[j]);
    if(crypto_sign_signature_internal(sig, &n, msg, sizes[j], pre,
                                     contexts[j]+2, rnd, sk)) return 1;
    if(crypto_sign_verify(sig, n, msg, sizes[j], ctx, contexts[j], pk)) return 1;
    if(fwrite(pk, 1, sizeof(pk), stdout) != sizeof(pk) ||
       fwrite(sk, 1, sizeof(sk), stdout) != sizeof(sk) ||
       fwrite(sig, 1, n, stdout) != n) return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  uint8_t seed[32] = {1}, rnd[32] = {2}, pre[2] = {0, 0};
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  uint8_t pk2[CRYPTO_PUBLICKEYBYTES], sk2[CRYPTO_SECRETKEYBYTES];
  uint8_t saved_sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES], sm[CRYPTO_BYTES+32], opened[32];
  uint8_t msg[32] = {3}, ctx[255] = {4};
  size_t n, opened_len;
  int mode;
  if(argc == 2 && strcmp(argv[1], "--vectors") == 0) return vectors();

  CHECK(qgp_dsa87_keypair(pk, sk) == 0);
  CHECK(qgp_dsa87_sign(sig, &n, msg, sizeof(msg), sk) == 0);
  CHECK(qgp_dsa87_verify(sig, n, msg, sizeof(msg), pk) == 0);
  memcpy(saved_sk, sk, sizeof(sk));

  for(mode = 1; mode <= 3; ++mode) {
    rng_mode = mode;
    memset(pk2, 0xA5, sizeof(pk2)); memset(sk2, 0xA5, sizeof(sk2));
    rng_calls = 0;
    CHECK(qgp_dsa87_keypair(pk2, sk2) == -1);
    CHECK(rng_calls == 1);
    CHECK(all_zero(pk2, sizeof(pk2)) && all_zero(sk2, sizeof(sk2)));

    memset(sig, 0xA5, sizeof(sig)); n = 123; rng_calls = 0;
    CHECK(qgp_dsa87_sign(sig, &n, msg, sizeof(msg), sk) == -1);
    CHECK(rng_calls == 1 && n == 0);
    CHECK(all_zero(sig, sizeof(sig)));

    memset(sig, 0xA5, sizeof(sig)); n = 123; rng_calls = 0;
    CHECK(qgp_dsa87_sign_ctx(sig, &n, msg, sizeof(msg), ctx, sizeof(ctx), sk) == -1);
    CHECK(rng_calls == 1 && n == 0);
    CHECK(all_zero(sig, sizeof(sig)));

    n = 123;
    CHECK(crypto_sign(sm, &n, msg, sizeof(msg), NULL, 0, sk) == -1);
    CHECK(n == 0 && all_zero(sm, CRYPTO_BYTES));
    memcpy(sm, msg, sizeof(msg)); n = 123;
    CHECK(crypto_sign(sm, &n, sm, sizeof(msg), NULL, 0, sk) == -1);
    CHECK(n == 0);
    CHECK(memcmp(sk, saved_sk, sizeof(sk)) == 0);

    /* Explicit seed/rnd APIs do not depend on the RNG and must still work. */
    rng_calls = 0;
    CHECK(qgp_dsa87_keypair_derand(pk2, sk2, seed) == 0);
    CHECK(crypto_sign_signature_internal(sig, &n, msg, sizeof(msg),
                                        pre, sizeof(pre), rnd, sk2) == 0);
    CHECK(rng_calls == 0);
    CHECK(qgp_dsa87_verify(sig, n, msg, sizeof(msg), pk2) == 0);
  }

  rng_mode = 0;
  CHECK(qgp_dsa87_keypair_derand(pk, sk, seed) == 0);
  CHECK(crypto_sign_keypair_from_seed(pk2, sk2, seed) == 0);
  CHECK(memcmp(pk, pk2, sizeof(pk)) == 0 && memcmp(sk, sk2, sizeof(sk)) == 0);
  CHECK(qgp_dsa87_sign_ctx(sig, &n, msg, sizeof(msg), ctx, sizeof(ctx), sk) == 0);
  CHECK(qgp_dsa87_verify_ctx(sig, n, msg, sizeof(msg), ctx, sizeof(ctx), pk) == 0);
  CHECK(qgp_dsa87_verify(sig, n, msg, sizeof(msg), pk) != 0);
  sig[0] ^= 1;
  CHECK(qgp_dsa87_verify_ctx(sig, n, msg, sizeof(msg), ctx, sizeof(ctx), pk) != 0);
  memcpy(sm, msg, sizeof(msg));
  CHECK(crypto_sign(sm, &n, sm, sizeof(msg), NULL, 0, sk) == 0);
  CHECK(crypto_sign_open(opened, &opened_len, sm, n, NULL, 0, pk) == 0);
  CHECK(opened_len == sizeof(msg) && memcmp(opened, msg, sizeof(msg)) == 0);
  n = 123; rng_calls = 0;
  CHECK(crypto_sign_signature(sig, &n, msg, sizeof(msg), ctx, 256, sk) == -1);
  CHECK(n == 0 && rng_calls == 0);
  n = 123;
  CHECK(crypto_sign(sm, &n, msg, sizeof(msg), ctx, 256, sk) == -1);
  CHECK(n == 0);
  printf("ML-DSA RNG/compatibility: %u checks, %u failures\n", checks, failures);
  return failures ? 1 : 0;
}
