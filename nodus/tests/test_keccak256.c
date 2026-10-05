/**
 * Nodus — Keccak-256 known-answer test (shared/crypto/hash/keccak256.c)
 *
 * What it proves: keccak256() as linked into libnodus (the EVM engine's
 * keccak object, nodus_evm_keccak) returns the expected digest for the
 * empty input, "abc", one byte below / at / above the 136-byte rate, two
 * full rate blocks and a 1000-byte multi-block input — i.e. the XKCP
 * Keccak-f[1600] that replaced the previous permutation (red-team 1), the
 * sponge's absorb across block boundaries and the 0x01 padding.
 *
 * Expected values are copied from shared/evm/tests/test_rlp_mpt.c
 * test_keccak: "" and "abc" from the execution-specs reference cited there
 * (base_types/tests/test_keccak_dispatch.py:29-36); the pattern inputs,
 * byte i = (7*i + 3) mod 256, from the independent FIPS 202 oracle
 * shared/evm/tests/addr32_oracle.py (keccak256()).
 *
 * Requires: a build with the EVM runtime (NODUS_EVM_ENABLED); nothing else.
 * How it can lie: it checks the digest only, not keccak256_hex or the
 * eth_address_* helpers.
 */

#include "crypto/hash/keccak256.h"
#include <stdio.h>
#include <string.h>

static int failed = 0;

static int hex_eq(const uint8_t *h, const char *hex)
{
    char got[65];
    for (size_t i = 0; i < 32; i++)
        snprintf(got + 2 * i, 3, "%02x", h[i]);
    return strcmp(got, hex) == 0;
}

static void check(const uint8_t *in, size_t n, const char *hex,
                  const char *what)
{
    uint8_t h[32];
    int rc = keccak256(in, n, h);
    if (rc == 0 && hex_eq(h, hex)) {
        printf("  %-40s PASS\n", what);
    } else {
        printf("  %-40s FAIL (rc=%d)\n", what, rc);
        failed++;
    }
}

int main(void)
{
    printf("test_keccak256: Keccak-256 known answers\n");

    check((const uint8_t *)"", 0,
          "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
          "keccak256(\"\")");
    check((const uint8_t *)"abc", 3,
          "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
          "keccak256(\"abc\")");

    static const struct { size_t n; const char *hex; } multi[] = {
        { 135,  "00ef96af9cf4b24c7f269d922294444a197d0a33638c2e56634c57e892103a8f" },
        { 136,  "742061bcad767ed4c4f5883b1dcb1aad11afdcc140dc469d953759b127b9f9ed" },
        { 137,  "e3371f61e770abf254c34239c3b0099ad90594507415bc81dd0a10b9692bbf2a" },
        { 272,  "ac141fd7b0a0ffcd2e967254d508da3ec616596493c36fa304425647d90e6de5" },
        { 1000, "80cdc8dd52cbb3dbaea8f383209893fa2bb52efbd5aedbb4b26dcfe307fcdc9b" },
    };
    uint8_t in[1000];
    for (size_t i = 0; i < sizeof(in); i++)
        in[i] = (uint8_t)(i * 7 + 3);
    for (size_t k = 0; k < sizeof(multi) / sizeof(multi[0]); k++) {
        char what[64];
        snprintf(what, sizeof(what), "keccak256(%zu-byte pattern)",
                 multi[k].n);
        check(in, multi[k].n, multi[k].hex, what);
    }

    printf("%s: %d failure(s)\n", failed ? "FAILED" : "PASSED", failed);
    return failed ? 1 : 0;
}
