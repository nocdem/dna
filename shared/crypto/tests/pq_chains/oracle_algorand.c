/* Generates reference keys/messages against all 512 COMMITTED upstream KATs.
 * Compile ONLY with pristine algorand/falcon at the pinned commit, never the port.
 * Expected signatures are decoded from upstream test_deterministic1024_kat.h.
 * No private production data: all seeds are upstream's public test strings. */
#include "vector_io.h"
#include "deterministic.h"
#include "tests/test_deterministic1024_kat.h"

static size_t unhex(uint8_t *out, const char *s) {
    size_t n = strlen(s); CHECK(n % 2 == 0);
    for (size_t i = 0; i < n / 2; i++) {
        unsigned x; CHECK(sscanf(s + 2*i, "%2x", &x) == 1); out[i] = (uint8_t)x;
    }
    return n/2;
}
int main(int argc, char **argv) {
    CHECK(argc == 2); FILE *out = fopen(argv[1], "wb"); CHECK(out);
    CHECK(fwrite("PQPORT01", 1, 8, out) == 8); write32(out, 512);
    for (unsigned i = 0; i < 512; i++) {
        uint8_t pk[FALCON_DET1024_PUBKEY_SIZE], sk[FALCON_DET1024_PRIVKEY_SIZE];
        uint8_t sig[FALCON_DET1024_SIG_COMPRESSED_MAXSIZE], expected[sizeof sig];
        uint8_t ct[FALCON_DET1024_SIG_CT_SIZE], expected_ct[sizeof ct], msg[512];
        char seed[9], msg_seed[9]; shake256_context rng; size_t siglen;
        CHECK(snprintf(seed, sizeof seed, "key-%04u", i) == 8);
        CHECK(snprintf(msg_seed, sizeof msg_seed, "msg-%04u", i) == 8);
        shake256_init_prng_from_seed(&rng, msg_seed, 8); shake256_extract(&rng, msg, i);
        shake256_init_prng_from_seed(&rng, seed, 8);
        CHECK(falcon_det1024_keygen(&rng, sk, pk) == 0);
        CHECK(falcon_det1024_sign_compressed(sig, &siglen, sk, msg, i) == 0);
        size_t n = unhex(expected, FALCON_DET1024_KAT[i]);
        CHECK(siglen == n && memcmp(sig, expected, n) == 0);
        CHECK(falcon_det1024_verify_compressed(expected, n, pk, msg, i) == 0);
        CHECK(falcon_det1024_convert_compressed_to_ct(ct, expected, n) == 0);
        if (i < 32) {
            CHECK(unhex(expected_ct, FALCON_DET1024_KAT_CT[i]) == sizeof ct);
            CHECK(memcmp(ct, expected_ct, sizeof ct) == 0);
        }
        write32(out, 1); write32(out, 1024); write32(out, i);
        write32(out, KEYGEN | SIGN | VALID | CT);
        write_blob(out, seed, 8); write_blob(out, msg, i); write_blob(out, NULL, 0);
        write_blob(out, pk, sizeof pk); write_blob(out, sk, sizeof sk);
        write_blob(out, expected, n); write_blob(out, NULL, 0); write_blob(out, ct, sizeof ct);
    }
    CHECK(fclose(out) == 0);
    printf("Algorand reference: 512 committed signature KATs, 32 committed CT KATs; %lu checks\n", checks);
    return 0;
}
