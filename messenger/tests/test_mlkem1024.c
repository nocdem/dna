/**
 * @file test_mlkem1024.c
 * @brief ML-KEM-1024 (FIPS 203) known-answer tests
 *
 * Fixtures: messenger/tests/fixtures/mlkem/ — see PIN.md in that directory
 * for provenance, license and per-file purpose. Two sources:
 *   - NIST ACVP-Server @975de31 (FIPS 203 FINAL) — authoritative for
 *     KeyGen, Encaps, Decaps and both input-check kinds (case 1).
 *   - C2SP/CCTV@4448f20 — draft-era KeyGen (its d/z do NOT reproduce the
 *     final G(d||k); PIN.md §2), kept only for Encaps/Decaps-against-a-
 *     given-keypair, the modulus rejection sweep and the strcmp-style
 *     ciphertext (cases 2-4).
 * Five cases, each printing PASS/FAIL; main() returns non-zero if ANY case
 * failed.
 *
 * This exercises shared/crypto/enc/qgp_mlkem.{c,h} (the ML-KEM-1024 wrapper
 * over the pq-crystals/kyber `standard` @ d5b791c reference), NOT the
 * legacy round-3 API (that KAT is test_kyber1024.c, against
 * fixtures/kyber_r3_legacy_kat.h).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "crypto/enc/qgp_mlkem.h"
#include "crypto/enc/kem/fips202.h"   /* namespaced shake256 — used by the
                                       * implicit-rejection check in case 5,
                                       * NOT by qgp_mlkem.c's own internals. */

#ifndef MLKEM_FIXTURES_DIR
#error "MLKEM_FIXTURES_DIR not defined — see tests/CMakeLists.txt"
#endif
#ifndef MLKEM_MODULUS_VECTORS
#error "MLKEM_MODULUS_VECTORS not defined — see tests/CMakeLists.txt"
#endif
#ifndef MLKEM_ACVP_VECTORS
#error "MLKEM_ACVP_VECTORS not defined — see tests/CMakeLists.txt"
#endif

#define TEST_PASSED(name) printf("   \xE2\x9C\x93 %s\n", name)
#define TEST_FAILED(name) printf("   \xE2\x9C\x97 %s\n", name)

#define EK_BYTES QGP_MLKEM1024_PUBLICKEYBYTES
#define DK_BYTES QGP_MLKEM1024_SECRETKEYBYTES
#define CT_BYTES QGP_MLKEM1024_CIPHERTEXTBYTES
#define SS_BYTES QGP_MLKEM1024_SHAREDSECRET_BYTES

/* dk layout offsets (FIPS 203, k=4 — see qgp_mlkem.c): dk_pke(1536) ||
 * ek-copy(1568) || H(ek)(32) || z(32) = 3168 total. */
#define DK_HCHECK_OFF 1536
#define DK_HASH_OFF   3104
#define DK_Z_OFF      3136

/* ---------------------------------------------------------------------- */
/* Small helpers: hex decode, fixture path join, "label = hexvalue" lines */
/* ---------------------------------------------------------------------- */

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes exactly outlen*2 hex chars from hex (which may be longer; only
 * the first outlen*2 chars are consumed) into out[outlen]. Returns 0 on
 * success, -1 if hex is too short or contains a non-hex char. */
static int hex_decode(const char *hex, uint8_t *out, size_t outlen)
{
    size_t i;
    if (strlen(hex) < outlen * 2)
        return -1;
    for (i = 0; i < outlen; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static char *fixture_path(const char *name)
{
    size_t n = strlen(MLKEM_FIXTURES_DIR) + 1 + strlen(name) + 1;
    char *p = malloc(n);
    if (p)
        snprintf(p, n, "%s/%s", MLKEM_FIXTURES_DIR, name);
    return p;
}

/* Splits a "label = value" line in place: NUL-terminates the label at the
 * space before '=', returns a pointer to the value (after "= "). Returns
 * NULL if the line has no " = " separator. */
static char *split_label_value(char *line, char **value_out)
{
    char *eq = strstr(line, " = ");
    if (!eq)
        return NULL;
    *eq = '\0';
    *value_out = eq + 3;
    return line;
}

static void strip_eol(char *line)
{
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';
}

/* ---------------------------------------------------------------------- */
/* Case 1: acvp-ML-KEM-1024.txt.gz — NIST ACVP-Server @975de31 (FIPS 203  */
/* FINAL). One record per line: "<kind> key=hex key=hex ...", fields      */
/* separated by a single space, lines starting with '#' are comments.    */
/* ---------------------------------------------------------------------- */

#define ACVP_MAX_LINE   32768
#define ACVP_MAX_TOKENS 16

/* Splits line in place on ' ' (single-space separator, per PIN.md §1);
 * returns the token count. tokens[0] is the record kind (e.g. "keyGen"),
 * has no '=' and is skipped by acvp_field below. */
static int acvp_tokenize(char *line, char **tokens, int max_tokens)
{
    int n = 0;
    char *p = line;
    while (*p && n < max_tokens) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        tokens[n++] = p;
        while (*p && *p != ' ')
            p++;
        if (*p) {
            *p = '\0';
            p++;
        }
    }
    return n;
}

/* Finds a "key=value" token by exact key match (boundary-checked: the
 * character right after the matched key must be '=', so "k" cannot match
 * "dk=..." or "ek=..." — the same exact-match discipline as
 * split_label_value above, just for space-separated key=value tokens
 * instead of " = " lines). Returns a pointer to the value, or NULL. */
static const char *acvp_field(char **tokens, int ntok, const char *key)
{
    size_t klen = strlen(key);
    int i;
    for (i = 0; i < ntok; i++) {
        if (strncmp(tokens[i], key, klen) == 0 && tokens[i][klen] == '=')
            return tokens[i] + klen + 1;
    }
    return NULL;
}

typedef struct {
    long total, pass;
} acvp_kind_count_t;

static int test_acvp(void)
{
    int failed = 0;
    FILE *f;
    char *line;
    char *tokens[ACVP_MAX_TOKENS];
    acvp_kind_count_t keygen = {0, 0}, encap = {0, 0}, decap = {0, 0};
    acvp_kind_count_t ekcheck = {0, 0}, dkcheck = {0, 0};
    uint8_t ct_zero[CT_BYTES];

    printf("\n1. acvp-ML-KEM-1024.txt.gz (NIST ACVP-Server @975de31, FIPS 203 FINAL)...\n");

    memset(ct_zero, 0, sizeof(ct_zero));

    f = fopen(MLKEM_ACVP_VECTORS, "r");
    if (!f) {
        TEST_FAILED("MLKEM_ACVP_VECTORS: fopen failed (configure-time gunzip missing?)");
        return 1;
    }

    line = malloc(ACVP_MAX_LINE);
    if (!line) {
        fclose(f);
        return 1;
    }

    while (fgets(line, ACVP_MAX_LINE, f)) {
        int ntok;
        const char *kind;

        strip_eol(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        ntok = acvp_tokenize(line, tokens, ACVP_MAX_TOKENS);
        if (ntok < 1)
            continue;
        kind = tokens[0];

        if (strcmp(kind, "keyGen") == 0) {
            const char *d_hex = acvp_field(tokens, ntok, "d");
            const char *z_hex = acvp_field(tokens, ntok, "z");
            const char *ek_hex = acvp_field(tokens, ntok, "ek");
            const char *dk_hex = acvp_field(tokens, ntok, "dk");
            uint8_t d[32], z[32], ek_exp[EK_BYTES], dk_exp[DK_BYTES];
            uint8_t coins[64], ek[EK_BYTES], dk[DK_BYTES];

            keygen.total++;
            if (!d_hex || !z_hex || !ek_hex || !dk_hex ||
                hex_decode(d_hex, d, sizeof(d)) != 0 ||
                hex_decode(z_hex, z, sizeof(z)) != 0 ||
                hex_decode(ek_hex, ek_exp, sizeof(ek_exp)) != 0 ||
                hex_decode(dk_hex, dk_exp, sizeof(dk_exp)) != 0) {
                TEST_FAILED("ACVP keyGen: line parse failure");
                failed = 1;
                continue;
            }
            memcpy(coins, d, 32);
            memcpy(coins + 32, z, 32);
            if (qgp_mlkem1024_keypair_derand(ek, dk, coins) != 0 ||
                memcmp(ek, ek_exp, EK_BYTES) != 0 ||
                memcmp(dk, dk_exp, DK_BYTES) != 0) {
                TEST_FAILED("ACVP keyGen: keypair_derand(d||z) != (ek, dk)");
                failed = 1;
                continue;
            }
            keygen.pass++;

        } else if (strcmp(kind, "encap") == 0) {
            const char *ek_hex = acvp_field(tokens, ntok, "ek");
            const char *dk_hex = acvp_field(tokens, ntok, "dk");
            const char *m_hex = acvp_field(tokens, ntok, "m");
            const char *c_hex = acvp_field(tokens, ntok, "c");
            const char *k_hex = acvp_field(tokens, ntok, "k");
            uint8_t ek[EK_BYTES], dk[DK_BYTES], m[32], c_exp[CT_BYTES], k_exp[32];
            uint8_t c[CT_BYTES], k[32], ss[32];

            encap.total++;
            if (!ek_hex || !dk_hex || !m_hex || !c_hex || !k_hex ||
                hex_decode(ek_hex, ek, sizeof(ek)) != 0 ||
                hex_decode(dk_hex, dk, sizeof(dk)) != 0 ||
                hex_decode(m_hex, m, sizeof(m)) != 0 ||
                hex_decode(c_hex, c_exp, sizeof(c_exp)) != 0 ||
                hex_decode(k_hex, k_exp, sizeof(k_exp)) != 0) {
                TEST_FAILED("ACVP encap: line parse failure");
                failed = 1;
                continue;
            }
            if (qgp_mlkem1024_encapsulate_derand(c, k, ek, m) != 0 ||
                memcmp(c, c_exp, CT_BYTES) != 0 ||
                memcmp(k, k_exp, sizeof(k_exp)) != 0) {
                TEST_FAILED("ACVP encap: encapsulate_derand(ek, m) != (c, k)");
                failed = 1;
                continue;
            }
            if (qgp_mlkem1024_decapsulate(ss, c_exp, dk) != 0 ||
                memcmp(ss, k_exp, sizeof(k_exp)) != 0) {
                TEST_FAILED("ACVP encap: decapsulate(dk, c) != k");
                failed = 1;
                continue;
            }
            encap.pass++;

        } else if (strcmp(kind, "decap") == 0) {
            const char *dk_hex = acvp_field(tokens, ntok, "dk");
            const char *c_hex = acvp_field(tokens, ntok, "c");
            const char *k_hex = acvp_field(tokens, ntok, "k");
            uint8_t dk[DK_BYTES], c[CT_BYTES], k_exp[32], ss[32];

            decap.total++;
            if (!dk_hex || !c_hex || !k_hex ||
                hex_decode(dk_hex, dk, sizeof(dk)) != 0 ||
                hex_decode(c_hex, c, sizeof(c)) != 0 ||
                hex_decode(k_hex, k_exp, sizeof(k_exp)) != 0) {
                TEST_FAILED("ACVP decap: line parse failure");
                failed = 1;
                continue;
            }
            /* Both `reason`s (valid_decapsulation, modified_ciphertext)
             * must decapsulate to the recorded k — the latter is implicit
             * rejection, ACVP's k already IS J(z||c) for that case. */
            if (qgp_mlkem1024_decapsulate(ss, c, dk) != 0 ||
                memcmp(ss, k_exp, sizeof(k_exp)) != 0) {
                TEST_FAILED("ACVP decap: decapsulate(dk, c) != k");
                failed = 1;
                continue;
            }
            decap.pass++;

        } else if (strcmp(kind, "ekCheck") == 0) {
            const char *ek_hex = acvp_field(tokens, ntok, "ek");
            const char *tp_hex = acvp_field(tokens, ntok, "testPassed");
            uint8_t ek[EK_BYTES];
            int want_pass;

            ekcheck.total++;
            if (!ek_hex || !tp_hex ||
                hex_decode(ek_hex, ek, sizeof(ek)) != 0) {
                TEST_FAILED("ACVP ekCheck: line parse failure");
                failed = 1;
                continue;
            }
            if (strcmp(tp_hex, "true") == 0)
                want_pass = 1;
            else if (strcmp(tp_hex, "false") == 0)
                want_pass = 0;
            else {
                TEST_FAILED("ACVP ekCheck: unrecognised testPassed value");
                failed = 1;
                continue;
            }
            if ((qgp_mlkem1024_ek_check(ek) == 0) != want_pass) {
                TEST_FAILED("ACVP ekCheck: ek_check(ek) != testPassed");
                failed = 1;
                continue;
            }
            ekcheck.pass++;

        } else if (strcmp(kind, "dkCheck") == 0) {
            const char *dk_hex = acvp_field(tokens, ntok, "dk");
            const char *tp_hex = acvp_field(tokens, ntok, "testPassed");
            uint8_t dk[DK_BYTES], ss[32];
            int want_pass;

            dkcheck.total++;
            if (!dk_hex || !tp_hex ||
                hex_decode(dk_hex, dk, sizeof(dk)) != 0) {
                TEST_FAILED("ACVP dkCheck: line parse failure");
                failed = 1;
                continue;
            }
            if (strcmp(tp_hex, "true") == 0)
                want_pass = 1;
            else if (strcmp(tp_hex, "false") == 0)
                want_pass = 0;
            else {
                TEST_FAILED("ACVP dkCheck: unrecognised testPassed value");
                failed = 1;
                continue;
            }
            /* Only the FIPS 203 §7.3 hash-check result matters here (the
             * fixture's dk_check exercises the hash check alone via a
             * fixed all-zero ciphertext) — do not compare the shared
             * secret, per the dispatch brief. */
            if ((qgp_mlkem1024_decapsulate(ss, ct_zero, dk) == 0) != want_pass) {
                TEST_FAILED("ACVP dkCheck: decapsulate(dk, 0) rc != testPassed");
                failed = 1;
                continue;
            }
            dkcheck.pass++;
        }
        /* Unknown kinds are ignored (forward compatibility with a wider
         * future extraction) — but every KNOWN kind above is counted, and
         * the zero-records guard below still catches an empty/broken file. */
    }

    free(line);
    fclose(f);

    printf("   keyGen  %ld/%ld\n", keygen.pass, keygen.total);
    printf("   encap   %ld/%ld\n", encap.pass, encap.total);
    printf("   decap   %ld/%ld\n", decap.pass, decap.total);
    printf("   ekCheck %ld/%ld\n", ekcheck.pass, ekcheck.total);
    printf("   dkCheck %ld/%ld\n", dkcheck.pass, dkcheck.total);

    if (keygen.total == 0 || encap.total == 0 || decap.total == 0 ||
        ekcheck.total == 0 || dkcheck.total == 0) {
        TEST_FAILED("ACVP: at least one kind had 0 records (silent parse failure?)");
        failed = 1;
    }
    if (keygen.pass != keygen.total || encap.pass != encap.total ||
        decap.pass != decap.total || ekcheck.pass != ekcheck.total ||
        dkcheck.pass != dkcheck.total) {
        failed = 1;
    }
    if (!failed)
        TEST_PASSED("all ACVP records (keyGen/encap/decap/ekCheck/dkCheck) match");

    return failed;
}

/* ---------------------------------------------------------------------- */
/* Case 2: intermediate-ML-KEM-1024.txt — encaps/decaps against the       */
/* file's own (ek, dk), NOT its KeyGen (CCTV's d/z implement the FIPS 203 */
/* DRAFT's G(d), not the FINAL standard's G(d||k) — PIN.md §2).           */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint8_t ek[EK_BYTES], dk[DK_BYTES], m[32], K[32], c[CT_BYTES];
    int have_ek, have_dk, have_m, have_K, have_c;
} intermediate_vectors_t;

static int load_intermediate_vectors(intermediate_vectors_t *v)
{
    char *path = fixture_path("intermediate-ML-KEM-1024.txt");
    FILE *f;
    char *line;
    int ok = 1;

    memset(v, 0, sizeof(*v));
    if (!path)
        return 0;
    f = fopen(path, "r");
    free(path);
    if (!f) {
        TEST_FAILED("intermediate-ML-KEM-1024.txt: fopen failed");
        return 0;
    }

    line = malloc(32768);
    if (!line) {
        fclose(f);
        return 0;
    }

    while (fgets(line, 32768, f)) {
        char *value;
        char *label;
        strip_eol(line);
        label = split_label_value(line, &value);
        if (!label)
            continue;
        /* d and z (draft-era KeyGen inputs) are intentionally NOT parsed —
         * PIN.md §2: they do not reproduce the final G(d||k). */
        if (strcmp(label, "ek") == 0)
            v->have_ek = (hex_decode(value, v->ek, sizeof(v->ek)) == 0);
        else if (strcmp(label, "dk") == 0)
            v->have_dk = (hex_decode(value, v->dk, sizeof(v->dk)) == 0);
        else if (strcmp(label, "m") == 0)
            v->have_m = (hex_decode(value, v->m, sizeof(v->m)) == 0);
        else if (strcmp(label, "K") == 0)
            v->have_K = (hex_decode(value, v->K, sizeof(v->K)) == 0);
        else if (strcmp(label, "c") == 0)
            v->have_c = (hex_decode(value, v->c, sizeof(v->c)) == 0);
    }

    free(line);
    fclose(f);

    ok = v->have_ek && v->have_dk && v->have_m && v->have_K && v->have_c;
    if (!ok)
        TEST_FAILED("intermediate-ML-KEM-1024.txt: missing/malformed ek,dk,m,K or c");
    return ok;
}

static int test_intermediate(const intermediate_vectors_t *v)
{
    int failed = 0;
    uint8_t ct2[CT_BYTES], ss2[SS_BYTES];
    uint8_t ss3[SS_BYTES];

    printf("\n2. intermediate-ML-KEM-1024.txt (encaps/decaps against its own ek/dk"
           " — KeyGen NOT tested, draft-era)...\n");

    if (qgp_mlkem1024_encapsulate_derand(ct2, ss2, v->ek, v->m) != 0) {
        TEST_FAILED("encapsulate_derand(ek, m) failed");
        return 1;
    }
    if (memcmp(ct2, v->c, CT_BYTES) != 0) { TEST_FAILED("encapsulate_derand: c mismatch"); failed = 1; }
    else TEST_PASSED("encapsulate_derand(ek, m) -> c matches");
    if (memcmp(ss2, v->K, SS_BYTES) != 0) { TEST_FAILED("encapsulate_derand: K mismatch"); failed = 1; }
    else TEST_PASSED("encapsulate_derand(ek, m) -> K matches");

    if (qgp_mlkem1024_decapsulate(ss3, v->c, v->dk) != 0) {
        TEST_FAILED("decapsulate(dk, c) failed");
        failed = 1;
    } else if (memcmp(ss3, v->K, SS_BYTES) != 0) {
        TEST_FAILED("decapsulate(dk, c) -> K mismatch");
        failed = 1;
    } else {
        TEST_PASSED("decapsulate(dk, c) -> K matches");
    }

    return failed;
}

/* ---------------------------------------------------------------------- */
/* Case 3: modulus-ML-KEM-1024.txt.gz — ek_check must reject every line,  */
/* plus an exhaustive per-coefficient rejection sweep on a known-good ek. */
/* ---------------------------------------------------------------------- */

/* Overwrite 12-bit coefficient index p (0..1023) of a KYBER_POLYVECBYTES-
 * packed buffer with value v, using the exact inverse of the poly_frombytes
 * bit layout qgp_mlkem1024_ek_check reads (kem/poly.c poly_frombytes):
 * c0 = a0 | (a1&0x0F)<<8, c1 = a1>>4 | a2<<4. */
static void set_coeff(uint8_t *packed, unsigned int p, uint16_t v)
{
    unsigned int g = p / 2;
    uint8_t *grp = packed + 3 * g;
    if ((p % 2) == 0) {
        grp[0] = (uint8_t)(v & 0xFF);
        grp[1] = (uint8_t)((grp[1] & 0xF0) | ((v >> 8) & 0x0F));
    } else {
        grp[1] = (uint8_t)((grp[1] & 0x0F) | ((uint8_t)(v & 0x0F) << 4));
        grp[2] = (uint8_t)(v >> 4);
    }
}

static int test_modulus(const intermediate_vectors_t *v)
{
    int failed = 0;
    FILE *f;
    char *line;
    long total = 0, rejected = 0;
    unsigned int p;

    printf("\n3. modulus-ML-KEM-1024.txt.gz (invalid ek rejection) + exhaustive sweep...\n");

    f = fopen(MLKEM_MODULUS_VECTORS, "r");
    if (!f) {
        TEST_FAILED("MLKEM_MODULUS_VECTORS: fopen failed (configure-time gunzip missing?)");
        return 1;
    }

    line = malloc(4096);
    if (!line) {
        fclose(f);
        return 1;
    }

    while (fgets(line, 4096, f)) {
        uint8_t ek[EK_BYTES];
        strip_eol(line);
        if (line[0] == '\0')
            continue;
        total++;
        if (hex_decode(line, ek, EK_BYTES) != 0) {
            TEST_FAILED("modulus vector: hex decode failed");
            failed = 1;
            continue;
        }
        if (qgp_mlkem1024_ek_check(ek) == 0) {
            TEST_FAILED("modulus vector: ek_check ACCEPTED an invalid ek");
            failed = 1;
        } else {
            rejected++;
        }
    }
    free(line);
    fclose(f);

    if (!failed) {
        printf("   %ld/%ld invalid encapsulation keys correctly rejected\n", rejected, total);
        TEST_PASSED("modulus-ML-KEM-1024.txt.gz: every line rejected");
    }

    /* Exhaustive self-check: every coefficient position, every out-of-range
     * value, on a known-GOOD ek (from case 1's fixture). */
    for (p = 0; p < 1024; p++) {
        uint32_t val;
        for (val = 3329; val <= 4095; val++) {
            uint8_t ek_mut[EK_BYTES];
            memcpy(ek_mut, v->ek, EK_BYTES);
            set_coeff(ek_mut, p, (uint16_t)val);
            if (qgp_mlkem1024_ek_check(ek_mut) == 0) {
                printf("   \xE2\x9C\x97 exhaustive sweep: p=%u v=%u ACCEPTED\n", p, val);
                failed = 1;
                goto sweep_done;
            }
        }
    }
sweep_done:
    if (!failed)
        TEST_PASSED("exhaustive sweep: every (position, out-of-range value) rejected");

    if (qgp_mlkem1024_ek_check(v->ek) != 0) {
        TEST_FAILED("exhaustive sweep: untouched known-good ek was rejected");
        failed = 1;
    } else {
        TEST_PASSED("untouched known-good ek is accepted");
    }

    return failed;
}

/* ---------------------------------------------------------------------- */
/* Case 4: strcmp-ML-KEM-1024.txt — a ciphertext with an embedded zero     */
/* byte, to catch strcmp()-style comparisons in Decaps.                   */
/* ---------------------------------------------------------------------- */

static int test_strcmp_vector(void)
{
    int failed = 0;
    char *path = fixture_path("strcmp-ML-KEM-1024.txt");
    FILE *f;
    char *line;
    uint8_t dk[DK_BYTES], c[CT_BYTES], K[SS_BYTES], ss[SS_BYTES];
    int have_dk = 0, have_c = 0, have_K = 0;

    printf("\n4. strcmp-ML-KEM-1024.txt (ciphertext contains a zero byte)...\n");

    if (!path)
        return 1;
    f = fopen(path, "r");
    free(path);
    if (!f) {
        TEST_FAILED("strcmp-ML-KEM-1024.txt: fopen failed");
        return 1;
    }

    line = malloc(8192);
    if (!line) {
        fclose(f);
        return 1;
    }
    while (fgets(line, 8192, f)) {
        char *value;
        char *label;
        strip_eol(line);
        label = split_label_value(line, &value);
        if (!label)
            continue;
        if (strcmp(label, "dk") == 0)
            have_dk = (hex_decode(value, dk, sizeof(dk)) == 0);
        else if (strcmp(label, "c") == 0)
            have_c = (hex_decode(value, c, sizeof(c)) == 0);
        else if (strcmp(label, "K") == 0)
            have_K = (hex_decode(value, K, sizeof(K)) == 0);
    }
    free(line);
    fclose(f);

    if (!have_dk || !have_c || !have_K) {
        TEST_FAILED("strcmp-ML-KEM-1024.txt: missing/malformed dk, c or K");
        return 1;
    }

    if (qgp_mlkem1024_decapsulate(ss, c, dk) != 0) {
        TEST_FAILED("decapsulate(dk, c) failed");
        failed = 1;
    } else if (memcmp(ss, K, SS_BYTES) != 0) {
        TEST_FAILED("decapsulate(dk, c) -> K mismatch (strcmp-style bug?)");
        failed = 1;
    } else {
        TEST_PASSED("decapsulate(dk, c) -> K matches despite embedded zero byte");
    }
    return failed;
}

/* ---------------------------------------------------------------------- */
/* Case 5: dk hash-check negative + ciphertext implicit rejection.        */
/* ---------------------------------------------------------------------- */

static int test_negative_checks(void)
{
    int failed = 0;
    uint8_t ek[EK_BYTES], dk[DK_BYTES];
    uint8_t ct[CT_BYTES], K[SS_BYTES];
    uint8_t dk_bad[DK_BYTES];
    uint8_t ss[SS_BYTES];

    printf("\n5. dk hash-check negative + ciphertext implicit rejection...\n");

    if (qgp_mlkem1024_keypair(ek, dk) != 0 ||
        qgp_mlkem1024_encapsulate(ct, K, ek) != 0) {
        TEST_FAILED("setup: keypair/encapsulate failed");
        return 1;
    }

    /* FIPS 203 §7.3 hash check: corrupt one byte of dk[3104:3136) (the
     * stored H(ek)) -> decapsulate must refuse, WITHOUT decapsulating. */
    memcpy(dk_bad, dk, DK_BYTES);
    dk_bad[DK_HASH_OFF] ^= 0x01;
    if (qgp_mlkem1024_decapsulate(ss, ct, dk_bad) != -1) {
        TEST_FAILED("decapsulate accepted a dk with a corrupted H(ek) hash-check field");
        failed = 1;
    } else {
        TEST_PASSED("decapsulate rejects a corrupted dk hash-check field");
    }

    /* Implicit rejection: flip one ciphertext byte -> decapsulate still
     * returns 0 (dk itself is untouched, so its own hash check passes), but
     * ss must differ from K and must equal FIPS 203's J(z || c) =
     * SHAKE256(z || c, 32) (kem/symmetric.h rkprf) — round-3 differs here
     * (SHAKE256(z || H(c)), design doc §2 F4). Computed here with the
     * upstream one-shot shake256, not re-derived. */
    {
        uint8_t ct_bad[CT_BYTES];
        uint8_t ss_bad[SS_BYTES];
        uint8_t buf[32 + CT_BYTES];
        uint8_t expect_ss_bad[SS_BYTES];

        memcpy(ct_bad, ct, CT_BYTES);
        ct_bad[0] ^= 0x01;

        if (qgp_mlkem1024_decapsulate(ss_bad, ct_bad, dk) != 0) {
            TEST_FAILED("decapsulate of a corrupted ciphertext returned an error"
                        " (should implicitly reject, not fail)");
            failed = 1;
        } else if (memcmp(ss_bad, K, SS_BYTES) == 0) {
            TEST_FAILED("corrupted ciphertext produced the ORIGINAL shared secret");
            failed = 1;
        } else {
            memcpy(buf, dk + DK_Z_OFF, 32);
            memcpy(buf + 32, ct_bad, CT_BYTES);
            shake256(expect_ss_bad, SS_BYTES, buf, sizeof(buf));
            if (memcmp(ss_bad, expect_ss_bad, SS_BYTES) != 0) {
                TEST_FAILED("implicit-rejection value != SHAKE256(z || ct_bad, 32)");
                failed = 1;
            } else {
                TEST_PASSED("implicit rejection: ss = SHAKE256(z || ct_bad, 32), != K");
            }
        }
    }

    return failed;
}

/* ---------------------------------------------------------------------- */

int main(void)
{
    int failed = 0;
    intermediate_vectors_t v;

    printf("=== ML-KEM-1024 (FIPS 203) Known-Answer Tests ===\n");

    failed += test_acvp();

    if (!load_intermediate_vectors(&v)) {
        printf("\n=== FATAL: could not load intermediate-ML-KEM-1024.txt ===\n");
        return 1;
    }

    failed += test_intermediate(&v);
    failed += test_modulus(&v);
    failed += test_strcmp_vector();
    failed += test_negative_checks();

    printf("\n");
    if (failed == 0) {
        printf("=== All ML-KEM-1024 Tests Passed ===\n");
        return 0;
    }
    printf("=== %d Test(s) Failed ===\n", failed);
    return 1;
}
