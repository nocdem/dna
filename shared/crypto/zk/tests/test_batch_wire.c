/**
 * @file test_batch_wire.c
 * @brief P2L-d d4.b KAT — the DZKF v4 batched-proof wire codec
 *        (dnac_batch_wire_encode/decode, fri_proof_codec.c d4.a) against the
 *        oracle's wire_v4 bytes (tools/vectors/batch_proof.json — every
 *        scenario verify_batch-gated in-oracle at 82cfad73; the wire bytes are
 *        an independent SECOND encoder implementation in the oracle).
 *
 * Gates per scenario:
 *   1. decode: wire_v4 → dnac_batch_wire_decode == OK; is_zk / num_instances
 *      match the vector.
 *   2. verify: the DECODED package feeds dnac_batch_verify end-to-end
 *      (insts / prep_map are verifier-side fixtures via load_pscenario) —
 *      accept + (α, ζ) byte-match. The wire carries NO opening points; the
 *      verifier samples ζ itself (the v3 H2 class closed by construction).
 *   3. re-encode: the decoded package → dnac_batch_wire_encode → byte-match
 *      the oracle wire (C encoder == oracle encoder).
 *   4. prove+encode: dnac_batch_prove from scratch → encode → byte-match the
 *      oracle wire (the full C pipeline emits the canonical wire).
 * Negatives: bad magic / v4-on-v3-decoder + version-3-patched-on-v4-decoder /
 * truncation / noncanonical field / bad is_zk flag / inconsistent total_len /
 * trailing byte.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../fri_proof_codec.h"
#include "batch_test_util.h"

static int g_checks = 0;
static int g_fails = 0;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        g_checks++;                                                           \
        if (!(cond)) {                                                        \
            g_fails++;                                                        \
            fprintf(stderr, "  FAIL: ");                                      \
            fprintf(stderr, __VA_ARGS__);                                     \
            fprintf(stderr, "\n");                                            \
        }                                                                     \
    } while (0)

/* wire_v4 hex string → malloc'd bytes (caller frees). */
static uint8_t *wire_from_hex(const jv_t *v, size_t *out_len)
{
    if (!v || v->kind != JV_STR) return NULL;
    size_t hl = strlen(v->str);
    if (hl == 0 || (hl & 1)) return NULL;
    uint8_t *buf = (uint8_t *)malloc(hl / 2);
    if (!buf) return NULL;
    for (size_t k = 0; k < hl / 2; k++) {
        unsigned hi, lo;
        char c1 = v->str[2 * k], c2 = v->str[2 * k + 1];
        if (c1 >= '0' && c1 <= '9') hi = (unsigned)(c1 - '0');
        else if (c1 >= 'a' && c1 <= 'f') hi = (unsigned)(c1 - 'a' + 10);
        else { free(buf); return NULL; }
        if (c2 >= '0' && c2 <= '9') lo = (unsigned)(c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f') lo = (unsigned)(c2 - 'a' + 10);
        else { free(buf); return NULL; }
        buf[k] = (uint8_t)(hi * 16 + lo);
    }
    *out_len = hl / 2;
    return buf;
}

int main(int argc, char **argv)
{
    const char *path = "tools/vectors/batch_proof.json";
    if (argc >= 2) path = argv[1];

    size_t blen = 0;
    char *fbuf = load_file(path, &blen);
    if (!fbuf) {
        fprintf(stderr, "cannot load %s\n", path);
        return 2;
    }
    printf("loaded %s (%zu bytes)\n", path, blen);
    jp_t jp = { fbuf, 0, blen };
    jv_t *doc = jp_value(&jp);
    if (!doc) {
        fprintf(stderr, "JSON parse failed\n");
        free(fbuf);
        return 2;
    }
    const jv_t *scens = jv_get(doc, "scenarios");
    if (!scens || scens->kind != JV_ARR || scens->n == 0) {
        fprintf(stderr, "no scenarios\n");
        return 2;
    }

    static pscenario_t sc;
    uint8_t *first_wire = NULL; /* scenario-0 wire kept for the negatives */
    size_t first_len = 0;

    for (size_t s = 0; s < scens->n; s++) {
        const jv_t *js = scens->items[s];
        const jv_t *name = jv_get(js, "name");
        const char *nm =
            name && name->kind == JV_STR ? name->str : "(unnamed)";
        if (!load_pscenario(js, &sc)) {
            CHECK(0, "%s: fixture load failed", nm);
            continue;
        }
        size_t wlen = 0;
        uint8_t *wire = wire_from_hex(jv_get(js, "wire_v4"), &wlen);
        uint64_t exp_len = 0;
        CHECK(wire != NULL, "%s: wire_v4 hex parse", nm);
        CHECK(sv_u64(jv_get(js, "wire_v4_len"), &exp_len) &&
                  (size_t)exp_len == wlen,
              "%s: wire_v4_len mismatch", nm);
        if (!wire) continue;

        /* ---- gate 1: decode ---- */
        dnac_batch_wire_package_t *pkg = NULL;
        dnac_fri_codec_status_t cs = dnac_batch_wire_decode(wire, wlen, &pkg);
        CHECK(cs == DNAC_FRI_CODEC_OK, "%s: decode = %d", nm, (int)cs);
        if (cs != DNAC_FRI_CODEC_OK) { free(wire); continue; }
        CHECK(dnac_batch_wire_is_zk(pkg) == sc.is_zk, "%s: wire is_zk", nm);
        CHECK(dnac_batch_wire_num_instances(pkg) == sc.n,
              "%s: wire num_instances", nm);

        /* verifier-side prep map (matrix order = instance order in the
         * fixtures — matches common.preprocessed.matrix_to_instance). */
        uint32_t prep_map[MAX_INST], num_prep = 0;
        for (uint32_t i = 0; i < sc.n; i++) {
            if (sc.insts[i].preprocessed_width > 0) prep_map[num_prep++] = i;
        }

        /* ---- gate 2: decoded package verifies end-to-end ---- */
        dnac_batch_verify_out_t out;
        memset(&out, 0, sizeof(out));
        dnac_batch_verify_status_t vs = dnac_batch_verify(
            sc.insts, dnac_batch_wire_opened(pkg), sc.n, sc.is_zk,
            dnac_batch_wire_commits(pkg), num_prep ? prep_map : NULL,
            num_prep, dnac_batch_wire_params(pkg),
            dnac_batch_wire_proof(pkg), dnac_batch_wire_rand_openings(pkg),
            &out);
        CHECK(vs == DNAC_BV_OK,
              "%s: verify(decoded) = %d (fri=%d bad_inst=%u bus=%s)", nm,
              (int)vs, (int)out.fri_status, out.bad_instance,
              out.failed_bus ? out.failed_bus : "-");
        gold_fp2_t ea, ez;
        CHECK(jv_fp2(jv_get(js, "alpha"), &ea) &&
                  fp2_eq_limbs(out.alpha, ea),
              "%s: alpha mismatch", nm);
        CHECK(jv_fp2(jv_get(js, "zeta"), &ez) && fp2_eq_limbs(out.zeta, ez),
              "%s: zeta mismatch", nm);

        /* ---- gate 3: re-encode byte-match ---- */
        uint8_t *re = NULL;
        size_t re_len = 0;
        cs = dnac_batch_wire_encode(
            dnac_batch_wire_is_zk(pkg), dnac_batch_wire_num_instances(pkg),
            dnac_batch_wire_commits(pkg), dnac_batch_wire_opened(pkg),
            dnac_batch_wire_rand_openings(pkg), dnac_batch_wire_params(pkg),
            dnac_batch_wire_proof(pkg), &re, &re_len);
        CHECK(cs == DNAC_FRI_CODEC_OK, "%s: re-encode = %d", nm, (int)cs);
        CHECK(re && re_len == wlen && memcmp(re, wire, wlen) == 0,
              "%s: re-encode BYTE MISMATCH (len %zu vs %zu)", nm, re_len,
              wlen);
        free(re);

        /* ---- gate 4: prove from scratch → encode → oracle byte-match ---- */
        dnac_batch_proof_t *p = NULL;
        dnac_prover_status_t ps = dnac_batch_prove(
            sc.insts, sc.wits, sc.n, sc.is_zk, &sc.params, sc.nrc,
            sc.is_zk ? sc.draws : NULL, sc.is_zk ? sc.num_draws : 0, NULL, 0,
            NULL, 0, 0, &p);
        CHECK(ps == DNAC_PROVER_OK, "%s: dnac_batch_prove = %d", nm, (int)ps);
        if (ps == DNAC_PROVER_OK) {
            dnac_batch_vcommits_t pcm;
            dnac_batch_proof_commits(p, &pcm);
            dnac_batch_vopened_t popen[MAX_INST];
            for (uint32_t i = 0; i < sc.n; i++)
                popen[i] = *dnac_batch_proof_opened(p, i);
            uint8_t *pe = NULL;
            size_t pe_len = 0;
            cs = dnac_batch_wire_encode(
                sc.is_zk, sc.n, &pcm, popen,
                dnac_batch_proof_rand_openings(p), &sc.params,
                dnac_batch_proof_fri(p), &pe, &pe_len);
            CHECK(cs == DNAC_FRI_CODEC_OK, "%s: prove-encode = %d", nm,
                  (int)cs);
            CHECK(pe && pe_len == wlen && memcmp(pe, wire, wlen) == 0,
                  "%s: prove→encode BYTE MISMATCH vs oracle wire (len %zu "
                  "vs %zu)",
                  nm, pe_len, wlen);
            free(pe);
            dnac_batch_proof_free(p);
        }

        dnac_batch_wire_free(pkg);
        printf("  scenario %-16s n=%u is_zk=%d -> decode+verify+re-encode+"
               "prove-encode byte-match\n",
               nm, sc.n, sc.is_zk);
        if (s == 0) {
            first_wire = wire;
            first_len = wlen;
        } else {
            free(wire);
        }
    }

    /* ---- negatives (decode fail-close) ---- */
    if (first_wire) {
        uint8_t *mut = (uint8_t *)malloc(first_len + 1);
        dnac_batch_wire_package_t *pkg = NULL;
        if (!mut) return 2;

        /* N1: bad magic. */
        memcpy(mut, first_wire, first_len);
        mut[0] ^= 0xFF;
        CHECK(dnac_batch_wire_decode(mut, first_len, &pkg) ==
                  DNAC_FRI_CODEC_ERR_BAD_MAGIC,
              "N1: bad magic must be BAD_MAGIC");

        /* N2a RETIRED (d4.d): it asserted that the v3 single-instance decoder
         * rejects a v4 buffer on VERSION. There is no v3 decoder any more —
         * the whole v3 uni-stark path, wire included, is deleted — so the
         * direction is vacuous. N2b below keeps the live half: a version-3
         * buffer must never be accepted by the v4 decoder. */
        /* N2b: a version-3-patched buffer on the v4 decoder. */
        memcpy(mut, first_wire, first_len);
        mut[4] = 3;
        mut[5] = 0;
        CHECK(dnac_batch_wire_decode(mut, first_len, &pkg) ==
                  DNAC_FRI_CODEC_ERR_BAD_VERSION,
              "N2b: version 3 on the v4 decoder must be BAD_VERSION");

        /* N3: truncation mid-field (header-only buffer, total_len = 10). */
        {
            uint8_t tiny[10];
            memcpy(tiny, first_wire, 6);
            tiny[6] = 10; tiny[7] = 0; tiny[8] = 0; tiny[9] = 0;
            CHECK(dnac_batch_wire_decode(tiny, 10, &pkg) ==
                      DNAC_FRI_CODEC_ERR_TRUNCATED,
                  "N3: mid-field truncation must be TRUNCATED");
        }

        /* N4: noncanonical field — first main-commit lane := p
         * (header 10 + is_zk 4 + n 4 = offset 18). */
        memcpy(mut, first_wire, first_len);
        {
            uint64_t p_le = 0xFFFFFFFF00000001ull; /* GOLDILOCKS_P */
            for (int k = 0; k < 8; k++)
                mut[18 + k] = (uint8_t)(p_le >> (8 * k));
        }
        CHECK(dnac_batch_wire_decode(mut, first_len, &pkg) ==
                  DNAC_FRI_CODEC_ERR_NONCANONICAL,
              "N4: lane >= p must be NONCANONICAL");

        /* N5: is_zk flag = 2 (offset 10). */
        memcpy(mut, first_wire, first_len);
        mut[10] = 2;
        CHECK(dnac_batch_wire_decode(mut, first_len, &pkg) ==
                  DNAC_FRI_CODEC_ERR_NONCANONICAL,
              "N5: is_zk flag 2 must be NONCANONICAL");

        /* N6: total_len != buffer length. */
        memcpy(mut, first_wire, first_len);
        mut[6] = (uint8_t)(mut[6] + 1);
        CHECK(dnac_batch_wire_decode(mut, first_len, &pkg) ==
                  DNAC_FRI_CODEC_ERR_INCONSISTENT_LENGTH,
              "N6: patched total_len must be INCONSISTENT_LENGTH");

        /* N7: trailing byte (total_len patched to match). */
        memcpy(mut, first_wire, first_len);
        mut[first_len] = 0;
        {
            uint32_t tl = (uint32_t)(first_len + 1);
            for (int k = 0; k < 4; k++)
                mut[6 + k] = (uint8_t)(tl >> (8 * k));
        }
        CHECK(dnac_batch_wire_decode(mut, first_len + 1, &pkg) ==
                  DNAC_FRI_CODEC_ERR_TRAILING,
              "N7: trailing byte must be TRAILING");

        /* N8 / N9 (d4.d): the v4 decoder's ALLOCATION guards — rd_count_fixed /
         * rd_count_var -> ERR_LENGTH_OVERFLOW and rd_depth -> ERR_BAD_DEPTH
         * (fri_proof_codec.c). Both are LIVE on the consensus path
         * (dnac_batch_wire_decode is what dnac_shielded_verify_statement calls)
         * and they are the first thing an attacker-supplied blob hits, so they
         * must not go untested: their previous coverage lived in the retired
         * v3 test_fri_proof_codec.
         *
         * Method: a DETERMINISTIC sweep — no RNG, fixed buffer, fixed order.
         * Every u32 field of the wire sits at an offset ≡ 10 (mod 4): the
         * header is 10 bytes and every element after it (u32 count/flag, 16-byte
         * fp2, 32-byte digest, 8-byte salt lane) is a multiple of 4. So we walk
         * offset 10, 14, 18, ..., set that u32 to 0xFFFFFFFF, and decode. A
         * count field must trip LENGTH_OVERFLOW; a Merkle depth field must trip
         * BAD_DEPTH (0xFFFFFFFF > DNAC_FRI_WIRE_MAX_SIBLINGS). Offsets that are
         * not structural (e.g. the low half of a Goldilocks lane) legitimately
         * decode or fail otherwise and are simply skipped — the assertion is
         * that BOTH guard classes are observed on real mutations of a real
         * proof, not that every offset rejects. */
        {
            int saw_overflow = 0, saw_depth = 0;
            size_t off;
            for (off = 10; off + 4 <= first_len; off += 4) {
                dnac_batch_wire_package_t *np = NULL;
                dnac_fri_codec_status_t cs;
                memcpy(mut, first_wire, first_len);
                mut[off] = 0xFF; mut[off + 1] = 0xFF;
                mut[off + 2] = 0xFF; mut[off + 3] = 0xFF;
                cs = dnac_batch_wire_decode(mut, first_len, &np);
                if (cs == DNAC_FRI_CODEC_OK) {
                    dnac_batch_wire_free(np);
                } else if (cs == DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW) {
                    saw_overflow = 1;
                } else if (cs == DNAC_FRI_CODEC_ERR_BAD_DEPTH) {
                    saw_depth = 1;
                }
                if (saw_overflow && saw_depth) break;
            }
            CHECK(saw_overflow,
                  "N8: no mutation reached ERR_LENGTH_OVERFLOW — the count "
                  "guard (rd_count_fixed/rd_count_var) is untested");
            CHECK(saw_depth,
                  "N9: no mutation reached ERR_BAD_DEPTH — the Merkle depth "
                  "guard (rd_depth) is untested");
        }

        free(mut);
        free(first_wire);
    } else {
        CHECK(0, "no scenario-0 wire for the negatives");
    }

    jv_free(doc);
    free(fbuf);

    printf("\nbatch_wire total     %26d checks\n", g_checks);
    printf("batch_wire failed    %26d\n", g_fails);
    if (g_fails == 0) {
        printf("\nP2L-d d4.b BATCH WIRE GATE: GREEN\n");
        return 0;
    }
    fprintf(stderr, "\nP2L-d d4.b BATCH WIRE GATE: RED\n");
    return 1;
}
