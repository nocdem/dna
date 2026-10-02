/**
 * gen_ruleset_pins — writes nodus/include/nodus/nodus_ruleset_pins.h
 *
 * Governing record: docs/plans/decisions/2026-09-25-web-wallet-nodus-send-
 * transport.md, addendum 2026-09-29 "Yol 2" (operator: "Ve tamam ikinci
 * yoldan devam edelim peki."). The browser wallet cannot link the witness
 * (sqlite, cometbft port), so the few values its SPEND builder needs from
 * the node's compiled runtime table are written into a GENERATED header:
 *
 *   - CORE (domain 1): domain_id, runtime_kind, runtime_abi,
 *     ruleset_version, ruleset_hash — the identity tuple a CORE leg carries;
 *   - SYSTEM (domain 0): the same tuple for a SYSTEM leg (the staking
 *     envelopes' record leg — the addendum extended by the ORCHESTRATOR,
 *     2026-09-30, same mechanism and trust);
 *   - SYSTEM (domain 0) metering policy: policy_version, the seven scalar
 *     weights, max_block_env_bytes, every authoritative runtime_op with its
 *     weight, and the committed policy identity digest.
 *
 * The values are READ from the compiled runtime table (generation 1,
 * nodus_runtime_for_generation — the same lookup nodus-cli's
 * cli_builtin_runtime() uses) — never restated by hand. The
 * table must pass nodus_witness_runtime_selfcheck() and the policy's
 * digest must equal the descriptor-committed one, or nothing is written.
 *
 * Output is deterministic: no timestamp, no path, no host data — the same
 * table always gives the same bytes. test_ruleset_pins regenerates it on
 * every ctest run and byte-compares with the checked-in header, so a
 * ruleset change without a regenerated header is a red build.
 *
 * Usage: gen_ruleset_pins <output-path>
 * CMake: target `regen_ruleset_pins` writes the checked-in header.
 *
 * Built with -DGEN_RULESET_PINS_NO_MAIN, this file provides only
 * nodus_ruleset_pins_render() (test_ruleset_pins links it that way).
 */

#include "witness/nodus_witness_runtime.h"
#include "dnac/ledger_ids.h"
#include "dnac/domain_wire.h"
#include "dnac/res_meter.h"
#include "crypto/utils/qgp_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "GEN_RULESET_PINS"

/* ── Growable text buffer ─────────────────────────────────────────── */

typedef struct {
    char   *buf;
    size_t  len;
    size_t  cap;
    int     err;
} pins_out_t;

static void out_printf(pins_out_t *o, const char *fmt, ...) {
    if (o->err) return;
    for (;;) {
        va_list ap;
        va_start(ap, fmt);
        int n = vsnprintf(o->buf + o->len, o->cap - o->len, fmt, ap);
        va_end(ap);
        if (n < 0) { o->err = 1; return; }
        if ((size_t)n < o->cap - o->len) { o->len += (size_t)n; return; }
        size_t ncap = o->cap * 2 + (size_t)n + 1;
        char *nb = realloc(o->buf, ncap);
        if (!nb) { o->err = 1; return; }
        o->buf = nb;
        o->cap = ncap;
    }
}

/* 64 bytes as a brace initializer, 8 bytes per line. */
static void out_hash_init(pins_out_t *o, const char *name, const uint8_t h[64]) {
    out_printf(o, "#define %s { \\\n", name);
    for (int i = 0; i < 64; i++) {
        if (i % 8 == 0) out_printf(o, "    ");
        out_printf(o, "0x%02x%s", h[i], i == 63 ? "" : ",");
        if (i % 8 == 7) out_printf(o, i == 63 ? " }\n" : " \\\n");
        else out_printf(o, " ");
    }
}

/* HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.1):
 * the compiled table is a list of rule-set GENERATIONS, so the pinned
 * tuple is looked up by (domain, generation) — never "the first entry of
 * this domain". This header pins GENERATION 1, the rule set every chain
 * runs until its RULESET_GEN2 height; its bytes are unchanged by HF-4.
 * A pins header carrying every generation (and the readers choosing the
 * generation from the node's dnac_ruleset_info answer) is the clients'
 * part of HF-4 (design §1.6) — its consumers (nodus_v2_spend.c,
 * nodus_v2_stake.c) read the macro names below. */
#define PINS_GENERATION NODUS_RT_GEN_1

/**
 * Render the header text from the compiled runtime table.
 * @param out      receives a malloc'd, NUL-terminated buffer (caller frees)
 * @param out_len  receives its length without the NUL
 * @return 0 / -1 (table unhealthy, policy mismatch, allocation failure)
 */
int nodus_ruleset_pins_render(char **out, size_t *out_len) {
    if (!out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;

    if (nodus_witness_runtime_selfcheck() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "runtime table selfcheck failed — no pins written");
        return -1;
    }

    const nodus_domain_runtime_t *core =
        nodus_runtime_for_generation(PINS_GENERATION, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *sys =
        nodus_runtime_for_generation(PINS_GENERATION, DNA_DOMAIN_SYSTEM);
    if (!core || !sys || !sys->meter_policy) {
        QGP_LOG_ERROR(LOG_TAG, "CORE / SYSTEM entry or SYSTEM meter policy missing");
        return -1;
    }

    const dna_meter_policy_t *p = sys->meter_policy;
    uint8_t digest[DNA_DOM_HASH_LEN];
    if (dna_meter_policy_check(p) != 0 ||
        dna_meter_policy_digest(p, digest) != 0 ||
        memcmp(digest, sys->descriptor.meter_policy_digest, DNA_DOM_HASH_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "SYSTEM meter policy does not match its committed digest");
        return -1;
    }

    /* Authoritative ops, ascending — dna_meter_op_weight fails for an op
     * whose presence bit is clear (it has no weight, not a zero one). */
    uint32_t ops[DNA_METER_OP_SPACE];
    uint64_t wts[DNA_METER_OP_SPACE];
    uint32_t n_ops = 0;
    for (uint32_t op = 0; op < DNA_METER_OP_SPACE; op++) {
        uint64_t w = 0;
        if (dna_meter_op_weight(p, op, &w) == 0) {
            ops[n_ops] = op;
            wts[n_ops] = w;
            n_ops++;
        }
    }
    if (n_ops == 0) {
        QGP_LOG_ERROR(LOG_TAG, "SYSTEM meter policy prices no op");
        return -1;
    }

    pins_out_t o = { .buf = malloc(4096), .len = 0, .cap = 4096, .err = 0 };
    if (!o.buf) return -1;
    o.buf[0] = '\0';

    out_printf(&o,
        "/**\n"
        " * nodus_ruleset_pins.h — GENERATED FILE, DO NOT EDIT.\n"
        " *\n"
        " * Written by nodus/tools/gen_ruleset_pins.c from the node's compiled\n"
        " * runtime table (nodus_runtime_builtin_table(), nodus_witness_runtime.c).\n"
        " * Regenerate: cmake --build <nodus build dir> --target regen_ruleset_pins\n"
        " * Checked by: ctest -R test_ruleset_pins (a fresh generation must be\n"
        " * byte-identical to this file; any difference fails the build's tests).\n"
        " *\n"
        " * Governing record: docs/plans/decisions/2026-09-25-web-wallet-nodus-\n"
        " * send-transport.md, addendum 2026-09-29 \"Yol 2\". Consumer: the browser\n"
        " * wallet's SPEND and staking builders, which cannot link the witness\n"
        " * (the CORE tuple signs a CORE leg, the SYSTEM tuple a SYSTEM leg).\n"
        " * It must rebuild\n"
        " * the SYSTEM meter policy from the fields below (dna_meter_op_set +\n"
        " * dna_meter_policy_seal), recompute dna_meter_policy_digest, and refuse\n"
        " * to send when that differs from NODUS_PIN_SYS_METER_POLICY_DIGEST_INIT.\n"
        " *\n"
        " * Byte arrays are brace initializers (macros), not objects, so including\n"
        " * this header defines nothing:\n"
        " *   static const uint8_t h[64] = NODUS_PIN_CORE_RULESET_HASH_INIT;\n"
        " */\n"
        "\n"
        "#ifndef NODUS_RULESET_PINS_H\n"
        "#define NODUS_RULESET_PINS_H\n"
        "\n");

    out_printf(&o, "/* ── CORE (domain %u) ruleset identity ── */\n\n",
               (unsigned)core->domain_id);
    out_printf(&o, "#define NODUS_PIN_CORE_DOMAIN_ID        %uu\n", (unsigned)core->domain_id);
    out_printf(&o, "#define NODUS_PIN_CORE_RUNTIME_KIND     %uu\n", (unsigned)core->runtime_kind);
    out_printf(&o, "#define NODUS_PIN_CORE_RUNTIME_ABI      %uu\n", (unsigned)core->runtime_abi);
    out_printf(&o, "#define NODUS_PIN_CORE_RULESET_VERSION  %uu\n", (unsigned)core->ruleset_version);
    out_printf(&o, "\n");
    out_hash_init(&o, "NODUS_PIN_CORE_RULESET_HASH_INIT", core->ruleset_hash);

    /* The SYSTEM tuple a SYSTEM leg (STAKE / DELEGATE / UNDELEGATE —
     * nodus/src/client/nodus_v2_stake.c) carries and signs over
     * (env_preflight.c dna_env_call_commit): same mechanism and trust as
     * the CORE tuple above (the "Yol 2" addendum, extended). */
    out_printf(&o, "\n/* ── SYSTEM (domain %u) ruleset identity ── */\n\n",
               (unsigned)sys->domain_id);
    out_printf(&o, "#define NODUS_PIN_SYS_DOMAIN_ID         %uu\n", (unsigned)sys->domain_id);
    out_printf(&o, "#define NODUS_PIN_SYS_RUNTIME_KIND      %uu\n", (unsigned)sys->runtime_kind);
    out_printf(&o, "#define NODUS_PIN_SYS_RUNTIME_ABI       %uu\n", (unsigned)sys->runtime_abi);
    out_printf(&o, "#define NODUS_PIN_SYS_RULESET_VERSION   %uu\n", (unsigned)sys->ruleset_version);
    out_printf(&o, "\n");
    out_hash_init(&o, "NODUS_PIN_SYS_RULESET_HASH_INIT", sys->ruleset_hash);

    out_printf(&o, "\n/* ── SYSTEM (domain %u) metering policy ── */\n\n",
               (unsigned)sys->domain_id);
    out_printf(&o, "#define NODUS_PIN_SYS_METER_POLICY_VERSION       %uu\n",
               (unsigned)p->policy_version);
    out_printf(&o, "#define NODUS_PIN_SYS_METER_W_BASE               %lluull\n",
               (unsigned long long)p->w_base);
    out_printf(&o, "#define NODUS_PIN_SYS_METER_W_CALLBYTE           %lluull\n",
               (unsigned long long)p->w_callbyte);
    out_printf(&o, "#define NODUS_PIN_SYS_METER_W_AUTHBYTE           %lluull\n",
               (unsigned long long)p->w_authbyte);
    out_printf(&o, "#define NODUS_PIN_SYS_METER_W_EFFECT             %lluull\n",
               (unsigned long long)p->w_effect);
    out_printf(&o, "#define NODUS_PIN_SYS_METER_W_EFFECTBYTE         %lluull\n",
               (unsigned long long)p->w_effectbyte);
    out_printf(&o, "#define NODUS_PIN_SYS_METER_W_READ               %lluull\n",
               (unsigned long long)p->w_read);
    out_printf(&o, "#define NODUS_PIN_SYS_METER_W_WRITE              %lluull\n",
               (unsigned long long)p->w_write);
    out_printf(&o, "#define NODUS_PIN_SYS_METER_MAX_BLOCK_ENV_BYTES  %lluull\n",
               (unsigned long long)p->max_block_env_bytes);
    out_printf(&o, "\n/* Authoritative runtime ops (ascending) and their weights; an op not\n"
                   " * listed has NO weight (fail-closed), not a zero one. */\n");
    out_printf(&o, "#define NODUS_PIN_SYS_METER_OP_COUNT  %uu\n", (unsigned)n_ops);
    out_printf(&o, "#define NODUS_PIN_SYS_METER_OPS_INIT {");
    for (uint32_t i = 0; i < n_ops; i++)
        out_printf(&o, " %uu%s", (unsigned)ops[i], i + 1 == n_ops ? " }\n" : ",");
    out_printf(&o, "#define NODUS_PIN_SYS_METER_OP_WEIGHTS_INIT {");
    for (uint32_t i = 0; i < n_ops; i++)
        out_printf(&o, " %lluull%s", (unsigned long long)wts[i], i + 1 == n_ops ? " }\n" : ",");
    out_printf(&o, "\n");
    out_hash_init(&o, "NODUS_PIN_SYS_METER_POLICY_DIGEST_INIT", digest);

    out_printf(&o, "\n#endif /* NODUS_RULESET_PINS_H */\n");

    if (o.err) {
        free(o.buf);
        return -1;
    }
    *out = o.buf;
    *out_len = o.len;
    return 0;
}

#ifndef GEN_RULESET_PINS_NO_MAIN
int main(int argc, char **argv) {
    if (argc != 2) {
        QGP_LOG_ERROR(LOG_TAG, "usage: gen_ruleset_pins <output-path>");
        return 2;
    }
    char *text = NULL;
    size_t len = 0;
    if (nodus_ruleset_pins_render(&text, &len) != 0)
        return 1;

    FILE *f = fopen(argv[1], "wb");
    if (!f) {
        QGP_LOG_ERROR(LOG_TAG, "cannot open %s for writing", argv[1]);
        free(text);
        return 1;
    }
    size_t w = fwrite(text, 1, len, f);
    int close_rc = fclose(f);
    free(text);
    if (w != len || close_rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "short write to %s", argv[1]);
        return 1;
    }
    QGP_LOG_INFO(LOG_TAG, "wrote %s (%zu bytes)", argv[1], len);
    return 0;
}
#endif
