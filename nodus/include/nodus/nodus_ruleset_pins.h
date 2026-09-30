/**
 * nodus_ruleset_pins.h — GENERATED FILE, DO NOT EDIT.
 *
 * Written by nodus/tools/gen_ruleset_pins.c from the node's compiled
 * runtime table (nodus_runtime_builtin_table(), nodus_witness_runtime.c).
 * Regenerate: cmake --build <nodus build dir> --target regen_ruleset_pins
 * Checked by: ctest -R test_ruleset_pins (a fresh generation must be
 * byte-identical to this file; any difference fails the build's tests).
 *
 * Governing record: docs/plans/decisions/2026-09-25-web-wallet-nodus-
 * send-transport.md, addendum 2026-09-29 "Yol 2". Consumer: the browser
 * wallet's SPEND builder, which cannot link the witness. It must rebuild
 * the SYSTEM meter policy from the fields below (dna_meter_op_set +
 * dna_meter_policy_seal), recompute dna_meter_policy_digest, and refuse
 * to send when that differs from NODUS_PIN_SYS_METER_POLICY_DIGEST_INIT.
 *
 * Byte arrays are brace initializers (macros), not objects, so including
 * this header defines nothing:
 *   static const uint8_t h[64] = NODUS_PIN_CORE_RULESET_HASH_INIT;
 */

#ifndef NODUS_RULESET_PINS_H
#define NODUS_RULESET_PINS_H

/* ── CORE (domain 1) ruleset identity ── */

#define NODUS_PIN_CORE_DOMAIN_ID        1u
#define NODUS_PIN_CORE_RUNTIME_KIND     1u
#define NODUS_PIN_CORE_RUNTIME_ABI      1u
#define NODUS_PIN_CORE_RULESET_VERSION  4u

#define NODUS_PIN_CORE_RULESET_HASH_INIT { \
    0xb8, 0x7a, 0xab, 0xb8, 0x32, 0x4d, 0xc0, 0x5f, \
    0xd0, 0x54, 0x46, 0x90, 0x18, 0x0c, 0xec, 0xe1, \
    0x3b, 0x6e, 0x28, 0x60, 0x78, 0xdb, 0x99, 0x73, \
    0x9c, 0xaa, 0x65, 0xf0, 0x06, 0xd0, 0xb1, 0xd1, \
    0x41, 0x54, 0xed, 0x74, 0xea, 0xb7, 0x8c, 0xf4, \
    0x8b, 0x7f, 0xc4, 0x18, 0xde, 0xdc, 0xad, 0x86, \
    0x84, 0xa4, 0x85, 0x77, 0x9a, 0xac, 0xf2, 0xa0, \
    0xa6, 0xae, 0x40, 0xe0, 0x0d, 0x81, 0x88, 0x52 }

/* ── SYSTEM (domain 0) metering policy ── */

#define NODUS_PIN_SYS_METER_POLICY_VERSION       2u
#define NODUS_PIN_SYS_METER_W_BASE               1ull
#define NODUS_PIN_SYS_METER_W_CALLBYTE           1ull
#define NODUS_PIN_SYS_METER_W_AUTHBYTE           1ull
#define NODUS_PIN_SYS_METER_W_EFFECT             1ull
#define NODUS_PIN_SYS_METER_W_EFFECTBYTE         1ull
#define NODUS_PIN_SYS_METER_W_READ               1ull
#define NODUS_PIN_SYS_METER_W_WRITE              1ull
#define NODUS_PIN_SYS_METER_MAX_BLOCK_ENV_BYTES  2097152ull

/* Authoritative runtime ops (ascending) and their weights; an op not
 * listed has NO weight (fail-closed), not a zero one. */
#define NODUS_PIN_SYS_METER_OP_COUNT  7u
#define NODUS_PIN_SYS_METER_OPS_INIT { 1u, 2u, 3u, 4u, 5u, 6u, 7u }
#define NODUS_PIN_SYS_METER_OP_WEIGHTS_INIT { 1ull, 1ull, 1ull, 1ull, 1ull, 1ull, 1ull }

#define NODUS_PIN_SYS_METER_POLICY_DIGEST_INIT { \
    0x8f, 0x1f, 0x9c, 0xb2, 0xa5, 0x32, 0xbb, 0x28, \
    0x7f, 0xc0, 0xd5, 0xa1, 0xd6, 0x3d, 0xa2, 0xca, \
    0xb5, 0xc4, 0x86, 0x1a, 0x53, 0xe3, 0x91, 0xc3, \
    0xf5, 0xb4, 0xb7, 0xdb, 0xdd, 0x36, 0x49, 0x8b, \
    0xd8, 0xca, 0x8b, 0x14, 0x50, 0x1d, 0x69, 0x54, \
    0xfd, 0x5a, 0xc0, 0x6a, 0x5e, 0x3c, 0x12, 0xbd, \
    0xf4, 0xaf, 0x05, 0x71, 0xf3, 0x31, 0xd4, 0xf5, \
    0x29, 0x9d, 0xaf, 0x26, 0x68, 0x74, 0x6f, 0x32 }

#endif /* NODUS_RULESET_PINS_H */
