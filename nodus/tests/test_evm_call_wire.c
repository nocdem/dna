/**
 * test_evm_call_wire.c — Nodus EVM Faz 4 "one codec": the EVM leg's call bytes
 * (runtime ops 1-5) and the CORE EVMFUND call (CORE op 9), decoded by the
 * NODE path (design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md
 * rev 3 §2; shared/dnac/evm_call_wire.{c,h}).
 *
 * What is pinned:
 *   1. every op's fixed byte vector — assembled here field by field from
 *      the §2 layout (never by the codec's encoder) — decodes through the
 *      node's head decoder nodus_rt_evm_call_head (the CORE EVMFUND hook,
 *      the block gas sum, the conflict keys) and the full decoder
 *      dna_evm_call_decode (the EVM runtime's rtevm_decode is a static
 *      wrapper of it) to exactly the fields written; and the encoder
 *      reproduces the vector byte for byte;
 *   2. the refusals: wrong ver, a trailing byte, a short call, an unknown
 *      op, an access-list key count larger than the bytes, CREATE initcode
 *      one byte over EIP-3860;
 *   3. head vs full decode: a CALL whose TAIL is malformed still has a
 *      head (its declared gas counts in the block gas sum, design §8) and
 *      is refused by the full decode;
 *   4. the EVMFUND call for roles FEE 1 / DEPOSIT 2 / RELEASE 3: the node's
 *      role_for_op, the pairing rule nodus_rt_evm_pair_check on a real
 *      encoded envelope, the strict decode (16 change outputs accepted,
 *      17 refused; a non-native or upper-case output, zero inputs,
 *      non-ascending inputs, a trailing byte refused) and the read count
 *      of each role (nodus_rt_core_read_plan's shape);
 *   5. the block gas share nodus_rt_evm_env_block_gas: CALL/CREATE their
 *      declared gas_limit, a bridge op 21 000;
 *   6. (red-team 1 F3) the access-list cursor dna_evm_access_next: one
 *      linear pass in wire order, a repeated address preserved, every
 *      truncation and an oversized key count refused.
 *
 * HOW IT CAN LIE: the codec is one implementation decoding vectors its
 * author wrote from the same design text — this proves the node and every
 * client that links the codec agree, not that §2 is the right layout. The
 * EVM runtime's static rtevm_decode and the CORE hook's static
 * rtn_evmfund_parse are reached only through their exported neighbours
 * (call_head, pair_check); test_v2_evm drives them end to end.
 * Requires nothing beyond a default build (no EVM engine link).
 */

#include "witness/nodus_witness_runtime.h"
#include "dnac/evm_call_wire.h"
#include "dnac/env_wire.h"
#include "dnac/ledger_ids.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks = 0;
#define CHECK(cond, msg)                                                \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,    \
                    __LINE__, msg);                                     \
            return 1;                                                   \
        }                                                               \
        g_checks++;                                                     \
    } while (0)

/* ── a field-by-field vector writer (independent of the codec) ────────── */

typedef struct { uint8_t b[60000]; size_t n; } vec_t;

static void v_byte(vec_t *v, uint8_t x) { v->b[v->n++] = x; }
static void v_rep(vec_t *v, uint8_t x, size_t k) {
    memset(v->b + v->n, x, k);
    v->n += k;
}
static void v_be(vec_t *v, uint64_t x, unsigned k) {
    for (unsigned i = 0; i < k; i++)
        v->b[v->n++] = (uint8_t)(x >> (8u * (k - 1u - i)));
}
static void v_bytes(vec_t *v, const uint8_t *p, size_t k) {
    memcpy(v->b + v->n, p, k);
    v->n += k;
}

static int all_eq(const uint8_t *p, uint8_t x, size_t k) {
    for (size_t i = 0; i < k; i++)
        if (p[i] != x) return 0;
    return 1;
}

static const uint8_t DATA4[4] = { 0xa9, 0x05, 0x9c, 0xbb };

/* CALL: ver 01 ‖ to 0x11×32 ‖ value 0…05 ‖ gas 100 000 ‖ nonce 7 ‖
 * n_acc 1 ‖ (addr 0x22×32 ‖ n_keys 1 ‖ key 0x33×32) ‖ data_len 4 ‖ DATA4 */
static void vec_call(vec_t *v) {
    v->n = 0;
    v_byte(v, 0x01);
    v_rep(v, 0x11, 32);
    v_rep(v, 0x00, 31); v_byte(v, 0x05);
    v_be(v, 100000, 8);
    v_be(v, 7, 8);
    v_be(v, 1, 2);
    v_rep(v, 0x22, 32); v_be(v, 1, 2); v_rep(v, 0x33, 32);
    v_be(v, 4, 4);
    v_bytes(v, DATA4, 4);
}

/* CREATE: ver ‖ value 0 ‖ gas 3 000 000 ‖ nonce 0 ‖ n_acc 0 ‖
 * initcode_len 3 ‖ 60 00 f3 */
static void vec_create(vec_t *v) {
    static const uint8_t init[3] = { 0x60, 0x00, 0xf3 };
    v->n = 0;
    v_byte(v, 0x01);
    v_rep(v, 0x00, 32);
    v_be(v, 3000000, 8);
    v_be(v, 0, 8);
    v_be(v, 0, 2);
    v_be(v, 3, 4);
    v_bytes(v, init, 3);
}

static void vec_deposit(vec_t *v) {          /* 17 bytes */
    v->n = 0;
    v_byte(v, 0x01);
    v_be(v, 250000000ull, 8);                /* 2.5 NODUS */
    v_be(v, 3, 8);
}

static void vec_withdraw(vec_t *v) {         /* 81 bytes */
    v->n = 0;
    v_byte(v, 0x01);
    v_be(v, 100000000ull, 8);
    v_be(v, 4, 8);
    v_rep(v, 0x44, 64);
}

static void vec_redeem(vec_t *v) {           /* 137 bytes */
    v->n = 0;
    v_byte(v, 0x01);
    v_rep(v, 0x55, 64);
    v_be(v, 42, 8);
    v_rep(v, 0x66, 64);
}

/* encode(decode(vec)) == vec */
static int reencodes(uint32_t op, const vec_t *v) {
    dna_evm_call_t c;
    if (dna_evm_call_decode(op, v->b, v->n, &c) != 0) return 0;
    size_t n = 0, w = 0;
    if (dna_evm_call_encoded_size(&c, &n) != 0 || n != v->n) return 0;
    uint8_t *out = malloc(n);
    int ok = out && dna_evm_call_encode(&c, out, n, &w) == 0 && w == n &&
             memcmp(out, v->b, n) == 0;
    free(out);
    return ok;
}

static int test_ops(void) {
    static vec_t v;
    nodus_rt_evm_head_t h;
    dna_evm_call_t c;

    /* CALL */
    vec_call(&v);
    CHECK(v.n == 81 + 2 + 34 + 32 + 4 + 4, "CALL vector length");
    CHECK(nodus_rt_evm_call_head(NODUS_RT_EVM_CALL, v.b, v.n, &h) == 0 &&
          h.op == NODUS_RT_EVM_CALL && h.gas_limit == 100000 &&
          h.nonce == 7 && h.to == v.b + 1 && h.value == v.b + 33 &&
          h.rest_off == 81 && !h.dest_fp && !h.ticket_id &&
          h.amount_raw == 0, "CALL head (node)");
    CHECK(dna_evm_call_decode(NODUS_RT_EVM_CALL, v.b, v.n, &c) == 0 &&
          all_eq(c.to, 0x11, 32) && c.value_wei[31] == 5 &&
          all_eq(c.value_wei, 0, 31) && c.gas_limit == 100000 &&
          c.nonce == 7 && c.n_access == 1 && c.n_access_keys == 1 &&
          c.access_len == 34 + 32 && c.data_len == 4 &&
          memcmp(c.data, DATA4, 4) == 0, "CALL full decode");
    {
        const uint8_t *addr = NULL, *keys = NULL;
        uint16_t nk = 0;
        size_t off = 0;
        CHECK(dna_evm_access_next(c.access, c.access_len, &off, &addr, &nk,
                                  &keys) == 0 &&
              all_eq(addr, 0x22, 32) && nk == 1 && all_eq(keys, 0x33, 32) &&
              off == c.access_len, "CALL access entry 0 (cursor)");
        CHECK(dna_evm_access_next(c.access, c.access_len, &off, &addr, &nk,
                                  &keys) != 0 && off == c.access_len &&
              !addr && nk == 0 && !keys,
              "the cursor refuses past the body, outputs cleared");
    }
    CHECK(reencodes(NODUS_RT_EVM_CALL, &v), "CALL re-encodes byte for byte");

    /* CREATE */
    vec_create(&v);
    CHECK(nodus_rt_evm_call_head(NODUS_RT_EVM_CREATE, v.b, v.n, &h) == 0 &&
          h.gas_limit == 3000000 && h.nonce == 0 && !h.to &&
          h.value == v.b + 1 && h.rest_off == 49, "CREATE head (node)");
    CHECK(dna_evm_call_decode(NODUS_RT_EVM_CREATE, v.b, v.n, &c) == 0 &&
          c.n_access == 0 && !c.access && c.data_len == 3 &&
          c.data[0] == 0x60 && c.data[2] == 0xf3, "CREATE full decode");
    CHECK(reencodes(NODUS_RT_EVM_CREATE, &v), "CREATE re-encodes");

    /* DEPOSIT */
    vec_deposit(&v);
    CHECK(v.n == DNA_EVM_DEPOSIT_CALL_LEN, "DEPOSIT length 17");
    CHECK(nodus_rt_evm_call_head(NODUS_RT_EVM_DEPOSIT, v.b, v.n, &h) == 0 &&
          h.amount_raw == 250000000ull && h.nonce == 3 && !h.dest_fp &&
          h.rest_off == 17, "DEPOSIT head (node)");
    CHECK(reencodes(NODUS_RT_EVM_DEPOSIT, &v), "DEPOSIT re-encodes");

    /* WITHDRAW */
    vec_withdraw(&v);
    CHECK(v.n == DNA_EVM_WITHDRAW_CALL_LEN, "WITHDRAW length 81");
    CHECK(nodus_rt_evm_call_head(NODUS_RT_EVM_WITHDRAW, v.b, v.n, &h) == 0 &&
          h.amount_raw == 100000000ull && h.nonce == 4 &&
          h.dest_fp == v.b + 17 && all_eq(h.dest_fp, 0x44, 64),
          "WITHDRAW head (node)");
    CHECK(reencodes(NODUS_RT_EVM_WITHDRAW, &v), "WITHDRAW re-encodes");

    /* REDEEM */
    vec_redeem(&v);
    CHECK(v.n == DNA_EVM_REDEEM_CALL_LEN, "REDEEM length 137");
    CHECK(nodus_rt_evm_call_head(NODUS_RT_EVM_REDEEM, v.b, v.n, &h) == 0 &&
          h.ticket_id == v.b + 1 && all_eq(h.ticket_id, 0x55, 64) &&
          h.amount_raw == 42 && h.dest_fp == v.b + 73 && h.nonce == 0,
          "REDEEM head (node)");
    CHECK(reencodes(NODUS_RT_EVM_REDEEM, &v), "REDEEM re-encodes");
    return 0;
}

static int test_refusals(void) {
    static vec_t v;
    nodus_rt_evm_head_t h;
    dna_evm_call_t c;

    /* wrong ver, every op */
    vec_deposit(&v);
    v.b[0] = 0x02;
    CHECK(nodus_rt_evm_call_head(NODUS_RT_EVM_DEPOSIT, v.b, v.n, &h) != 0,
          "ver 2 refused");
    vec_call(&v);
    v.b[0] = 0x00;
    CHECK(dna_evm_call_decode(NODUS_RT_EVM_CALL, v.b, v.n, &c) != 0,
          "CALL ver 0 refused");

    /* trailing byte / short, bridge ops */
    vec_withdraw(&v);
    v_byte(&v, 0x00);
    CHECK(nodus_rt_evm_call_head(NODUS_RT_EVM_WITHDRAW, v.b, v.n, &h) != 0,
          "WITHDRAW trailing byte refused");
    vec_redeem(&v);
    CHECK(nodus_rt_evm_call_head(NODUS_RT_EVM_REDEEM, v.b, v.n - 1, &h) != 0,
          "REDEEM short refused");

    /* unknown op */
    vec_deposit(&v);
    CHECK(nodus_rt_evm_call_head(6, v.b, v.n, &h) != 0 &&
          nodus_rt_evm_call_head(0, v.b, v.n, &h) != 0, "op 0 / 6 refused");

    /* CALL trailing byte after the data */
    vec_call(&v);
    v_byte(&v, 0x00);
    CHECK(dna_evm_call_decode(NODUS_RT_EVM_CALL, v.b, v.n, &c) != 0,
          "CALL trailing byte refused");

    /* access key count larger than the bytes: n_keys 0xFFFF */
    vec_call(&v);
    v.b[81 + 2 + 32] = 0xFF;
    v.b[81 + 2 + 33] = 0xFF;
    CHECK(dna_evm_call_decode(NODUS_RT_EVM_CALL, v.b, v.n, &c) != 0,
          "access n_keys beyond the bytes refused");

    /* §8: the HEAD of a CALL with a malformed tail still decodes — its
     * declared gas counts in the block gas sum — the full decode refuses */
    CHECK(nodus_rt_evm_call_head(NODUS_RT_EVM_CALL, v.b, v.n, &h) == 0 &&
          h.gas_limit == 100000, "malformed-tail CALL keeps its head");

    /* CREATE initcode: 49 152 accepted, 49 153 refused (EIP-3860) */
    for (uint32_t L = DNA_EVM_MAX_INITCODE; L <= DNA_EVM_MAX_INITCODE + 1;
         L++) {
        v.n = 0;
        v_byte(&v, 0x01);
        v_rep(&v, 0x00, 32);
        v_be(&v, 21000, 8);
        v_be(&v, 0, 8);
        v_be(&v, 0, 2);
        v_be(&v, L, 4);
        v_rep(&v, 0x5b, L);
        int r = dna_evm_call_decode(NODUS_RT_EVM_CREATE, v.b, v.n, &c);
        if (L == DNA_EVM_MAX_INITCODE)
            CHECK(r == 0, "initcode at the EIP-3860 cap accepted");
        else
            CHECK(r != 0, "initcode one byte over the cap refused");
    }
    return 0;
}

/* red-team 1 F3 — the access list is walked by ONE cursor (no per-entry
 * re-walk): a 3-entry body with the SAME address twice (Prague allows
 * repeats; the engine charges every listed entry) steps entry by entry in
 * wire order, duplicates preserved, and every truncation refuses. */
static int test_access_cursor(void) {
    static uint8_t body[34 * 3 + 32 * 3];
    size_t n = 0;
    const uint8_t a1[32] = { 0xA1 }, a2[32] = { 0xA2 };
    uint8_t k2[64];
    memset(k2, 0x5C, sizeof(k2));
    CHECK(dna_evm_access_put(body, sizeof(body), &n, a1, 0, NULL) == 0 &&
          dna_evm_access_put(body, sizeof(body), &n, a2, 2, k2) == 0 &&
          dna_evm_access_put(body, sizeof(body), &n, a1, 1, k2) == 0 &&
          n == 34 * 3 + 32 * 3, "three entries written (a1 repeated)");
    size_t used = 0;
    uint64_t keys_total = 0;
    CHECK(dna_evm_access_walk(body, n, 3, &used, &keys_total) == 0 &&
          used == n && keys_total == 3, "walk: whole body, 3 keys");

    const uint8_t *addr = NULL, *keys = NULL;
    uint16_t nk = 0;
    size_t off = 0;
    CHECK(dna_evm_access_next(body, n, &off, &addr, &nk, &keys) == 0 &&
          addr == body && nk == 0 && !keys && off == 34,
          "entry 0: a1, no keys");
    CHECK(dna_evm_access_next(body, n, &off, &addr, &nk, &keys) == 0 &&
          addr == body + 34 && addr[0] == 0xA2 && nk == 2 &&
          keys == body + 68 && off == 34 + 34 + 64, "entry 1: a2, 2 keys");
    CHECK(dna_evm_access_next(body, n, &off, &addr, &nk, &keys) == 0 &&
          addr[0] == 0xA1 && nk == 1 && off == n,
          "entry 2: a1 AGAIN (duplicate preserved), 1 key");

    /* every proper prefix that cuts an entry refuses at that entry */
    for (size_t cut = 0; cut < n; cut++) {
        size_t o = 0;
        int steps = 0, rc = 0;
        while (steps < 3 &&
               (rc = dna_evm_access_next(body, cut, &o, &addr, &nk, &keys))
                   == 0)
            steps++;
        CHECK(steps < 3 && rc != 0 && o <= cut,
              "a truncated body refuses before the last entry");
    }
    /* a key count beyond the bytes refuses without moving the cursor */
    body[34 + 32] = 0xFF;
    body[34 + 33] = 0xFF;
    off = 34;
    CHECK(dna_evm_access_next(body, n, &off, &addr, &nk, &keys) != 0 &&
          off == 34, "n_keys beyond the bytes refused, cursor unchanged");
    off = 0;
    CHECK(dna_evm_access_next(NULL, 0, &off, &addr, &nk, &keys) != 0 &&
          dna_evm_access_next(body, n, NULL, &addr, &nk, &keys) != 0,
          "NULL body / cursor refused");
    return 0;
}

/* ── EVMFUND ─────────────────────────────────────────────────────────── */

/* One native change record: owner = `hexc` × 128 (lowercase hex char),
 * amount, token zero, seed 0x77×32. */
static void v_out(vec_t *v, char hexc, uint64_t amount) {
    v_rep(v, (uint8_t)hexc, 128);
    v_be(v, amount, 8);
    v_rep(v, 0x00, 64);
    v_rep(v, 0x77, 32);
}

/* ver ‖ role ‖ n_in ‖ nullifiers 0x01…, 0x02…, … ‖ n_out ‖ outputs */
static void vec_fund(vec_t *v, uint8_t role, uint8_t n_in, uint8_t n_out) {
    v->n = 0;
    v_byte(v, 0x01);
    v_byte(v, role);
    v_byte(v, n_in);
    for (uint8_t i = 0; i < n_in; i++) v_rep(v, (uint8_t)(i + 1), 64);
    v_byte(v, n_out);
    for (uint8_t o = 0; o < n_out; o++) v_out(v, 'a', 1000u + o);
}

/* Encode [CORE leg 0 (core_op, fund call)] + [EVM leg 1] and decode it. */
static int env_view(const vec_t *fund, uint32_t core_op, uint32_t evm_dom,
                    uint32_t evm_op, const vec_t *evm, uint8_t *buf,
                    size_t cap, dna_env_view_t *out) {
    dna_env_leg_in_t legs[2];
    uint8_t a = 0;
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[0].hdr.runtime_op = core_op;
    legs[0].hdr.ruleset_version = 6;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = 1;
    legs[0].hdr.call_len = (uint32_t)fund->n;
    legs[0].hdr.auth_len = 1;
    legs[0].call_data = fund->b;
    legs[0].auth_data = &a;
    legs[1].hdr.domain_id = evm_dom;
    legs[1].hdr.runtime_op = evm_op;
    legs[1].hdr.ruleset_version = 1;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = 1;
    legs[1].hdr.call_len = (uint32_t)evm->n;
    legs[1].hdr.auth_len = 1;
    legs[1].call_data = evm->b;
    legs[1].auth_data = &a;
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.res_max_total_units = 1;
    in.leg_count = 2;
    in.legs = legs;
    size_t used = 0;
    if (dna_env_encode(&in, buf, cap, &used) != 0) return -1;
    return dna_env_decode(buf, used, out);
}

static int test_evmfund(void) {
    static vec_t f, e;
    static uint8_t buf[70000];
    static dna_env_view_t view;
    dna_evmfund_call_t d;

    /* the role each op's CORE sibling must carry (node + codec agree) */
    CHECK(nodus_rt_evm_role_for_op(NODUS_RT_EVM_CALL) == 1 &&
          nodus_rt_evm_role_for_op(NODUS_RT_EVM_CREATE) == 1 &&
          nodus_rt_evm_role_for_op(NODUS_RT_EVM_DEPOSIT) == 2 &&
          nodus_rt_evm_role_for_op(NODUS_RT_EVM_WITHDRAW) == 3 &&
          nodus_rt_evm_role_for_op(NODUS_RT_EVM_REDEEM) == 3 &&
          nodus_rt_evm_role_for_op(6) == 0, "role_for_op 1/1/2/3/3/0");

    /* role FEE + CALL, one input, one change */
    vec_fund(&f, 1, 1, 1);
    CHECK(f.n == 3 + 64 + 1 + 232, "FEE vector length");
    CHECK(dna_evmfund_decode(f.b, f.n, &d) == 0 && d.role == 1 &&
          d.n_in == 1 && d.in_nul == f.b + 3 && d.n_out == 1 &&
          d.outs == f.b + 68, "FEE decode");
    vec_call(&e);
    CHECK(env_view(&f, DNA_CORERULE_EVMFUND, DNA_DOMAIN_EVM,
                   NODUS_RT_EVM_CALL, &e, buf, sizeof(buf), &view) == 0 &&
          nodus_rt_evm_pair_check(&view) == 0, "FEE + CALL paired (node)");
    CHECK(nodus_rt_evm_env_block_gas(&view, DNA_DOMAIN_EVM) == 100000,
          "CALL block gas share = declared gas_limit");

    /* role DEPOSIT + DEPOSIT, two inputs, no change */
    vec_fund(&f, 2, 2, 0);
    CHECK(dna_evmfund_decode(f.b, f.n, &d) == 0 && d.role == 2 &&
          d.n_in == 2 && d.n_out == 0 && !d.outs, "DEPOSIT decode");
    vec_deposit(&e);
    CHECK(env_view(&f, DNA_CORERULE_EVMFUND, DNA_DOMAIN_EVM,
                   NODUS_RT_EVM_DEPOSIT, &e, buf, sizeof(buf), &view) == 0 &&
          nodus_rt_evm_pair_check(&view) == 0, "DEPOSIT paired (node)");
    CHECK(nodus_rt_evm_env_block_gas(&view, DNA_DOMAIN_EVM) ==
          NODUS_RT_EVM_BRIDGE_GAS, "bridge block gas share = 21 000");

    /* role RELEASE + WITHDRAW / REDEEM */
    vec_fund(&f, 3, 1, 1);
    vec_withdraw(&e);
    CHECK(env_view(&f, DNA_CORERULE_EVMFUND, DNA_DOMAIN_EVM,
                   NODUS_RT_EVM_WITHDRAW, &e, buf, sizeof(buf), &view) == 0 &&
          nodus_rt_evm_pair_check(&view) == 0, "RELEASE + WITHDRAW paired");
    vec_redeem(&e);
    CHECK(env_view(&f, DNA_CORERULE_EVMFUND, DNA_DOMAIN_EVM,
                   NODUS_RT_EVM_REDEEM, &e, buf, sizeof(buf), &view) == 0 &&
          nodus_rt_evm_pair_check(&view) == 0, "RELEASE + REDEEM paired");

    /* mismatched role: FEE beside a DEPOSIT */
    vec_fund(&f, 1, 1, 0);
    vec_deposit(&e);
    CHECK(env_view(&f, DNA_CORERULE_EVMFUND, DNA_DOMAIN_EVM,
                   NODUS_RT_EVM_DEPOSIT, &e, buf, sizeof(buf), &view) == 0 &&
          nodus_rt_evm_pair_check(&view) != 0, "role mismatch refused");

    /* 16 change outputs accepted (the node's RTN_SPEND_MAX_OUT), 17 not */
    vec_fund(&f, 1, 1, 16);
    CHECK(dna_evmfund_decode(f.b, f.n, &d) == 0 && d.n_out == 16,
          "16 change outputs accepted");
    {
        size_t n = 0, w = 0;
        static uint8_t re[sizeof(f.b)];
        CHECK(dna_evmfund_encoded_size(&d, &n) == 0 && n == f.n &&
              dna_evmfund_encode(&d, re, sizeof(re), &w) == 0 && w == n &&
              memcmp(re, f.b, n) == 0, "16-output call re-encodes");
    }
    vec_fund(&f, 1, 1, 17);
    CHECK(dna_evmfund_decode(f.b, f.n, &d) != 0, "17 change outputs refused");

    /* 15 inputs accepted, 16 / 0 refused */
    vec_fund(&f, 3, 15, 0);
    CHECK(dna_evmfund_decode(f.b, f.n, &d) == 0 && d.n_in == 15,
          "15 inputs accepted");
    vec_fund(&f, 3, 16, 0);
    CHECK(dna_evmfund_decode(f.b, f.n, &d) != 0, "16 inputs refused");
    vec_fund(&f, 3, 0, 0);
    CHECK(dna_evmfund_decode(f.b, f.n, &d) != 0, "0 inputs refused");

    /* inputs not strictly ascending */
    vec_fund(&f, 1, 2, 0);
    memset(f.b + 3 + 64, 0x01, 64);          /* input 1 == input 0 */
    CHECK(dna_evmfund_decode(f.b, f.n, &d) != 0, "equal inputs refused");

    /* non-native change, upper-case owner, zero amount */
    vec_fund(&f, 1, 1, 1);
    f.b[68 + 136] = 0x01;
    CHECK(dna_evmfund_decode(f.b, f.n, &d) != 0, "non-native change refused");
    vec_fund(&f, 1, 1, 1);
    f.b[68] = 'A';
    CHECK(dna_evmfund_decode(f.b, f.n, &d) != 0, "upper-case owner refused");
    vec_fund(&f, 1, 1, 1);
    memset(f.b + 68 + 128, 0, 8);
    CHECK(dna_evmfund_decode(f.b, f.n, &d) != 0, "zero-amount change refused");

    /* trailing byte, wrong ver, unknown role */
    vec_fund(&f, 1, 1, 0);
    v_byte(&f, 0x00);
    CHECK(dna_evmfund_decode(f.b, f.n, &d) != 0, "trailing byte refused");
    vec_fund(&f, 1, 1, 0);
    f.b[0] = 0x02;
    CHECK(dna_evmfund_decode(f.b, f.n, &d) != 0, "ver 2 refused");
    vec_fund(&f, 4, 1, 0);
    CHECK(dna_evmfund_decode(f.b, f.n, &d) != 0, "role 4 refused");

    /* the read count each role's read plan requests */
    CHECK(dna_evmfund_reads(1, 3) == 4 && dna_evmfund_reads(2, 3) == 5 &&
          dna_evmfund_reads(3, 1) == 3 && dna_evmfund_reads(9, 1) == 0,
          "reads: FEE n+1, DEPOSIT / RELEASE n+2");
    return 0;
}

int main(void) {
    if (test_ops() != 0) return 1;
    if (test_refusals() != 0) return 1;
    if (test_access_cursor() != 0) return 1;
    if (test_evmfund() != 0) return 1;
    printf("test_evm_call_wire: %d checks passed\n", g_checks);
    return 0;
}
