/**
 * @file shared/dnac/evm_call_wire.h
 * @brief Nodus EVM — the call bytes of an EVM leg (runtime ops 1-5) and of its
 *        paired CORE EVMFUND leg (CORE op 9): encode + strict decode.
 *
 * Design: docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3 §2
 * ("İşlem şekilleri ve kanonik kodlama"). Decisions:
 * docs/plans/decisions/2026-10-04-nodus-evm-kurultay-k1.md (operator decisions
 * 1, 3, 4: CORE-funded ceiling fee, q = 10^10, explicit 64-byte withdraw
 * recipient + contract tickets), 2026-10-04-nodus-evm-kurultay-k2-summary.md.
 *
 * ── THE EVM LEG (domain 2) — every integer BIG-ENDIAN, exact length ────
 *   CALL     (op 1)  ver u8 = 1 ‖ to[32] ‖ value_wei[32] ‖ gas_limit u64 ‖
 *                    nonce u64 ‖ access ‖ data_len u32 ‖ data
 *   CREATE   (op 2)  ver ‖ value_wei[32] ‖ gas_limit u64 ‖ nonce u64 ‖
 *                    access ‖ initcode_len u32 ‖ initcode
 *                    (initcode_len <= 49 152, EIP-3860)
 *   DEPOSIT  (op 3)  ver ‖ amount_raw u64 ‖ nonce u64            (17 B)
 *   WITHDRAW (op 4)  ver ‖ amount_raw u64 ‖ nonce u64 ‖ dest_fp[64] (81 B)
 *   REDEEM   (op 5)  ver ‖ ticket_id[64] ‖ amount_raw u64 ‖ dest_fp[64]
 *                                                               (137 B)
 *   access = n_acc u16 ‖ n_acc × (addr[32] ‖ n_keys u16 ‖ n_keys × key[32])
 *   (repeats are allowed, as in Prague — design §2).
 *
 * ── ONE CODEC (Nodus EVM Faz 4) ────────────────────────────────────────────
 * This file IS the node's decoder, not a restatement of it: the node's
 * call-head decoder (nodus_witness_runtime.c nodus_rt_evm_call_head — the
 * CORE EVMFUND hook, the block gas sum, the conflict keys), the EVM
 * runtime's full decode (nodus_witness_rt_evm.c rtevm_decode) and the CORE
 * EVMFUND parse (nodus_witness_rt_native.c rtn_evmfund_parse) all call the
 * functions below, and the wallet (send.wasm) and nodus-cli build with
 * them — so a client and the node cannot disagree about these bytes. The
 * node pins every constant restated here against its own with
 * _Static_assert (nodus_witness_runtime.c, nodus_witness_rt_native.c).
 *
 * ── THE CORE EVMFUND LEG (CORE op 9) ──────────────────────────────────
 *   ver u8 = 1 ‖ role u8 ‖ in_count u8 (1..15) ‖ in_count × nullifier[64]
 *   (strictly ascending) ‖ out_count u8 (0..16) ‖ out_count × output[232]
 *   output = owner_fp hex[128, lowercase] ‖ amount u64 (> 0) ‖ token[64]
 *   (all zero: native) ‖ seed[32]
 * EXACT length. Amount and recipient are NEVER here: they are the sibling
 * EVM leg's call bytes (design §2, the SYSFUND discipline).
 * Resolved against the node (F3-C2, rtn_evmfund_parse +
 * rtn_xfer_section_parse with RTN_SPEND_MAX_IN 15 / RTN_SPEND_MAX_OUT 16 /
 * min_out 0): roles FEE 1 / DEPOSIT 2 / RELEASE 3 (NODUS_RT_EVMFUND_ROLE_*),
 * ver 1, the transfer section of SPEND with 0..16 NATIVE change outputs
 * (the wallet's former 0..1 bound was this file's provisional choice and
 * is gone). The funding leg READS in_count + 1 keys (the inputs and the
 * reward pool) for FEE and in_count + 2 for DEPOSIT / RELEASE (+ the CORE
 * EVM reserve) — nodus_rt_core_read_plan; dna_evmfund_reads below.
 *
 * ── PURITY ───────────────────────────────────────────────────────────
 * No allocation, no clock, no RNG, no nodus header (the ledger_ids.h rule).
 * Decoders BORROW the caller's buffer (pointers into it, nothing copied).
 * Every reject returns -1 and leaves *out zeroed / *written_out 0.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNA_EVM_CALL_WIRE_H
#define DNA_EVM_CALL_WIRE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── the EVM leg ───────────────────────────────────────────────────── */

/** The one call-bytes version (design §2 `ver`). */
#define DNA_EVM_CALL_VER          1u

/** Runtime ops of the EVM domain (design §2). */
#define DNA_EVM_OP_CALL           1u
#define DNA_EVM_OP_CREATE         2u
#define DNA_EVM_OP_DEPOSIT        3u
#define DNA_EVM_OP_WITHDRAW       4u
#define DNA_EVM_OP_REDEEM         5u

#define DNA_EVM_ADDR_LEN          32u   /* a Nodus EVM address           */
#define DNA_EVM_WORD_LEN          32u   /* value_wei, access-list key    */
#define DNA_EVM_FP_LEN            64u   /* a Nodus fingerprint (raw)     */
#define DNA_EVM_TICKET_ID_LEN     64u

/** EIP-3860 initcode cap (shared/evm/evm.h EVM_MAX_INITCODE_SIZE). */
#define DNA_EVM_MAX_INITCODE      49152u

/** Exact lengths of the bridge ops. */
#define DNA_EVM_DEPOSIT_CALL_LEN  17u   /* 1 + 8 + 8                     */
#define DNA_EVM_WITHDRAW_CALL_LEN 81u   /* 1 + 8 + 8 + 64                */
#define DNA_EVM_REDEEM_CALL_LEN   137u  /* 1 + 64 + 8 + 64               */

/** Wei per raw unit (operator decision k1 #3: 1 raw unit = 10^10 wei). */
#define DNA_EVM_Q                 10000000000ull

/**
 * One EVM leg's call, native form. Which fields are meaningful depends on
 * `op` (the others are zero after decode and ignored by encode):
 *   CALL      to, value_wei, gas_limit, nonce, access, data
 *   CREATE    value_wei, gas_limit, nonce, access, data (= initcode)
 *   DEPOSIT   amount_raw, nonce
 *   WITHDRAW  amount_raw, nonce, dest_fp
 *   REDEEM    ticket_id, amount_raw, dest_fp
 * `access` is the access list's wire BODY (the bytes after its u16 count):
 * n_access × (addr[32] ‖ n_keys u16 ‖ n_keys × key[32]), `access_len`
 * bytes; dna_evm_access_next steps through it. A NULL pointer is allowed
 * only with a zero length.
 */
typedef struct {
    uint32_t       op;
    uint8_t        to[DNA_EVM_ADDR_LEN];
    uint8_t        value_wei[DNA_EVM_WORD_LEN];
    uint64_t       gas_limit;
    uint64_t       nonce;
    uint16_t       n_access;
    uint64_t       n_access_keys;      /* decode output: Σ n_keys          */
    const uint8_t *access;
    size_t         access_len;
    const uint8_t *data;
    uint32_t       data_len;
    uint64_t       amount_raw;
    uint8_t        dest_fp[DNA_EVM_FP_LEN];
    uint8_t        ticket_id[DNA_EVM_TICKET_ID_LEN];
} dna_evm_call_t;

/**
 * Walk an access-list body of `n_access` entries at the front of `body`
 * (at most `avail` bytes). Strict: every n_keys is bounded by the bytes
 * that remain. @param used_out bytes the body occupies; @param keys_out
 * Σ n_keys (either may be NULL). @return 0 / -1.
 */
int dna_evm_access_walk(const uint8_t *body, size_t avail, uint16_t n_access,
                        size_t *used_out, uint64_t *keys_out);

/**
 * ONE cursor step over an access-list body of `len` bytes: the entry at
 * body[*off] — its address, key count and keys (n_keys × 32 bytes, NULL
 * when none) — then *off advances past it. Start with *off = 0; a caller
 * visiting n_access entries makes n_access calls, so materializing a list
 * is ONE linear pass (red-team 1 F3). The entry must fit the bytes that
 * remain (the dna_evm_access_walk bound). Pointers borrow `body`.
 * @return 0 / -1 (the outputs are NULL / 0 and *off is unchanged).
 */
int dna_evm_access_next(const uint8_t *body, size_t len, size_t *off,
                        const uint8_t **addr_out, uint16_t *n_keys_out,
                        const uint8_t **keys_out);

/**
 * Append one access-list entry (addr ‖ n_keys u16 ‖ keys) at dst[*off],
 * dst holding `cap` bytes. @return 0 / -1 (no room, NULL with keys).
 */
int dna_evm_access_put(uint8_t *dst, size_t cap, size_t *off,
                       const uint8_t addr[DNA_EVM_ADDR_LEN], uint16_t n_keys,
                       const uint8_t *keys);

/**
 * The FIXED HEAD of an EVM call — what every consumer that does not need
 * the access list or the data reads (the CORE EVMFUND hook: amount and
 * recipient; the block gas sum: the declared gas_limit; the mempool
 * conflict keys: the nonce / the ticket id). CALL / CREATE: `ver` and
 * every field up to and including nonce must be present — the tail (access
 * list, data) is NOT checked here, so a CALL whose tail is malformed still
 * carries its declared gas into the block gas sum (design §8: "a failed or
 * refused item keeps its share"); bridge ops: EXACT length.
 *   CALL     ver ‖ to[32] ‖ value[32] ‖ gas_limit u64 ‖ nonce u64 ‖ …
 *   CREATE   ver ‖ value[32] ‖ gas_limit u64 ‖ nonce u64 ‖ …
 *   DEPOSIT  ver ‖ amount_raw u64 ‖ nonce u64                (exact 17)
 *   WITHDRAW ver ‖ amount_raw u64 ‖ nonce u64 ‖ dest_fp[64]  (exact 81)
 *   REDEEM   ver ‖ ticket_id[64] ‖ amount_raw u64 ‖ dest_fp[64] (exact 137)
 * Pointers borrow `call`.
 */
typedef struct {
    uint32_t       op;
    uint64_t       gas_limit;    /* CALL / CREATE                         */
    uint64_t       nonce;        /* CALL / CREATE / DEPOSIT / WITHDRAW    */
    uint64_t       amount_raw;   /* DEPOSIT / WITHDRAW / REDEEM           */
    const uint8_t *value;        /* CALL / CREATE [32]                    */
    const uint8_t *to;           /* CALL [32]                             */
    const uint8_t *dest_fp;      /* WITHDRAW / REDEEM [64]                */
    const uint8_t *ticket_id;    /* REDEEM [64]                           */
    size_t         rest_off;     /* CALL / CREATE: offset of the access
                                  * list; bridge ops: the call length     */
} dna_evm_head_t;

/** Decode the fixed head (above). *out zeroed first, `op` always set.
 *  @return 0 / -1 malformed (unknown op, wrong ver, short / long). */
int dna_evm_call_head(uint32_t op, const uint8_t *call, size_t len,
                      dna_evm_head_t *out);

/** Exact encoded length of `c` for runtime op `c->op`. @return 0 / -1. */
int dna_evm_call_encoded_size(const dna_evm_call_t *c, size_t *out);

/**
 * Encode `c` (op `c->op`) into dst. Rejects what the decoder rejects
 * (unknown op, a malformed access body, CREATE initcode over the cap, a
 * length that does not fit u32) and dst_cap below the length.
 * @param written_out MANDATORY; 0 on every reject. @return 0 / -1.
 */
int dna_evm_call_encode(const dna_evm_call_t *c, uint8_t *dst, size_t dst_cap,
                        size_t *written_out);

/**
 * Decode the call bytes of runtime op `op` — `ver` first, exact length,
 * trailing bytes reject. *out borrows `src`; zeroed on reject.
 * @return 0 / -1.
 */
int dna_evm_call_decode(uint32_t op, const uint8_t *src, size_t len,
                        dna_evm_call_t *out);

/* ── the CORE EVMFUND leg (the node's layout — see the header block) ── */

/** CORE runtime op of the funding leg (design §1/§2 "CORE op 9";
 *  nodus_witness_runtime.h DNA_CORERULE_EVMFUND). */
#define DNA_EVMFUND_CORE_OP       9u
#define DNA_EVMFUND_VER           1u   /* NODUS_RT_EVMFUND_CALL_VER       */

/** Roles (design §2; nodus_witness_runtime.h NODUS_RT_EVMFUND_ROLE_*). */
#define DNA_EVMFUND_ROLE_FEE      1u   /* CALL / CREATE                  */
#define DNA_EVMFUND_ROLE_DEPOSIT  2u   /* DEPOSIT: amount_raw is locked  */
#define DNA_EVMFUND_ROLE_RELEASE  3u   /* WITHDRAW / REDEEM              */

#define DNA_EVMFUND_MAX_IN        15u  /* RTN_SPEND_MAX_IN                */
#define DNA_EVMFUND_MAX_OUT       16u  /* RTN_SPEND_MAX_OUT (change only) */
#define DNA_EVMFUND_OUT_LEN       232u /* owner128 ‖ amount8 ‖ token64 ‖
                                        * seed32 (RTN_SPEND_OUT_LEN)     */

/** The logical reads the funding leg's read plan requests for `role` with
 *  `n_in` inputs (nodus_rt_core_read_plan): the inputs + the reward pool,
 *  + the CORE EVM reserve for DEPOSIT / RELEASE. 0 for an unknown role. */
uint32_t dna_evmfund_reads(uint8_t role, uint8_t n_in);

typedef struct {
    uint8_t        role;
    uint8_t        n_in;
    const uint8_t *in_nul;    /* n_in × 64, strictly ascending            */
    uint8_t        n_out;
    const uint8_t *outs;      /* n_out × DNA_EVMFUND_OUT_LEN              */
} dna_evmfund_call_t;

/** The role the CORE leg must carry beside EVM op `op`; 0 for none. */
uint8_t dna_evmfund_role_for_op(uint32_t op);

/** Exact encoded length (2 + 1 + 64·n_in + 1 + 232·n_out). @return 0/-1. */
int dna_evmfund_encoded_size(const dna_evmfund_call_t *c, size_t *out);

/**
 * Encode. Rejects a role outside {FEE, DEPOSIT, RELEASE}, n_in outside
 * 1..15, nullifiers not strictly ascending, n_out > 16, and an output that
 * is not lowercase-hex owner ‖ amount > 0 ‖ zero token.
 * @param written_out MANDATORY; 0 on every reject. @return 0 / -1.
 */
int dna_evmfund_encode(const dna_evmfund_call_t *c, uint8_t *dst,
                       size_t dst_cap, size_t *written_out);

/** Strict decode of the same layout; *out borrows `src`, zeroed on reject.
 *  @return 0 / -1. */
int dna_evmfund_decode(const uint8_t *src, size_t len,
                       dna_evmfund_call_t *out);

/* ── the canonical receipt (design §7) ─────────────────────────────────
 *   "NDS.EVMRCPT.v1\0\0" ‖ status u8 (1 success / 0 failure) ‖ op u8 ‖
 *   evm_gas_used u64 ‖ created[32] (a successful CREATE, else zero) ‖
 *   output_len u32 ‖ output ‖ n_logs u32 ‖
 *   n_logs × (addr[32] ‖ n_topics u8 (0..4) ‖ topics ‖ data_len u32 ‖
 *   data) ‖ wei_destroyed[32] ‖ n_tickets u16 ‖ n_tickets × ticket_id[64]
 * The node's encoder is nodus_witness_rt_evm.c rcpt_build; `Data` (the
 * ExecTxResult field) is SHA3-512 of these bytes. This decoder is what the
 * node's evm_receipt RPC and the clients read a stored receipt with. */

#define DNA_EVM_RCPT_TAG_LEN      16u
#define DNA_EVM_RCPT_MAX_TOPICS   4u

/** A decoded receipt; every pointer borrows the source bytes. */
typedef struct {
    uint8_t        status;
    uint8_t        op;
    uint64_t       gas_used;
    const uint8_t *created;        /* 32                                  */
    const uint8_t *output;
    uint32_t       output_len;
    uint32_t       n_logs;
    const uint8_t *logs;           /* the n_logs entries, logs_len bytes  */
    size_t         logs_len;
    const uint8_t *wei_destroyed;  /* 32, big-endian                      */
    uint16_t       n_tickets;
    const uint8_t *tickets;        /* n_tickets × 64                      */
} dna_evm_rcpt_t;

/** Strict decode of a canonical receipt: the tag, status 0/1, every
 *  length bounded by the bytes that remain, n_topics <= 4, EXACT length.
 *  *out zeroed on reject. @return 0 / -1. */
int dna_evm_rcpt_decode(const uint8_t *src, size_t len, dna_evm_rcpt_t *out);

/** One log of a decoded receipt. `*cursor` is the offset into r->logs of
 *  the next entry (start at 0); on success it advances past the entry.
 *  Pointers borrow the receipt bytes. @return 0 / -1 (no further entry or
 *  malformed). */
int dna_evm_rcpt_log_next(const dna_evm_rcpt_t *r, size_t *cursor,
                          const uint8_t **addr_out, uint8_t *n_topics_out,
                          const uint8_t **topics_out,
                          const uint8_t **data_out, uint32_t *data_len_out);

#ifdef __cplusplus
}
#endif

#endif /* DNA_EVM_CALL_WIRE_H */
