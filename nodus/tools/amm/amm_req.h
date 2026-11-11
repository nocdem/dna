/**
 * @file amm_req.h
 * @brief nodus-amm: parse and verify the user's signed requests; refuse a
 *        reused request number (plan component row `amm_req`).
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 8)
 * section 6 (6.1 USDT -> NODUS typed request, 6.2 Nodus-key requests, 6.4.1 -
 * 6.4.4 and 6.4.6 the exact texts), section 22 question 12 (first choices);
 * givens items 13, 16, 30, 57, 71 (the user-signed texts of 6.4, first
 * choices, are agreed: operator 2026-11-10 "1 ok"), 72, 73, 77.
 *
 * FOUR KINDS
 *   USDT -> NODUS      EIP-712 v4 typed data, the user's Ethereum key
 *                      (6.4.3): UsdtToNodusRequest, domain
 *                      EIP712Domain(string name,uint256 chainId), `name` =
 *                      the setting eip712_name, `chainId` = the setting
 *                      eth_chain_id.
 *   NODUS -> USDT      plain text, the user's Nodus key (6.4.4).
 *   liquidity add      two halves, both before any payment (6.4.6): the
 *                      Ethereum half is the typed LiquidityAddRequest with
 *                      the same domain, the Nodus half a plain text; they
 *                      must name the same two addresses, the same two raw
 *                      amounts and the same request number.
 *   liquidity withdraw plain text, the Nodus key only (6.4.6).
 *
 * WHAT THE CALLER GIVES. DECODED FIELDS, not JSON: the typed kinds take the
 * message fields as the C strings of 6.4.3 (`sender` as "0x" + 40 lowercase
 * hex, `destination` as 128 lowercase hex, the three numbers as decimal
 * strings) and the 65-byte signature; the text kinds take the exact text
 * bytes, the 2592-byte public key and the 4627-byte signature. Reading the
 * `0x`-hex JSON body of 6.4.7 into these is amm_http's work (DEFERRED with
 * the paths and answer encodings).
 *
 * EVERY REFUSAL IS A CODE, never a partial result: on a non-zero return the
 * output struct must not be used. The refusal WORDS the site shows are
 * DEFERRED (plan 6.4.7).
 *
 * ORDER OF CHECKS (cheapest and least trusting first; the journal is read
 * last, so only an authentic request reaches it):
 *   1. format: every byte rule of 6.4.2 / 6.4.3  -> AMM_REQ_FORMAT
 *   2. text kinds: `Chain ID` line equals the node's chain id -> AMM_REQ_CHAIN
 *   3. text kinds: the Nodus address in the text equals SHA3-512(public key)
 *      (plan 6.2; nodus-site-verify-wasm.c:22-28) -> AMM_REQ_ADDRESS
 *   4. signature: typed kinds recover the signer and refuse unless it
 *      equals the Ethereum address in the message; text kinds verify with
 *      nodus_verify_site_message over the setting expected_origin
 *      -> AMM_REQ_SIGNATURE
 *   5. liquidity add: the two halves agree -> AMM_REQ_PAIR
 *   6. the request number was not accepted before from the same address
 *      (journal store, plan 6.1) -> AMM_REQ_REUSED
 *
 * REQUEST NUMBERS. These functions only READ the journal's permanent
 * (sender, request number) store (amm_journal_req_marker_exists), keyed by
 * the signing address in the journal's own form: 40 lowercase hex for an
 * Ethereum address (no "0x"), 128 lowercase hex for a Nodus address. The
 * marker is WRITTEN by amm_journal_approve in the approval transaction, which
 * refuses a reuse again itself (AMM_J_REQ_REUSED), so a race between this
 * check and the write cannot accept a number twice. A liquidity add checks
 * the number under BOTH addresses (6.4.6). Writing the marker of a liquidity
 * operation, and finding the stored position a withdraw names, are journal
 * and engine work, not here.
 */
#ifndef AMM_REQ_H
#define AMM_REQ_H

#include <stddef.h>
#include <stdint.h>

#include "amm_cfg.h"
#include "amm_journal.h"
#include "nodus/nodus_types.h"

/** Longest Nodus-key text at its bounds: liquidity add 574 bytes (plan
 *  6.4.2; NODUS -> USDT 563, withdraw 375). A longer text is not canonical. */
#define AMM_REQ_TEXT_MAX 574

typedef enum {
    AMM_REQ_OK        = 0,
    AMM_REQ_FORMAT    = 1,   /* a byte or value rule of 6.4.2 / 6.4.3 broken   */
    AMM_REQ_CHAIN     = 2,   /* `Chain ID` is not the node's chain id          */
    AMM_REQ_ADDRESS   = 3,   /* Nodus address != SHA3-512(public key)          */
    AMM_REQ_SIGNATURE = 4,   /* not 27/28, r or s out of range, recovery
                              * failed, signer != sender, or the Nodus
                              * signature does not verify over the origin      */
    AMM_REQ_PAIR      = 5,   /* the two halves of a liquidity add differ       */
    AMM_REQ_REUSED    = 6,   /* request number already accepted from this
                              * address                                        */
    AMM_REQ_ERR       = -1   /* bad argument or a journal / crypto fault       */
} amm_req_rc_t;

/* ── building blocks (EIP-712, exposed so the test can compose the
 *    reference's own example by hand; no generic encoder is built) ───────── */

/** keccak256("\x19\x01" || domainSeparator || hashStruct(message))
 *  (eip-712.md:48, :133). @return 0 / -1. */
int amm_req_eip712_digest(const uint8_t domain_separator[32],
                          const uint8_t struct_hash[32], uint8_t out[32]);

/** hashStruct of EIP712Domain(string name,uint256 chainId): keccak256(typeHash
 *  || keccak256(name) || uint256(chain_id)) (eip-712.md:113-125). @return 0 / -1. */
int amm_req_domain_separator(const char *name, uint64_t chain_id, uint8_t out[32]);

/** The signer of `digest`: signature r || s || v, v exactly 27 or 28, r and s
 *  in 1..N-1 (the ecrecover port, shared/evm/evm_precompile.c:154-174,
 *  execution-specs ecrecover.py:49-54); the address is the last 20 bytes of
 *  keccak256 of the 64-byte public key. A high s is accepted, as ecrecover
 *  accepts it; a second encoding of one signature carries the same request
 *  number and is refused as a reuse (plan 6.4.3). @return 0 / -1 (refused). */
int amm_req_eth_recover(const uint8_t digest[32], const uint8_t sig[65],
                        uint8_t addr_out[20]);

/* ── USDT -> NODUS (6.4.3) ─────────────────────────────────────────────── */

typedef struct {
    const char *sender;               /* "0x" + 40 lowercase hex              */
    const char *destination;          /* 128 lowercase hex (a `string`)       */
    const char *amount;               /* decimal, USDT raw, <= 2^64 - 1       */
    const char *minimum_to_receive;   /* decimal, NODUS raw, <= 2^64 - 1      */
    const char *request_number;       /* decimal, <= 2^64 - 1                 */
    uint8_t     signature[65];        /* r || s || v                          */
} amm_req_usdt_in_t;

typedef struct {
    char     sender[41];              /* 40 lowercase hex, no "0x" (journal)  */
    char     destination[129];        /* 128 lowercase hex                    */
    uint64_t amount;                  /* USDT raw                             */
    uint64_t minimum;                 /* NODUS raw                            */
    uint64_t request_number;
    uint8_t  req_no[32];              /* big-endian, as the journal stores it */
} amm_req_usdt_t;

/** The digest the user signs for `r` under the domain (`eip712_name`,
 *  `chain_id`). @return 0 / -1. */
int amm_req_usdt_digest(const char *eip712_name, uint64_t chain_id,
                        const amm_req_usdt_t *r, uint8_t out[32]);

/** Parse, verify, and refuse a reused request number. `j` is the journal.
 *  @return an amm_req_rc_t. */
int amm_req_usdt_verify(const amm_cfg_t *cfg, amm_journal_t *j,
                        const amm_req_usdt_in_t *in, amm_req_usdt_t *out);

/* ── the Nodus-key texts (6.4.4, 6.4.6) ────────────────────────────────── */

typedef struct {
    const uint8_t        *text;       /* the exact signed bytes               */
    size_t                text_len;
    const nodus_pubkey_t *public_key;
    const nodus_sig_t    *signature;
} amm_req_nodus_in_t;

typedef struct {
    char     sender[129];             /* Nodus address, 128 lowercase hex     */
    char     destination[41];         /* 40 lowercase hex, no "0x"            */
    uint64_t amount;                  /* NODUS raw                            */
    uint64_t minimum;                 /* USDT raw                             */
    char     transfer_id[129];        /* wire id of the held NODUS transfer,
                                       * 128 lowercase hex; the journal's
                                       * incoming id is "nodus:" + this       */
    uint64_t request_number;
    uint8_t  req_no[32];
} amm_req_nodus_to_usdt_t;

int amm_req_nodus_to_usdt_verify(const amm_cfg_t *cfg, amm_journal_t *j,
                                 const amm_req_nodus_in_t *in,
                                 amm_req_nodus_to_usdt_t *out);

/* ── liquidity add (6.4.6) ─────────────────────────────────────────────── */

typedef struct {
    const char *ethereum_address;     /* "0x" + 40 lowercase hex              */
    const char *nodus_address;        /* 128 lowercase hex (a `string`)       */
    const char *usdt_amount;          /* decimal, USDT raw                    */
    const char *nodus_amount;         /* decimal, NODUS raw                   */
    const char *request_number;       /* decimal                              */
    uint8_t     signature[65];
} amm_req_liq_eth_in_t;

typedef struct {
    char     ethereum_address[41];    /* 40 lowercase hex, no "0x"            */
    char     nodus_address[129];
    uint64_t usdt_amount;
    uint64_t nodus_amount;
    char     transfer_id[129];        /* from the Nodus half                  */
    uint64_t request_number;
    uint8_t  req_no[32];
} amm_req_liq_add_t;

/** Typed digest of LiquidityAddRequest(address ethereumAddress,string
 *  nodusAddress,uint256 usdtAmount,uint256 nodusAmount,uint256 requestNumber)
 *  under the domain. Uses the address, amount and request-number fields of
 *  `r`. @return 0 / -1. */
int amm_req_liq_add_digest(const char *eip712_name, uint64_t chain_id,
                           const amm_req_liq_add_t *r, uint8_t out[32]);

/** Both halves must verify and agree; the request number is checked under
 *  both addresses. */
int amm_req_liquidity_add_verify(const amm_cfg_t *cfg, amm_journal_t *j,
                                 const amm_req_liq_eth_in_t *eth,
                                 const amm_req_nodus_in_t *nodus,
                                 amm_req_liq_add_t *out);

/* ── liquidity withdraw (6.4.6) ────────────────────────────────────────── */

typedef struct {
    char     ethereum_address[41];    /* 40 lowercase hex, no "0x"            */
    char     nodus_address[129];      /* the signer                           */
    uint32_t basis_points;            /* 1..10000                             */
    uint64_t request_number;
    uint8_t  req_no[32];
} amm_req_liq_withdraw_t;

/** The Nodus key only. Whether the two addresses are a stored position is
 *  the engine's check (plan 6.4.6), not made here. */
int amm_req_liquidity_withdraw_verify(const amm_cfg_t *cfg, amm_journal_t *j,
                                      const amm_req_nodus_in_t *in,
                                      amm_req_liq_withdraw_t *out);

#endif /* AMM_REQ_H */
