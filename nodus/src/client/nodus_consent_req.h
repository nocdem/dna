/**
 * @file nodus/src/client/nodus_consent_req.h
 * @brief The consent REQUEST CODE Nodus Connect shows, and the node config
 *        lookup `nodus-cli consent <code>` needs — parse and read, no I/O
 *        beyond the one config file, no signing.
 *
 * Governing record: docs/plans/decisions/2026-10-14-consent-request-code.md.
 * Connect shows one line,
 *
 *     nodus-consent-v1:<role>:<owner hex128>:<expiry decimal>:<chain hex64>
 *
 * and the node operator runs `sudo nodus-cli consent <code>`. This module
 * turns the code into the four values the EXISTING consent path
 * (nodus-cli cmd_validator_consent → dna_valbind_consent_msg / _sign,
 * shared/dnac/valbind_wire.c) already takes as --owner / --expiry /
 * --chain-id and the storage-or-validator choice. The code is unsigned and
 * never reaches the chain: it only carries parameters to the node owner,
 * who confirms them before anything is signed. The signed consent message,
 * its ctx and the consent text format are NOT touched here.
 *
 * Strict form — anything else is refused with a message:
 *   - the prefix `nodus-consent-v1:` exactly;
 *   - role `storage` (op 3 STORAGE_REGISTER) or `witness` (op 1 STAKE);
 *   - owner exactly 128 lowercase hex chars;
 *   - expiry digits only, no leading zero, not 0, fits uint64;
 *   - chain id exactly 64 lowercase hex chars;
 *   - exactly five ':'-separated fields, no whitespace, nothing after.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_CONSENT_REQ_H
#define NODUS_CONSENT_REQ_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_CONSENT_REQ_PREFIX     "nodus-consent-v1:"
#define NODUS_CONSENT_REQ_OWNER_HEX  128u   /* 64-byte owner fingerprint  */
#define NODUS_CONSENT_REQ_CHAIN_HEX  64u    /* 32-byte chain id           */
#define NODUS_CONSENT_REQ_EXPIRY_MAX 20u    /* digits of UINT64_MAX       */

/* Bound on the node config file nodus_consent_req_read_config reads. */
#define NODUS_CONSENT_REQ_CONFIG_MAX (1024u * 1024u)

typedef struct {
    int      storage;      /* 1: `storage` (op 3); 0: `witness` (op 1) */
    char     owner_hex[NODUS_CONSENT_REQ_OWNER_HEX + 1];
    uint64_t expiry;
    char     expiry_dec[NODUS_CONSENT_REQ_EXPIRY_MAX + 1];
    char     chain_hex[NODUS_CONSENT_REQ_CHAIN_HEX + 1];
} nodus_consent_req_t;

/**
 * Parse a request code.
 *
 * @param code    the code as pasted (NUL-terminated)
 * @param out     filled on success; zeroed on failure
 * @param err     a human-readable refusal on failure (may be NULL)
 * @param errcap  size of err
 * @return 0 on success, -1 on refusal
 */
int nodus_consent_req_parse(const char *code, nodus_consent_req_t *out,
                            char *err, size_t errcap);

/**
 * Read the node's JSON config (the file nodus-core / nodus-storage /
 * nodus-witness start from, default /etc/nodus.conf), at most
 * NODUS_CONSENT_REQ_CONFIG_MAX bytes.
 *
 * "identity_path": a non-empty string, required; refused (not truncated)
 *                  when it does not fit cap.
 * "tcp_port":      an integer 1..65535, optional; when absent *tcp_port is
 *                  left unchanged.
 *
 * Without json-c in the build this always returns -1 ("give -i").
 *
 * @return 0 on success, -1 with a message in err
 */
int nodus_consent_req_read_config(const char *path, char *identity_path,
                                  size_t cap, uint16_t *tcp_port,
                                  char *err, size_t errcap);

/**
 * The confirmation answer: 1 when the line (trailing "\r\n" ignored) is
 * "y" or "yes" in any case, 0 for anything else, including NULL.
 */
int nodus_consent_req_answer_yes(const char *line);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CONSENT_REQ_H */
