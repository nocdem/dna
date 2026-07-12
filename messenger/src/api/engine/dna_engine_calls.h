#ifndef DNA_ENGINE_CALLS_H
#define DNA_ENGINE_CALLS_H

/*
 * DNA Engine — Calls Module (PQ VoIP Faz A: signaling + key agreement)
 *
 * Live-engine glue over the tested headless core (dna_call_crypto/fsm/orch).
 * Owns the orchestrator + a per-call secret keystore (ephemeral Kyber keypair,
 * K_call), drives the handshake, verifies inbound signatures, and sends signed
 * responses over the Seal message channel. Media (audio) is Faz B.
 *
 * All incoming call handling starts at dna_calls_handle_incoming(), invoked by
 * the transport receive branch when a decrypted message body is a call_signal.
 *
 * @file dna_engine_calls.h
 */

#include "dna/dna_engine.h"   /* dna_engine_t, DNA_API */

#ifdef __cplusplus
extern "C" {
#endif

/* Lifecycle — called from dna_engine_create/destroy. Returns opaque ctx. */
void *dna_calls_ctx_create(void);
void  dna_calls_ctx_destroy(void *calls_ctx);

/* Handle a decrypted incoming call-signal body (transport receive branch).
 * sender_fp = authenticated sender fingerprint (128 hex). body = plaintext JSON.
 * Verifies the inner signature, enforces contacts-only for INVITE, drives the
 * orchestrator, and sends any response. Silently ignores malformed/unauth input. */
void dna_calls_handle_incoming(dna_engine_t *engine,
                               const char *sender_fp, const char *body);

/* Public user actions (FFI). Return 0 on success, negative on error. */
DNA_API int dna_engine_call_invite(dna_engine_t *engine, const char *peer_fp);
DNA_API int dna_engine_call_accept(dna_engine_t *engine, const char *call_id_hex);
DNA_API int dna_engine_call_reject(dna_engine_t *engine, const char *call_id_hex);
DNA_API int dna_engine_call_hangup(dna_engine_t *engine, const char *call_id_hex);

#ifdef __cplusplus
}
#endif

#endif /* DNA_ENGINE_CALLS_H */
