/**
 * @file fuzz_wasm_abort_stubs.c
 * @brief Link-only definitions for the messenger wasm32 FUZZ build.
 *
 * TEST CODE ONLY — linked by messenger/tests/fuzz/build_wasm32.sh, never
 * into anything shipped.
 *
 * The files the wasm32 fuzz targets compile unchanged (dna_api.c,
 * dht_offline_queue.c, dht_contact_request.c, dht_contactlist.c) also
 * contain DHT I/O and keyring code the parsers under test never call.
 * wasm-ld refuses a link with undefined symbols, so each of them is
 * defined here with its real prototype (the header is included, so the
 * compiler checks every signature) and a body that aborts. If a fuzz run
 * ever reaches one, the harness is exercising something it was not built
 * for, and the abort says so; nothing returns a made-up result.
 *
 * json-c is NOT stubbed: build_wasm32.sh links the real wasm32 json-c 0.17
 * (web-wallet/scripts/build-jsonc-wasm.sh, the frozen app's tag).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_platform.h"
#include "dht/shared/nodus_ops.h"
#include "dht/shared/dht_dm_outbox.h"

/* ── keyring / platform (dna_api.c: dna_sign_message, dna_key_fingerprint) */

const char *qgp_platform_app_data_dir(void) { abort(); }
int qgp_key_load(const char *path, qgp_key_t **key_out) { abort(); }
void qgp_key_free(qgp_key_t *key) { abort(); }
void qgp_hash_from_bytes(qgp_hash_t *hash, const uint8_t *data, size_t len) { abort(); }
void qgp_hash_to_hex(const qgp_hash_t *hash, char *hex_out, size_t hex_size) { abort(); }

/* ── DHT I/O (dht_offline_queue.c, dht_contact_request.c) ───────────────── */

int nodus_ops_put(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint32_t ttl, uint64_t vid) { abort(); }
int nodus_ops_get(const uint8_t *key, size_t key_len,
                  uint8_t **data_out, size_t *len_out) { abort(); }
int nodus_ops_get_all(const uint8_t *key, size_t key_len,
                      uint8_t ***values_out, size_t **lens_out,
                      size_t *count_out) { abort(); }
size_t nodus_ops_listen(const uint8_t *key, size_t key_len,
                        nodus_ops_listen_cb_t callback,
                        void *user_data,
                        nodus_ops_listen_cleanup_t cleanup) { abort(); }
void nodus_ops_cancel_listen(size_t token) { abort(); }
int dht_dm_queue_message(const char *sender, const char *recipient,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint64_t seq_num, uint32_t ttl_seconds,
                         const uint8_t *salt) { abort(); }
