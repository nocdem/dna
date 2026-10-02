/**
 * Nodus — Server-side Media Request Handlers
 *
 * Handles media put (chunked upload), get_meta, and get_chunk
 * requests from authenticated clients on the Tier 2 TCP port. DHT side
 * (split S4): called from nodus_dht_client_request with the request's
 * origin slot; replies go back through the DHT host.
 *
 * @file nodus_media_handler.h
 */

#ifndef NODUS_MEDIA_HANDLER_H
#define NODUS_MEDIA_HANDLER_H

#include "dht/nodus_dht.h"
#include "protocol/nodus_tier2.h"

#ifdef __cplusplus
extern "C" {
#endif

/** `client_fp`: the requesting session's authenticated identity (the
 *  media owner on chunk 0). */
void handle_t2_media_put(nodus_dht_t *dht, int slot,
                         const nodus_key_t *client_fp,
                         nodus_tier2_msg_t *msg);
void handle_t2_media_get_meta(nodus_dht_t *dht, int slot,
                              nodus_tier2_msg_t *msg);
void handle_t2_media_get_chunk(nodus_dht_t *dht, int slot,
                               nodus_tier2_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_MEDIA_HANDLER_H */
