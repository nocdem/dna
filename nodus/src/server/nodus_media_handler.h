/**
 * Nodus — Server-side Media Request Handlers
 *
 * Handles media put (chunked upload), get_meta, and get_chunk
 * requests from authenticated clients on the Tier 2 TCP port.
 *
 * @file nodus_media_handler.h
 */

#ifndef NODUS_MEDIA_HANDLER_H
#define NODUS_MEDIA_HANDLER_H

#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"

#ifdef __cplusplus
extern "C" {
#endif

void handle_t2_media_put(nodus_server_t *srv, nodus_session_t *sess,
                         nodus_tier2_msg_t *msg);
void handle_t2_media_get_meta(nodus_server_t *srv, nodus_session_t *sess,
                              nodus_tier2_msg_t *msg);
void handle_t2_media_get_chunk(nodus_server_t *srv, nodus_session_t *sess,
                               nodus_tier2_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_MEDIA_HANDLER_H */
