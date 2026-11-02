/* Shared 4002 pool. Approved component-split item 28; encrypted-sessions
 * build plan 4.1 e. Every connection uses nodus_inter_session. */
#ifndef NODUS_INTER_DIAL_H
#define NODUS_INTER_DIAL_H
#include "transport/nodus_tcp.h"
#define NODUS_INTER_POOL_IDLE_SEC 180
/* Pinned lookup considers outbound connections only. No dial-side IP rule. */
nodus_tcp_conn_t *nodus_inter_pool_find(nodus_tcp_t *, const char *, uint16_t,
                                        const nodus_key_t *);
nodus_tcp_conn_t *nodus_inter_pool_dial(nodus_tcp_t *, const char *, uint16_t,
                                        const nodus_key_t *);
/* Preframed plaintext is parsed, then queued/sealed by the transport once. */
int nodus_inter_pool_send_framed(nodus_tcp_t *, const char *, uint16_t,
                                 const nodus_key_t *, const uint8_t *, size_t);
void nodus_inter_pool_sweep(nodus_tcp_t *, uint64_t now);
bool nodus_inter_frame_is_replication(const uint8_t *, size_t);
#endif
