/**
 * Nodus — WebSocket entry: pure handshake + frame codec (RFC 6455)
 *
 * The browser-facing entry of the client port (decision
 * docs/plans/decisions/2026-09-25-web-wallet-nodus-send-transport.md).
 * A local TLS proxy (Caddy) terminates TLS on 443 and forwards plain ws to
 * a 127.0.0.1-only listening socket owned by the SAME client transport as
 * port 4001 (nodus_tcp.c, `ws_listen_fd`). Once the HTTP Upgrade completes,
 * the WebSocket payload bytes are the ordinary nodus frame stream: they are
 * unmasked and appended to the connection's read buffer, and every outgoing
 * nodus frame is wrapped in one binary WebSocket frame.
 *
 * This module holds NO socket and does NO I/O. It is an incremental state
 * machine over byte buffers so it can be unit-tested and fuzzed on its own;
 * the transport glue in nodus_tcp.c calls it.
 *
 * References (RFC 6455): §1.3 / §4.2.1 / §4.2.2 opening handshake and
 * Sec-WebSocket-Accept, §5.2 base framing, §5.3 client-to-server masking,
 * §5.4 fragmentation, §5.5 control frames, §7.4 status codes.
 *
 * @file nodus_ws.h
 */

#ifndef NODUS_WS_H
#define NODUS_WS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Limits ──────────────────────────────────────────────────────── */

/** Upper bound on the HTTP Upgrade request head (request line + headers +
 *  the terminating empty line). A head that has not ended within this many
 *  bytes is refused without a response. */
#define NODUS_WS_HS_MAX              8192

/** Upgrade requests still in progress per transport. A slow Upgrade holds a
 *  pool slot; this caps how many the proxy can hold at once. */
#define NODUS_WS_MAX_HANDSHAKING     64

/** Seconds from accept (conn->connected_at) within which the Upgrade must
 *  complete; nodus_tcp_ws_sweep() closes the connection afterwards. */
#define NODUS_WS_HANDSHAKE_TIMEOUT_S 10

/** Per real-IP limit among WebSocket connections. Same value as the TCP
 *  client port's CRIT-5 limit, counted SEPARATELY (the decision's "20 + 20"):
 *  WS connections are not counted against TCP and vice versa. */
#define NODUS_WS_MAX_CONNS_PER_IP    20

/** Largest client→server frame payload accepted: one full nodus frame
 *  (header + NODUS_MAX_FRAME_TCP). Larger → close 1009 before any byte of
 *  the payload is buffered. */
#define NODUS_WS_MAX_PAYLOAD  ((uint64_t)NODUS_MAX_FRAME_TCP + NODUS_FRAME_HEADER_SIZE)

/** RFC 6455 §5.5: control frame payloads are at most 125 bytes. */
#define NODUS_WS_CTRL_MAX            125

/** Largest server→client frame header (FIN/opcode + 127 + 8-byte length;
 *  server frames are never masked, §5.1). */
#define NODUS_WS_SERVER_HDR_MAX      10

/** base64(SHA-1) = 28 characters. */
#define NODUS_WS_ACCEPT_LEN          28

#define NODUS_WS_MAX_ORIGINS         8
#define NODUS_WS_ORIGIN_MAX          256

/** Default allowed Origin when the configuration names none. */
#define NODUS_WS_DEFAULT_ORIGIN      "https://wallet.nodusnetwork.io"

/* ── Opcodes (§5.2) and close codes (§7.4.1) ─────────────────────── */

#define NODUS_WS_OP_CONT     0x0
#define NODUS_WS_OP_TEXT     0x1
#define NODUS_WS_OP_BINARY   0x2
#define NODUS_WS_OP_CLOSE    0x8
#define NODUS_WS_OP_PING     0x9
#define NODUS_WS_OP_PONG     0xA

#define NODUS_WS_CLOSE_NORMAL        1000
#define NODUS_WS_CLOSE_PROTOCOL      1002
#define NODUS_WS_CLOSE_UNSUPPORTED   1003
/** 1005 "no status received" is never put on the wire (§7.4.1); here it
 *  means "reply with an EMPTY close body". */
#define NODUS_WS_CLOSE_NO_STATUS     1005
#define NODUS_WS_CLOSE_TOO_BIG       1009
#define NODUS_WS_CLOSE_INTERNAL      1011

/* ── Allowed origins ─────────────────────────────────────────────── */

typedef struct {
    char origin[NODUS_WS_MAX_ORIGINS][NODUS_WS_ORIGIN_MAX];
    int  count;
} nodus_ws_origins_t;

/** Append one origin. -1 when the list is full, the string is empty, too
 *  long, or carries a control character / space. */
int nodus_ws_origins_add(nodus_ws_origins_t *o, const char *origin);

/** Reset to the single default origin (NODUS_WS_DEFAULT_ORIGIN). */
void nodus_ws_origins_default(nodus_ws_origins_t *o);

/* ── Opening handshake (§4.2.1 / §4.2.2) ─────────────────────────── */

#define NODUS_WS_HS_NEED_MORE   0
#define NODUS_WS_HS_OK          1
#define NODUS_WS_HS_REJECT    (-1)

typedef struct {
    /** On REJECT: the HTTP status to answer with (400 / 403 / 426), or 0 to
     *  close without any response (oversized head). */
    int         status;
    /** On REJECT: fixed text naming the failed check, for the log line.
     *  Never contains network input. */
    const char *reason;
    /** On OK: length of the request head including the final CRLF CRLF.
     *  Bytes after it (if any) are already WebSocket frames. */
    size_t      consumed;
    /** On OK: Sec-WebSocket-Accept value, NUL-terminated. */
    char        accept[NODUS_WS_ACCEPT_LEN + 1];
    /** On OK: the client offered the "binary" subprotocol. */
    bool        proto_binary;
    /** On OK: the client's address. From the LAST X-Forwarded-For value when
     *  the socket peer is 127.0.0.1 (the local proxy), the socket peer
     *  address otherwise. Normalised through inet_pton/inet_ntop. */
    char        real_ip[64];
} nodus_ws_hs_result_t;

/**
 * Parse an Upgrade request head from buf[0..len).
 *
 * @param sock_ip   the TCP peer address of the connection (dotted IPv4).
 * @param origins   allowed Origin values (exact byte match).
 * @return NODUS_WS_HS_NEED_MORE (head incomplete, still under the limit),
 *         NODUS_WS_HS_OK, or NODUS_WS_HS_REJECT (res->status/reason set).
 */
int nodus_ws_handshake_parse(const uint8_t *buf, size_t len,
                             const char *sock_ip,
                             const nodus_ws_origins_t *origins,
                             nodus_ws_hs_result_t *res);

/** Write the "101 Switching Protocols" response for an OK result.
 *  Returns the byte count (no NUL counted), 0 if cap is too small. */
size_t nodus_ws_handshake_response(const nodus_ws_hs_result_t *res,
                                   char *out, size_t cap);

/** Write a refusal response for a REJECT status (400/403/426).
 *  Returns the byte count, 0 for status 0 or if cap is too small. */
size_t nodus_ws_reject_response(int status, char *out, size_t cap);

/** Sec-WebSocket-Accept = base64(SHA-1(key || GUID)) (§1.3, §4.2.2).
 *  SHA-1 through OpenSSL libcrypto EVP_sha1. Returns 0 / -1. */
int nodus_ws_accept_key(const char *key, size_t key_len,
                        char out[NODUS_WS_ACCEPT_LEN + 1]);

/**
 * Resolve the client address. If sock_ip is "127.0.0.1" the connection came
 * through the local proxy: xff (the whole X-Forwarded-For value, may be NULL)
 * must be present and its LAST comma-separated element must parse as an
 * IPv4 or IPv6 address; that address is the result. Any other sock_ip is
 * returned as-is and xff is ignored.
 * @return 0 on success, -1 if the proxy header is missing or malformed.
 */
int nodus_ws_real_ip(const char *sock_ip, const char *xff, size_t xff_len,
                     char out[64]);

/* ── Frame parser (client → server, §5.2-§5.5) ───────────────────── */

/** Where the parser delivers what it decoded. */
typedef struct {
    /** Unmasked data payload bytes (binary + continuation frames), in order.
     *  Return non-zero to refuse (e.g. read buffer full) → close 1009. */
    int  (*on_data)(void *ctx, const uint8_t *data, size_t len);
    /** A complete PING frame (payload ≤ 125 bytes). The caller answers with
     *  a PONG carrying the same payload. Non-zero return → close 1011. */
    int  (*on_ping)(void *ctx, const uint8_t *payload, size_t len);
    void *ctx;
} nodus_ws_sink_t;

typedef struct nodus_ws_parser {
    uint8_t     hdr[14];      /* header bytes of the current frame */
    uint8_t     hdr_len;      /* collected so far */
    uint8_t     hdr_need;     /* total header size once known (2 until then) */
    uint8_t     opcode;       /* current frame's opcode */
    bool        fin;
    bool        in_payload;   /* header complete, reading payload */
    bool        in_message;   /* a fragmented binary message is open */
    bool        closed;       /* a close / error was returned — feed no more */
    uint8_t     mask[4];
    uint8_t     mask_pos;
    uint64_t    remaining;    /* payload bytes still to read */
    uint8_t     ctrl[NODUS_WS_CTRL_MAX];
    uint8_t     ctrl_len;
    const char *reason;       /* fixed text of the last close cause */
} nodus_ws_parser_t;

#define NODUS_WS_FEED_OK          0   /* all input consumed, keep going */
#define NODUS_WS_FEED_ERROR       1   /* violation: send close(*code) and drop */
#define NODUS_WS_FEED_PEER_CLOSE  2   /* peer sent close: reply close(*code) and drop */

void nodus_ws_parser_init(nodus_ws_parser_t *p);

/**
 * Feed raw socket bytes. The buffer is unmasked IN PLACE (hence non-const).
 * Partial headers and payloads carry over between calls.
 * @param code  set on ERROR / PEER_CLOSE: the close code to send back
 *              (NODUS_WS_CLOSE_NO_STATUS = empty close body).
 */
int nodus_ws_feed(nodus_ws_parser_t *p, uint8_t *in, size_t len,
                  const nodus_ws_sink_t *sink, uint16_t *code);

/* ── Server → client frames (§5.2; never masked, §5.1) ───────────── */

/** Header size for a FIN=1 unmasked frame carrying payload_len bytes. */
size_t nodus_ws_frame_header_len(uint64_t payload_len);

/** Write a FIN=1 unmasked frame header. Returns its size, 0 if cap is too
 *  small. */
size_t nodus_ws_frame_header(uint8_t opcode, uint64_t payload_len,
                             uint8_t *out, size_t cap);

/** Write a complete close frame (code NODUS_WS_CLOSE_NO_STATUS = empty
 *  body). Returns its size (2 or 4), 0 if cap is too small. */
size_t nodus_ws_close_frame(uint16_t code, uint8_t *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WS_H */
