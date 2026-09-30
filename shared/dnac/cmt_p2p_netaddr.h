/**
 * @file shared/dnac/cmt_p2p_netaddr.h
 * @brief cometbft @v0.38.26 `p2p/netaddress.go`, `p2p/key.go` (the ID)
 *        and `p2p/errors.go` ported to C — peer addresses `id@ip:port`.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F3 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md §2
 * row "netaddress.go, key.go, errors.go", §9). Consumers: the NodeInfo,
 * peer, transport and switch of the same phase; nothing in the running
 * node constructs one yet. Additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── THE ID (key.go:34-44) ──────────────────────────────────────────────
 * `ID` is the lowercase hex of `pubKey.Address()` (`PubKeyToID`, :44).
 * Here the key is the node's ML-DSA-87 identity key and the address is
 * `cmt_pub_key_address` (cmt_validator_set.c:356 → cmt_address_hash,
 * cmt_tmhash.h: SHA3-512(pk)[0..31]) — so `IDByteLength` (:14,
 * `crypto.AddressSize`) is 32 here, not 20, and an ID is 64 hex digits.
 * That width is the approved substitution already in force for every
 * address in the port (cmt_tmhash.h CMT_TMHASH_TRUNCATED_SIZE); nothing
 * new is chosen.
 *
 * `validateID` (netaddress.go:407-419) accepts upper- AND lowercase hex
 * (`hex.DecodeString`), but IDs are compared as STRINGS everywhere
 * (switch.go:319, :786, transport.go:433, :465): an uppercase ID in a
 * config validates and never matches the lowercase ID a connection
 * yields. Kept as the reference has it.
 *
 * ── IP ADDRESSES (Go `net.IP`) ─────────────────────────────────────────
 * An IP is 16 bytes plus a length (0 = nil, 4 or 16), mirroring
 * `net.IP`: IPv4 is carried in its IPv4-mapped 16-byte form (what
 * `net.ParseIP` returns), `Equal` treats the 4- and 16-byte forms of one
 * IPv4 address as equal (Go 1.21.5 src/net/ip.go:359-370), `String`
 * prints an IPv4-mapped address as a dotted quad (ip.go:295-309) and an
 * IPv6 address per RFC 5952 (netip.go:873-906). Parsing is
 * `netip.ParseAddr` with zones refused (ip.go:494-507, netip.go:114-333).
 * Go sources read: the local toolchain Go 1.21.5 (/usr/local/go/src);
 * the reference's go.mod names go 1.22.11 — the Go standard library is
 * not in the pinned tarball.
 *
 * ── DEVIATIONS ─────────────────────────────────────────────────────────
 *   R-P2P-24 (proposed) NO NAME RESOLUTION. `NewNetAddressString`
 *            resolves a host name with `net.LookupIP` (:95-102) and
 *            `NewNetAddress` accepts a resolved `net.Addr`; shared/dnac is
 *            socket-free, so a host that is not an IP literal is refused
 *            with CMT_P2P_ERR_NETADDR_LOOKUP — the very error
 *            `DialPeersAsync` / `AddPersistentPeers` already skip
 *            (switch.go:488, :591). Consequence: `persistent_peers` and a
 *            NodeInfo `listen_addr` must be IP literals.
 *   `NewNetAddress` panics on an invalid ID (:55-57) and on a non-TCP
 *   address (:44-53): here CMT_FAULT (R-P2P-21's rule for panics).
 *   (F4) `NetAddressFromProto` (:139-153) copies ANY string into the ID;
 *   an ID here has fixed storage (CMT_P2P_ID_CAP), so a wire ID longer
 *   than CMT_P2P_ID_HEX_LEN is replaced by CMT_P2P_NETADDR_OVERLONG_ID,
 *   which `validateID` refuses exactly as it refuses the long original —
 *   the address stays constructible and fails `Valid()` later, where the
 *   reference's does (addrbook.go:649-651).
 * NOT ported: `Dial` / `DialTimeout` (:234-250 — the host's sockets,
 * cmt_p2p_transport.h), `MakePoWTarget` and the node-key file functions
 * (key.go:62-117 — the node key is the existing nodus identity). The
 * proto conversions (:139-186) are ported below (phase F4, for PEX).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Pure functions of their inputs; no clock, no randomness, nothing here
 * is consensus state (p2p-port design §6 D1).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_P2P_NETADDR_H
#define CMT_P2P_NETADDR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"                    /* CMT_OK / CMT_REJECT / CMT_FAULT */
#include "crypto/sign/qgp_dilithium.h"     /* QGP_DSA87_PUBLICKEYBYTES        */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ errors.go — one code per reference error type / flag ═════════════ */

/**
 * The reference's error TYPES (errors.go) as one enum. 0 = nil. Positive,
 * so they never collide with CMT_FAULT (-2), which the functions of this
 * layer keep for a NULL argument or an allocation failure.
 * `ErrRejected` (:17-28) carries one of six flags; each is its own code.
 */
typedef enum {
    CMT_P2P_ERR_NONE                        = 0,
    CMT_P2P_ERR_FILTER_TIMEOUT              = 1,   /* :8-13   (never raised: R-P2P-25) */
    CMT_P2P_ERR_REJECTED_AUTH_FAILURE       = 2,   /* :22 isAuthFailure     */
    CMT_P2P_ERR_REJECTED_DUPLICATE          = 3,   /* :23 isDuplicate       */
    CMT_P2P_ERR_REJECTED_FILTERED           = 4,   /* :24 isFiltered        */
    CMT_P2P_ERR_REJECTED_INCOMPATIBLE       = 5,   /* :25 isIncompatible    */
    CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID  = 6,   /* :26 isNodeInfoInvalid */
    CMT_P2P_ERR_REJECTED_SELF               = 7,   /* :27 isSelf            */
    CMT_P2P_ERR_SWITCH_DUPLICATE_PEER_ID    = 8,   /* :99-107   */
    CMT_P2P_ERR_SWITCH_DUPLICATE_PEER_IP    = 9,   /* :109-117  */
    CMT_P2P_ERR_SWITCH_CONNECT_TO_SELF      = 10,  /* :119-126  */
    CMT_P2P_ERR_SWITCH_AUTH_FAILURE         = 11,  /* :128-139  */
    CMT_P2P_ERR_TRANSPORT_CLOSED            = 12,  /* :141-146  */
    CMT_P2P_ERR_PEER_REMOVAL                = 13,  /* :148-153  */
    CMT_P2P_ERR_NETADDR_NO_ID               = 14,  /* :157-163  */
    CMT_P2P_ERR_NETADDR_INVALID             = 15,  /* :165-172  */
    CMT_P2P_ERR_NETADDR_LOOKUP              = 16,  /* :174-181  */
    CMT_P2P_ERR_CURRENTLY_DIALING_OR_EXISTING = 17, /* :183-191 */
    /** A plain `error` with no type of its own in the reference: the dial
     *  itself failed or timed out (`net.DialTimeout`, transport.go:216),
     *  or the socket failed under a connection being upgraded. */
    CMT_P2P_ERR_NET                         = 18,
    /** `ErrRejected{isAuthFailure}` whose cause is the handshake deadline
     *  (transport.go:546, :588 SetDeadline → an i/o timeout inside
     *  MakeSecretConnection / handshake). Split out of AUTH_FAILURE so a
     *  test and a log can tell the two apart; every caller treats it as
     *  AUTH_FAILURE (`cmt_p2p_err_is_rejected`). */
    CMT_P2P_ERR_REJECTED_TIMEOUT            = 19,
    /** The switch is not running / the peer failed to start. */
    CMT_P2P_ERR_NOT_RUNNING                 = 20,
    /** The inbound listener limit is reached. The reference never returns
     *  this — its LimitListener blocks Accept instead (transport.go:261-
     *  263); here it is the answer to a host that accepted anyway. */
    CMT_P2P_ERR_LIMIT                       = 21,
    /** The host's handshake job queue refused a job (R-P2P-8, §2R4 P3). */
    CMT_P2P_ERR_BUSY                        = 22
} cmt_p2p_err_t;

/** True for every `ErrRejected` flag (errors.go:17-28). */
bool cmt_p2p_err_is_rejected(int err);

/** A static description (for logs). Never NULL. */
const char *cmt_p2p_err_str(int err);

/* ══ key.go — the ID ══════════════════════════════════════════════════ */

/** key.go:14 `IDByteLength = crypto.AddressSize` — 32 here (file header). */
#define CMT_P2P_ID_BYTE_LENGTH  CMT_TMHASH_TRUNCATED_SIZE
/** Hex digits of a valid ID. */
#define CMT_P2P_ID_HEX_LEN      (2 * CMT_P2P_ID_BYTE_LENGTH)
/** Storage for an ID string plus its NUL. */
#define CMT_P2P_ID_CAP          (CMT_P2P_ID_HEX_LEN + 1)

#define CMT_P2P_NODE_PK_SIZE    QGP_DSA87_PUBLICKEYBYTES   /* 2592 */

/** key.go:44 `PubKeyToID` — lowercase hex of the key's address.
 *  @return CMT_OK; CMT_FAULT on NULL or a hash backend failure. */
int cmt_p2p_pubkey_to_id(const uint8_t pk[CMT_P2P_NODE_PK_SIZE],
                         char out[CMT_P2P_ID_CAP]);

/** netaddress.go:407-419 `validateID`: non-empty, hex (either case), and
 *  exactly CMT_P2P_ID_BYTE_LENGTH bytes once decoded.
 *  @return CMT_P2P_ERR_NONE or CMT_P2P_ERR_NETADDR_INVALID. */
int cmt_p2p_validate_id(const char *id, size_t len);

/* ══ Go net.IP ════════════════════════════════════════════════════════ */

#define CMT_P2P_IPV4_LEN 4
#define CMT_P2P_IPV6_LEN 16
/** Longest `net.IP.String` (ip.go:295): "ffff:…:ffff" = 39. */
#define CMT_P2P_IP_STR_MAX 48

/** A Go `net.IP`: `len` 0 (nil), 4 or 16 bytes of `b`. */
typedef struct {
    uint8_t b[CMT_P2P_IPV6_LEN];
    uint8_t len;
} cmt_p2p_ip_t;

/** ip.go:494-507 `ParseIP` (netip.ParseAddr, zones refused): the 16-byte
 *  form. @return true on success. */
bool cmt_p2p_ip_parse(const char *s, size_t len, cmt_p2p_ip_t *out);

/** ip.go:47-56 `IPv4(a,b,c,d)` — the 16-byte IPv4-mapped form. */
cmt_p2p_ip_t cmt_p2p_ip_v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

/** ip.go:212-224 `To4`: true and the 4 bytes when `ip` is IPv4. */
bool cmt_p2p_ip_to4(const cmt_p2p_ip_t *ip, uint8_t out4[4]);

/** ip.go:359-370 `Equal`. */
bool cmt_p2p_ip_equal(const cmt_p2p_ip_t *a, const cmt_p2p_ip_t *b);

/** ip.go:120-122 `IsUnspecified`. */
bool cmt_p2p_ip_is_unspecified(const cmt_p2p_ip_t *ip);

/** ip.go:125-130 `IsLoopback`. */
bool cmt_p2p_ip_is_loopback(const cmt_p2p_ip_t *ip);

/** ip.go:295-309 `String` ("<nil>" for a nil IP).
 *  @return the length written (NUL-terminated), 0 if `cap` is too small. */
size_t cmt_p2p_ip_string(const cmt_p2p_ip_t *ip, char *out, size_t cap);

/* ══ Go net.SplitHostPort / JoinHostPort (ipsock.go:164-243) ══════════ */

/** ipsock.go:164-219. On success `*host` / `*port` point into `s`.
 *  @return true on success. */
bool cmt_p2p_split_host_port(const char *s, size_t len,
                             const char **host, size_t *host_len,
                             const char **port, size_t *port_len);

/* ══ netaddress.go — NetAddress ═══════════════════════════════════════ */

/** Longest `String()`: 64 + "@" + "[" + 39 + "]:" + 5 = 112. */
#define CMT_P2P_NETADDR_STR_MAX 128

/** netaddress.go:25-29. `id[0] == 0` is the reference's empty ID. */
typedef struct {
    char         id[CMT_P2P_ID_CAP];
    cmt_p2p_ip_t ip;
    uint16_t     port;
} cmt_p2p_netaddr_t;

/** netaddress.go:21 `EmptyNetAddress`. */
#define CMT_P2P_EMPTY_NET_ADDRESS "<nil-NetAddress>"

/** netaddress.go:33-36 `IDAddressString(id, protocolHostPort)` —
 *  "id@hostPort", the protocol prefix removed (:399-405).
 *  @return the length written (NUL-terminated), 0 if `cap` is too small. */
size_t cmt_p2p_id_address_string(const char *id, const char *proto_host_port,
                                 size_t proto_host_port_len,
                                 char *out, size_t cap);

/**
 * netaddress.go:43-64 `NewNetAddress(id, tcpAddr)`: the connection's
 * remote IP and port, with `id`.
 * @return CMT_OK; CMT_FAULT on NULL or an invalid ID (the reference
 *         panics, :55-57).
 */
int cmt_p2p_netaddr_new(const char *id, const cmt_p2p_ip_t *ip, uint16_t port,
                        cmt_p2p_netaddr_t *out);

/**
 * netaddress.go:70-112 `NewNetAddressString("id@ip:port")`, protocol
 * prefix allowed.
 * @return CMT_P2P_ERR_NONE; CMT_P2P_ERR_NETADDR_NO_ID (:73-75);
 *         CMT_P2P_ERR_NETADDR_INVALID (bad ID :78-80, host:port :85-93,
 *         port :104-107); CMT_P2P_ERR_NETADDR_LOOKUP (not an IP literal —
 *         R-P2P-24); CMT_FAULT on NULL.
 */
int cmt_p2p_netaddr_new_string(const char *s, size_t len,
                               cmt_p2p_netaddr_t *out);

/** netaddress.go:132-137 `NewNetAddressIPPort` (no ID). */
cmt_p2p_netaddr_t cmt_p2p_netaddr_new_ip_port(const cmt_p2p_ip_t *ip,
                                              uint16_t port);

/* ══ netaddress.go:139-186 — the proto conversions (phase F4) ═════════ */

/** proto/tendermint/p2p/types.proto:8-12 `NetAddress` — the generated
 *  struct's three fields, the strings as (pointer, length) into the
 *  buffer they were read from (or into the caller's buffers when
 *  produced by `cmt_p2p_netaddr_to_proto`). */
typedef struct {
    const uint8_t *id;       /* field 1, string */
    size_t         id_len;
    const uint8_t *ip;       /* field 2, string */
    size_t         ip_len;
    uint32_t       port;     /* field 3, uint32 */
} cmt_p2p_netaddr_pb_t;

/** The largest `NetAddress` message ToProto can produce: ID (64 hex) +
 *  IP string (≤ CMT_P2P_IP_STR_MAX) + port (≤ 65535, 3 varint bytes),
 *  with their tags and length prefixes. */
#define CMT_P2P_NETADDR_PROTO_MAX \
    (1 + 1 + CMT_P2P_ID_HEX_LEN + 1 + 1 + CMT_P2P_IP_STR_MAX + 1 + 3)

/** The ID a wire ID longer than CMT_P2P_ID_HEX_LEN becomes (file header):
 *  not hex, so `cmt_p2p_validate_id` refuses it. */
#define CMT_P2P_NETADDR_OVERLONG_ID "x"

/**
 * types.pb.go `NetAddress.Unmarshal`: the tag loop (fields 1-3, unknown
 * fields skipped, a repeated field's last value wins, a varint port is
 * truncated to uint32 as `m.Port |= uint32(b&0x7F) << shift` does).
 * @return CMT_OK; CMT_REJECT (malformed); CMT_FAULT on NULL.
 */
int cmt_p2p_netaddr_pb_unmarshal(const uint8_t *in, size_t len,
                                 cmt_p2p_netaddr_pb_t *pb);

/**
 * types.pb.go:357-382 `NetAddress.MarshalToSizedBuffer` (every field
 * omitted when empty / zero).
 * @return CMT_OK; CMT_REJECT (`cap` too small); CMT_FAULT on NULL.
 */
int cmt_p2p_netaddr_pb_marshal(const cmt_p2p_netaddr_pb_t *pb, uint8_t *out,
                               size_t cap, size_t *out_len);

/**
 * netaddress.go:139-153 `NetAddressFromProto`: `net.ParseIP(pb.IP)`, a
 * port < 1<<16, the ID copied as-is (an over-long one → the file header's
 * sentinel). The ID is NOT validated here (the reference does not either).
 * @return CMT_P2P_ERR_NONE; CMT_P2P_ERR_NETADDR_INVALID for the two
 *         reference `fmt.Errorf`s (bad IP :141-143, port :144-146);
 *         CMT_FAULT on NULL.
 */
int cmt_p2p_netaddr_from_proto(const cmt_p2p_netaddr_pb_t *pb,
                               cmt_p2p_netaddr_t *out);

/** netaddress.go:155-165 `NetAddressesFromProto` — the first error stops
 *  it (nothing is returned then). */
int cmt_p2p_netaddrs_from_proto(const cmt_p2p_netaddr_pb_t *pbs, int n,
                                cmt_p2p_netaddr_t *out);

/** netaddress.go:177-186 `ToProto` — ID, `IP.String()` (written into
 *  `ip_buf`, which `pb->ip` then points into), port.
 *  @return CMT_OK; CMT_FAULT on NULL. */
int cmt_p2p_netaddr_to_proto(const cmt_p2p_netaddr_t *na,
                             char ip_buf[CMT_P2P_IP_STR_MAX],
                             cmt_p2p_netaddr_pb_t *pb);

/** netaddress.go:167-175 `NetAddressesToProto` — NULL entries skipped.
 *  `ip_bufs` holds one IP string per entry.
 *  @return the number of entries written to `pbs`. */
int cmt_p2p_netaddrs_to_proto(const cmt_p2p_netaddr_t *const *nas, int n,
                              char (*ip_bufs)[CMT_P2P_IP_STR_MAX],
                              cmt_p2p_netaddr_pb_t *pbs);

/** netaddress.go:211-222 `String` — "id@ip:port" ("ip:port" without an
 *  ID; EmptyNetAddress for NULL). @return length, 0 if `cap` too small. */
size_t cmt_p2p_netaddr_string(const cmt_p2p_netaddr_t *na, char *out,
                              size_t cap);

/** netaddress.go:224-232 `DialString` — "ip:port" / "[ip6]:port". */
size_t cmt_p2p_netaddr_dial_string(const cmt_p2p_netaddr_t *na, char *out,
                                   size_t cap);

/** netaddress.go:190-195 `Equals` — the two `String()`s are equal. */
bool cmt_p2p_netaddr_equals(const cmt_p2p_netaddr_t *a,
                            const cmt_p2p_netaddr_t *b);

/** netaddress.go:198-208 `Same` — same DialString, or the same non-empty
 *  ID. */
bool cmt_p2p_netaddr_same(const cmt_p2p_netaddr_t *a,
                          const cmt_p2p_netaddr_t *b);

/** netaddress.go:263-275 `Valid`.
 *  @return CMT_P2P_ERR_NONE or CMT_P2P_ERR_NETADDR_INVALID. */
int cmt_p2p_netaddr_valid(const cmt_p2p_netaddr_t *na);

/** netaddress.go:253-259 `Routable`. */
bool cmt_p2p_netaddr_routable(const cmt_p2p_netaddr_t *na);

/** netaddress.go:278-281 `HasID`. */
bool cmt_p2p_netaddr_has_id(const cmt_p2p_netaddr_t *na);

/** netaddress.go:284-286 `Local` — loopback or 0.0.0.0/8. */
bool cmt_p2p_netaddr_local(const cmt_p2p_netaddr_t *na);

/** netaddress.go:289-336 `ReachabilityTo` (the address book's, F4). */
int cmt_p2p_netaddr_reachability_to(const cmt_p2p_netaddr_t *na,
                                    const cmt_p2p_netaddr_t *o);

/* netaddress.go:338-397 — the special ranges. */
bool cmt_p2p_netaddr_rfc1918(const cmt_p2p_netaddr_t *na);
bool cmt_p2p_netaddr_rfc3849(const cmt_p2p_netaddr_t *na);
bool cmt_p2p_netaddr_rfc3927(const cmt_p2p_netaddr_t *na);
bool cmt_p2p_netaddr_rfc3964(const cmt_p2p_netaddr_t *na);
bool cmt_p2p_netaddr_rfc4193(const cmt_p2p_netaddr_t *na);
bool cmt_p2p_netaddr_rfc4380(const cmt_p2p_netaddr_t *na);
bool cmt_p2p_netaddr_rfc4843(const cmt_p2p_netaddr_t *na);
bool cmt_p2p_netaddr_rfc4862(const cmt_p2p_netaddr_t *na);
bool cmt_p2p_netaddr_rfc6052(const cmt_p2p_netaddr_t *na);
bool cmt_p2p_netaddr_rfc6145(const cmt_p2p_netaddr_t *na);
bool cmt_p2p_netaddr_onion_cat_tor(const cmt_p2p_netaddr_t *na);

#ifdef __cplusplus
}
#endif

#endif /* CMT_P2P_NETADDR_H */
