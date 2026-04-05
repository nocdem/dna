# Nodus Circuit Protocol (VPN Mesh — Faz 1)

**Status:** Faz 1 — foundation only (no onion crypto, no rate limits, auto-accept)
**Introduced:** Nodus v0.10.0
**Scope:** Peer-to-peer circuit relay through the Nodus cluster. Two authenticated
Nodus clients (DNA Connect users) establish a bidirectional stream through one or
two Nodus servers. Foundation for future file transfer, VoIP, and bulk-data
infrastructure.

---

## 1. Overview

A **circuit** is a bidirectional byte stream tunneled between two Nodus clients
(source user and target user) via the Nodus cluster. It reuses the existing
authenticated TCP 4001 (client) and TCP 4002 (inter-node) transports — no new
ports, no new auth.

Circuits are addressed per-session by a 64-bit `cid`. The initiating client
chooses its own `cid`; the remote client receives a server-assigned `cid` in an
inbound push. Each side uses its own `cid` to tag outbound data frames.

**Faz 1 targets:**
- File transfer (chunked over `circ_data`).
- VoIP signalling (control channel only; media in Faz 2).
- General bulk-data tunnelling between authenticated peers.

**Faz 1 is NOT:**
- End-to-end encrypted at the circuit layer (rely on payload-level E2E).
- Onion-routed (no per-hop Kyber wrapping yet).
- Offline-capable (peer offline → immediate error, no queuing).
- Rate-limited per-circuit (no token bucket yet).

---

## 2. Architecture

Routing is chosen automatically by the originating Nodus server from the target
user's presence: `nodus_presence_is_online(dst_fp, &peer_idx)`.

### 2.1 Cross-nodus (3 hops — default)

```
  User1                 Nodus A                 Nodus B                 User2
   │                      │                        │                      │
   │──circ_open(cid=C1,──▶│                        │                      │
   │    fp=User2)         │                        │                      │
   │   (TCP 4001)         │──ri_open(ups=U1,──────▶│                      │
   │                      │    src=User1,dst=User2)│                      │
   │                      │       (TCP 4002)       │──circ_inbound(cid=C2,▶
   │                      │                        │    fp=User1)         │
   │                      │                        │   (TCP 4001)         │
   │                      │◀──ri_open_ok(ups=U1,───│                      │
   │                      │      dns=D1)           │                      │
   │◀──circ_open_ok(C1)───│                        │                      │
   │                      │                        │                      │
   │═══circ_data(C1,d)═══▶│═══ri_data(D1,d)═══════▶│═══circ_data(C2,d)═══▶│
   │◀══circ_data(C1,d)════│◀══ri_data(U1,d)════════│◀══circ_data(C2,d)════│
   │                      │                        │                      │
   │──circ_close(C1)─────▶│──ri_close(D1)─────────▶│──circ_close(C2)─────▶│
```

- `U1` / `D1` live in each node's global inter-node circuit table
  (`nodus_inter_circuit_table_t`).
- `C1` / `C2` live in each user-session's per-session circuit table
  (`nodus_circuit_table_t`).
- Each side addresses the other by **the peer's `cid`**. When Nodus A sends
  `ri_data`, it writes the cid Nodus B expects (`D1`). When Nodus B sends
  `ri_data` back, it writes `U1`.

### 2.2 Same-nodus (2 hops — local bridge)

```
  User1                     Nodus A                     User2
   │                          │                           │
   │──circ_open(cid=C1,──────▶│                           │
   │    fp=User2)             │                           │
   │   (TCP 4001)             │──circ_inbound(cid=C2,────▶│
   │                          │    fp=User1)              │
   │◀──circ_open_ok(C1)───────│   (TCP 4001)              │
   │                          │                           │
   │═══circ_data(C1,d)═══════▶│═══circ_data(C2,d)════════▶│
   │◀══circ_data(C1,d)════════│◀══circ_data(C2,d)═════════│
   │                          │                           │
   │──circ_close(C1)─────────▶│──circ_close(C2)──────────▶│
```

- No inter-node circuit; the server copies frames directly between the two
  TCP 4001 sessions.
- Each session's entry has `is_local_bridge=true`, `bridge_peer_sess`,
  `bridge_peer_cid` pointing at the other user.

---

## 3. Wire Protocol

All circuit messages ride the existing CBOR-framed Nodus wire format:
7-byte header (`magic=0x4E44`, `version=0x01`, `length=u32`) followed by a CBOR
map `{y, t, q, tok?, a}` where `y ∈ {'q','r','e'}`, `t` is a txn-id, `q` is the
method string, `tok` is the 32-byte session token (where required), and `a` is
the method-specific argument map.

### 3.1 Client ↔ Nodus (TCP 4001, Tier 2)

Encoders live in `nodus/src/protocol/nodus_tier2.c`; decoder populates
`nodus_tier2_msg_t::circ_*` fields.

| Method | Dir | Query/Resp | `a` arguments | Notes |
|--------|-----|------------|----------------|-------|
| `circ_open` | C→N | query | `{ cid: u64, fp: bytes(64) }` | `fp` = target peer fingerprint. `cid` = client's own session-unique id. |
| `circ_open_ok` | N→C | response | `{ cid: u64 }` | Echoes client's `cid`. |
| `circ_open_err` | N→C | error | `{ cid: u64, code: int }` | `code` ∈ `NODUS_ERR_{CIRCUIT_LIMIT,PEER_OFFLINE,…}`. |
| `circ_inbound` | N→C | query (push) | `{ cid: u64, fp: bytes(64) }` | `cid` = server-assigned id on target's session. `fp` = originator. Auto-accept in Faz 1. |
| `circ_data` | C↔N | query (no resp) | `{ cid: u64, d: bytes }` | `d` ≤ 64 KiB. Fire-and-forget. |
| `circ_close` | C↔N | query (no resp) | `{ cid: u64 }` | Idempotent. |

Client → Nodus calls require `tok=session_token`. Nodus → Client pushes carry no
token. `circ_data` / `circ_close` are explicitly fire-and-forget — no `_ok`
response frame, the server simply forwards.

### 3.2 Inter-node (TCP 4002)

Inter-node TCP 4002 is already Dilithium5-mutually-authed at connect time. The
circuit messages add no extra signing. Encoders live in the same
`nodus_tier2.c`; decoder populates `nodus_tier2_msg_t::ri_*` fields.

| Method | Dir | Query/Resp | `a` arguments | Notes |
|--------|-----|------------|----------------|-------|
| `ri_open` | A→B | query | `{ ups: u64, src: bytes(64), dst: bytes(64) }` | `ups` = A's upstream circuit id. |
| `ri_open_ok` | B→A | response | `{ ups: u64, dns: u64 }` | `dns` = B's downstream circuit id. |
| `ri_open_err` | B→A | error | `{ ups: u64, code: int }` | Target session missing → `PEER_OFFLINE`. |
| `ri_data` | A↔B | query (no resp) | `{ cid: u64, d: bytes }` | `cid` = the id the *receiver* stored as `our_cid`. |
| `ri_close` | A↔B | query (no resp) | `{ cid: u64 }` | Idempotent. |

---

## 4. State Machines

### 4.1 Same-nodus bridge

```
  (User1 sess)                          (User2 sess)
  ────────────                          ────────────
  IDLE                                  IDLE
    │ circ_open(C1, User2_fp)            │
    ▼                                    │
  ALLOC local_bridge slot C1 ──────────▶ ALLOC local_bridge slot C2
    │                                    │  (bridge_peer_sess = User1 sess,
    │                                    │   bridge_peer_cid = C1)
    │     ◀── circ_inbound(C2, User1_fp)─┤
  OPEN  ◀── circ_open_ok(C1) ────────────┤
    │                                    │
    │ circ_data(C1,d) ───────────────────▶ circ_data(C2,d)  (forwarded)
    │ circ_data(C1,d) ◀──────────────────── circ_data(C2,d) (forwarded)
    │                                    │
    │ circ_close(C1) ─────────────────────▶ circ_close(C2)
  FREED                                  FREED
```

### 4.2 Cross-nodus

Originator side (Nodus A, User1's session):

```
  IDLE
    │ circ_open(C1, User2_fp)
    ▼
  presence lookup → peer_idx=B
    │
    ▼
  ALLOC inter-circuit U1 on A (is_originator=true, pending_open=true,
                               local_sess=User1, local_cid=C1,
                               client_txn_id=txn)
    │
    │ send ri_open(ups=U1, src=User1, dst=User2) on TCP 4002 to B
    ▼
  WAIT_OPEN_OK ──── ri_open_err ─────▶ circ_open_err(C1, code) → FREE U1, C1
    │
    │ ri_open_ok(ups=U1, dns=D1)
    ▼
  RECORD peer_cid=D1, clear pending_open; send circ_open_ok(C1) to User1
    │
  OPEN
    │ circ_data(C1,d)  → ri_data(D1,d) to B
    │ ri_data(U1,d)    → circ_data(C1,d) to User1
    │
    │ circ_close(C1) | ri_close(U1) | session drop
    ▼
  FREE U1, FREE C1
```

Target side (Nodus B, User2's session):

```
  listens on TCP 4002 from A
    │ ri_open(ups=U1, src=User1, dst=User2)
    ▼
  find_session_by_fp(User2) → User2 sess (or NOT_FOUND → ri_open_err PEER_OFFLINE)
    │
    ▼
  ALLOC inter-circuit D1 on B (is_originator=false, peer_cid=U1, peer_conn=A,
                               local_sess=User2, local_cid=C2)
  ALLOC session circuit C2 on User2 sess (inter=D1)
    │
    │ send ri_open_ok(ups=U1, dns=D1) on TCP 4002 to A
    │ send circ_inbound(C2, User1_fp) to User2 on TCP 4001
    ▼
  OPEN
    │ circ_data(C2,d) → ri_data(U1,d) to A
    │ ri_data(D1,d)   → circ_data(C2,d) to User2
    │
    │ circ_close | ri_close | session drop
    ▼
  FREE D1, FREE C2
```

---

## 5. Constants

Declared in `nodus/include/nodus/nodus_types.h`:

| Constant | Value | Meaning |
|----------|-------|---------|
| `NODUS_MAX_CIRCUITS_PER_SESSION` | `16` | Hard cap on concurrent circuits per TCP 4001 session. |
| `NODUS_MAX_CIRCUIT_PAYLOAD` | `65536` (64 KiB) | Max `d` bytes per `circ_data` / `ri_data` frame. |
| `NODUS_INTER_CIRCUITS_MAX` | `256` | Hard cap on concurrent inter-node circuits this server participates in (originator+target combined). |

Client SDK mirror: `NODUS_CLIENT_MAX_CIRCUITS` in `nodus/include/nodus/nodus.h`.

---

## 6. Error Codes

Declared in `nodus/include/nodus/nodus_types.h`:

| Code | Name | Meaning |
|------|------|---------|
| 16 | `NODUS_ERR_CIRCUIT_LIMIT` | Per-session or server-wide circuit table full. |
| 17 | `NODUS_ERR_CIRCUIT_NOT_FOUND` | `cid` does not refer to a live circuit. |
| 18 | `NODUS_ERR_PEER_OFFLINE` | Target peer not connected to any cluster member. |
| 19 | `NODUS_ERR_CIRCUIT_CLOSED` | Peer tore down the circuit (reported on data after close). |

Returned inside `circ_open_err.code` (client-visible) or `ri_open_err.code`
(inter-node only).

---

## 7. Client SDK API

Declared in `nodus/include/nodus/nodus.h`; implemented in
`nodus/src/client/nodus_client.c`.

```c
int  nodus_circuit_open(nodus_client_t *client, const nodus_key_t *peer_fp,
                        nodus_circuit_data_cb  on_data,
                        nodus_circuit_close_cb on_close,
                        void *user,
                        nodus_circuit_handle_t **out);

void nodus_circuit_set_inbound_cb(nodus_client_t *client,
                                  nodus_circuit_inbound_cb cb, void *user);

int  nodus_circuit_attach(nodus_circuit_handle_t *h,
                          nodus_circuit_data_cb  on_data,
                          nodus_circuit_close_cb on_close,
                          void *user);

int  nodus_circuit_send(nodus_circuit_handle_t *h,
                        const uint8_t *data, size_t len);

int  nodus_circuit_close(nodus_circuit_handle_t *h);
```

- `nodus_circuit_open` — allocate a client-side circuit handle, send `circ_open`,
  resolve on `circ_open_ok` / `circ_open_err`.
- `nodus_circuit_set_inbound_cb` — install the process-wide callback invoked when
  an incoming `circ_inbound` arrives; callback receives an unattached handle.
- `nodus_circuit_attach` — bind data/close callbacks to an inbound handle (must
  be called before the first `circ_data` is delivered).
- `nodus_circuit_send` — enqueue a `circ_data` frame (≤ `NODUS_MAX_CIRCUIT_PAYLOAD`).
- `nodus_circuit_close` — send `circ_close` and free the handle.

Handles are statically allocated inside `nodus_client_t::circuits[]`
(`NODUS_CLIENT_MAX_CIRCUITS` slots).

---

## 8. Threat Model & Faz 1 Limitations

Faz 1 is an **infrastructure preview** intended for authenticated clients on a
trusted Nodus cluster. Known limitations:

- **No circuit-layer encryption.** Frames are in cleartext on each hop (TCP 4001
  is cleartext today; TCP 4002 is cleartext but inter-node peers are mutually
  authenticated with Dilithium5). Applications MUST apply payload E2E encryption
  if confidentiality from the Nodus operator is required.
- **No onion encryption.** The originating Nodus server learns
  `(src_fp, dst_fp)`; the target server learns the same. No mixing.
- **Auto-accept.** The target client has no hook to reject a circuit before data
  starts flowing; the only defence is `nodus_circuit_close`.
- **No offline queueing.** If `presence_is_online(dst_fp)` returns false, the
  originator gets `circ_open_err(PEER_OFFLINE)` immediately.
- **Trust cluster membership.** Routing assumes the cluster's
  `nodus_presence_is_online` / inter-node TCP 4002 topology is honest.
- **No rate limits.** A malicious client can saturate `NODUS_MAX_CIRCUITS_PER_SESSION`
  and send 64 KiB frames as fast as the server loop will forward them. Global
  `NODUS_INTER_CIRCUITS_MAX` is the only backstop.
- **No replay/ordering guarantees beyond TCP.** `circ_data` is fire-and-forget;
  delivery order is TCP's, but no per-circuit sequence number is enforced.
- **Peer addressing trusts the fingerprint.** No per-circuit identity handshake
  between User1 and User2 — applications must verify the far-end fingerprint at
  the payload layer.

---

## 9. Faz 2 Roadmap

- **Kyber1024 onion crypto.** Per-hop ML-KEM wrapping so each Nodus server
  learns only its immediate neighbours.
- **3-hop configurable routing.** Client-selectable path through N Nodus
  servers (not just 1 or 2).
- **DNA Connect Flutter integration.** Dart FFI bindings over
  `nodus_circuit_*`, wired into file-transfer and call-signalling UI.
- **Offline-peer queueing.** Short-lived DHT hints so `circ_open` can resolve
  when the target comes online.
- **Accept / reject UX.** Pre-data accept handshake so the target client can
  decline based on peer identity, circuit purpose, etc.
- **Per-circuit rate limits.** Token-bucket on bytes/sec per circuit + global
  fairness across circuits on one session.
- **UDP / QUIC fast path.** Lossy-tolerant transport mode for VoIP media.

---

## 10. Source Map

| Concern | File(s) |
|---------|---------|
| Wire protocol encode/decode | `nodus/src/protocol/nodus_tier2.{h,c}` |
| Per-session circuit table | `nodus/src/circuit/nodus_circuit.{h,c}` |
| Global inter-node circuit table | `nodus/src/circuit/nodus_inter_circuit.{h,c}` |
| Server dispatch (circ_*, ri_*) | `nodus/src/server/nodus_server.c` (`handle_t2_circ_*`, `handle_inter_ri_*`) |
| Client SDK | `nodus/src/client/nodus_client.c`, `nodus/include/nodus/nodus.h` |
| Constants / error codes | `nodus/include/nodus/nodus_types.h` |
