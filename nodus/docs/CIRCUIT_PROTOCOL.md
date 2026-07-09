# Nodus Circuit Protocol (VPN Mesh — Faz 1 + E2E)

**Status:** Faz 1 + per-circuit E2E encryption (Kyber1024). Still: no per-hop
onion mixing, no rate limits, auto-accept.
**Introduced:** Nodus v0.10.0 (foundation); per-circuit E2E layer added in
v0.10.2–v0.10.5 (commits `d474ba24`, `436f2b5b`, `37e813c9`)
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

**Shipped after the original Faz 1 scope:**
- **Per-circuit E2E encryption.** `nodus_circuit_open_e2e()` Kyber1024-encapsulates
  to the peer's Kyber public key; both ends derive an AES-256-GCM session key.
  Relay servers forward the ciphertext opaquely (see § 3.3). Circuits opened via
  plain `nodus_circuit_open()` remain cleartext at the relay.

**Still NOT:**
- Onion-routed (no per-hop Kyber wrapping — both servers learn `(src_fp, dst_fp)`).
- Forward-secret (E2E encapsulates to the peer's *static* Kyber key from its
  profile; compromise of that key exposes past circuit traffic).
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
| `circ_open` | C→N | query | `{ cid: u64, fp: bytes(64), ect?: bytes(1568) }` | `fp` = target peer fingerprint. `cid` = client's own session-unique id. `ect` = optional Kyber1024 ciphertext for per-circuit E2E (present when opened via `nodus_circuit_open_e2e`). |
| `circ_open_ok` | N→C | response | `{ cid: u64 }` | Echoes client's `cid`. |
| `circ_open_err` | N→C | error | `{ cid: u64, code: int }` | `code` ∈ `NODUS_ERR_{CIRCUIT_LIMIT,PEER_OFFLINE,…}`. |
| `circ_inbound` | N→C | query (push) | `{ cid: u64, fp: bytes(64), ect?: bytes(1568) }` | `cid` = server-assigned id on target's session. `fp` = originator. `ect` relayed opaquely from the originator's `circ_open`. Auto-accept in Faz 1. |
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
| `ri_open` | A→B | query | `{ ups: u64, src: bytes(64), dst: bytes(64), ect?: bytes(1568) }` | `ups` = A's upstream circuit id. `ect` relayed opaquely (E2E onion layer — neither server can decrypt it). |
| `ri_open_ok` | B→A | response | `{ ups: u64, dns: u64 }` | `dns` = B's downstream circuit id. |
| `ri_open_err` | B→A | error | `{ ups: u64, code: int }` | Target session missing → `PEER_OFFLINE`. |
| `ri_data` | A↔B | query (no resp) | `{ cid: u64, d: bytes }` | `cid` = the id the *receiver* stored as `our_cid`. |
| `ri_close` | A↔B | query (no resp) | `{ cid: u64 }` | Idempotent. |

### 3.3 Per-circuit E2E encryption (onion layer)

When a circuit is opened with `nodus_circuit_open_e2e()`:

1. The initiator Kyber1024-encapsulates to the **peer's static Kyber public key**
   (obtained out-of-band, e.g. from the peer's DHT profile), producing
   `(e2e_ct, e2e_ss)`. `e2e_ct` rides the `circ_open` as the `ect` field.
2. Every relay hop (`handle_t2_circ_open` → `ri_open` → `circ_inbound` in
   `nodus_server.c`) forwards `ect` **opaquely** — servers cannot decapsulate it.
3. The target decapsulates `ect` with its Kyber secret key on `circ_inbound`.
4. Both ends derive the session key with the shared channel-crypto KDF
   (`nodus_channel_crypto_init`, `src/crypto/nodus_channel_crypto.h`):
   `key = HKDF-SHA3-256(salt = nc ‖ ns, ikm = e2e_ss, info = "nodus-channel-v1")`
   where the nonces are **deterministic**: `nc` = first 32 bytes of the
   initiator's fingerprint, `ns` = first 32 bytes of the target's fingerprint
   (`nodus_client.c` — both sides compute the same values, no extra round-trip).
5. Each `circ_data` payload is then AES-256-GCM encrypted:
   `[12-byte nonce ‖ ciphertext ‖ 16-byte tag]` (+28 bytes overhead), with a
   monotonic counter nonce and minimum-expected-counter replay check on receive
   (correct over TCP's ordered delivery; a UDP transport would need
   window-based replay protection instead).

If the target has no Kyber key or decapsulation fails, the inbound handle stays
`e2e_active=false` and payloads are treated as cleartext — the initiator's
encrypted frames will not decrypt, so the circuit is effectively unusable
rather than silently downgraded.

**Test coverage (honest):** same-nodus E2E is verified live in
`tests/test_circuit_live.c` (both ends `e2e_active`, encrypted payload
round-trip). **Cross-nodus E2E has no live test** — `tests/test_circuit_cross_live.c`
exercises the relay path without `ect`. The cross-nodus E2E path is code-complete
(`nodus_server.c` forwards `ect` through `ri_open`) but unproven end-to-end.

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

int  nodus_circuit_open_e2e(nodus_client_t *client, const nodus_key_t *peer_fp,
                            const uint8_t *peer_kyber_pk,
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
  resolve on `circ_open_ok` / `circ_open_err`. **No E2E** — payload is cleartext
  at the relay unless the application encrypts it itself.
- `nodus_circuit_open_e2e` — same as above but Kyber1024-encapsulates to
  `peer_kyber_pk` and sends the ciphertext as `ect`; all `circ_data` payloads on
  the handle are transparently AES-256-GCM encrypted/decrypted (see § 3.3).
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

- **E2E is opt-in.** Circuits opened via `nodus_circuit_open_e2e` are end-to-end
  encrypted (Kyber1024 + AES-256-GCM, § 3.3) and the relay sees only ciphertext.
  Circuits opened via plain `nodus_circuit_open` carry cleartext payloads at the
  relay. Transport hops are additionally encrypted since v0.10.2+: the client↔server
  TCP 4001 tunnel and inter-node TCP 4002 both run Kyber1024 channel encryption
  (commits `b0881f1a`, `3e858320`), with Dilithium5 mutual auth on 4002.
- **No forward secrecy.** E2E encapsulates to the peer's long-lived static Kyber
  key; compromising it retroactively exposes recorded circuit traffic. Per-circuit
  ephemeral keys are future work.
- **No onion mixing.** The originating Nodus server learns
  `(src_fp, dst_fp)`; the target server learns the same. No per-hop wrapping.
- **Cross-nodus E2E untested live.** Only the same-nodus E2E path has live test
  coverage (§ 3.3).
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

- ~~**Kyber1024 E2E crypto.**~~ **DONE** (v0.10.2–v0.10.5) — per-circuit
  client↔client encryption, § 3.3. Remaining crypto work: per-hop ML-KEM
  wrapping (true onion, so each Nodus server learns only its immediate
  neighbours) and per-circuit **ephemeral** keys for forward secrecy.
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
