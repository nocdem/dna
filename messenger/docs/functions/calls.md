# Call Subsystem (PQ VoIP)

**Status:** Faz A — call-control plane (signaling + key agreement). Media (audio) is Faz B.
**Headers:** `src/api/engine/dna_call_crypto.h`, `dna_call_fsm.h`, `dna_call_orch.h`
**Determinism/security note:** the call path is non-consensus (never touches `state_root`).
All crypto reuses audited primitives only (ML-KEM-1024, ML-DSA-87, HKDF-SHA3-256, SHA3-512);
no new primitive. Signaling rides the Seal message channel (see `PROTOCOL.md` §9).

The headless core (§1–3) is unit-tested in `messenger/tests/test_call_*.c`. The engine module
(§4) wires it into the live engine: it owns the orchestrator, verifies inbound signatures,
enforces contacts-only ringing, and sends signed responses over Seal. Incoming call signals are
routed to it from the transport receive path (a `type:"call_signal"` branch that never stores
the body as chat).

---

## 1. Call Crypto (`dna_call_crypto.h`)

### Per-call key agreement

```c
int dna_call_derive_key(
    const uint8_t ss_eph[32],     // ephemeral-KEM shared secret
    const uint8_t ss_static[32],  // static-KEM shared secret
    const uint8_t caller_fp[64],  // raw Dilithium5 fingerprint (caller)
    const uint8_t callee_fp[64],  // raw fingerprint (callee)
    const uint8_t call_id[16],    // 128-bit per-call id
    const uint8_t eph_pk[1568],   // ephemeral ML-KEM-1024 public key
    uint8_t key_out[32]);         // -> K_call (AES-256)
```

`K_call = HKDF-SHA3-256(salt = caller_fp[0:32] ‖ callee_fp[0:32], ikm = ss_eph ‖ ss_static,
info = "dna-call-v1" ‖ call_id ‖ SHA3-512(eph_pk)[0:32])`. The salt binds both endpoints; the
static secret adds identity depth without weakening the forward secrecy that comes from
destroying `ss_eph` at teardown. Returns `DNA_CALL_OK` (0) / negative.

### Canonical signal signing

```c
int dna_call_sign_body(const char *body, size_t body_len, const uint8_t *dsa_sk,
                       char *out, size_t out_cap, size_t *out_len);
int dna_call_verify_body(const char *signed_body, size_t signed_len, const uint8_t *dsa_pk);
```

The signed content is the signal body with an empty `"sig":""` slot. Signing computes
Dilithium5 over those exact bytes and splices the base64 signature into the slot. **Verification
operates on the exact received bytes** (blanks the sig value back to empty, verifies) — never
re-serializing — so it is immune to JSON-encoder differences between C and Dart. The inner
signature is load-bearing: the direct-message receive path does not verify Seal's own
signature, so this binds `eph_pk` (and the ACCEPT ciphertexts) to the caller identity.

### Canonical signal build / parse

```c
int dna_call_build_body(const dna_call_signal_t *sig,
                        char *out, size_t out_cap, size_t *out_len);
int dna_call_parse_body(const char *body, size_t body_len, dna_call_parsed_t *out);
```

`dna_call_build_body` emits the fixed-order per-kind JSON body with the `"sig":""` slot
(hand-built single C encoder — deterministic bytes). `dna_call_parse_body` extracts typed
fields from a received body and is bounds-safe against arbitrary/adversarial input (exact-length
base64 checks; malformed/truncated/non-JSON rejected). `dna_call_signal_t` /
`dna_call_parsed_t` carry `kind`, `call_id`, `seq`, and per-kind `caller`/`eph_pk`/`eph_ct`/
`static_ct`/`reason`. Kinds: `INVITE`, `RINGING`, `ACCEPT`, `REJECT`, `BUSY`, `END`.

---

## 2. Call State Machine (`dna_call_fsm.h`)

```c
dna_call_state_t dna_call_fsm_step(dna_call_state_t state,
                                   dna_call_event_t event,
                                   dna_call_action_t *action);
```

Pure, table-driven `(state, event) → (state', action)`. States: `CALL_IDLE`, `CALL_INVITING`,
`CALL_RINGING`, `CALL_ACTIVE`, `CALL_ENDED`. No wall-clock (a timeout enters as
`CALL_EV_TIMEOUT`), no allocation, no I/O. Unhandled `(state,event)` pairs are idempotent
no-ops (late/duplicate signals cannot corrupt); `CALL_ENDED` is absorbing. Actions include
`SEND_INVITE`, `SEND_RINGING`, `ACCEPT`, `OPEN_MEDIA`, `SEND_REJECT`, `END`, `TEARDOWN`.

---

## 3. Call Orchestrator (`dna_call_orch.h`)

Mutex-guarded live-call table + bounded ended-call ring. All time is an injected `now_ms`.

```c
dna_call_orch_t *dna_call_orch_create(void);
void             dna_call_orch_destroy(dna_call_orch_t *o);

// Registry
int  dna_call_orch_register(dna_call_orch_t *o, const uint8_t call_id[16],
                            const uint8_t peer_fp[64], dna_call_dir_t dir,
                            uint64_t now_ms, uint64_t window_ms);
int  dna_call_orch_find(dna_call_orch_t *o, const uint8_t call_id[16]);
int  dna_call_orch_accept_seq(dna_call_orch_t *o, int slot, uint32_t seq);
int  dna_call_orch_arm_gate(dna_call_orch_t *o, int slot, uint64_t now_ms, uint64_t window_ms);
int  dna_call_orch_gate(dna_call_orch_t *o, const uint8_t originator_fp[64], uint64_t now_ms);
void dna_call_orch_end(dna_call_orch_t *o, int slot);
int  dna_call_orch_is_ended(dna_call_orch_t *o, const uint8_t call_id[16]);
int  dna_call_orch_expire(dna_call_orch_t *o, uint64_t now_ms);

// Signal -> FSM driver
dna_call_action_t dna_call_orch_start(dna_call_orch_t *o, const uint8_t call_id[16],
                                      const uint8_t peer_fp[64], uint64_t now_ms, uint64_t window_ms);
dna_call_action_t dna_call_orch_on_signal(dna_call_orch_t *o, const dna_call_parsed_t *p,
                                          const uint8_t sender_fp[64], uint64_t now_ms, uint64_t window_ms);
dna_call_action_t dna_call_orch_user(dna_call_orch_t *o, const uint8_t call_id[16],
                                     dna_call_event_t user_event, uint64_t now_ms, uint64_t gate_window_ms);
dna_call_state_t  dna_call_orch_state(dna_call_orch_t *o, const uint8_t call_id[16]);
```

Key behaviors:

- **Consent gate (F-GATE):** `arm_gate` (called on local accept) then a one-shot, windowed
  `gate` check keyed on the peer fingerprint — the inbound media circuit is authorized only for
  a peer the local user accepted, and only once.
- **Dedup (F-DEDUP):** per-call peer-sequence high-water; a single direction is numbered here,
  so caller/callee `seq=1` never collide. Primary idempotency is the FSM.
- **Ended-call ring (R8):** fixed-capacity LRU; replayed INVITEs for an ended call are
  suppressed.
- **Glare:** if a peer INVITEs while we have a concurrent outbound call to them, the lower raw
  16-byte `call_id` wins — deterministic, so both peers pick the same survivor.
- **`on_signal`** enforces `sender_fp == call peer`, deduplicates, drives the FSM, arms the gate
  on accept, and tears the call down (moving it to the ended ring) on any terminal transition.

---

## 4. Engine Module (`dna_engine_calls.h`)

Live-engine glue. The engine owns a calls context (`dna_calls_ctx_create/destroy`, invoked from
`dna_engine_create/destroy`) holding the orchestrator + a mutex-guarded per-call secret keystore
(ephemeral Kyber keypair, `K_call`). Time is a real `CLOCK_MONOTONIC` reading fed to the pure
orchestrator.

```c
// Incoming (called by the transport receive branch for call_signal bodies)
void dna_calls_handle_incoming(dna_engine_t *engine, const char *sender_fp, const char *body);

// Public user actions (FFI)
int  dna_engine_call_invite(dna_engine_t *engine, const char *peer_fp);      // send INVITE
int  dna_engine_call_accept(dna_engine_t *engine, const char *call_id_hex);  // send ACCEPT
int  dna_engine_call_reject(dna_engine_t *engine, const char *call_id_hex);  // send REJECT
int  dna_engine_call_hangup(dna_engine_t *engine, const char *call_id_hex);  // send END
```

`dna_calls_handle_incoming` parses the body, verifies the **inner Dilithium signature** against
the sender's cached keyserver pubkey (`keyserver_cache_get`), drops INVITEs from
non-contacts/blocked senders (`contacts_db_exists`/`contacts_db_is_blocked`), drives the
orchestrator, and — on the caller side receiving ACCEPT — decapsulates both ciphertexts and
derives `K_call` for Faz B. `dna_engine_call_accept` encapsulates to the caller's ephemeral +
static Kyber keys, derives `K_call`, and sends the signed ACCEPT. Responses are built +
inner-signed (`dna_call_sign_body` with the local `identity.dsa`) and sent via
`dna_engine_send_message` (so they inherit Seal E2E + Spillway).

**Receive routing:** `messenger_transport.c` (`transport_message_received_internal`) intercepts a
decrypted `type:"call_signal"` body and hands it to `dna_calls_handle_incoming`, then returns
before `message_backup_save` — so call signals never render as chat.

**UI events.** The module dispatches engine events for the app:
- `DNA_EVENT_CALL_INCOMING` — an INVITE arrived (show the ring UI). `data.call`: `call_id`,
  `peer_fp`.
- `DNA_EVENT_CALL_STATE` — call state changed. `data.call`: `call_id`, `peer_fp`,
  `state` (`dna_call_ui_state_t`: 0=ringing, 1=active, 2=ended), `is_incoming`.

## 5. Flutter integration (Faz A UI)

FFI: `DnaEngine.callInvite/callAccept/callReject/callHangup` (in `lib/ffi/dna_engine.dart`,
bound in `dna_bindings.dart`). Incoming calls + state changes surface as `CallIncomingEvent` /
`CallStateEvent` on the `DnaEngine.events` stream. `lib/providers/call_provider.dart`
(`callProvider`, a `NotifierProvider<CallNotifier, CallSession?>`) holds the single active call
and is driven by those events (routed in `event_handler.dart`). `lib/screens/call/call_screen.dart`
is the full-screen call UI, overlaid over the whole app by a `builder` in `main.dart` while a call
exists; the chat screen's phone button starts a call. Strings are localized (`callIncoming`,
`callCalling`, `callConnected`, `callAnswer`, `callDecline`, `callEnd`, `callStart`); no crypto
terms in the UI. Media (voice) is Faz B — "Connected" means the secure channel is established.

**Related — F-SIG (observe-only, phase 1):** the transport now also verifies the Seal signature
over the plaintext of *every* inbound message against the sender's cached Dilithium pubkey and
logs a warning on mismatch (never drops yet). Enforcement is a device-tested phase 2.

## 6. Tests

| File | Covers |
|------|--------|
| `tests/test_call_crypto.c` | `K_call` spec-conformance, forward secrecy, pair-binding, KEM round-trip |
| `tests/test_call_sign.c` | sign/verify round-trip, tamper/wrong-key rejection, byte-exact verification |
| `tests/test_call_signal.c` | per-kind body build, base64 payloads, build→sign→verify |
| `tests/test_call_parse.c` | field extraction, exact-length base64, malformed-input rejection (ASan) |
| `tests/test_call_fsm.c` | all transitions, absorbing ENDED, idempotent no-ops, purity |
| `tests/test_call_orch.c` | registry: capacity, dedup, consent gate, ended-ring LRU, expiry |
| `tests/test_call_driver.c` | caller/callee flows, glare tie-break, replayed-ended suppression |

Build/run: `cd messenger/tests/build && cmake .. && make && ctest -R test_call`.
