# Post-Quantum Voice/Video Calls Design

**Component:** Real-Time Audio/Video Communication
**Status:** Research & Planning Phase
**Dependencies:** P2P Transport Layer (Phase 9.1), Existing PQ Crypto (Kyber512, Dilithium3)

---

## OVERVIEW

DNA Messenger will support post-quantum secure voice and video calls using a custom architecture that bypasses WebRTC's quantum-vulnerable DTLS handshake. Instead of relying on standard WebRTC with ECDHE/ECDSA, we use DNA's existing Kyber512 and Dilithium3 implementations for session key establishment, then stream media over SRTP with post-quantum derived keys.

**Key Principle:** Quantum-safe key exchange via DNA messaging + standard SRTP media transport = Post-quantum voice/video calls

---

## WHY NOT STANDARD WEBRTC?

### WebRTC Security Model

Standard WebRTC uses:
- **DTLS-SRTP** for key exchange and media channel setup
- **ECDHE** (Elliptic Curve Diffie-Hellman Ephemeral) for key agreement
- **ECDSA** (Elliptic Curve Digital Signature Algorithm) for authentication
- **AES-GCM** for media encryption (quantum-safe)

### Quantum Vulnerability

```
┌────────────────────────────────────────────────────────┐
│           Standard WebRTC Call Setup                    │
├────────────────────────────────────────────────────────┤
│  1. DTLS Handshake (ECDHE + ECDSA)  ← VULNERABLE!     │
│     ↓                                                   │
│  2. Derive SRTP Keys                                    │
│     ↓                                                   │
│  3. Stream Media (AES-GCM)           ← Quantum-Safe    │
└────────────────────────────────────────────────────────┘

Problem: Quantum computer can break ECDHE/ECDSA in the handshake,
         recover session keys, and decrypt the media stream.
```

### Current State of PQ in WebRTC (2025)

- **IETF Draft:** Post-quantum TLS/DTLS 1.3 with ML-KEM exists
- **Browser Support:** None (experimental only)
- **DTLS 1.3:** Not widely implemented
- **Migration Timeline:** 3-5 years for ecosystem adoption
- **Large Key Problem:** Kyber public keys (1568 bytes) cause DTLS fragmentation

**Conclusion:** Waiting for WebRTC standards is too slow. We have everything we need today.

---

## DNA MESSENGER SOLUTION

### Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│         DNA Post-Quantum Voice/Video Architecture            │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │         Phase 1: Signaling (DNA Encrypted Messaging)   │  │
│  │  - Kyber512 key exchange                               │  │
│  │  - Dilithium3 signatures                               │  │
│  │  - ICE candidate exchange                              │  │
│  │  - Call setup/accept/reject/hangup                     │  │
│  └────────────────────┬───────────────────────────────────┘  │
│                       │ (Derives SRTP Master Key)            │
│                       ▼                                        │
│  ┌────────────────────────────────────────────────────────┐  │
│  │         Phase 2: NAT Traversal (libnice)               │  │
│  │  - ICE/STUN/TURN                                       │  │
│  │  - UDP hole punching                                   │  │
│  │  - Direct P2P connection                               │  │
│  └────────────────────┬───────────────────────────────────┘  │
│                       │                                        │
│                       ▼                                        │
│  ┌────────────────────────────────────────────────────────┐  │
│  │         Phase 3: Media Transport (SRTP)                │  │
│  │  - AES-256-GCM encryption                              │  │
│  │  - HMAC-SHA256 authentication                          │  │
│  │  - RTP for audio/video streaming                       │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

### Key Differences from WebRTC

| Component | Standard WebRTC | DNA Messenger |
|-----------|-----------------|---------------|
| **Key Exchange** | DTLS (ECDHE) | Kyber512 via DNA messaging |
| **Authentication** | DTLS (ECDSA) | Dilithium3 signatures |
| **Signaling** | WebSocket/HTTP | DNA encrypted messaging |
| **Media Transport** | SRTP (AES-GCM) | SRTP (AES-256-GCM) |
| **NAT Traversal** | ICE/STUN/TURN | ICE/STUN/TURN (libnice) |
| **Quantum Security** | **VULNERABLE** | **QUANTUM-SAFE** |

---

## SIGNALING PROTOCOL

### Call Setup Flow

```
┌─────────┐                                             ┌─────────┐
│  Alice  │                                             │   Bob   │
└────┬────┘                                             └────┬────┘
     │                                                       │
     │ 1. Generate ephemeral Kyber512 keypair              │
     │    (kyber_pk_A, kyber_sk_A)                         │
     │                                                       │
     │ 2. Create CALL_INVITE message:                       │
     │    - call_id (UUID)                                  │
     │    - kyber_pk_A (1568 bytes)                         │
     │    - ice_candidates_A                                │
     │    - media_capabilities (audio/video)                │
     │    - timestamp                                        │
     │    - signature (Dilithium3)                          │
     │                                                       │
     │────────── DNA Encrypted Message ─────────────────────>│
     │                                                       │
     │                                             3. Verify signature
     │                                             4. Generate kyber_pk_B, kyber_sk_B
     │                                             5. Kyber Encapsulate:
     │                                                shared_secret = kyber_encap(kyber_pk_A)
     │                                                ciphertext_B (Kyber ciphertext)
     │                                                       │
     │                                             6. Create CALL_ACCEPT:
     │                                                - call_id
     │                                                - ciphertext_B (1568 bytes)
     │                                                - ice_candidates_B
     │                                                - signature (Dilithium3)
     │                                                       │
     │<──────────── DNA Encrypted Message ───────────────────│
     │                                                       │
     │ 7. Kyber Decapsulate:                                │
     │    shared_secret = kyber_decap(ciphertext_B, kyber_sk_A)
     │                                                       │
     │ 8. Both derive SRTP keys:                            │
     │    srtp_master_key = HKDF(shared_secret, call_id)    │
     │    srtp_master_salt = HKDF(shared_secret, call_id)   │
     │                                                       │
     │ 9. Perform ICE connectivity checks                    │
     │<─────────────── UDP hole punching ───────────────────>│
     │                                                       │
     │ 10. Establish P2P connection                          │
     │<══════════════ Direct UDP stream ════════════════════>│
     │                                                       │
     │ 11. Start streaming media (SRTP with PQ-derived keys)│
     │<══════════════ Audio/Video RTP ══════════════════════>│
     │                                                       │
```

### Message Formats

**CALL_INVITE:**
```c
typedef struct {
    uint8_t call_id[16];                    // UUID
    uint8_t kyber_pubkey[1568];             // Kyber512 public key
    ice_candidate_t ice_candidates[10];     // ICE candidates
    uint8_t num_candidates;
    enum { AUDIO_ONLY, VIDEO_ONLY, AUDIO_VIDEO } media_type;
    uint64_t timestamp;
    uint8_t signature[3309];                // Dilithium3 signature
} call_invite_t;
```

**CALL_ACCEPT:**
```c
typedef struct {
    uint8_t call_id[16];                    // UUID (matches invite)
    uint8_t kyber_ciphertext[1568];         // Kyber512 ciphertext
    ice_candidate_t ice_candidates[10];     // ICE candidates
    uint8_t num_candidates;
    uint64_t timestamp;
    uint8_t signature[3309];                // Dilithium3 signature
} call_accept_t;
```

**CALL_REJECT / CALL_HANGUP:**
```c
typedef struct {
    uint8_t call_id[16];
    enum { REJECT_BUSY, REJECT_DECLINED, HANGUP_NORMAL } reason;
    uint64_t timestamp;
    uint8_t signature[3309];
} call_end_t;
```

### Key Derivation

Once both parties have the shared secret from Kyber512, derive SRTP keys:

```c
// HKDF-SHA256 for key derivation
uint8_t srtp_master_key[32];      // 256-bit key
uint8_t srtp_master_salt[14];     // 112-bit salt

// HKDF Extract
uint8_t prk[32];
hmac_sha256(shared_secret, 32, call_id, 16, prk);

// HKDF Expand
hkdf_expand(prk, 32, "DNA-SRTP-Master-Key", srtp_master_key, 32);
hkdf_expand(prk, 32, "DNA-SRTP-Master-Salt", srtp_master_salt, 14);

// Initialize SRTP context
srtp_context_t *srtp_ctx = srtp_create_context(
    srtp_master_key, 32,
    srtp_master_salt, 14,
    SRTP_AES_256_GCM  // Use AES-256 instead of AES-128
);
```

---

## MEDIA TRANSPORT

### SRTP Configuration

**Encryption:** AES-256-GCM (instead of standard AES-128-GCM)
**Authentication:** HMAC-SHA256
**Key Length:** 256 bits (quantum-resistant key size)

### RTP Payload Types

**Audio Codecs:**
- Opus (48kHz, stereo) - Primary
- G.722 (16kHz, wideband) - Fallback

**Video Codecs:**
- VP8 (WebM) - Primary
- H.264 (baseline profile) - Fallback

### Media Stack

```c
┌────────────────────────────────────────┐
│      Application (DNA Messenger)       │
├────────────────────────────────────────┤
│         Audio/Video Capture            │
│  - Microphone input (PortAudio)        │
│  - Camera input (V4L2/DirectShow)      │
├────────────────────────────────────────┤
│         Audio/Video Encoding           │
│  - libopus (audio)                     │
│  - libvpx or libx264 (video)           │
├────────────────────────────────────────┤
│         RTP Packetization              │
│  - RTP headers                         │
│  - Timestamp synchronization           │
├────────────────────────────────────────┤
│         SRTP Encryption                │
│  - AES-256-GCM (PQ-derived keys)       │
│  - HMAC-SHA256 authentication          │
├────────────────────────────────────────┤
│         Network Transport              │
│  - UDP sockets (libnice P2P)           │
│  - ICE/STUN/TURN                       │
└────────────────────────────────────────┘
```

---

## NAT TRAVERSAL

### Reuse P2P Infrastructure

Voice/video calls use the **same NAT traversal** as messaging (Phase 9.1):

- **libnice** for ICE/STUN/TURN
- **Same STUN servers** (Google, Cloudflare, etc.)
- **Same TURN servers** (optional relay)

### ICE Candidate Exchange

ICE candidates exchanged via DNA messaging (not via DTLS):

```c
typedef struct {
    char ip[46];                    // IPv4 or IPv6
    uint16_t port;
    enum {
        CANDIDATE_HOST,             // Local IP
        CANDIDATE_REFLEXIVE,        // Public IP (via STUN)
        CANDIDATE_RELAY             // TURN server
    } type;
    uint32_t priority;
} ice_candidate_t;
```

**Process:**
1. Gather candidates (local, reflexive, relay)
2. Include in CALL_INVITE / CALL_ACCEPT messages
3. Perform connectivity checks (all pairs)
4. Select best candidate pair (lowest latency)
5. Establish UDP connection

---

## SESSION MANAGEMENT

### Call States

```c
typedef enum {
    CALL_STATE_IDLE,            // No active call
    CALL_STATE_INVITING,        // Outgoing call (waiting for accept)
    CALL_STATE_RINGING,         // Incoming call (waiting for user)
    CALL_STATE_CONNECTING,      // ICE negotiation in progress
    CALL_STATE_ACTIVE,          // Call in progress (streaming media)
    CALL_STATE_ENDED            // Call finished
} call_state_t;
```

### Session Context

```c
typedef struct {
    uint8_t call_id[16];
    char peer_identity[256];
    call_state_t state;

    // Crypto
    uint8_t shared_secret[32];          // From Kyber512
    uint8_t srtp_master_key[32];
    uint8_t srtp_master_salt[14];
    srtp_context_t *srtp_send;
    srtp_context_t *srtp_recv;

    // Transport
    nat_traversal_context_t *nat_ctx;
    int media_socket_fd;

    // Media
    enum { AUDIO_ONLY, VIDEO_ONLY, AUDIO_VIDEO } media_type;
    void *audio_encoder;                // Opus context
    void *video_encoder;                // VP8/H.264 context

    // Statistics
    uint64_t start_time;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} call_session_t;
```

### API Design

```c
// Initialize voice/video subsystem
int dna_call_init(dna_context_t *ctx);

// Start outgoing call
int dna_call_start(dna_context_t *ctx,
                   const char *peer_identity,
                   enum { AUDIO_ONLY, VIDEO_ONLY, AUDIO_VIDEO } media_type,
                   uint8_t *call_id_out);

// Accept incoming call
int dna_call_accept(dna_context_t *ctx, const uint8_t *call_id);

// Reject incoming call
int dna_call_reject(dna_context_t *ctx, const uint8_t *call_id,
                    enum { REJECT_BUSY, REJECT_DECLINED } reason);

// Hangup active call
int dna_call_hangup(dna_context_t *ctx, const uint8_t *call_id);

// Get call state
call_state_t dna_call_get_state(dna_context_t *ctx, const uint8_t *call_id);

// Mute/unmute microphone
int dna_call_set_audio_muted(dna_context_t *ctx, const uint8_t *call_id, bool muted);

// Enable/disable camera
int dna_call_set_video_enabled(dna_context_t *ctx, const uint8_t *call_id, bool enabled);

// Get call statistics
int dna_call_get_stats(dna_context_t *ctx, const uint8_t *call_id,
                       call_stats_t *stats_out);

// Cleanup
void dna_call_shutdown(dna_context_t *ctx);
```

---

## FORWARD SECRECY

### Ephemeral Keys

**Key Principle:** Generate new Kyber512 keypair for every call

```c
// Each call uses fresh keys
for (each new call) {
    // Generate ephemeral Kyber512 keypair
    kyber512_keypair(kyber_pk_ephemeral, kyber_sk_ephemeral);

    // Use for this call only
    // Keys destroyed after call ends
}
```

**Benefits:**
- Each call has unique session keys
- Compromise of one call doesn't affect others
- Long-term Kyber/Dilithium keys only used for identity/signatures

### Key Rotation (Optional Enhancement)

For long calls (>1 hour), periodically rotate SRTP keys:

```c
// Every 3600 seconds (1 hour), re-key
if (call_duration > 3600) {
    // Generate new ephemeral keys
    kyber512_keypair(kyber_pk_new, kyber_sk_new);

    // Send REKEY message (same as CALL_INVITE)
    // Derive new SRTP keys
    // Switch to new keys atomically
}
```

---

## TECHNOLOGY STACK

### Required Libraries

| Component | Library | Language | Purpose |
|-----------|---------|----------|---------|
| **PQ Crypto** | Kyber512 (vendored) | C | Key encapsulation |
| **PQ Crypto** | Dilithium3 (vendored) | C | Digital signatures |
| **NAT Traversal** | libnice | C | ICE/STUN/TURN |
| **SRTP** | libsrtp2 | C | Secure RTP encryption |
| **Audio Codec** | libopus | C | Opus encoding/decoding |
| **Video Codec** | libvpx or libx264 | C | VP8 or H.264 |
| **Audio I/O** | PortAudio or ALSA | C | Microphone/speaker |
| **Video I/O** | V4L2 (Linux) / DirectShow (Windows) | C | Camera capture |

**Total New Dependencies:** 4-5 libraries (all mature, widely-used)

### Platform Support

**Linux:**
- Audio: ALSA / PulseAudio via PortAudio
- Video: V4L2 (Video4Linux2)
- NAT: libnice (GStreamer project)

**Windows:**
- Audio: DirectSound / WASAPI via PortAudio
- Video: DirectShow / Media Foundation
- NAT: libnice (cross-platform)

**macOS:**
- Audio: CoreAudio via PortAudio
- Video: AVFoundation
- NAT: libnice

---

## SECURITY CONSIDERATIONS

### Threat Model

**Protected Against:**
- ✅ **Quantum attacks** - Kyber512 key exchange
- ✅ **Man-in-the-middle** - Dilithium3 signatures
- ✅ **Eavesdropping** - AES-256-GCM encryption
- ✅ **Replay attacks** - SRTP includes sequence numbers
- ✅ **Forward secrecy** - Ephemeral keys per call

**NOT Protected Against:**
- ❌ **Traffic analysis** - Observers see call duration, packet sizes
  - *Future:* Constant-rate padding, dummy packets
- ❌ **Compromised devices** - Malware can capture before encryption
  - *Mitigation:* Secure boot, attestation (future)

### Verification

**Problem:** How does Alice know she's talking to the real Bob?

**Solution:** Short Authentication String (SAS) verification

```
1. Both parties compute:
   sas_hash = SHA256(shared_secret || call_id || alice_identity || bob_identity)

2. Display first 40 bits as 8 decimal digits:
   Alice sees: 1234 5678
   Bob sees:   1234 5678

3. Alice: "My code is 1234 5678"
   Bob: "I have 1234 5678 too"
   → Verified!
```

**Why This Works:**
- 40-bit SAS = 2^40 = 1 trillion combinations
- Attacker has 1 in 1 trillion chance of matching SAS
- Spoken verification prevents MITM

---

## COMPARISON WITH OTHER SYSTEMS

### Signal

**Approach:** PQXDH (X25519 + Kyber) for messaging, standard WebRTC for calls
**Calls:** Uses WebRTC DTLS (quantum-vulnerable as of 2025)
**DNA Advantage:** Full post-quantum for both messaging AND calls

### Wire

**Approach:** Standard WebRTC with DTLS
**Calls:** Quantum-vulnerable
**DNA Advantage:** Post-quantum key exchange

### Jami (Ring)

**Approach:** OpenDHT + custom SRTP
**Calls:** Uses SDES (insecure key exchange)
**DNA Advantage:** Kyber512 instead of SDES

### DNA Messenger

**Approach:** Kyber512/Dilithium3 signaling + SRTP media
**Calls:** Fully quantum-safe
**Unique Feature:** Post-quantum from day one

---

## IMPLEMENTATION PLAN

### Phase 1: Signaling (4 weeks)

**Tasks:**
- Implement call invite/accept/reject messages
- Integrate Kyber512 key exchange (already have library)
- Add Dilithium3 signatures for call messages
- Store call sessions in SQLite

**Deliverables:**
- Call setup flow working (no media yet)
- Unit tests for signaling protocol

### Phase 2: NAT Traversal (4 weeks)

**Tasks:**
- Integrate libnice (already planned for Phase 9.1)
- Implement ICE candidate gathering
- Add STUN server support
- Test UDP hole punching

**Deliverables:**
- P2P UDP connection established
- Works across NAT/firewalls

### Phase 3: Audio Calls (4 weeks)

**Tasks:**
- Integrate libopus (audio codec)
- Add PortAudio (microphone/speaker)
- Implement SRTP encryption (libsrtp2)
- RTP packetization/depacketization

**Deliverables:**
- Working audio calls (Opus codec)
- Basic call UI (desktop app)

### Phase 4: Video Calls (4 weeks)

**Tasks:**
- Integrate libvpx (VP8 codec)
- Add camera capture (V4L2/DirectShow)
- Video rendering (SDL2 or Qt)
- Handle audio/video synchronization

**Deliverables:**
- Working video calls (VP8 codec)
- Video preview and remote video display

### Phase 5: Polish & Testing (4 weeks)

**Tasks:**
- Call quality tuning (bitrate, resolution)
- Network adaptation (jitter buffer, FEC)
- Call statistics and monitoring
- End-to-end testing (Linux, Windows, macOS)

**Deliverables:**
- Production-ready voice/video
- User documentation
- Performance benchmarks

**Total Timeline:** ~20 weeks (5 months)

---

## TESTING PLAN

### Unit Tests

- Kyber512 key exchange (encapsulate/decapsulate)
- HKDF key derivation
- Call message serialization/deserialization
- SRTP encryption/decryption

### Integration Tests

- Full call flow (invite → accept → media → hangup)
- NAT traversal (same LAN, different LANs, behind NAT)
- Audio/video codec (encode → transmit → decode)
- Error handling (network failure, codec failure)

### Performance Tests

- Call setup time (target: <2 seconds)
- Audio latency (target: <100ms)
- Video latency (target: <200ms)
- Packet loss resilience (target: works at 5% loss)

### Security Tests

- MITM attack (SAS verification)
- Replay attack (SRTP sequence numbers)
- Eavesdropping (capture encrypted packets, verify undecryptable)

---

## FUTURE ENHANCEMENTS

### Phase 1: Group Calls

**Approach:** Mesh topology (each peer connects to all others)

```
Alice ←→ Bob
  ↕       ↕
Carol ←→ Dave
```

**Limitation:** Scales to ~8 participants (64 connections for 8 peers)

### Phase 2: Selective Forwarding Unit (SFU)

**Approach:** Central server forwards video (doesn't decrypt)

```
Alice → SFU → Bob
         ↓
       Carol
```

**Advantage:** Scales to 100+ participants
**Note:** SFU doesn't need to decrypt (end-to-end encryption preserved)

### Phase 3: Screen Sharing

**Codec:** H.264 high-profile (better compression for desktop content)
**Framerate:** 5-10 FPS (lower than video)
**Resolution:** Match user's screen

### Phase 4: Recording

**Approach:** Local recording only (preserves E2E)
**Format:** WebM (VP8/Opus) or MP4 (H.264/AAC)
**Storage:** Local filesystem, optionally encrypted with user password

---

## ADVANTAGES SUMMARY

### Why DNA's Approach is Better

1. **Full Quantum Resistance**
   - Key exchange: Kyber512 (NIST PQC standard)
   - Signatures: Dilithium3 (NIST PQC standard)
   - No quantum-vulnerable components

2. **Uses Existing Infrastructure**
   - Same Kyber/Dilithium libraries as messaging
   - Same P2P transport as Phase 9
   - No new crypto dependencies

3. **Independent of Standards**
   - Don't wait for WebRTC DTLS 1.3 + ML-KEM
   - Don't wait for browser implementations
   - Can deploy today (desktop/mobile apps)

4. **Better Privacy**
   - Signaling goes through DNA's encrypted channel
   - No separate signaling server needed
   - Fully peer-to-peer

5. **Forward Secrecy**
   - Ephemeral keys per call
   - Old calls can't be decrypted even if long-term keys compromised

6. **Following Best Practices**
   - Similar to Signal's PQXDH approach
   - Uses proven PQC algorithms (NIST standards)
   - Short Authentication String (SAS) for verification

---

## REFERENCES

### Standards

- **NIST FIPS 203:** Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber)
- **NIST FIPS 204:** Module-Lattice-Based Digital Signature Algorithm (ML-DSA / Dilithium)
- **RFC 3711:** The Secure Real-time Transport Protocol (SRTP)
- **RFC 8829:** JavaScript Session Establishment Protocol (JSEP)
- **RFC 8445:** Interactive Connectivity Establishment (ICE)

### Libraries

- **pq-crystals-kyber:** https://github.com/pq-crystals/kyber
- **pq-crystals-dilithium:** https://github.com/pq-crystals/dilithium
- **libnice:** https://nice.freedesktop.org/
- **libsrtp:** https://github.com/cisco/libsrtp
- **libopus:** https://opus-codec.org/
- **libvpx:** https://github.com/webmproject/libvpx

### Inspiration

- **Signal PQXDH:** Quantum-resistant key agreement (X25519 + Kyber)
- **Jami:** P2P messenger with OpenDHT
- **Wire:** End-to-end encrypted group calls

---

**Document Version:** 1.0
**Last Updated:** 2025-10-17
**Author:** DNA Messenger Development Team
**Status:** Research & Planning Phase
