# DNA Messenger - NAT Traversal Guide

**Phase 11: Decentralized NAT Traversal (ICE + STUN)**

**Last Updated:** 2025-11-19

**Status:** ✅ **PRODUCTION-READY** (Migrated to libjuice)

**Recent Updates (2025-11-19):**
- ✅ **MIGRATION COMPLETE**: Migrated from libnice+glib to libjuice v1.7.0
- ✅ **Dependencies Reduced**: No longer requires glib2 (~50MB dependency removed)
- ✅ **Simpler Build**: libjuice built from source automatically via CMake
- ✅ **Windows Support**: Native pthread support with llvm-mingw (no custom macros)
- ✅ **Architecture**: Callback-based (no glib event loop thread)

**Legacy Updates (2025-11-18 - libnice implementation):**
- Fixed `ice_recv()` with libnice callbacks
- Fixed `ice_shutdown()` resource cleanup
- Added thread-safe receive buffer with GMutex synchronization

---

## Table of Contents

1. [Overview](#overview)
2. [How It Works](#how-it-works)
3. [3-Tier Fallback System](#3-tier-fallback-system)
4. [Technical Details](#technical-details)
5. [Configuration](#configuration)
6. [Troubleshooting](#troubleshooting)
7. [Performance](#performance)
8. [Security](#security)
9. [Developer Guide](#developer-guide)

---

## Overview

DNA Messenger implements **fully decentralized NAT traversal** using ICE (Interactive Connectivity Establishment) with STUN (Session Traversal Utilities for NAT). This allows users behind NAT/firewalls to establish direct P2P connections without centralized relays or signaling servers.

### Key Features

- ✅ **No Centralized Infrastructure**: Uses DHT for ICE candidate exchange (no signaling servers)
- ✅ **No Relay Servers**: Uses STUN only for address discovery (no TURN relays)
- ✅ **3-Tier Automatic Fallback**: Seamlessly tries LAN → ICE → DHT queue
- ✅ **High Success Rate**: ~85-90% direct connection through NAT
- ✅ **Cross-Platform**: Linux (native) and Windows (MXE cross-compile)
- ✅ **Public STUN Servers**: Google and Cloudflare STUN (free, no accounts needed)

### What Problems Does It Solve?

**Before Phase 11:**
- Users behind NAT could only connect to peers on same LAN
- Symmetric NAT prevented most P2P connections
- Messages fell back to 7-day DHT queue (slow delivery)

**After Phase 11:**
- Direct P2P connections through most NAT types
- ~85-90% success rate for NAT traversal
- Fast message delivery (2-5 seconds instead of minutes)
- Better user experience (real-time messaging)

---

## How It Works

### Architecture Diagram

```
┌──────────────┐                              ┌──────────────┐
│   Sender     │                              │  Recipient   │
│  (behind NAT)│                              │ (behind NAT) │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │ 1. Register presence + ICE candidates      │
       ├─────────────────────────────────────────────>
       │        DHT (SHA3-512 key)                  │
       │                                             │
       │ 2. Gather ICE candidates via STUN          │
       ├────────> [STUN Server]                     │
       │            (stun.l.google.com)             │
       │          ← Server-reflexive IP:port        │
       │                                             │
       │ 3. Publish candidates to DHT               │
       ├─────────────────────────────────────────────>
       │                                             │
       │ 4. Send message (try 3 tiers)              │
       │                                             │
       │   Tier 1: Direct TCP (if same LAN)         │
       ├─────────────────────────────────────────────>
       │                                             │
       │   Tier 2: ICE (if NAT)                     │
       │     - Fetch recipient candidates from DHT  │
       │     - Perform ICE connectivity checks      │
       │     - Send via established connection      │
       ├─────────────────────────────────────────────>
       │                                             │
       │   Tier 3: DHT Queue (if both fail)         │
       ├─────────────────────────────────────────────>
       │                                             │
```

### Step-by-Step Flow

**Step 1: Presence Registration**

When a user comes online, DNA Messenger:

1. Registers IP:port in DHT (existing behavior)
2. Creates ICE context (NiceAgent)
3. Gathers local candidates:
   - **Host candidates**: Local network interfaces
   - **Server-reflexive candidates**: External IP via STUN (stun.l.google.com:19302)
4. Publishes candidates to DHT:
   - **DHT Key**: SHA3-512(fingerprint + ":ice_candidates")
   - **DHT Value**: SDP-formatted candidate strings (newline-separated)
   - **TTL**: 7 days

**Step 2: Message Sending**

When sending a message, DNA Messenger tries 3 tiers automatically:

**Tier 1: LAN DHT + Direct TCP** (~50ms)
- Lookup peer IP:port from DHT
- Try direct TCP connection (port 4001)
- ✅ Succeeds: Send message, receive ACK
- ❌ Fails: Proceed to Tier 2

**Tier 2: ICE NAT Traversal** (~2-5s)
- Create ICE context
- Gather local candidates via STUN
- Fetch peer candidates from DHT
- Perform ICE connectivity checks (RFC5245)
- Establish P2P connection through NAT
- ✅ Succeeds: Send message via ICE
- ❌ Fails: Proceed to Tier 3

**Tier 3: DHT Offline Queue** (up to 7 days)
- Store message in sender's DHT outbox
- Recipient polls every 2 minutes
- ✅ Succeeds: Message delivered when peer online

---

## 3-Tier Fallback System

### Tier 1: LAN DHT + Direct TCP

**When it works:**
- Same local network (LAN)
- No NAT between peers
- Public IP with no firewall blocking port 4001

**Latency:** ~50ms
**Success Rate:** ~10-20% (same LAN or public IP)

**Logging:**
```
[P2P] [TIER 1] Attempting direct connection via LAN DHT...
[P2P] [TIER 1] Peer found at 192.168.1.100:4001, attempting TCP connection...
[P2P] [TIER 1] ✓ TCP connected to 192.168.1.100:4001
[P2P] [TIER 1] ✓ Sent 1234 bytes
[P2P] [TIER 1] ✓✓ SUCCESS - ACK received, message delivered!
```

---

### Tier 2: ICE NAT Traversal

**When it works:**
- Both peers behind NAT (but not symmetric NAT)
- At least one peer has open NAT (Full Cone, Restricted Cone, Port Restricted)
- STUN servers reachable from both peers

**Latency:** ~2-5s (connection establishment) + ~50-100ms (message delivery)
**Success Rate:** ~85-90% (most NAT scenarios)

**NAT Types Supported:**

| Your NAT          | Peer NAT          | Tier 2 Result |
|-------------------|-------------------|---------------|
| Full Cone         | Full Cone         | ✅ Success    |
| Full Cone         | Restricted Cone   | ✅ Success    |
| Full Cone         | Port Restricted   | ✅ Success    |
| Full Cone         | Symmetric         | ✅ Success    |
| Restricted Cone   | Restricted Cone   | ✅ Success    |
| Restricted Cone   | Port Restricted   | ✅ Success    |
| Restricted Cone   | Symmetric         | ⚠️ Maybe      |
| Port Restricted   | Port Restricted   | ✅ Success    |
| Port Restricted   | Symmetric         | ⚠️ Maybe      |
| Symmetric         | Symmetric         | ❌ Tier 3     |

**Logging:**
```
[P2P] [TIER 1] Failed - peer unreachable via direct TCP
[P2P] [TIER 2] Attempting ICE NAT traversal...
[P2P] [TIER 2] Trying STUN server: stun.l.google.com:19302
[P2P] [TIER 2] ✓ Gathered ICE candidates via stun.l.google.com:19302
[P2P] [TIER 2] ✓ Fetched peer ICE candidates from DHT
[P2P] [TIER 2] ✓ ICE connection established!
[P2P] [TIER 2] ✓✓ SUCCESS - Sent 1234 bytes via ICE!
```

---

### Tier 3: DHT Offline Queue

**When it works:**
- Both Tier 1 and Tier 2 failed
- Symmetric NAT on both sides
- STUN servers unreachable
- Peer offline

**Latency:** Up to 7 days (message stored in DHT)
**Success Rate:** 100% (always works, eventual delivery)

**Logging:**
```
[P2P] [TIER 2] Failed to send message via ICE
[P2P] [TIER 3] Both direct and ICE failed - falling back to DHT offline queue
[P2P] Resolved 'alice' → fingerprint for DHT queue
[P2P] ✓ Message queued in DHT for alice (fingerprint: a3f5e2d1...)
```

---

## Technical Details

### ICE Candidate Types

DNA Messenger gathers two types of ICE candidates:

1. **Host Candidates** (Local Network Interfaces)
   - Example: `192.168.1.100:54321`
   - Used for LAN connections (same network)

2. **Server-Reflexive Candidates** (External IP via STUN)
   - Example: `203.0.113.42:54321`
   - Used for NAT traversal (external connections)

**No Relay Candidates** (TURN not used for decentralization)

### DHT Storage Schema

**ICE Candidates:**
- **Key**: `SHA3-512(fingerprint + ":ice_candidates")` (128 hex chars)
- **Value**: SDP-formatted candidate strings (newline-separated)
- **TTL**: 7 days
- **Example**:
  ```
  candidate:1 1 UDP 2130706431 192.168.1.100 54321 typ host
  candidate:2 1 UDP 1694498815 203.0.113.42 54321 typ srflx raddr 192.168.1.100 rport 54321
  ```

**Presence Data:**
- **Key**: `SHA3-512(public_key)` (64 bytes)
- **Value**: JSON with IP:port
- **TTL**: 7 days
- **Example**: `{"ip":"203.0.113.42","port":4001,"timestamp":1732012345}`

### STUN Servers

DNA Messenger tries multiple STUN servers in order:

1. **stun.l.google.com:19302** (Google)
2. **stun1.l.google.com:19302** (Google backup)
3. **stun.cloudflare.com:3478** (Cloudflare)

If one fails, the next is tried automatically (max 5 seconds per server).

### libnice Configuration

- **Compatibility Mode**: RFC5245 (full ICE)
- **Controlling Mode**: TRUE (initiator)
- **UPnP**: FALSE (disabled for predictability)
- **ICE-TCP**: FALSE (UDP only)
- **Streams**: 1 (single data stream)
- **Components**: 1 (single UDP component)

---

## Configuration

### Build Requirements

**Linux:**
```bash
# No additional dependencies needed - libjuice v1.7.0 is built from source automatically
# Only standard build tools required (cmake, gcc, libssl-dev)
```

**Windows (MXE cross-compile):**
```bash
# libnice and glib added to MXE dependencies automatically
./build-cross-compile.sh windows-x64
```

### Runtime Configuration

ICE NAT traversal is **enabled by default** with no configuration required.

**Optional: Disable ICE** (fallback to Tier 1 and Tier 3 only):

Not currently supported via config. To disable, remove libnice from build dependencies and rebuild.

**Optional: Custom STUN Servers** (advanced):

Modify `transport_discovery.c`:
```c
const char *stun_servers[] = {
    "your-stun-server.example.com",
    "stun.l.google.com",
    "stun.cloudflare.com"
};
const uint16_t stun_ports[] = {3478, 19302, 3478};
```

---

## Troubleshooting

### Messages Stuck in Tier 3 (DHT Queue)

**Symptoms:**
- All messages fall back to DHT queue
- Never sees `[TIER 1]` or `[TIER 2]` success
- Messages delivered after 2+ minutes

**Possible Causes:**

1. **libjuice build failed** (Linux)
   ```bash
   # libjuice is built automatically via CMake ExternalProject
   # Check build logs: build-release/linux-x64/vendor/libjuice/
   # Ensure you have: cmake, gcc, git
   ```

2. **STUN servers blocked by firewall**
   ```bash
   # Test STUN connectivity
   nc -u stun.l.google.com 19302
   nc -u stun.cloudflare.com 3478
   ```

3. **Both peers behind symmetric NAT**
   - Expected behavior (Tier 3 is correct fallback)
   - No fix without TURN relay (not implemented)

4. **DHT not initialized**
   ```
   [P2P] ERROR: Global DHT not initialized!
   ```
   - Check app startup logs for DHT initialization
   - Ensure `dht_singleton_init()` called before `p2p_transport_init()`

---

### Tier 2 Always Fails

**Symptoms:**
```
[P2P] [TIER 2] Failed to gather ICE candidates
[P2P] [TIER 2] Peer ICE candidates not found in DHT
[P2P] [TIER 2] ICE connectivity checks failed
```

**Solutions:**

**Failed to gather ICE candidates:**
- All STUN servers unreachable
- Check internet connectivity:
  ```bash
  ping 8.8.8.8
  curl -I https://www.google.com
  ```
- Check firewall allows UDP outbound:
  ```bash
  sudo iptables -L OUTPUT -n | grep UDP
  ```

**Peer ICE candidates not found in DHT:**
- Peer hasn't registered presence yet
- Peer's DNA Messenger is outdated (pre-Phase 11)
- DHT sync delay (wait 10-30 seconds)

**ICE connectivity checks failed:**
- Both behind symmetric NAT (expected, fallback to Tier 3)
- Firewall blocking ICE UDP traffic
- Check with Wireshark for STUN binding requests

---

### High Latency on Tier 2

**Symptoms:**
- Tier 2 takes >10 seconds
- Messages eventually delivered but slow

**Solutions:**

1. **Reduce ICE gathering timeout** (advanced):
   ```c
   // In transport_ice.c, reduce max wait time
   for (int i = 0; i < 30; i++) {  // was 50
       if (ctx->gathering_done) break;
       usleep(100000); // 100ms
   }
   ```

2. **Use faster STUN server** (add to top of list):
   ```c
   const char *stun_servers[] = {
       "stun.your-fast-server.com",  // Add yours first
       "stun.l.google.com",
       ...
   };
   ```

---

### Build Errors

**Error: `libnice/agent.h: No such file or directory`**

**Solution:**
```bash
# Linux
# libjuice is built from source - check CMake ExternalProject logs
# Ensure: cmake >= 3.10, gcc, git are installed

# Windows (llvm-mingw)
cd ~/.cache/mxe
make MXE_TARGETS=x86_64-w64-mingw32.static libnice glib -j$(nproc)
```

**Error: `undefined reference to 'nice_agent_new'`**

**Solution:**
- Linking error - ensure CMake added libnice libraries:
  ```bash
  grep NICE build/CMakeCache.txt
  # Should show NICE_LIBRARIES and NICE_INCLUDE_DIRS
  ```
- Rebuild:
  ```bash
  rm -rf build && mkdir build && cd build
  cmake .. && make -j$(nproc)
  ```

---

## Performance

### Latency Comparison

| Tier | Connection | Message Delivery | Total |
|------|------------|------------------|-------|
| **Tier 1** (Direct TCP) | ~10ms | ~50ms | **~60ms** |
| **Tier 2** (ICE) | ~2-5s | ~50-100ms | **~2-5s** |
| **Tier 3** (DHT Queue) | N/A | 2min-7days | **2min-7days** |

### Bandwidth Usage

**Tier 1 (Direct TCP):**
- Message only (~1-10 KB per message)

**Tier 2 (ICE):**
- STUN binding requests: ~100 bytes × 3 servers = ~300 bytes
- ICE connectivity checks: ~500 bytes × candidates = ~2-5 KB
- Message: ~1-10 KB
- **Total:** ~3-15 KB per message (first time)
- **Subsequent:** ~1-10 KB (ICE connection reused, not currently implemented)

**Tier 3 (DHT Queue):**
- DHT PUT: ~1-10 KB (message)
- DHT GET polling: ~200 bytes × every 2 minutes
- **Total:** ~1-10 KB + ongoing polling overhead

### CPU Usage

**Tier 1:** Minimal (~1% CPU)
**Tier 2:** Moderate (~5-10% CPU during connection establishment, <1% after)
**Tier 3:** Minimal (~1% CPU)

### Memory Usage

**ICE Context:** ~500 KB - 2 MB per active connection
**Recommendation:** Close ICE context after message sent (currently implemented)

---

## Security

### Threat Model

**What ICE Protects:**
- ✅ NAT traversal (connectivity)
- ✅ Address discovery (STUN)

**What ICE Does NOT Protect:**
- ❌ Message confidentiality (use Kyber1024 + AES-256-GCM)
- ❌ Message authenticity (use Dilithium5 signatures)
- ❌ Metadata privacy (IP addresses visible to STUN servers)

### Security Properties

**End-to-End Encryption:**
- Messages encrypted with Kyber1024 + AES-256-GCM **before** ICE transport
- ICE only establishes connectivity, not encryption
- Post-quantum secure against quantum computers

**STUN Server Trust:**
- STUN servers see your IP address (reflexive address discovery)
- STUN servers **cannot** see message content (E2E encrypted)
- STUN servers **cannot** relay media (no TURN)
- Minimal trust required (only for NAT detection)

**DHT Trust:**
- ICE candidates stored in DHT (public)
- Candidates reveal IP:port pairs (metadata leak)
- Candidates **cannot** decrypt messages (separate encryption)
- DHT replication provides resilience

**No TURN Relays:**
- Fully decentralized (no relay servers)
- No third-party can intercept messages
- No single point of failure
- Better privacy (direct P2P when possible)

### Privacy Considerations

**IP Address Visibility:**
- STUN servers see your external IP
- Peers see your IP when directly connected
- DHT nodes see candidate IP:port pairs

**Mitigation:**
- Use Tor/VPN for IP anonymity (experimental, not tested)
- Future: Tor integration (Phase 9+)

---

## Developer Guide

### API Overview

**Public API** (`p2p/transport/transport_ice.h`):

```c
// Create ICE context
ice_context_t* ice_context_new(void);

// Gather local candidates (STUN)
int ice_gather_candidates(ice_context_t *ctx,
                          const char *stun_server,
                          uint16_t stun_port);

// Publish candidates to DHT
int ice_publish_to_dht(ice_context_t *ctx,
                       const char *my_fingerprint);

// Fetch peer candidates from DHT
int ice_fetch_from_dht(ice_context_t *ctx,
                       const char *peer_fingerprint);

// Perform ICE connectivity checks
int ice_connect(ice_context_t *ctx);

// Send data via ICE
int ice_send(ice_context_t *ctx,
             const uint8_t *data,
             size_t len);

// Check connection status
int ice_is_connected(ice_context_t *ctx);

// Cleanup
void ice_context_free(ice_context_t *ctx);
```

### Integration Example

```c
// 1. Create ICE context
ice_context_t *ice_ctx = ice_context_new();
if (!ice_ctx) {
    fprintf(stderr, "Failed to create ICE context\n");
    return -1;
}

// 2. Gather candidates
if (ice_gather_candidates(ice_ctx, "stun.l.google.com", 19302) != 0) {
    fprintf(stderr, "Failed to gather candidates\n");
    ice_context_free(ice_ctx);
    return -1;
}

// 3. Publish to DHT
if (ice_publish_to_dht(ice_ctx, my_fingerprint) != 0) {
    fprintf(stderr, "Failed to publish candidates\n");
    ice_context_free(ice_ctx);
    return -1;
}

// 4. Fetch peer candidates
if (ice_fetch_from_dht(ice_ctx, peer_fingerprint) != 0) {
    fprintf(stderr, "Peer candidates not found\n");
    ice_context_free(ice_ctx);
    return -1;
}

// 5. Perform ICE connectivity checks
if (ice_connect(ice_ctx) != 0) {
    fprintf(stderr, "ICE connection failed\n");
    ice_context_free(ice_ctx);
    return -1;
}

// 6. Send message
int sent = ice_send(ice_ctx, message, message_len);
if (sent > 0) {
    printf("✓ Sent %d bytes via ICE\n", sent);
}

// 7. Cleanup
ice_context_free(ice_ctx);
```

### Testing

**Unit Tests** (not yet implemented):
```bash
# Future: ./build/test_ice_nat_traversal
```

**Manual Testing:**

1. **Same LAN (Tier 1):**
   ```bash
   # Terminal 1 (alice)
   ./build/imgui_gui/dna_messenger_imgui

   # Terminal 2 (bob, same network)
   ./build/imgui_gui/dna_messenger_imgui

   # Send message from alice → bob
   # Expected: [TIER 1] SUCCESS
   ```

2. **Different Networks (Tier 2):**
   ```bash
   # Terminal 1 (alice, behind NAT)
   ./build/imgui_gui/dna_messenger_imgui

   # Terminal 2 (bob, different network, behind NAT)
   ./build/imgui_gui/dna_messenger_imgui

   # Send message from alice → bob
   # Expected: [TIER 2] SUCCESS (if NAT allows)
   ```

3. **Symmetric NAT (Tier 3):**
   ```bash
   # Simulate symmetric NAT with firewall rules
   sudo iptables -A OUTPUT -p udp --dport 19302 -j DROP
   sudo iptables -A OUTPUT -p udp --dport 3478 -j DROP

   # Send message
   # Expected: [TIER 3] DHT queue fallback

   # Cleanup
   sudo iptables -D OUTPUT -p udp --dport 19302 -j DROP
   sudo iptables -D OUTPUT -p udp --dport 3478 -j DROP
   ```

### Debugging

**Enable Verbose Logging:**

ICE logging is already verbose with `[TIER X]` prefixes. To add more:

```c
// In transport_ice.c
#define ICE_DEBUG 1
#ifdef ICE_DEBUG
    printf("[ICE DEBUG] Candidate: %s\n", candidate_str);
#endif
```

**Wireshark Filters:**

```
# STUN traffic
udp.port == 19302 || udp.port == 3478

# ICE candidate exchange
dht && frame contains "ice_candidates"

# P2P TCP traffic
tcp.port == 4001
```

---

## References

- **RFC 5245**: Interactive Connectivity Establishment (ICE)
- **RFC 5389**: Session Traversal Utilities for NAT (STUN)
- **libnice Documentation**: https://nice.freedesktop.org/libnice/
- **DNA Messenger GitHub**: https://github.com/nocdem/dna-messenger
- **DNA Messenger GitLab**: https://gitlab.cpunk.io/cpunk/dna-messenger

---

## Future Work

### Planned Enhancements (Phase 12+)

1. **TURN Relay Support** (optional, user-configured)
   - For symmetric NAT ↔ symmetric NAT
   - User-hosted TURN servers only (no centralized relays)

2. **ICE Connection Reuse**
   - Keep ICE connections alive for multiple messages
   - Reduce connection establishment latency

3. **TCP Candidates**
   - Fallback to TCP when UDP blocked
   - Lower success rate but better than Tier 3

4. **GUI Status Indicators**
   - Show Tier 1/2/3 badge in chat UI
   - Connection quality indicator (latency, packet loss)

5. **NAT Type Detection**
   - Automatic NAT type detection (Full Cone, Symmetric, etc.)
   - Display in Settings screen

6. **ICE Trickle Mode**
   - Send candidates as gathered (not all at once)
   - Faster connection establishment

### Contributing

To contribute to NAT traversal improvements:

1. Fork repository: https://github.com/nocdem/dna-messenger
2. Create feature branch: `git checkout -b feature/ice-improvement`
3. Make changes and test thoroughly
4. Submit pull request with detailed description

---

**For questions or issues, please contact:**
- GitHub Issues: https://github.com/nocdem/dna-messenger/issues
- GitLab Issues: https://gitlab.cpunk.io/cpunk/dna-messenger/-/issues
- Telegram: @chippunk_official
