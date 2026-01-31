# Transport Layer Functions

**Directory:** `transport/`

Transport layer providing DHT-based presence system and offline message queue.

> **Phase 14 (v0.3.154):** Direct P2P messaging removed - all messaging now uses DHT-only path.
> **v0.4.61:** ICE/STUN/TURN removed for privacy. Future voice/video will use alternative transport.
> **v0.4.61:** Renamed from `p2p_*` to `transport_*` for clarity (no P2P, only DHT).

---

## Transport Core (`transport/transport.h`)

### Lifecycle

| Function | Description |
|----------|-------------|
| `transport_t* transport_init(const transport_config_t*, ...)` | Initialize transport layer |
| `int transport_start(transport_t*)` | Start DHT bootstrap |
| `void transport_stop(transport_t*)` | Stop transport layer |
| `void transport_free(transport_t*)` | Free transport context |
| `int transport_deliver_message(transport_t*, const uint8_t*, size_t)` | Deliver message via registered callback |

### Presence System

| Function | Description |
|----------|-------------|
| `int transport_register_presence(transport_t*)` | Register presence timestamp in DHT |

### DHT Offline Queue

| Function | Description |
|----------|-------------|
| `int transport_check_offline_messages(transport_t*, const char* sender_fp, bool publish_watermarks, bool force_full_sync, size_t*)` | Check for offline messages in DHT (sender_fp=NULL for all contacts, force_full_sync=true bypasses smart sync for startup) |
| `int transport_queue_offline_message(transport_t*, const char*, const char*, const uint8_t*, size_t, uint64_t)` | Queue message for offline recipient |

---

## Messenger Transport Integration (`messenger_transport.h`)

### Lifecycle

| Function | Description |
|----------|-------------|
| `int messenger_transport_init(messenger_context_t*)` | Initialize transport for messenger (DHT bootstrap + presence registration) |
| `void messenger_transport_shutdown(messenger_context_t*)` | Shutdown transport and release resources |

### Messaging

| Function | Description |
|----------|-------------|
| `int messenger_queue_to_dht(messenger_context_t*, const char*, const uint8_t*, size_t, uint64_t)` | Queue encrypted message to DHT (Spillway) |
| `void messenger_transport_message_callback(const char*, const uint8_t*, size_t, void*)` | Callback when message arrives via DHT |

### Presence & Discovery

| Function | Description |
|----------|-------------|
| `bool messenger_transport_peer_online(messenger_context_t*, const char*)` | Check if peer is online via DHT |
| `int messenger_transport_list_online_peers(messenger_context_t*, char***, int*)` | Get list of online peers |
| `int messenger_transport_refresh_presence(messenger_context_t*)` | Re-announce presence (5-minute interval) |
| `int messenger_transport_lookup_presence(messenger_context_t*, const char*, uint64_t*)` | Lookup peer's last-seen timestamp from DHT |

### Offline Messages

| Function | Description |
|----------|-------------|
| `int messenger_transport_check_offline_messages(messenger_context_t*, const char*, bool publish_watermarks, bool force_full_sync, size_t*)` | Poll DHT for offline messages (force_full_sync=true for startup sync, false for periodic polling) |

---

## Removed Functions

The following functions were removed during the p2p → transport refactoring:

| Removed Function | Removal Version | Reason |
|-----------------|-----------------|--------|
| `p2p_transport_start()` TCP listener | v0.4.61 | TCP listener not used (DHT-only) |
| `p2p_lookup_peer()` | v0.4.61 | Dead code - direct P2P removed |
| `p2p_lookup_presence_by_fingerprint()` | v0.4.61 | Dead code - replaced by `messenger_transport_lookup_presence()` |
| `p2p_get_connected_peers()` | v0.4.61 | Dead code - no direct connections |
| `p2p_disconnect_peer()` | v0.4.61 | Dead code - no direct connections |
| `p2p_get_stats()` | v0.4.61 | Dead code - simplified API |
| `p2p_send_message()` | v0.3.154 | Dead code - Phase 14 DHT-only |
