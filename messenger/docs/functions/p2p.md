# P2P Transport Functions

**Directory:** `p2p/`

P2P transport layer providing DHT-based peer discovery and presence system.

> **Phase 14 (v0.3.154):** Direct P2P messaging removed - all messaging now uses DHT-only path.
> P2P/ICE infrastructure preserved for future voice/video calls.

---

## P2P Transport (`p2p_transport.h`)

### Core API

| Function | Description |
|----------|-------------|
| `p2p_transport_t* p2p_transport_init(const p2p_config_t*, ...)` | Initialize P2P transport layer |
| `int p2p_transport_start(p2p_transport_t*)` | Start DHT bootstrap + TCP listener |
| `void p2p_transport_stop(p2p_transport_t*)` | Stop transport and close connections |
| `void p2p_transport_free(p2p_transport_t*)` | Free transport context |
| `int p2p_transport_deliver_message(p2p_transport_t*, const uint8_t*, const uint8_t*, size_t)` | Deliver message via callback |

> **Note:** `p2p_transport_get_dht_context()` was removed in Phase 14 (v0.3.122). Use `dht_singleton_get()` directly.

### Peer Discovery

| Function | Description |
|----------|-------------|
| `int p2p_register_presence(p2p_transport_t*)` | Register presence in DHT |
| `int p2p_lookup_peer(p2p_transport_t*, const uint8_t*, peer_info_t*)` | Look up peer in DHT |
| `int p2p_lookup_presence_by_fingerprint(p2p_transport_t*, const char*, uint64_t*)` | Look up presence by fingerprint |

### DHT Offline Queue

| Function | Description |
|----------|-------------|
| `int p2p_check_offline_messages(p2p_transport_t*, const char* sender_fp, size_t*)` | Check for offline messages in DHT (sender_fp=NULL for all contacts) |
| `int p2p_queue_offline_message(p2p_transport_t*, const char*, const char*, const uint8_t*, size_t, uint64_t)` | Queue message for offline recipient |

> **Removed in v0.3.154:** `p2p_send_message()` - was dead code since Phase 14 (DHT-only messaging)

### Connection Management

| Function | Description |
|----------|-------------|
| `int p2p_get_connected_peers(p2p_transport_t*, uint8_t(*)[2592], size_t, size_t*)` | Get connected peers |
| `int p2p_disconnect_peer(p2p_transport_t*, const uint8_t*)` | Disconnect from peer |
| `int p2p_get_stats(p2p_transport_t*, size_t*, size_t*, size_t*, size_t*)` | Get transport statistics |
