# DNA Nodus - Post-Quantum DHT Bootstrap + STUN/TURN Server

**Version:** 0.3
**Security:** FIPS 204 / ML-DSA-87 (Dilithium5) - NIST Category 5

## Overview

DNA Nodus is the bootstrap and relay infrastructure for DNA Messenger. It provides:

1. **DHT Bootstrap Node** - Entry point for new clients joining the DHT network
2. **STUN Server** - NAT traversal via Session Traversal Utilities for NAT
3. **TURN Server** - Relay server for clients behind symmetric NAT
4. **Credential Manager** - DHT-based authentication for TURN access

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       DNA Nodus v0.3                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐│
│  │ DHT Context │  │ TURN Server │  │ Credential UDP Server││
│  │   (4000)    │  │   (3478)    │  │       (3479)         ││
│  └─────────────┘  └─────────────┘  └──────────────────────┘│
│         │                │                    │             │
│         │                │                    │             │
│  ┌──────┴────────────────┴────────────────────┴──────────┐ │
│  │              SQLite Persistence Layer                  │ │
│  │         /var/lib/dna-dht/bootstrap.state.values.db    │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

DNA Nodus uses a JSON configuration file at `/etc/dna-nodus.conf`. No CLI arguments are needed.

### Configuration File Format

```json
{
    "dht_port": 4000,
    "seed_nodes": [
        "154.38.182.161",
        "164.68.105.227",
        "164.68.116.180"
    ],
    "persistence_path": "/var/lib/dna-dht/bootstrap.state",
    "turn_port": 3478,
    "credential_port": 3479,
    "relay_port_begin": 49152,
    "relay_port_end": 65535,
    "credential_ttl_seconds": 604800,
    "identity": "dna-bootstrap-node",
    "public_ip": "auto",
    "verbose": false
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `dht_port` | 4000 | UDP port for DHT operations |
| `seed_nodes` | US-1 | List of seed node IPs |
| `persistence_path` | `/var/lib/dna-dht/bootstrap.state` | SQLite database path |
| `turn_port` | 3478 | UDP port for STUN/TURN |
| `credential_port` | 3479 | UDP port for direct credential requests |
| `relay_port_begin` | 49152 | Start of relay port range |
| `relay_port_end` | 65535 | End of relay port range |
| `credential_ttl_seconds` | 604800 | TURN credential validity (7 days) |
| `identity` | `dna-bootstrap-node` | Node identity string |
| `public_ip` | `auto` | Public IP (or "auto" to detect) |
| `verbose` | false | Enable verbose logging |

## Components

### 1. DHT Bootstrap Node

The DHT bootstrap node provides:
- Entry point for new clients joining the network
- Dilithium5 signature enforcement for all DHT operations
- SQLite persistence for DHT values
- Bootstrap registry for peer discovery

**Key Features:**
- Mandatory post-quantum signatures (FIPS 204 compliant)
- 7-day TTL for stored values
- Automatic peer discovery via DHT registry
- Cross-node value synchronization

### 2. STUN/TURN Server (libjuice)

DNA Nodus includes a STUN/TURN server using libjuice:

**STUN (UDP 3478):**
- Binding requests for NAT discovery
- Reflexive address discovery
- ICE candidate gathering support

**TURN (UDP 3478):**
- Relay for symmetric NAT traversal
- Authenticated allocations
- Credential-based access control

### 3. Credential UDP Server (Port 3479)

The credential UDP server provides fast, direct TURN credential requests bypassing DHT.

**Protocol: DNAC (DNA Credentials)**
- Magic: `0x444E4143` ("DNAC")
- Version: 1
- Port: 3479 (UDP)

**Request Flow (Direct UDP):**
1. Client connects to any bootstrap server on UDP port 3479
2. Client sends signed request: `[magic][version][type][timestamp][fingerprint][nonce][signature]`
3. Server verifies timestamp freshness (5-minute tolerance)
4. Server generates username/password, adds to libjuice TURN server
5. Server responds with TURN credentials: `[magic][version][type][count][server_entries]`

**Why UDP instead of DHT polling?**
- **Faster:** ~50ms vs ~300ms+ for DHT round-trip
- **More reliable:** Direct connection, no DHT propagation delays
- **Simpler:** No need for DHT watchers or polling loops
- **Fallback:** DHT-based credentials still available as backup

**Security Features:**
- Timestamp validation (5-minute tolerance)
- Dilithium5 signature verification (TODO: full implementation)
- Random nonce prevents replay attacks
- Credential TTL enforcement (7 days default)

### 4. Legacy Credential Manager (DHT-based)

The DHT-based credential manager is kept as fallback:

**Request Flow (DHT Fallback):**
1. Client creates signed request with Dilithium5 key
2. Request includes: version, type, timestamp, nonce, pubkey, signature
3. Request published to DHT key: `SHA3-512(fingerprint + ":turn_request")`
4. Nodus polls for requests, verifies signature and timestamp
5. Nodus generates username/password and adds to TURN server
6. Response published to DHT key: `SHA3-512(fingerprint + ":turn_credentials")`

**Credential Sync:**
- Credentials synced between nodus instances via DHT
- All nodus servers accept credentials from any issuer
- 1-hour sync TTL with frequent refresh

## Protocol Details

### UDP Credential Protocol (Port 3479)

**Magic Header:** `0x444E4143` ("DNAC" in ASCII)

### Request Format (Client → Server)

```
Offset  Size   Field
0       4      Magic (0x444E4143)
4       1      Version (1)
5       1      Type (1 = credential request)
6       8      Timestamp (Unix epoch, big-endian)
14      128    Fingerprint (hex string, null-padded)
142     32     Nonce (random bytes)
174     4627   Dilithium5 signature (over timestamp+fingerprint+nonce)
─────────────────────────────────────────────────────────────────
Total: 4801 bytes
```

### Response Format (Server → Client)

```
Offset  Size   Field
0       4      Magic (0x444E4143)
4       1      Version (1)
5       1      Type (2 = credential response)
6       1      Server count (1-4)

Per server entry (330 bytes each):
+0      64     Host (null-terminated string)
+64     2      Port (big-endian)
+66     128    Username (null-terminated string)
+194    128    Password (null-terminated string)
+322    8      Expires (Unix epoch, big-endian)
```

### Error Response

```
Offset  Size   Field
0       4      Magic (0x444E4143)
4       1      Version (1)
5       1      Type (3 = error)
6       1      Error code
```

### Legacy DHT Protocol (Fallback)

For DHT-based credential exchange (used as fallback):

**DHT Request Format:**
```
Offset  Size   Field
0       1      Version (1)
1       1      Type (1 = credential request)
2       8      Timestamp (Unix epoch, little-endian)
10      32     Nonce (random)
42      2592   Dilithium5 public key
2634    4627   Dilithium5 signature (over bytes 0-2633)
```

**DHT Response Format:**
```
Offset  Size   Field
0       1      Version (1)
1       1      Type (2 = credential response)
2       1      Server count

Per server (330 bytes each):
+0      64     Host
+64     2      Port
+66     128    Username
+194    128    Password
+322    8      Expires (Unix epoch)
```

## Deployment

### Systemd Service

DNA Nodus includes a systemd service file:

```bash
# Copy service file
sudo cp vendor/opendht-pq/tools/systemd/dna-nodus.service /etc/systemd/system/

# Create config
sudo cp vendor/opendht-pq/tools/dna-nodus.conf.example /etc/dna-nodus.conf

# Create persistence directory
sudo mkdir -p /var/lib/dna-dht

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable dna-nodus
sudo systemctl start dna-nodus
```

### Manual Start

```bash
# Build
mkdir build && cd build
cmake -DBUILD_GUI=OFF .. && make -j$(nproc)

# Run (loads /etc/dna-nodus.conf)
./vendor/opendht-pq/tools/dna-nodus
```

### Production Servers

Current DNA Nodus servers:
- **US-1:** 154.38.182.161:4000 (DHT) / :3478 (TURN) / :3479 (CRED)
- **EU-1:** 164.68.105.227:4000 (DHT) / :3478 (TURN) / :3479 (CRED)
- **EU-2:** 164.68.116.180:4000 (DHT) / :3478 (TURN) / :3479 (CRED)

### Update All Servers

To update all production servers at once:

```bash
./update-nodus-servers.sh
```

This script runs `nodus_build.sh` on each server sequentially (US-1, EU-1, EU-2).

To update a single server manually:

```bash
ssh root@154.38.182.161 "cd /opt/dna-messenger && bash nodus_build.sh"  # US-1
ssh root@164.68.105.227 "cd /opt/dna-messenger && bash nodus_build.sh"  # EU-1
ssh root@164.68.116.180 "cd /opt/dna-messenger && bash nodus_build.sh"  # EU-2
```

## Monitoring

### Status Output

DNA Nodus prints status every 60 seconds:

```
[1 min] [5 nodes] [128 values] | DB: 1024 | TURN: 3 creds | Issued: 12
```

Fields:
- **nodes** - Number of DHT nodes discovered
- **values** - Number of values in DHT routing table
- **DB** - Values in SQLite persistence
- **TURN** - Active TURN credentials
- **Issued** - Total credentials issued

### Peer Discovery

Every 5 minutes, nodus:
1. Refreshes own registration in bootstrap registry
2. Fetches registry for new peers
3. Connects to discovered peers
4. Updates credential manager's TURN server list

## Files Created

```
/opt/dna-messenger/
├── vendor/opendht-pq/tools/
│   ├── dna-nodus.cpp              # Main entry point
│   ├── nodus_config.h             # Config structure
│   ├── nodus_config.cpp           # JSON config loader
│   ├── turn_server.h              # TURN server wrapper
│   ├── turn_server.cpp            # libjuice wrapper impl
│   ├── turn_credential_manager.h  # Credential manager API (DHT-based)
│   ├── turn_credential_manager.cpp# DHT credential handling (fallback)
│   ├── turn_credential_udp.h      # UDP credential server API
│   ├── turn_credential_udp.cpp    # Direct UDP credential handling
│   ├── dna-nodus.conf.example     # Example config file
│   └── systemd/
│       └── dna-nodus.service      # Systemd service file
├── vendor/nlohmann/
│   └── json.hpp                   # JSON parser (header-only)
└── p2p/transport/
    ├── turn_credentials.h         # Client credential API
    └── turn_credentials.c         # Client credential request (UDP + DHT fallback)
```

## Client Integration

### ICE Connection with TURN Fallback

The transport layer (`transport_juice.c`) now supports TURN fallback:

1. Client gathers ICE candidates via STUN
2. Client exchanges candidates via DHT
3. Client attempts ICE connectivity checks
4. **If ICE fails:** Request TURN credentials from nodus
5. Retry ICE with TURN relay candidates

### Client Credential Flow

The client tries UDP first for speed, then falls back to DHT:

```c
// 1. Initialize credential client
turn_credentials_init();

// 2. Check cache for valid credentials
turn_credentials_t creds;
if (turn_credentials_get_cached(fingerprint, &creds) != 0) {
    // 3. Request new credentials from nodus
    // Internally: tries UDP (port 3479) first, then DHT fallback
    turn_credentials_request(fingerprint, pubkey, privkey, &creds, 30000);
}

// 4. Use credentials for TURN
juice_turn_server_t turn = {
    .host = creds.servers[0].host,
    .port = creds.servers[0].port,
    .username = creds.servers[0].username,
    .password = creds.servers[0].password
};
```

**Bootstrap Servers (hardcoded in client):**
```c
static const char *bootstrap_servers[] = {
    "154.38.182.161",   // US-1
    "164.68.105.227",   // EU-1
    "164.68.116.180",   // EU-2
    NULL
};
#define CREDENTIAL_UDP_PORT 3479
```

## Security Considerations

1. **Post-Quantum Signatures** - All DHT operations require Dilithium5 signatures
2. **Timestamp Freshness** - Requests older than 5 minutes are rejected
3. **Replay Protection** - Nonce tracking prevents credential request replay
4. **Credential Rotation** - 7-day TTL with automatic renewal
5. **No Anonymous Access** - TURN requires authenticated credentials

## Troubleshooting

### Common Issues

**1. Config not loading**
```bash
# Check config exists
cat /etc/dna-nodus.conf

# Check JSON syntax
python3 -m json.tool /etc/dna-nodus.conf
```

**2. Port binding failure**
```bash
# Check port availability
netstat -tulpn | grep -E '4000|3478|3479'

# Run with root for privileged ports
sudo ./dna-nodus
```

**3. No peer discovery**
```bash
# Verify seed nodes are reachable
nc -uvz 154.38.182.161 4000
```

**4. TURN credentials not syncing**
```bash
# Check DHT connectivity
# Watch for "[CRED] Synced credential" messages
```

## Version History

- **v0.3.1** - Added direct UDP credential server (port 3479), faster than DHT polling
- **v0.3** - Added TURN server and credential management
- **v0.2** - Added bootstrap registry and peer discovery
- **v0.1** - Initial DHT bootstrap with SQLite persistence
