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
│  │ DHT Context │  │ TURN Server │  │ Credential Manager   ││
│  │   (4000)    │  │   (3478)    │  │   (DHT-based auth)   ││
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

### 3. Credential Manager

The credential manager handles DHT-based TURN authentication:

**Request Flow:**
1. Client creates signed request with Dilithium5 key
2. Request includes: version, type, timestamp, nonce, pubkey, signature
3. Request published to DHT key: `SHA3-512(fingerprint + ":turn_request")`
4. Nodus verifies signature and timestamp freshness
5. Nodus generates username/password and adds to TURN server
6. Response published to DHT key: `SHA3-512(fingerprint + ":turn_credentials")`

**Security Features:**
- Timestamp validation (5-minute tolerance)
- Nonce tracking for replay protection
- Dilithium5 signature verification
- Credential TTL enforcement

**Credential Sync:**
- Credentials synced between nodus instances via DHT
- All nodus servers accept credentials from any issuer
- 1-hour sync TTL with frequent refresh

## Protocol Details

### TURN Credential Request Format

```
Offset  Size   Field
0       1      Version (1)
1       1      Type (1 = credential request)
2       8      Timestamp (Unix epoch, little-endian)
10      32     Nonce (random)
42      2592   Dilithium5 public key
2634    4627   Dilithium5 signature (over bytes 0-2633)
```

### TURN Credential Response Format

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
- **US-1:** 154.38.182.161:4000 (DHT) / :3478 (TURN)
- **EU-1:** 164.68.105.227:4000 (DHT) / :3478 (TURN)
- **EU-2:** 164.68.116.180:4000 (DHT) / :3478 (TURN)

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
│   ├── turn_credential_manager.h  # Credential manager API
│   ├── turn_credential_manager.cpp# DHT credential handling
│   ├── dna-nodus.conf.example     # Example config file
│   └── systemd/
│       └── dna-nodus.service      # Systemd service file
├── vendor/nlohmann/
│   └── json.hpp                   # JSON parser (header-only)
└── p2p/transport/
    ├── turn_credentials.h         # Client credential API
    └── turn_credentials.c         # Client credential request
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

```c
// 1. Initialize credential client
turn_credentials_init();

// 2. Check cache for valid credentials
turn_credentials_t creds;
if (turn_credentials_get_cached(fingerprint, &creds) != 0) {
    // 3. Request new credentials from nodus
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
netstat -tulpn | grep -E '4000|3478'

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

- **v0.3** - Added TURN server and credential management
- **v0.2** - Added bootstrap registry and peer discovery
- **v0.1** - Initial DHT bootstrap with SQLite persistence
