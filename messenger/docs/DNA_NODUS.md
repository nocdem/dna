# DNA Nodus - Post-Quantum DHT Bootstrap Node

**Version:** 0.4.5
**Security:** FIPS 204 / ML-DSA-87 (Dilithium5) - NIST Category 5

## Overview

DNA Nodus is the bootstrap infrastructure for DNA Messenger. It provides:

1. **DHT Bootstrap Node** - Entry point for new clients joining the DHT network
2. **SQLite Persistence** - Durable storage for DHT values
3. **Bootstrap Registry** - Auto-discovery of peer nodus via DHT

**Privacy Note:** STUN/TURN was removed in v0.4.5 to eliminate IP address leakage to third-party servers. DNA Messenger now uses DHT-only messaging for improved privacy.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     DNA Nodus v0.4.5                         │
│                   (DHT-only, privacy-preserving)             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              DHT Context (UDP 4000)                      ││
│  │  - Post-quantum signatures (Dilithium5)                  ││
│  │  - Value persistence (SQLite)                            ││
│  │  - Bootstrap registry participation                      ││
│  └─────────────────────────────────────────────────────────┘│
│         │                                                    │
│  ┌──────┴──────────────────────────────────────────────────┐│
│  │              SQLite Persistence Layer                    ││
│  │         /var/lib/dna-dht/bootstrap.state.values.db      ││
│  └─────────────────────────────────────────────────────────┘│
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
| `identity` | `dna-bootstrap-node` | Node identity string |
| `public_ip` | `auto` | Public IP (or "auto" to detect) |
| `verbose` | false | Enable verbose logging |

**Note:** TURN configuration fields (`turn_port`, `credential_port`, etc.) are parsed but ignored for backwards compatibility with older config files.

## DHT Bootstrap Node

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

| Server | IP | DHT Port |
|--------|-----|----------|
| US-1 | 154.38.182.161 | 4000 |
| EU-1 | 164.68.105.227 | 4000 |
| EU-2 | 164.68.116.180 | 4000 |

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
[1 min] [5 nodes] [128 values] | DB: 1024
```

Fields:
- **nodes** - Number of DHT nodes discovered
- **values** - Number of values in DHT routing table
- **DB** - Values in SQLite persistence

### Peer Discovery

Every 5 minutes, nodus:
1. Refreshes own registration in bootstrap registry
2. Fetches registry for new peers
3. Connects to discovered peers

## Files

```
/opt/dna-messenger/
├── vendor/opendht-pq/tools/
│   ├── dna-nodus.cpp              # Main entry point
│   ├── nodus_config.h             # Config structure
│   ├── nodus_config.cpp           # JSON config loader
│   ├── nodus_version.h            # Version string
│   ├── dna-nodus.conf.example     # Example config file
│   └── systemd/
│       └── dna-nodus.service      # Systemd service file
└── vendor/nlohmann/
    └── json.hpp                   # JSON parser (header-only)
```

## Security Considerations

1. **Post-Quantum Signatures** - All DHT operations require Dilithium5 signatures
2. **No IP Leakage** - DHT-only mode prevents IP disclosure to third parties
3. **Distributed Architecture** - No central servers for message relay
4. **Timestamp-Only Presence** - Online status without IP disclosure

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
netstat -tulpn | grep 4000

# Run with root for privileged ports
sudo ./dna-nodus
```

**3. No peer discovery**
```bash
# Verify seed nodes are reachable
nc -uvz 154.38.182.161 4000
```

## Version History

- **v0.4.5** - Removed STUN/TURN for privacy (DHT-only mode)
- **v0.3.1** - Added direct UDP credential server (port 3479)
- **v0.3** - Added TURN server and credential management
- **v0.2** - Added bootstrap registry and peer discovery
- **v0.1** - Initial DHT bootstrap with SQLite persistence
