# DNA Messenger Bootstrap Server

This directory contains the dedicated bootstrap server implementation for the DNA Messenger DHT network.

## Architecture

Bootstrap servers are specialized DHT nodes that provide:
- **Persistent storage** for critical DHT values (identity keys, name registrations)
- **Network stability** through reliable 24/7 uptime
- **Keyserver service** for public key storage/lookup
- **Offline queue storage** for asynchronous message delivery

## Directory Structure

```
bootstrap/
├── core/                       # Bootstrap-specific core logic
│   ├── bootstrap_main.c        # Main binary entry point
│   ├── bootstrap_config.*      # Configuration management
│   ├── bootstrap_stats.*       # Metrics & monitoring
│   └── bootstrap_dht_context.* # DHT context with persistence logic
│
├── services/                   # Active bootstrap services
│   ├── value_storage/          # SQLite-backed DHT value persistence
│   │   ├── dht_value_storage.* # Storage implementation
│   │   └── migrate_storage_once.cpp # DB migration utility
│   ├── keyserver_service.*     # Keyserver storage service (wrapper)
│   └── queue_service.*         # Offline queue service (wrapper)
│
├── deployment/                 # Deployment scripts & configs
│   ├── deploy-bootstrap.sh     # VPS deployment automation
│   ├── monitor-bootstrap.sh    # Health monitoring
│   └── dna-dht-bootstrap.service # Systemd service config
│
├── extensions/                 # Future extensible services (empty for now)
│   └── README.md               # Plugin API documentation
│
└── CMakeLists.txt              # Minimal build system (no messenger/wallet deps)
```

## Build System

The bootstrap server uses a minimal subset of DNA Messenger libraries:

### Dependencies
- **Shared:** `dht/core/` (DHT context, errors, key generation)
- **Crypto:** `crypto/utils/` (SHA3, AES, Dilithium, Kyber for verification only)
- **External:** OpenDHT, SQLite3, GnuTLS

### NOT Included (Client-Only)
- Messenger core
- Wallet integration
- Blockchain RPC
- ImGui GUI
- Contact lists
- Identity backup
- Profile editing

**Result:** ~40% smaller binary, faster startup, minimal attack surface.

## Current Bootstrap Nodes

| Name | IP | Location | Status |
|------|-----|----------|--------|
| dna-bootstrap-us-1 | 154.38.182.161:4000 | US | Active |
| dna-bootstrap-eu-1 | 164.68.105.227:4000 | EU | Active |
| dna-bootstrap-eu-2 | 164.68.116.180:4000 | EU | Active |

## Services Provided

### 1. DHT Routing (Core)
- Kademlia peer discovery
- NAT traversal assistance
- Network stabilization

### 2. Value Storage
- **PERMANENT values:** Identity keys (never expire)
- **365-day values:** Name registrations (annual renewal)
- **Automatic republishing:** Background thread restores values on restart

### 3. Keyserver
- Public key publishing/lookup
- Name registration/resolution
- Blockchain address lookup
- Reverse fingerprint mapping

### 4. Offline Queue
- Model E sender outbox
- 7-day message queueing
- Signed value storage

## Deployment

### Quick Deploy
```bash
cd /opt/dna-messenger/bootstrap/deployment
./deploy-bootstrap.sh dna-bootstrap-us-1 154.38.182.161
```

### Monitor Health
```bash
./monitor-bootstrap.sh         # Check all 3 nodes
./monitor-bootstrap.sh 154.38.182.161  # Check specific node
```

### Manual Deployment
1. Build bootstrap binary:
   ```bash
   mkdir build && cd build
   cmake ..
   make persistent_bootstrap
   ```

2. Upload to VPS:
   ```bash
   scp build/bootstrap/persistent_bootstrap root@IP:/opt/dna-messenger/
   scp bootstrap/deployment/dna-dht-bootstrap.service root@IP:/etc/systemd/system/
   ```

3. Start service:
   ```bash
   ssh root@IP
   systemctl enable dna-dht-bootstrap
   systemctl start dna-dht-bootstrap
   ```

## Configuration

Bootstrap nodes are configured via `dht_config_t` in bootstrap_main.c:

```c
dht_config_t config = {
    .port = 4000,
    .is_bootstrap = true,  // Enables persistent storage
    .identity = "bootstrap-node",
    .bootstrap_nodes = {
        "154.38.182.161:4000",
        "164.68.105.227:4000",
        "164.68.116.180:4000"
    },
    .bootstrap_count = 3,
    .persistence_path = "/var/lib/dna-dht/bootstrap.state"
};
```

## Future Extensions

The `extensions/` directory is reserved for future services:

- **Name registration fees:** CPUNK payment integration
- **IPFS gateway:** Avatar/media pinning
- **Content moderation:** Wall post spam filtering
- **P2P relay:** NAT traversal relay for blocked clients

See `extensions/README.md` for plugin API documentation.

## Code Sharing with Client

Bootstrap uses a **hybrid approach:**

- **Shared core:** `dht/core/` (DHT context, crypto, key generation)
- **Shared keyserver:** `dht/keyserver/` (6 modules)
- **Shared queue/groups:** `dht/shared/` (offline queue, group storage)
- **Separate features:** Bootstrap has no messenger, wallet, or client-specific modules

This minimizes code duplication while maintaining clean separation.

## Maintenance

### Add New Bootstrap Node
1. Update `bootstrap/core/bootstrap_config.h` with new IP
2. Update `deployment/deploy-bootstrap.sh`
3. Update `deployment/monitor-bootstrap.sh`
4. Rebuild and deploy

### Upgrade Procedure
1. Deploy to test VPS first
2. Verify DHT network connectivity: `./monitor-bootstrap.sh <IP>`
3. Check value persistence: restart node, verify republishing
4. Rolling upgrade: one node at a time (maintain 2/3 quorum)

## Troubleshooting

### Bootstrap node not receiving peers
- Check firewall: port 4000 UDP+TCP
- Verify other bootstrap nodes are reachable
- Check systemd logs: `journalctl -u dna-dht-bootstrap -f`

### Value storage not persisting
- Check disk space: `/var/lib/dna-dht/`
- Verify SQLite database integrity: `sqlite3 bootstrap.state.values.db ".schema"`
- Check permissions: bootstrap process must own `/var/lib/dna-dht/`

### High memory usage
- Normal: 50-200MB for persistent storage
- Check orphaned values: `SELECT COUNT(*) FROM dht_values WHERE expires_at < ?`
- Run cleanup: DHT will auto-expire old values

## Security

### Hardening
- Run as non-root user (systemd User= directive)
- Minimal dependencies (no GUI, wallet, messenger)
- Read-only filesystem for binaries
- Firewall: only port 4000 exposed

### Attack Surface
- **DHT protocol:** OpenDHT handles malicious peers
- **Value storage:** Rate limiting + size limits (10MB max per value)
- **Keyserver:** Signature verification prevents spoofing
- **Offline queue:** Sender signatures prevent tampering

## Contact

- **GitLab:** https://gitlab.cpunk.io/cpunk/dna-messenger
- **GitHub:** https://github.com/nocdem/dna-messenger
- **Telegram:** @chippunk_official
- **Website:** https://cpunk.io
