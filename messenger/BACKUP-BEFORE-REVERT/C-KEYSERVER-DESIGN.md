# C Keyserver Design Document

**Date:** 2025-10-16
**Status:** Design Phase
**Purpose:** Replace Node.js keyserver with C implementation while preserving distributed functionality

---

## Executive Summary

This document outlines the design for rewriting the bcpunk keyserver in C. The current Node.js implementation uses Hypercore/Hyperbee for distributed storage, but the user wants a C-based solution.

**Key Challenge:** Hypercore Protocol has no official C implementation.

**Solution:** Hybrid architecture - C for keyserver logic, minimal Node.js for P2P replication layer.

---

## Current Architecture Analysis

### Node.js Keyserver (`bcpunk-server/keyserver.mjs`)

**Components:**
1. **Corestore** - Manages Hypercore storage
2. **Hypercore** - Append-only log (key-value backend)
3. **Hyperbee** - B-tree on Hypercore (distributed database)
4. **Hyperswarm** - P2P networking with NAT traversal
5. **@hyperswarm/rpc** - DHT-based RPC (no direct connection needed)

**Operations:**
1. **Lookup RPC Method**: Query identity from Hyperbee
2. **Publish RPC Method**:
   - Validate payload structure
   - Verify Dilithium3 signature (via C `verify_json` binary)
   - Check version monotonicity
   - Store in Hyperbee

**Data Model:**
```javascript
Key: "handle/device"
Value: {
  v: 1,                      // Schema version
  handle: "nocdem",
  device: "default",
  dilithium_pub: "<base64>",
  kyber_pub: "<base64>",
  inbox_key: "<hex>",        // 32-byte Hypercore key
  version: 7,                // Monotonic version
  updated_at: 1729087244,    // Unix timestamp
  sig: "<base64>"            // Dilithium3 signature
}
```

**Security Features:**
- Dilithium3 signature verification (post-quantum)
- Version monotonicity (prevents replay attacks)
- Timestamp validation (prevents stale updates)
- Payload structure validation

---

## Design Options

### Option 1: Pure C with Hypercore C Implementation
**Description:** Implement Hypercore Protocol from scratch in C

**Pros:**
- No Node.js dependency
- Full control over implementation
- Better performance

**Cons:**
- **MASSIVE UNDERTAKING** - Would need to implement:
  - Hypercore Protocol (append-only log with Merkle tree)
  - Hyperbee Protocol (B-tree on Hypercore)
  - Hyperswarm Protocol (DHT, NAT traversal, peer discovery)
  - @hyperswarm/rpc Protocol
- Months of development time
- High risk of bugs and incompatibilities

**Verdict:** ❌ **NOT RECOMMENDED** - Too much work for minimal gain

---

### Option 2: C with libhypercore Bindings
**Description:** Use existing C bindings for Hypercore

**Status:** ❌ **No official C bindings exist**
- Hypercore is JavaScript-only
- Unofficial ports exist but unmaintained
- Would still need to port Hyperbee, Hyperswarm, RPC

**Verdict:** ❌ **NOT FEASIBLE**

---

### Option 3: C Keyserver + PostgreSQL + Hypercore Mirror
**Description:** Hybrid architecture - C handles all keyserver logic, Node.js daemon mirrors to Hyperbee

**Architecture:**
```
┌─────────────────────────────────────────┐
│         C Keyserver (Main Logic)        │
│  - RPC server (libsodium crypto)        │
│  - PostgreSQL storage                   │
│  - Signature verification (verify_json) │
│  - Version control                      │
└────────────┬────────────────────────────┘
             │ IPC (Unix socket)
             ↓
┌────────────────────────────────────────┐
│    Node.js Mirror Daemon (Optional)    │
│  - Reads from PostgreSQL                │
│  - Publishes to Hyperbee                │
│  - Provides P2P replication             │
└────────────────────────────────────────┘
```

**Pros:**
- ✅ C for all keyserver logic (user requirement)
- ✅ Use existing 3 C utilities (sign_json, verify_json, export_pubkey)
- ✅ PostgreSQL = proven, mature database
- ✅ Reuse existing Hypercore infrastructure (optional P2P)
- ✅ Can run C keyserver standalone (no Node.js required)
- ✅ Node.js mirror is optional add-on (for P2P replication)

**Cons:**
- Requires PostgreSQL dependency
- Mirror daemon adds complexity (but optional)

**Verdict:** ✅ **RECOMMENDED** - Best balance of C implementation + distributed features

---

### Option 4: C Keyserver with Custom DHT
**Description:** Replace Hypercore with custom C-based DHT/storage

**Pros:**
- Pure C implementation
- No Node.js dependency

**Cons:**
- Lose Hypercore's benefits (Merkle trees, verifiable logs)
- Need to implement own DHT (OpenDHT? Mainline DHT?)
- Need to implement own P2P protocol
- More complex networking code

**Verdict:** ⚠️ **POSSIBLE** - But loses proven Hypercore infrastructure

---

## Recommended Architecture: Option 3

### Components

#### 1. C Keyserver (`keyserver.c`)

**Responsibilities:**
- Accept RPC requests via UDP socket
- Validate payload structure
- Verify Dilithium3 signatures (via `verify_json`)
- Check version monotonicity
- Store/retrieve identities in PostgreSQL
- Return responses

**Dependencies:**
- **libsodium** - For Ed25519 RPC keypair
- **libpq** - PostgreSQL client
- **json-c** - JSON parsing
- **libuv** or **libev** - Event loop for async I/O

**RPC Protocol:**
```c
// Request format (msgpack or JSON over UDP)
{
  "method": "lookup" | "publish",
  "params": { ... },
  "id": <request_id>
}

// Response format
{
  "success": true|false,
  "data": { ... },
  "error": "...",
  "id": <request_id>
}
```

#### 2. PostgreSQL Schema

```sql
CREATE TABLE keyserver_entries (
  id SERIAL PRIMARY KEY,

  -- Identity
  handle VARCHAR(32) NOT NULL,
  device VARCHAR(32) NOT NULL,
  identity VARCHAR(65) UNIQUE NOT NULL, -- "handle/device"

  -- Public keys (base64)
  dilithium_pub TEXT NOT NULL,
  kyber_pub TEXT NOT NULL,
  inbox_key CHAR(64) NOT NULL,          -- hex, 32 bytes

  -- Versioning
  version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,          -- Unix timestamp

  -- Signature
  sig TEXT NOT NULL,                    -- base64 Dilithium3 signature

  -- Schema version
  schema_version INTEGER NOT NULL DEFAULT 1,

  -- Metadata
  created_at TIMESTAMP DEFAULT NOW(),
  last_updated TIMESTAMP DEFAULT NOW(),

  -- Indexes
  CONSTRAINT unique_identity UNIQUE(handle, device)
);

-- Index for fast lookup
CREATE INDEX idx_identity ON keyserver_entries(identity);
CREATE INDEX idx_handle ON keyserver_entries(handle);
CREATE INDEX idx_version ON keyserver_entries(identity, version);
```

#### 3. Node.js Mirror Daemon (`keyserver-mirror.mjs`) - OPTIONAL

**Purpose:** Provides P2P replication to Hypercore network

**Responsibilities:**
- Monitor PostgreSQL for changes (LISTEN/NOTIFY or polling)
- Publish changes to Hyperbee
- Replicate via Hyperswarm
- Keep DHT-based RPC server running

**Why Optional:**
- C keyserver works standalone
- Mirror only needed for P2P replication
- Can be disabled for centralized deployments

---

## Implementation Plan

### Phase 1: Core C Keyserver ✅ START HERE

**Files to Create:**
1. `keyserver.c` - Main keyserver logic
2. `keyserver.h` - Public API header
3. `rpc_server.c` - RPC server implementation
4. `db.c` - PostgreSQL wrapper
5. `validation.c` - Payload validation
6. `CMakeLists.txt` - Build configuration

**Tasks:**
- [x] Design architecture
- [ ] Implement RPC server (UDP + libsodium)
- [ ] Implement PostgreSQL storage layer
- [ ] Integrate `verify_json` for signature verification
- [ ] Implement lookup method
- [ ] Implement publish method
- [ ] Add version monotonicity check
- [ ] Add timestamp validation
- [ ] Write unit tests

**Dependencies:**
```bash
# Debian/Ubuntu
sudo apt-get install libsodium-dev libpq-dev libjson-c-dev libuv1-dev

# Arch
sudo pacman -S libsodium postgresql-libs json-c libuv
```

### Phase 2: Testing & Validation

**Test Cases:**
1. Publish new identity (version 1)
2. Publish update (version 2+)
3. Reject old version (monotonicity)
4. Reject invalid signature
5. Reject invalid timestamp
6. Lookup existing identity
7. Lookup non-existent identity
8. Concurrent publish requests

**Load Testing:**
- 100 concurrent publish requests
- 1000 lookup requests/second
- Memory leak testing (valgrind)

### Phase 3: Node.js Mirror (Optional)

**Only if P2P replication needed:**
- [ ] Implement PostgreSQL monitor (LISTEN/NOTIFY)
- [ ] Publish changes to Hyperbee
- [ ] Sync on startup (replay from PostgreSQL)
- [ ] Handle conflicts (last-write-wins)

### Phase 4: Deployment

- [ ] Docker container
- [ ] Systemd service unit
- [ ] Configuration file (keyserver.conf)
- [ ] Deployment scripts
- [ ] Monitoring (Prometheus metrics)

---

## API Specification

### C Keyserver RPC Methods

#### 1. Lookup

**Request:**
```json
{
  "method": "lookup",
  "params": {
    "identity": "nocdem/default"
  },
  "id": 123
}
```

**Response (Success):**
```json
{
  "success": true,
  "data": {
    "v": 1,
    "handle": "nocdem",
    "device": "default",
    "dilithium_pub": "<base64>",
    "kyber_pub": "<base64>",
    "inbox_key": "<hex>",
    "version": 7,
    "updated_at": 1729087244,
    "sig": "<base64>"
  },
  "id": 123
}
```

**Response (Not Found):**
```json
{
  "success": false,
  "error": "Not found",
  "id": 123
}
```

#### 2. Publish

**Request:**
```json
{
  "method": "publish",
  "params": {
    "v": 1,
    "handle": "nocdem",
    "device": "default",
    "dilithium_pub": "<base64>",
    "kyber_pub": "<base64>",
    "inbox_key": "<hex>",
    "version": 8,
    "updated_at": 1729087300,
    "sig": "<base64>"
  },
  "id": 456
}
```

**Response (Success):**
```json
{
  "success": true,
  "data": {
    "key": "nocdem/default",
    "version": 8
  },
  "id": 456
}
```

**Response (Failure):**
```json
{
  "success": false,
  "error": "Version must be greater than 7",
  "id": 456
}
```

---

## Security Considerations

### 1. Signature Verification
- **Method:** Call `verify_json` binary via `execve()`
- **Timeout:** 5 seconds (prevent DoS)
- **Sandboxing:** Run in separate process with `fork()` + `waitpid()`

### 2. SQL Injection Prevention
- **Method:** Use parameterized queries (libpq `PQexecParams`)
- **Never:** Concatenate user input into SQL

### 3. Rate Limiting
- **Per-IP limits:** 10 publish/minute, 100 lookup/minute
- **Global limits:** 1000 publish/minute, 10000 lookup/minute
- **Implementation:** Token bucket algorithm

### 4. Memory Safety
- **Use:** Bounded buffers, explicit length checks
- **Avoid:** `strcpy`, `strcat`, `sprintf`
- **Tools:** valgrind, AddressSanitizer

### 5. Version Monotonicity
- **Check:** `new_version > existing_version`
- **Transaction:** Use PostgreSQL `SELECT FOR UPDATE` to prevent race conditions

---

## Performance Targets

### C Keyserver

**Lookup:**
- Latency: < 5ms (PostgreSQL query)
- Throughput: > 5000 req/s (single core)

**Publish:**
- Latency: < 50ms (signature verification + DB write)
- Throughput: > 500 req/s (signature verification bottleneck)

**Memory:**
- Baseline: < 10 MB
- Per connection: < 1 KB

### Comparison: Node.js vs C

| Metric | Node.js | C (Expected) |
|--------|---------|--------------|
| Lookup latency | 10-20ms | < 5ms |
| Publish latency | 80-150ms | < 50ms |
| Memory (baseline) | 60-80 MB | < 10 MB |
| Memory (1000 conn) | 150-200 MB | < 20 MB |
| Throughput (lookup) | 1000/s | > 5000/s |
| Throughput (publish) | 100/s | > 500/s |

---

## Migration Path

### Step 1: Deploy C Keyserver Alongside Node.js

**Setup:**
- Run C keyserver on port 5001
- Keep Node.js keyserver on port 5000
- Configure C keyserver to use same PostgreSQL database
- Node.js publishes to both PostgreSQL and Hyperbee

### Step 2: Test C Keyserver

**Validation:**
- Send test lookups/publishes to C keyserver
- Compare responses with Node.js keyserver
- Verify signature verification works
- Check version monotonicity

### Step 3: Migrate Clients

**Process:**
- Update client config to use C keyserver RPC key
- Gradual rollout (10% → 50% → 100%)
- Monitor error rates

### Step 4: Retire Node.js Keyserver

**Options:**
- Keep Node.js mirror for P2P replication
- OR: Implement C version of Hypercore replication (future)
- OR: Run centralized C keyserver only

---

## File Structure

```
/opt/dna-messenger/
├── keyserver-c/           # New C keyserver
│   ├── src/
│   │   ├── main.c         # Main entry point
│   │   ├── keyserver.c    # Core logic
│   │   ├── keyserver.h
│   │   ├── rpc_server.c   # RPC protocol
│   │   ├── rpc_server.h
│   │   ├── db.c           # PostgreSQL wrapper
│   │   ├── db.h
│   │   ├── validation.c   # Payload validation
│   │   ├── validation.h
│   │   └── config.c       # Config file parsing
│   ├── tests/
│   │   ├── test_keyserver.c
│   │   ├── test_rpc.c
│   │   └── test_db.c
│   ├── sql/
│   │   ├── schema.sql     # PostgreSQL schema
│   │   └── migrations/
│   ├── config/
│   │   └── keyserver.conf # Configuration file
│   ├── CMakeLists.txt
│   └── README.md
├── utils/
│   ├── sign_json.c        # Already exists
│   ├── verify_json.c      # Already exists
│   └── export_pubkey.c    # Already exists
└── dna-p2p-bridge/
    └── keyserver-mirror/  # Optional Node.js mirror
        └── mirror.mjs
```

---

## Configuration File Format

**Location:** `/etc/dna/keyserver.conf`

```ini
[server]
bind_address = 0.0.0.0
bind_port = 6773
rpc_public_key = <hex>      # Persistent Ed25519 key
rpc_secret_key = <hex>

[database]
host = localhost
port = 5432
dbname = dna_keyserver
user = keyserver
password = <password>
pool_size = 10

[security]
max_timestamp_skew = 3600   # 1 hour
rate_limit_publish = 10     # per IP per minute
rate_limit_lookup = 100     # per IP per minute
verify_json_path = /opt/dna-messenger/build/verify_json
verify_timeout = 5          # seconds

[logging]
level = info                # debug, info, warn, error
file = /var/log/dna/keyserver.log
max_size = 100M
rotate = 7                  # days

[mirror]
enabled = false             # Enable Node.js mirror
postgres_notify = true      # Use LISTEN/NOTIFY
```

---

## Advantages of C Implementation

### 1. Performance
- **5-10x faster** than Node.js for lookup
- **2-5x faster** for publish (signature verification bottleneck)
- **Lower latency** - No GC pauses

### 2. Memory Efficiency
- **10x less memory** than Node.js
- No V8 heap overhead
- Better for embedded systems

### 3. Security
- **Memory safety** - Explicit bounds checking
- **No prototype pollution** - C has no prototype chain
- **Smaller attack surface** - No npm dependencies

### 4. Integration
- **Same language** as main messenger (C)
- **Use existing utilities** - sign_json, verify_json, export_pubkey
- **PostgreSQL integration** - Same database as messenger

### 5. Deployment
- **Single binary** - No Node.js installation required
- **Static linking** - No dependency hell
- **Systemd integration** - Easy to manage as service

---

## Disadvantages vs Node.js

### 1. Development Time
- **Longer** - C is more verbose than JavaScript
- **More boilerplate** - Manual memory management

### 2. Ecosystem
- **Fewer libraries** - Node.js has npm
- **Manual implementations** - JSON parsing, HTTP, etc.

### 3. Hypercore Integration
- **No native support** - Would need Node.js mirror OR custom protocol
- **Lose P2P benefits** - If no mirror daemon

---

## Decision Matrix

| Factor | Weight | Node.js | C + PostgreSQL | C + Custom DHT |
|--------|--------|---------|----------------|----------------|
| Performance | 3 | 6 | 9 | 9 |
| Memory | 2 | 5 | 9 | 9 |
| Dev time | 3 | 9 | 7 | 4 |
| P2P features | 2 | 10 | 8 (with mirror) | 6 |
| Security | 3 | 7 | 9 | 8 |
| Maintainability | 2 | 8 | 7 | 5 |
| **Total** | | **114** | **125** | **103** |

**Winner:** ✅ **C + PostgreSQL + Optional Mirror**

---

## Next Steps

1. ✅ Complete this design document
2. [ ] Get user approval on architecture
3. [ ] Set up PostgreSQL schema
4. [ ] Implement C RPC server (minimal version)
5. [ ] Implement lookup method
6. [ ] Implement publish method
7. [ ] Add signature verification
8. [ ] Write tests
9. [ ] Deploy alongside Node.js keyserver
10. [ ] Migrate clients

---

## References

- **Current Node.js Implementation:** `/opt/dna-messenger/dna-p2p-bridge/bcpunk-server/keyserver.mjs`
- **C Utilities Documentation:** `/opt/dna-messenger/C-UTILITIES-FOR-KEYSERVER.md`
- **Hypercore Architecture:** `/opt/dna-messenger/HYPERCORE-TRANSPORT-ARCHITECTURE.md`
- **libsodium Documentation:** https://doc.libsodium.org/
- **PostgreSQL libpq:** https://www.postgresql.org/docs/current/libpq.html
- **json-c Documentation:** https://json-c.github.io/json-c/

---

**END OF DESIGN DOCUMENT**
