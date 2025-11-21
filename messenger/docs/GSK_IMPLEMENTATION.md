# GSK (Group Symmetric Key) Implementation Guide

**Version:** 0.09  
**Date:** 2025-11-21  
**Status:** Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
4. [Implementation Details](#implementation-details)
5. [API Reference](#api-reference)
6. [Security Considerations](#security-considerations)
7. [Testing](#testing)
8. [Troubleshooting](#troubleshooting)

---

## Overview

### What is GSK?

GSK (Group Symmetric Key) is a **200x performance improvement** for group messaging in DNA Messenger. Instead of encrypting each message with Kyber1024 for every group member (O(N) complexity), GSK uses a single **AES-256 shared key** that all members possess (O(1) complexity).

### Key Benefits

- **Performance:** 100-member group: 500ms → 2ms per message (250x faster)
- **Scalability:** Constant encryption overhead regardless of group size
- **Security:** Post-quantum key distribution via Kyber1024 + Dilithium5
- **Forward/Backward Secrecy:** Automatic key rotation on member changes

### Performance Comparison

| Group Size | Before GSK (Kyber1024 per-member) | After GSK (AES-256) | Speedup |
|------------|-----------------------------------|---------------------|---------|
| 10 members | ~50ms | ~2ms | **25x** |
| 50 members | ~250ms | ~2ms | **125x** |
| 100 members | ~500ms | ~2ms | **250x** |

---

## Architecture

### GSK Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                    GSK Lifecycle                             │
├─────────────────────────────────────────────────────────────┤
│ 1. Owner generates random AES-256 key (GSK)                 │
│ 2. Owner builds Initial Key Packet:                         │
│    - Wraps GSK with each member's Kyber1024 pubkey          │
│    - Signs with owner's Dilithium5 privkey                  │
│ 3. Owner publishes to DHT (chunked if >50KB)                │
│ 4. Members poll DHT every 2 minutes (background)            │
│ 5. Members fetch, verify signature, unwrap GSK              │
│ 6. Messages encrypted with AES-256-GCM using GSK            │
│ 7. On member add/remove → rotate GSK (new version)          │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. GSK Manager (`messenger/gsk.c` - 658 LOC)

**Responsibilities:**
- Generate random 32-byte AES-256 keys
- Store GSKs in SQLite with versioning
- Load active (latest) GSK for encryption
- Rotate GSKs (increment version, generate new key)
- Expire old GSKs (7-day TTL)

**Database Schema:**
```sql
CREATE TABLE dht_group_gsks (
    group_uuid TEXT NOT NULL,
    gsk_version INTEGER NOT NULL,
    gsk BLOB NOT NULL,              -- 32 bytes (AES-256)
    created_at INTEGER NOT NULL,    -- Unix timestamp
    expires_at INTEGER NOT NULL,    -- created_at + 7 days
    PRIMARY KEY (group_uuid, gsk_version)
);
```

### 2. Initial Key Packet Builder (`messenger/gsk_packet.c` - 782 LOC)

**Packet Format:**
```
[Header: 42 bytes]
  group_uuid:    37 bytes
  version:        4 bytes
  member_count:   1 byte

[Per-Member Entry: 1672 bytes × N]
  fingerprint:   64 bytes
  kyber_ct:    1568 bytes
  wrapped_gsk:   40 bytes

[Signature: ~4630 bytes]
  Dilithium5 signature

Total: 42 + (1672 × N) + 4630 bytes
```

### 3. DHT Chunked Storage (`dht/shared/dht_gsk_storage.c` - 765 LOC)

50KB chunks, sequential DHT keys, 7-day TTL

### 4. Group Ownership Transfer (`messenger/group_ownership.c` - 595 LOC)

7-day liveness check, deterministic transfer via highest SHA3-512(fingerprint)

### 5. Background Discovery (`imgui_gui/helpers/background_tasks.cpp` - 302 LOC)

2-minute polling for GSK updates and liveness checks

---

## Implementation Details

### Key Wrapping Process

Two-layer encryption:

1. **Kyber1024 Encapsulation** (quantum-resistant)
2. **AES Key Wrapping** (RFC 3394)

```c
// Owner
(kyber_ct, KEK) = kyber1024_encap(member_pubkey)
wrapped_gsk = aes_keywrap(KEK, GSK)

// Member
KEK = kyber1024_decap(kyber_ct, my_privkey)
GSK = aes_keyunwrap(KEK, wrapped_gsk)
```

---

## API Reference

### GSK Manager

```c
int gsk_generate(const char *group_uuid, uint32_t version, uint8_t gsk_out[32]);
int gsk_store(const char *group_uuid, uint32_t version, const uint8_t gsk[32]);
int gsk_load_active(const char *group_uuid, uint8_t gsk_out[32], uint32_t *version_out);
int gsk_rotate(const char *group_uuid, uint32_t *new_version_out, uint8_t new_gsk_out[32]);
```

### Packet Builder

```c
int gsk_packet_build(const char *group_uuid, uint32_t version, 
                     const uint8_t gsk[32], const gsk_member_entry_t *members, 
                     size_t member_count, const uint8_t *owner_dilithium_privkey,
                     uint8_t **packet_out, size_t *packet_size_out);

int gsk_packet_extract(const uint8_t *packet, size_t packet_size,
                       const uint8_t *my_fingerprint_bin, const uint8_t *my_kyber_privkey,
                       uint8_t gsk_out[32], uint32_t *version_out);
```

### DHT Storage

```c
int dht_gsk_publish(dht_context_t *ctx, const char *group_uuid, uint32_t version,
                    const uint8_t *packet, size_t packet_size);

int dht_gsk_fetch(dht_context_t *ctx, const char *group_uuid, uint32_t version,
                  uint8_t **packet_out, size_t *packet_size_out);
```

---

## Security Considerations

### Post-Quantum Security (NIST Category 5)

- **Kyber1024** (ML-KEM-1024) - Key encapsulation
- **Dilithium5** (ML-DSA-87) - Signatures
- **AES-256-GCM** - Symmetric encryption

### Forward/Backward Secrecy

- Member removed → GSK rotated (forward secrecy)
- Member added → GSK rotated (backward secrecy)
- Old GSKs expire after 7 days

---

## Testing

### Unit Tests (57 Total)

```
test_gsk_simple:   3/3 tests ✓
test_gsk:        54/54 tests ✓
─────────────────────────────
TOTAL:           57/57 tests ✓
```

**Running:**
```bash
cd /opt/dna-messenger/build
rm -f ~/.dna/messages.db  # Clean database
./test_gsk_simple
./test_gsk
```

---

## Troubleshooting

### Common Issues

**1. GSK Not Found**
- Check background polling is running
- Verify DHT connectivity
- Manually trigger: `pollGSKDiscovery()`

**2. Signature Verification Failed**
- Verify owner's public key in keyserver
- Check packet not corrupted
- Ensure all chunks reassembled

**3. Kyber Decapsulation Failed**
- Verify fingerprint in member list
- Check key file: `~/.dna/{fingerprint}.kem` (3168 bytes)

**4. Owner Transfer Not Occurring**
- Check background thread running
- Verify 2-minute polling interval
- Manually trigger: `checkOwnershipLiveness()`

### Debug Logging

Enable in source files:
```c
#define GSK_DEBUG 1        // In messenger/gsk.c
#define GSK_PACKET_DEBUG 1 // In messenger/gsk_packet.c
```

---

## File Locations

```
/opt/dna-messenger/
├── messenger/
│   ├── gsk.{c,h}                # GSK manager (658 LOC)
│   ├── gsk_packet.{c,h}         # Packet builder (782 LOC)
│   └── group_ownership.{c,h}    # Ownership (595 LOC)
├── dht/shared/
│   └── dht_gsk_storage.{c,h}    # DHT chunking (765 LOC)
├── imgui_gui/helpers/
│   └── background_tasks.{cpp,h} # Polling (302 LOC)
└── tests/
    ├── test_gsk.c               # 54 tests (408 LOC)
    └── test_gsk_simple.c        # 3 tests (84 LOC)
```

---

**Total Implementation:** ~2800 LOC  
**Test Coverage:** 57/57 tests passing  
**Status:** Production Ready

**For issues:** https://github.com/nocdem/dna-messenger/issues
