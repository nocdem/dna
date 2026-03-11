# Nodus Version Enforcement — Plan

**Status:** PLANNED (not started)
**Date:** 2026-03-10
**Priority:** Medium — implement before next breaking protocol change

## Problem

Nodus servers have no version checking. There's no way to:
1. Force operators to upgrade their nodus instances when critical fixes ship
2. Reject peers running incompatible protocol versions
3. Know what version a connected peer is running

## Two Features

### 1. Self Version Check (DHT minimum enforcement)

Same pattern as the messenger app: nodus-server checks the DHT-published `nodus_minimum` version on startup and periodically.

**Behavior:**
- On startup, fetch `dna:system:version` from DHT
- Compare local `NODUS_VERSION_STRING` against `nodus_minimum`
- If local < minimum: log a CRITICAL warning and **shut down**
- Re-check periodically (e.g. every 6 hours) so a newly published minimum takes effect without restart
- Grace period: 5 minutes after detecting below-minimum before shutdown (allows in-flight operations to complete)

**Implementation:**
- Add `nodus_version_check()` function in `src/server/` or new `src/version/`
- Uses existing nodus client SDK to GET the version DHT key
- Parse JSON, compare versions (reuse `compare_versions` pattern from messenger)
- Call from `nodus_server_run()` after initial bootstrap
- Add periodic timer in server event loop

### 2. Peer Version Handshake

During TCP connection setup (Tier 2 auth), peers exchange version info. Incompatible peers are rejected.

**Wire protocol change:**
- The auth handshake already has a challenge/response. Extend the auth_response (or add a new message after auth) to include:
  - `version_major`, `version_minor`, `version_patch` (3 bytes)
  - `min_version_major`, `min_version_minor`, `min_version_patch` (3 bytes, what this node requires of peers)

**Behavior:**
- After auth succeeds, both sides exchange version info
- If peer version < our `NODUS_MIN_PEER_VERSION`: disconnect with error code
- If our version < peer's minimum: disconnect (peer will reject us anyway)
- Log version of every connected peer for diagnostics
- `servers` CLI command should show peer versions

**Constants to add in `nodus_types.h`:**
```c
#define NODUS_MIN_PEER_VERSION_MAJOR 0
#define NODUS_MIN_PEER_VERSION_MINOR 6
#define NODUS_MIN_PEER_VERSION_PATCH 0
```

**Implementation files:**
- `nodus_types.h` — min peer version constants
- `nodus_tier2.c` — version exchange in auth flow
- `nodus_server.c` — version check on accept, logging
- `nodus_client.c` — send version during connect
- `nodus_auth.c` — integrate with auth handshake

### Backward Compatibility

This is a **breaking change** for the wire protocol — old peers won't send version info. Strategy:
1. First release: add version exchange as optional (don't reject peers that don't send it)
2. Second release: make version exchange mandatory, reject peers without it
3. This gives operators one release cycle to upgrade

## Dependencies

- DHT version publishing (already exists — `dna:system:version` key)
- Wire protocol version bump (header version byte: current is 1, bump to 2)

## Files to Modify

| File | Change |
|------|--------|
| `include/nodus/nodus_types.h` | Add min peer version constants, bump wire version |
| `src/server/nodus_server.c` | Startup version check, periodic re-check |
| `src/protocol/nodus_tier2.c` | Version exchange in auth flow |
| `src/server/nodus_auth.c` | Reject incompatible peers |
| `src/client/nodus_client.c` | Send version during connect |
| `tools/nodus-server.c` | CLI flag to skip version check (for testing) |
| `tools/nodus-cli.c` | Show peer versions in `servers` command |
