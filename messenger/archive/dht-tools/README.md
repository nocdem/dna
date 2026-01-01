# DHT Debug Tools (ARCHIVED)

This directory contains standalone DHT debug tools that were removed from the main build.

## Tools

### clear_outbox.c
Clears a specific sender's outbox for a recipient from the DHT.
```bash
./clear_outbox <sender_fingerprint> <recipient_fingerprint>
```

### query_outbox.c
Queries and displays messages from a specific sender's outbox.
```bash
./query_outbox <sender_fingerprint> <recipient_fingerprint>
```

### quick_lookup.c
Quick profile lookup tool for debugging DHT identity data.
```bash
./quick_lookup <name_or_fingerprint>
```

## Status

**ARCHIVED:** 2026-01-01

These tools were moved to archive because:
1. CLI tool (`dna-messenger-cli`) provides equivalent functionality
2. Not needed in normal builds
3. Cluttered the main dht/ directory

## Replacement

Use `dna-messenger-cli` instead:
- `lookup-profile <name|fp>` - Equivalent to quick_lookup
- DHT outbox operations available via internal API

## Building (if needed)

These tools are not built automatically. To build manually:
```bash
cd build
cmake -DBUILD_DHT_TOOLS=ON ..
make quick_lookup clear_outbox query_outbox
```

Note: CMake targets not currently defined - would need to add back to dht/CMakeLists.txt.
