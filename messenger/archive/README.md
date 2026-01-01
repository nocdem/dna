# Archive Directory

This directory contains deprecated legacy code that is no longer actively maintained.

## Contents

### imgui_gui/
**ImGui Desktop GUI (DEPRECATED)**
- Status: Archived as of 2026-01-01
- Replaced by: Flutter UI (`dna_messenger_flutter/`)
- Reason: Flutter provides better cross-platform support, native mobile apps, and modern UI
- **Do not use for new development**

### legacy-gui/
**Qt5 GUI (DEPRECATED)**
- Status: Archived as of 2025-11-21
- Replaced by: ImGui GUI (now also deprecated) → Flutter UI
- Reason: ImGui provided better cross-platform support at the time
- **Do not use for new development**

### dht-tools/
**DHT Debug Tools (ARCHIVED)**
- Status: Archived as of 2026-01-01
- Contains: quick_lookup.c, clear_outbox.c, query_outbox.c
- Replaced by: `dna-messenger-cli` tool (lookup-profile command)
- **For reference only - not built automatically**

### legacy-tools/
**Legacy CLI Tools (REMOVED)**
- Status: **DELETED** as of 2026-01-01
- Previously contained: keygen, sign, verify, encrypt, decrypt, export, keyring, lookup_name, utils
- Functions moved to:
  - `cmd_restore_key_from_seed` → `messenger/keygen.c`
  - `cmd_export_pubkey` → `crypto/utils/qgp_key.c`
  - `read_file_data/write_file_data` → `crypto/utils/qgp_platform_*.c`
  - All other functions were unused and removed

## Why Archived?

These components were moved to `archive/` to:
1. **Clean up root directory** - Reduce clutter and improve code organization
2. **Signal deprecation** - Make it clear these are not maintained
3. **Preserve history** - Keep code available for reference, but separate from active development
4. **Focus development** - All new work goes into Flutter UI

## Migration Guide

### For ImGui GUI Users
If you were using the ImGui GUI:
1. Switch to Flutter UI: `dna_messenger_flutter/`
2. All features are available in the new Flutter app
3. Settings and data are preserved (same database format)

### For CLI Tool Users
If you need CLI functionality:
1. Use `dna-messenger-cli` for testing and debugging
2. Or use the DNA Messenger API (`dna_api.h`) for programmatic access

## Build System

Archived components are NOT included in the main build:
- ImGui GUI: Standalone CMakeLists.txt (not linked from root)
- Legacy-tools: Functions moved to appropriate modules
- Legacy-gui: Qt5 dependencies no longer required

---

**Last Updated:** 2026-01-01
**Status:** imgui_gui archived, dht-tools archived, legacy-tools REMOVED, legacy-gui archived
