# Archive Directory

This directory contains deprecated legacy code that is no longer actively maintained.

## Contents

### legacy-gui/
**Qt5 GUI (DEPRECATED)**
- Status: Archived as of 2025-11-21
- Replaced by: ImGui GUI (`imgui_gui/`)
- Reason: ImGui provides better cross-platform support, simpler codebase, and faster development
- Last working version: v0.8.x
- **Do not use for new development**

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
4. **Focus development** - All new work goes into ImGui GUI

## Migration Guide

### For Qt5 GUI Users
If you were using the old Qt5 GUI:
1. Switch to ImGui GUI: `./build/imgui_gui/dna_messenger_imgui`
2. All features are available in the new GUI
3. Settings and data are preserved (same database format)

### For CLI Tool Users
If you were using legacy CLI tools directly:
1. Use the ImGui GUI instead (provides all functionality)
2. Or use the DNA Messenger API (`dna_api.h`) for programmatic access
3. CLI functionality is still available via internal functions in `dna_lib`

## Build System

Legacy-tools has been removed from the build. Functions have been moved to appropriate modules:
- Key restoration: `messenger/keygen.c`
- Public key export: `crypto/utils/qgp_key.c`
- File I/O: `crypto/utils/qgp_platform_*.c` (all platforms)

---

**Last Updated:** 2026-01-01
**Status:** legacy-tools REMOVED, legacy-gui archived
