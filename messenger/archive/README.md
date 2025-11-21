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
**Legacy CLI Tools**
- Status: Archived as of 2025-11-21
- Contains: keygen, sign, verify, encrypt, decrypt, export, keyring, lookup_name, utils
- Replaced by: ImGui GUI provides all functionality through UI
- Still compiled: Yes (linked into `dna_lib` for internal use)
- **Do not use directly - use GUI instead**

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

Legacy code is still compiled as part of `dna_lib` (for internal use), but paths are updated:
```cmake
# CMakeLists.txt references
archive/legacy-tools/keygen.c
archive/legacy-tools/sign.c
# etc.
```

## Future

These components may be removed entirely in a future major version. If you depend on any of this code:
1. Migrate to ImGui GUI now
2. Or copy the code into your own project (it's open source)
3. Check ROADMAP.md for deprecation timeline

---

**Last Updated:** 2025-11-21
**Status:** Archived, not maintained
**Replacement:** ImGui GUI (`imgui_gui/`)
