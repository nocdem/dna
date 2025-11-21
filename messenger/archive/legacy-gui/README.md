# Legacy Qt5 GUI (DEPRECATED)

**Status:** DEPRECATED - Archived 2025-11-18

**Replacement:** ImGui GUI (`/imgui_gui/` directory)

---

## Overview

This directory contains the original Qt5-based GUI implementation for DNA Messenger. It has been **deprecated and replaced** with the ImGui-based GUI (`/imgui_gui/`).

**This code is preserved for reference only and is NOT maintained.**

---

## Why Deprecated?

The Qt5 GUI was replaced with ImGui for several reasons:

1. **Cross-Platform:** ImGui provides better cross-platform support (Linux/Windows/macOS)
2. **Performance:** ImGui is lightweight and faster than Qt5
3. **Modern UI:** ImGui allows for more flexible and modern UI designs
4. **Smaller Binary:** Removes Qt5 dependencies (~50MB reduction)
5. **Active Development:** ImGui GUI is actively maintained and receives new features

---

## Contents

- **gui/** - Original Qt5 GUI implementation (29 files)
  - MainWindow.cpp - Main application window
  - WalletDialog.cpp - Wallet management UI
  - MessageWallDialog.cpp - Wall posts UI (deprecated)
  - RegisterDNANameDialog.cpp - Name registration UI
  - ReceiveDialog.cpp - Receive UI with QR codes
  - Various dialog and widget implementations

---

## Migration Complete

All Qt5 GUI features have been migrated to ImGui:

| Feature | Qt5 (Deprecated) | ImGui (Active) | Status |
|---------|------------------|----------------|--------|
| Identity Selection | MainWindow | identity_selection_screen.cpp | ✅ Complete |
| Chat Interface | MainWindow | chat_screen.cpp | ✅ Complete |
| Wallet Management | WalletDialog | wallet_screen.cpp | ✅ Complete |
| Wallet Send | WalletDialog | wallet_send_dialog.cpp | ✅ Complete |
| Wallet Receive | ReceiveDialog | wallet_receive_dialog.cpp | ✅ Complete |
| TX History | WalletDialog | wallet_transaction_history_dialog.cpp | ✅ Complete |
| Contacts List | MainWindow | contacts_sidebar.cpp | ✅ Complete |
| Add Contact | MainWindow | add_contact_dialog.cpp | ✅ Complete |
| Wall Posts | MessageWallDialog | message_wall_screen.cpp | ✅ Complete |
| Profile Editor | - | profile_editor_screen.cpp | ✅ Complete |
| Name Registration | RegisterDNANameDialog | register_name_screen.cpp | ✅ Complete |
| Settings | - | settings_screen.cpp | ✅ Complete |
| Group Invitations | - | chat_screen.cpp | ✅ Complete |
| Avatar System | - | profile_editor_screen.cpp | ✅ Complete |
| Community Voting | - | message_wall_screen.cpp | ✅ Complete |

---

## DO NOT USE

**⚠️ WARNING:** This code is NOT maintained and may contain:
- Outdated APIs
- Security vulnerabilities
- Incompatibilities with current backend
- Missing features (Phase 5.6+)

**DO NOT modify or build from this directory.**

---

## For Developers

If you need to reference the old Qt5 implementation:

1. **DO NOT** try to build or run this code
2. **DO** use it as reference for understanding legacy design decisions
3. **DO** port any missing features to the active ImGui GUI (`/imgui_gui/`)

---

## Active Development

**Current GUI:** `/imgui_gui/` (ImGui + OpenGL3 + GLFW3)

**Run the active GUI:**
```bash
cd /opt/dna-messenger
mkdir -p build && cd build
cmake .. && make -j$(nproc)
./imgui_gui/dna_messenger_imgui
```

---

**Archived:** 2025-11-18
**Last Active Version:** v0.1.120 (prior to Phase 10 completion)
