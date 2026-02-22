# UI Redesign — Trust Wallet Style

**Date:** 2026-02-23
**Status:** Approved
**Approach:** Design System First, then apply across screens

---

## Design Decisions

| Decision | Choice |
|----------|--------|
| **Navigation** | Bottom tabs (4) + More tab |
| **Main tabs** | Chats, Groups, Feed, More |
| **More tab contains** | Wallet, QR Scanner, Address Book, Starred, Blocked, Contact Requests, Settings, App Lock, Debug Log |
| **Color palette** | Cyan-to-Blue gradient (`#00D4FF` → `#0066FF`) |
| **Theme modes** | Both dark + light |
| **Visual style** | Full polish — cards, shadows, gradients, animations |
| **Approach** | Design System First — build component library, then apply |

---

## Color System

### Dark Theme

| Token | Color | Usage |
|-------|-------|-------|
| `background` | `#0A0E1A` | Main background (deep navy) |
| `surface` | `#131829` | Cards, sheets, elevated surfaces |
| `surfaceVariant` | `#1A2035` | Secondary cards, input fields |
| `primary` | Gradient `#00D4FF` → `#0066FF` | Buttons, active tabs, accents |
| `primaryFixed` | `#0066FF` | Solid fallback when gradient not possible |
| `onPrimary` | `#FFFFFF` | Text/icons on primary buttons |
| `text` | `#F0F2FA` | Primary text |
| `textSecondary` | `#8B95B8` | Muted/secondary text |
| `divider` | `#FFFFFF0F` | 6% white borders |
| `success` | `#34D399` | Online, sent, success states |
| `error` | `#EF4444` | Errors, destructive actions |
| `warning` | `#F59E0B` | Warnings, pending states |

### Light Theme

| Token | Color | Usage |
|-------|-------|-------|
| `background` | `#F5F7FA` | Light gray background |
| `surface` | `#FFFFFF` | White cards |
| `surfaceVariant` | `#EEF1F6` | Secondary surfaces |
| `primary` | Same gradient `#00D4FF` → `#0066FF` | Consistent brand |
| `text` | `#0F172A` | Dark text on light |
| `textSecondary` | `#64748B` | Muted text |
| `divider` | `#0000000F` | 6% black borders |

---

## Component Library

### Core Components

| Component | File | Description |
|-----------|------|-------------|
| `DnaCard` | `dna_card.dart` | Card with shadow + border radius, elevation levels (0-3), optional gradient header |
| `DnaButton` | `dna_button.dart` | Primary (gradient fill), secondary, ghost variants. Loading state. |
| `DnaIconButton` | `dna_icon_button.dart` | Circular icon button — solid, outlined, ghost. Badge overlay. |
| `DnaAvatar` | `dna_avatar.dart` | Rounded avatar, initials fallback, online status dot, sizes (sm/md/lg) |
| `DnaListTile` | `dna_list_tile.dart` | List row — leading icon/avatar, title+subtitle, trailing, swipe actions |
| `DnaChip` | `dna_chip.dart` | Tag/filter chip, selected state with gradient, count badge |
| `DnaBadge` | `dna_badge.dart` | Notification count badge, animated entrance |
| `DnaBottomSheet` | `dna_bottom_sheet.dart` | Modal bottom sheet, drag handle, rounded corners, backdrop blur |
| `DnaSkeleton` | `dna_skeleton.dart` | Loading placeholder with shimmer animation |
| `DnaSnackBar` | `dna_snack_bar.dart` | Toast with semantic colors |

### Navigation Components

| Component | File | Description |
|-----------|------|-------------|
| `DnaBottomBar` | `dna_bottom_bar.dart` | 4 tabs + active gradient icon/label, inactive muted, badge support |
| `DnaAppBar` | `dna_app_bar.dart` | Top bar with title, optional gradient background, actions |
| `DnaMoreMenu` | `dna_more_menu.dart` | Grid of feature cards + list of settings items |

### Input Components

| Component | File | Description |
|-----------|------|-------------|
| `DnaTextField` | `dna_text_field.dart` | Filled input, focus ring with gradient border |
| `DnaSearchBar` | `dna_search_bar.dart` | Search with icon, debounce, clear button |
| `DnaSwitch` | `dna_switch.dart` | Toggle with gradient track when on |

### Feedback Components

| Component | File | Description |
|-----------|------|-------------|
| `DnaDialog` | `dna_dialog.dart` | Confirmation/alert, rounded corners, blur backdrop |

---

## Modular File Architecture

```
lib/
├── design_system/
│   ├── theme/
│   │   ├── dna_colors.dart           # Color tokens (dark + light)
│   │   ├── dna_theme.dart            # ThemeData builder
│   │   ├── dna_typography.dart       # Text styles
│   │   ├── dna_spacing.dart          # Padding/margin constants
│   │   └── dna_gradients.dart        # Gradient definitions
│   ├── components/
│   │   ├── dna_card.dart
│   │   ├── dna_button.dart
│   │   ├── dna_icon_button.dart
│   │   ├── dna_avatar.dart
│   │   ├── dna_list_tile.dart
│   │   ├── dna_chip.dart
│   │   ├── dna_badge.dart
│   │   ├── dna_bottom_sheet.dart
│   │   ├── dna_skeleton.dart
│   │   └── dna_snack_bar.dart
│   ├── navigation/
│   │   ├── dna_bottom_bar.dart
│   │   ├── dna_app_bar.dart
│   │   └── dna_more_menu.dart
│   ├── inputs/
│   │   ├── dna_text_field.dart
│   │   ├── dna_search_bar.dart
│   │   └── dna_switch.dart
│   └── design_system.dart            # Barrel export
│
├── screens/                          # Each screen = folder
│   ├── chats/
│   │   ├── chats_screen.dart
│   │   └── widgets/
│   │       ├── chat_list_item.dart
│   │       ├── chat_search.dart
│   │       └── unread_indicator.dart
│   ├── chat/
│   │   ├── chat_screen.dart
│   │   └── widgets/
│   │       ├── message_bubble.dart
│   │       ├── message_input.dart
│   │       ├── emoji_bar.dart
│   │       └── image_message.dart
│   ├── groups/
│   │   ├── groups_screen.dart
│   │   └── widgets/
│   ├── feed/
│   │   ├── feed_screen.dart
│   │   └── widgets/
│   ├── wallet/
│   │   ├── wallet_screen.dart
│   │   └── widgets/
│   ├── settings/
│   │   ├── settings_screen.dart
│   │   └── widgets/
│   ├── more/
│   │   └── more_screen.dart
│   └── home/
│       └── home_screen.dart
│
├── providers/                        # Stays as-is
├── platform/                         # Stays as-is
├── utils/                            # Stays as-is
└── main.dart
```

**Principles:**
- One widget per file
- Screen-specific widgets in screen's `widgets/` folder
- Design system importable with: `import 'package:dna_messenger/design_system/design_system.dart';`
- Barrel export re-exports all components

---

## Navigation Structure

### Bottom Tab Bar (4 tabs)

| Tab | Icon | Badge |
|-----|------|-------|
| Chats | `FontAwesomeIcons.solidComment` | Unread count |
| Groups | `FontAwesomeIcons.userGroup` | Unread count |
| Feed | `FontAwesomeIcons.newspaper` | None |
| More | `FontAwesomeIcons.ellipsis` | None |

- Active tab: gradient icon + label, subtle indicator line
- Inactive: muted gray icon + label

### More Screen Contents

**Grid section (feature cards):**
- Wallet, QR Scanner, Address Book, Starred Messages, Blocked Users, Contact Requests

**List section (settings):**
- Settings, App Lock, Debug Log

### Screen Pattern

```
DnaAppBar → Title, optional actions (search, add)
Content  → Scrollable body with pull-to-refresh
DnaBottomBar → Persistent across all main screens
```

- FAB on Chats (new chat), Groups (new group), Feed (new post)
- Search integrated into app bar

---

## Screen Redesign Notes

### Chats
- Card-style list tiles with DnaAvatar, preview text, timestamp, unread DnaBadge
- Collapsible DnaSearchBar at top
- Swipe actions (delete, pin, mute)
- Online status: green dot on avatar with subtle glow

### Chat (Conversation)
- Rounded bubbles with shadows, gradient accent on sent messages
- Polished input bar with attachment, emoji, gradient send button
- Image messages with rounded corners, tap to fullscreen

### Groups
- Card tiles with group avatar (multi-member mosaic), member count badge
- FAB → bottom sheet for group creation

### Feed
- Card-based topic feed with vote buttons, comment counts
- Horizontal scrollable DnaChip filters (Subscribed, All, Official)

### Wallet (in More)
- Large balance card with gradient background
- Token list with crypto icons and price info
- Action row: Send, Receive, Swap buttons

### Settings (in More)
- Grouped sections with DnaCard containers
- Profile card at top with avatar, name, fingerprint
- DnaSwitch toggles with gradient track

### Identity Selection / Onboarding
- Welcome screen with gradient background, large logo
- Smooth animation into identity create/restore flow

---

## What Stays Unchanged

- All Riverpod providers
- All FFI bindings (C library interaction)
- All business logic and data flow
- Platform handlers (Android/Desktop)
- Font Awesome icons (restyled, not replaced)
