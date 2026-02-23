# Wallet Screen UI Enhancement - Design Document

**Date:** 2026-02-23
**Status:** Approved

## Context

The wallet screen is the weakest visual link after the Trust Wallet-style UI redesign. It uses plain `ListTile` rows and a basic `AppBar` with no visual hierarchy. This enhancement brings it in line with the new design system.

## Key Constraint

Single wallet per identity. One identity derives addresses on multiple chains (Cellframe, Ethereum, Solana, TRON). No multi-wallet selector needed.

## Design

### 1. Gradient Hero Card

Full-width card with `DnaGradients.primary` background:
- "My Wallet" label (small, white)
- Identity name (large, bold, white) from `getDisplayName()`
- Row of chain logo icons (ETH, SOL, CELL, TRX SVGs)
- Rounded corners (radiusLg: 16), subtle shadow

### 2. Action Buttons Row

Two circular buttons centered below the hero card:
- **Send** (arrow-up icon) - gradient border, opens send sheet
- **Receive** (arrow-down icon) - gradient border, opens receive sheet
- Label text below each circle

### 3. Assets List

Section header "Assets" with token count. Each token rendered as `DnaCard`:
- Left: 40px SVG token icon (fallback: colored initial CircleAvatar)
- Center: Token name (bold) + network label chip (CF20, ERC20, SPL, TRC20)
- Right: Balance amount (bold) + chevron
- Tap opens upgraded token detail sheet
- Respects hideZeroBalances setting

### 4. Token Detail Sheet (Full Upgrade)

- Gradient header band with token icon + balance + network label
- Address section with copy button (styled container)
- `DnaButton.primary()` gradient Send button
- Transaction list with DnaCard items (direction arrows, status chips)
- Better empty state with icon + message
- Pull-to-refresh for balance + transactions

## Components Used

From existing design system:
- `DnaGradients.primary`, `DnaGradients.primaryShader`
- `DnaCard`, `DnaButton`, `DnaChip`, `DnaAppBar`
- `DnaColors` semantic colors for status chips
- `DnaSpacing` for consistent layout
- `DnaSkeleton` for loading states

## Files Changed

- `lib/screens/wallet/wallet_screen.dart` — Full rewrite of main screen + detail sheet
