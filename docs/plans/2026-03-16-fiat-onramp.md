# Fiat On-Ramp — Buy Crypto with Card/Bank Transfer

**Date:** 2026-03-16
**Status:** PLANNED (next week)
**Priority:** HIGH

## Overview

Add "Buy" button to wallet screen. Opens WebView to fiat on-ramp provider. User buys crypto with card/bank transfer → crypto lands directly in their DNA Connect wallet.

## Recommended Provider: Transak

- 64+ countries (Turkey included)
- Credit/debit card + bank transfer
- 136+ cryptocurrencies
- 1-5% fee (provider takes it, not us)
- Non-custodial friendly — sends directly to user's address
- Free API key (revenue share model)
- WebView integration (no SDK needed)

**Backup:** Onramper (aggregator, 30+ providers, best price auto-select)

## Implementation

### 1. Get API Key
- Sign up at transak.com/dashboard
- Get staging key (test mode)
- Get production key after review (~1-2 days)

### 2. Flutter Changes

#### Buy Button in Wallet Screen
```dart
// In _TokenDetailSheet or wallet header
DnaButton(
  label: 'Buy',
  icon: FontAwesomeIcons.creditCard,
  onPressed: () => _openBuyCrypto(context, network, token, address),
)
```

#### WebView Screen
```dart
class BuyCryptoScreen extends StatelessWidget {
  final String walletAddress;
  final String cryptoCode;    // USDT, ETH, SOL, etc.
  final String network;       // ethereum, solana, tron

  String get transakUrl =>
    'https://global.transak.com/?apiKey=$apiKey'
    '&cryptoCurrencyCode=$cryptoCode'
    '&network=$network'
    '&walletAddress=$walletAddress'
    '&disableWalletAddressForm=true'
    '&hideMenu=true'
    '&themeColor=6C63FF';  // DNA purple

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Buy $cryptoCode')),
      body: WebViewWidget(
        controller: WebViewController()
          ..setJavaScriptMode(JavaScriptMode.unrestricted)
          ..loadRequest(Uri.parse(transakUrl)),
      ),
    );
  }
}
```

#### Network Mapping
```dart
const transakNetworks = {
  'Ethereum': 'ethereum',
  'Solana': 'solana',
  'Tron': 'tron',
  // Cellframe/Backbone: not supported by Transak (DEX only)
};
```

### 3. Token Support
| Token | Network | Transak Support |
|-------|---------|----------------|
| USDT | Ethereum, Solana, Tron | ✅ |
| USDC | Ethereum, Solana | ✅ |
| ETH | Ethereum | ✅ |
| SOL | Solana | ✅ |
| TRX | Tron | ✅ |
| CPUNK | Cellframe | ❌ (DEX/Bitcointry only) |

### 4. UX Flow
```
Wallet Screen → Tap USDT → Token Detail
  → "Buy USDT" button
  → Opens WebView (Transak)
  → User enters amount, picks payment method
  → Card/bank payment processed by Transak
  → USDT sent to user's DNA Connect wallet address
  → User returns to app, balance refreshes
```

### 5. Sell (Off-Ramp) — Phase 2
Transak also supports selling crypto → fiat to bank account.
Same WebView, different mode parameter.

## Dependencies
- `webview_flutter` package (or `flutter_inappwebview`)
- Transak API key
- No C changes needed
- No nodus changes needed

## Files to Create/Modify
- `lib/screens/wallet/buy_crypto_screen.dart` — NEW: WebView wrapper
- `lib/screens/wallet/wallet_screen.dart` — Add "Buy" button
- `pubspec.yaml` — Add webview_flutter dependency
- `android/app/src/main/AndroidManifest.xml` — INTERNET permission (already have)

## Effort
~1 day Flutter + 1-2 days API key approval

## Security Notes
- No user credentials touch our servers
- Card data handled entirely by Transak (PCI compliant)
- Wallet address is the only data sent to Transak
- Non-custodial: funds go directly to user's address
- No KYC data stored by DNA Connect
