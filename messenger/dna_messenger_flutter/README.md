# DNA Connect — Flutter App

Cross-platform UI for DNA Connect built with Flutter and Dart.

**Current Version:** v1.0.0-rc1

## Platforms

| Platform | Status |
|----------|--------|
| Android | Production |
| Linux | Production |
| Windows | Production |
| iOS | Planned |

## Quick Start

Requires the C library to be built first:

```bash
# Build C library
cd ../build && cmake .. && make -j$(nproc)

# Run Flutter app
cd ../dna_messenger_flutter
flutter pub get && flutter run
```

## Build

```bash
flutter build linux      # Linux desktop
flutter build apk        # Android APK
flutter build appbundle  # Android App Bundle (Play Store)
```

## Architecture

The Flutter app connects to the DNA Connect C library via `dart:ffi`:

- **FFI bindings:** `lib/ffi/dna_bindings.dart` — Hand-written C bindings
- **Dart wrapper:** `lib/ffi/dna_engine.dart` — Converts C callbacks to Futures/Streams
- **State management:** Riverpod providers in `lib/providers/`
- **Platform abstraction:** `lib/platform/` — Android vs Desktop handlers
- **Icons:** Font Awesome only (`FaIcon(FontAwesomeIcons.xxx)`)

## Documentation

See [docs/FLUTTER_UI.md](../docs/FLUTTER_UI.md) for comprehensive documentation including:
- Screen architecture and navigation
- FFI bindings to the C library
- State management (Riverpod)
- Platform-specific handling

## License

This Flutter application is [source-available (proprietary)](LICENSE).

The underlying C library and cryptographic libraries are licensed under [Apache 2.0](../LICENSE).
